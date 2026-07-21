"""
VPN Detector 规则引擎 — 数据驱动，从 YAML 配置加载规则定义。

架构：
    RuleEngine.load_yaml() → 生成 RuleDef 列表
    RuleEngine.match(feature) → 遍历所有 RuleDef，调用对应检测函数
    检测函数按 category 组织，每个函数返回 (matched, evidence)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from .config import (
    BLOCK_SIZES,
    CHROME_JA4_PREFIX,
    DOMAIN_KEYWORDS,
    FAMOUS_ENTERPRISE_SNI,
    JA4_GOLANG_PATTERN,
    RISK_TLDS,
    SPECIAL_PORTS,
)
from .utils import (
    all_domains,
    compile_domain_regex,
    count_unique_tlds,
    detect_random_local_domains,
    extract_ja4_cipher_count,
    flatten_pairs,
    get_ports,
    match_domain_keywords,
    max_block_ratio,
    protocol_text,
)

# ── 类型别名 ──
Feature = Dict[str, Any]
DetectFunc = Callable[[Feature], Tuple[bool, str]]


@dataclass
class RuleDef:
    id: str
    category: str
    description: str
    confidence: int
    detect: DetectFunc
    enabled: bool = True


@dataclass
class RuleMatch:
    rule_id: str
    category: str
    confidence: int
    evidence: str


@dataclass
class ComboScores:
    tls_spoof: int = 0
    raw_encrypted: int = 0
    endpoint_behavior: int = 0
    dns_sni_anomaly: int = 0
    ja4_fingerprint: int = 0
    port_protocol: int = 0

    @property
    def total(self) -> int:
        return (
            self.tls_spoof
            + self.raw_encrypted
            + self.endpoint_behavior
            + self.dns_sni_anomaly
            + self.ja4_fingerprint
            + self.port_protocol
        )

    def to_dict(self) -> Dict[str, int]:
        return {
            "tls_spoof": self.tls_spoof,
            "raw_encrypted": self.raw_encrypted,
            "endpoint_behavior": self.endpoint_behavior,
            "dns_sni_anomaly": self.dns_sni_anomaly,
            "ja4_fingerprint": self.ja4_fingerprint,
            "port_protocol": self.port_protocol,
        }


# ═══════════════════════════════════════════
# 检测函数（按 category 组织）
# ═══════════════════════════════════════════


def _val(f: Feature, key: str, default: Any = 0) -> Any:
    v = f.get(key, default)
    return v if v is not None else default


def _safe_float(f: Feature, key: str) -> float:
    return float(_val(f, key, 0) or 0)


def _safe_int(f: Feature, key: str) -> int:
    return int(_val(f, key, 0) or 0)


# ── L3 协议 ──


def _detect_ipsec_esp(f: Feature) -> Tuple[bool, str]:
    ip_proto = _val(f, "ip_proto_counts", {}) or {}
    esp = int(ip_proto.get("50", 0) or 0)
    if esp > 0:
        return True, f"检测到 IP proto 50 (ESP)，ESP 包数={esp}"
    return False, ""


def _detect_ipsec_ah(f: Feature) -> Tuple[bool, str]:
    ip_proto = _val(f, "ip_proto_counts", {}) or {}
    ah = int(ip_proto.get("51", 0) or 0)
    if ah > 0:
        return True, f"检测到 IP proto 51 (AH)，AH 包数={ah}"
    return False, ""


def _detect_ipsec_esp_ah(f: Feature) -> Tuple[bool, str]:
    ip_proto = _val(f, "ip_proto_counts", {}) or {}
    esp = int(ip_proto.get("50", 0) or 0)
    ah = int(ip_proto.get("51", 0) or 0)
    if esp > 0 or ah > 0:
        return True, f"检测到 IP proto 50/51：ESP={esp}, AH={ah}"
    return False, ""


# ── L4 UDP ──


def _detect_ipsec_ike(f: Feature) -> Tuple[bool, str]:
    prot = protocol_text(f)
    if any(x in prot for x in ["isakmp", "ike", "ikev2"]):
        return True, "tshark 协议列解析出 ISAKMP/IKE/IKEv2"
    return False, ""


def _detect_ipsec_natt(f: Feature) -> Tuple[bool, str]:
    if f.get("esp_in_udp_like"):
        udp4500 = _safe_int(f, "udp4500_count")
        return True, f"UDP 4500 呈现 ESP-in-UDP 结构，udp4500_count={udp4500}"
    return False, ""


def _detect_wireguard_port(f: Feature) -> Tuple[bool, str]:
    ports = get_ports(f)
    if 51820 in ports:
        return True, f"检测到 WireGuard 端口 UDP 51820，计数={ports[51820]}"
    return False, ""


def _detect_wireguard_proto(f: Feature) -> Tuple[bool, str]:
    prot = protocol_text(f)
    if "wg" in prot:
        return True, "tshark 协议列解析出 WireGuard (wg) 协议"
    return False, ""


def _detect_openvpn(f: Feature) -> Tuple[bool, str]:
    ports = get_ports(f)
    hits = [p for p in [1194, 1195] if p in ports]
    if hits:
        return True, f"检测到 OpenVPN 常见端口：{hits}"
    return False, ""


# ── L4 TCP ──


def _detect_port_mismatch_3306(f: Feature) -> Tuple[bool, str]:
    ports = get_ports(f)
    block_1428 = _safe_float(f, "block_1428_ratio")
    prot = protocol_text(f)
    if 3306 in ports and block_1428 >= 0.50 and "mysql" not in prot:
        return True, f"TCP 3306 非 MySQL 协议，1428 字节固定块占比={block_1428:.2f}"
    return False, ""


def _detect_special_port_encrypted(f: Feature) -> Tuple[bool, str]:
    ports = get_ports(f)
    special_hits = sorted([p for p in ports if p in SPECIAL_PORTS])
    if not special_hits:
        return False, ""

    tls_count = _safe_int(f, "tls_clienthello_count")
    _, best_ratio = max_block_ratio(f)
    no_tls_large = _safe_int(f, "no_tls_large_flow_count")

    if tls_count > 0 or best_ratio >= 0.30 or no_tls_large > 0:
        return True, f"命中特殊端口 {special_hits}，且存在 TLS/固定块/大载荷加密流"
    return False, ""


def _detect_ssh_keepalive(f: Feature) -> Tuple[bool, str]:
    ssh_syn = _safe_int(f, "ssh_syn_count")
    ssh_periodic = f.get("ssh_syn_periodic", False)
    ports = get_ports(f)
    if ssh_periodic and ssh_syn > 20 and 22 not in ports:
        return True, f"检测到周期性 SSH 端口 22 SYN 探测，次数={ssh_syn}（SSR obfs-plugin 保活特征）"
    return False, ""


def _detect_p2p_dual_channel(f: Feature) -> Tuple[bool, str]:
    ports = get_ports(f)
    hola_ports = {22225, 22226}
    hits = [p for p in ports if p in hola_ports]
    if not hits:
        return False, ""

    tls_count = _safe_int(f, "tls_clienthello_count")
    no_tls_large = _safe_int(f, "no_tls_large_flow_count")
    nonstandard_tls = _safe_int(f, "nonstandard_tls_flow_count")

    if tls_count > 0 and no_tls_large > 0 and (nonstandard_tls > 0 or tls_count > 10):
        return True, f"Hola P2P 双通道：端口 {hits} 非 TLS 数据 + TLS 控制通道（ClientHello={tls_count}）"
    return False, ""


# ── TLS / JA4 指纹 ──

_DOMAIN_RE = compile_domain_regex(DOMAIN_KEYWORDS)


def _detect_vpn_domain_sni(f: Feature) -> Tuple[bool, str]:
    domains = all_domains(f)
    hits = match_domain_keywords(domains, _DOMAIN_RE)
    if hits:
        uniq = sorted(set(hits))[:10]
        return True, "DNS/SNI 命中 VPN 专属域名：" + ", ".join(uniq)
    return False, ""


def _detect_chrome_ja4_no_alpn(f: Feature) -> Tuple[bool, str]:
    ja4s = [str(x[0]) for x in flatten_pairs(f.get("ja4_top", []))]
    alpn_missing = _safe_float(f, "alpn_missing_ratio")
    tls_count = _safe_int(f, "tls_clienthello_count")

    if alpn_missing < 0.90 or tls_count == 0:
        return False, ""

    for ja4 in ja4s:
        if re.match(CHROME_JA4_PREFIX, ja4) and alpn_missing >= 0.90:
            return True, f"JA4 类 Chrome ({ja4}) 但 ALPN 缺失率={alpn_missing:.2f}，TLS 指纹伪造"
    return False, ""


def _detect_ja4_non_browser(f: Feature) -> Tuple[bool, str]:
    """JA4 非浏览器指纹检测。

    浏览器范围：Chrome≈15, Firefox≈13, Safari≈11-14, Edge≈15。
    VPN 特征：闪电(GOST) 19 密码套件 + 无 ALPN，番茄/GOST 17 密码套件 + 无 ALPN。
    正常非浏览器 TLS（iOS/Windows 系统库）密码套件数可达 20-30，但有 ALPN。
    因此：密码套件异常 + 无 ALPN 才触发；单纯密码套件数 >= 25 才独立触发。
    """
    ja4s = [str(x[0]) for x in flatten_pairs(f.get("ja4_top", []))]
    alpn_missing = _safe_float(f, "alpn_missing_ratio")
    tls_count = _safe_int(f, "tls_clienthello_count")

    for ja4 in ja4s:
        cc = extract_ja4_cipher_count(ja4)
        if cc is None:
            continue

        # 条件 A：>= 25 密码套件 + 无 ALPN（Windows 系统 TLS 也有 30+ 套件但有 ALPN）
        if cc >= 25 and alpn_missing >= 0.80:
            return True, f"JA4 非浏览器指纹：{ja4}，密码套件数={cc}，ALPN缺失率={alpn_missing:.2f}"

        # 条件 B：TLS 1.0（6 密码套件，快帆特征）
        if cc <= 6 and tls_count > 0:
            return True, f"JA4 TLS 1.0 非浏览器指纹：{ja4}，密码套件数={cc}"

        # 条件 C：19 密码套件（闪电VPN）或 17（番茄/GOST）+ 无 ALPN 确认
        if cc == 19 and alpn_missing >= 0.80:
            return True, f"JA4 闪电VPN 指纹：{ja4}，密码套件数=19，ALPN缺失率={alpn_missing:.2f}"
        if cc == 17 and alpn_missing >= 0.80:
            return True, f"JA4 GOST 指纹：{ja4}，密码套件数=17，ALPN缺失率={alpn_missing:.2f}"

    return False, ""


def _detect_ja4_golang(f: Feature) -> Tuple[bool, str]:
    ja4s = [str(x[0]) for x in flatten_pairs(f.get("ja4_top", []))]
    for ja4 in ja4s:
        if re.match(JA4_GOLANG_PATTERN, ja4):
            return True, f"Go TLS 客户端指纹：{ja4}（Clash/Go 代理特征）"
    return False, ""


def _detect_single_cipher_suite(f: Feature) -> Tuple[bool, str]:
    unique_count = _safe_int(f, "cipher_suite_unique_count")
    cipher = f.get("single_cipher_suite", "")
    tls_count = _safe_int(f, "tls_clienthello_count")
    if unique_count == 1 and cipher and tls_count > 5:
        return True, f"100% 单一密码套件 {cipher}（硬编码 VPN TLS 配置），ClientHello={tls_count}"
    return False, ""


def _detect_tls_v1_0(f: Feature) -> Tuple[bool, str]:
    ja4s = [str(x[0]) for x in flatten_pairs(f.get("ja4_top", []))]
    for ja4 in ja4s:
        if re.match(r"^t10d", ja4):
            cc = extract_ja4_cipher_count(ja4)
            return True, f"TLS 1.0 版本 JA4={ja4}，密码套件数={cc}（快帆特征）"
    return False, ""


def _detect_sni_ip_mismatch(f: Feature) -> Tuple[bool, str]:
    sni_top = flatten_pairs(f.get("sni_top", []))
    top_endpoint = str(_val(f, "top_endpoint", ""))
    if not top_endpoint:
        return False, ""

    for sni, count in sni_top:
        sni_lower = sni.lower()
        for enterprise in FAMOUS_ENTERPRISE_SNI:
            if enterprise in sni_lower:
                return True, f"SNI 声称连接 {sni}，但实际连接 IP {top_endpoint}（SNI-IP 不匹配，极光VPN 特征）"
    return False, ""


def _detect_single_sni_monopoly(f: Feature) -> Tuple[bool, str]:
    """单一 SNI 垄断：仅在同时无 ALPN 且非标准端口时触发（排除正常单站点浏览）。"""
    sni_top = flatten_pairs(f.get("sni_top", []))
    alpn_missing = _safe_float(f, "alpn_missing_ratio")
    tls_count = _safe_int(f, "tls_clienthello_count")
    nonstandard_tls = _safe_int(f, "nonstandard_tls_flow_count")

    if not sni_top or tls_count < 10:
        return False, ""

    total_sni = sum(c for _, c in sni_top)
    top_sni, top_count = sni_top[0][0], sni_top[0][1]
    ratio = top_count / total_sni if total_sni > 0 else 0

    # 排除已知邮件/办公服务（googlemail, microsoft, amazon 等）
    known_services = {"googlemail.com", "gmail.com", "outlook.com", "office365.com",
                      "microsoft.com", "amazonaws.com", "apple.com", "icloud.com"}
    if any(svc in top_sni.lower() for svc in known_services):
        return False, ""

    # 必须同时满足：SNI 垄断 + 无 ALPN（TLS 隧道特征）+ 大量非标准端口
    if ratio >= 0.90 and alpn_missing >= 0.80 and nonstandard_tls >= 10:
        return True, (
            f"单一 SNI 垄断：{top_sni} 占比={ratio:.1%}，无 ALPN，"
            f"非标准端口 TLS={nonstandard_tls}，TLS 隧道伪装"
        )
    return False, ""


def _detect_regional_node_naming(f: Feature) -> Tuple[bool, str]:
    from .utils import detect_regional_node_naming as _check

    domains = all_domains(f)
    if _check(domains):
        # 找出匹配的域名
        import re as _re
        from .config import ISO_COUNTRY_CODES

        hits = []
        pattern = _re.compile(r"^([a-z]{2})\d+([-.]|$)", _re.IGNORECASE)
        for d in domains:
            label = str(d).lower().split(".")[0]
            m = pattern.match(label)
            if m and m.group(1) in ISO_COUNTRY_CODES:
                hits.append(d)
        return True, f"区域化节点命名检测：{', '.join(sorted(set(hits))[:5])}"
    return False, ""


# ── TCP 载荷 ──


def _detect_block_cipher(f: Feature, n: int, threshold: float, label: str) -> Tuple[bool, str]:
    ratio = _safe_float(f, f"block_{n}_ratio")
    if ratio >= threshold:
        return True, f"固定块 {n} 字节占比={ratio:.1%}（{label}）"
    return False, ""


def _make_block_detector(n: int, threshold: float, label: str) -> DetectFunc:
    def detect(f: Feature) -> Tuple[bool, str]:
        return _detect_block_cipher(f, n, threshold, label)
    return detect


# ── DNS 行为 ──


def _detect_mdns_hola(f: Feature) -> Tuple[bool, str]:
    dns_top = flatten_pairs(f.get("dns_top", []))
    for d, _ in dns_top:
        if "__hola__" in str(d):
            return True, f"mDNS 查询暴露 HolaVPN：{d}"
    return False, ""


def _detect_random_local_domains(f: Feature) -> Tuple[bool, str]:
    count = detect_random_local_domains(flatten_pairs(f.get("dns_top", [])))
    if count >= 5:
        return True, f"随机 .local 域名检测：{count} 个（天行VPN 节点发现特征）"
    return False, ""


def _detect_wpad_storm(f: Feature) -> Tuple[bool, str]:
    wpad = _safe_int(f, "wpad_query_count")
    if wpad > 500:
        return True, f"WPAD 查询风暴：{wpad} 次（代理环境异常，天行VPN 特征）"
    return False, ""


def _detect_cheap_tld_concentration(f: Feature) -> Tuple[bool, str]:
    domains = all_domains(f)
    unique_count = count_unique_tlds(domains, RISK_TLDS)
    if unique_count >= 3:
        # 找出命中的域名示例
        hits = [d for d in domains if any(d.endswith(tld) for tld in RISK_TLDS)]
        examples = sorted(set(hits))[:5]
        return True, f"高风险 TLD 集中：{unique_count} 种廉价 TLD，示例：{', '.join(examples)}"
    return False, ""


def _detect_dns_gap_tcp_reachable(f: Feature) -> Tuple[bool, str]:
    dns_top = flatten_pairs(f.get("dns_top", []))
    sni_top = flatten_pairs(f.get("sni_top", []))

    # 所有域名
    all_dom = [str(d[0]).lower() for d in dns_top + sni_top if d[0]]

    # 检查是否有高熵随机域名（>3.5）且 DNS 响应为空
    # 排除 CDN 域名：含连字符的描述性子域名（如 cdn-web-lenovo-kantu.xxx.com）
    from .utils import domain_entropy as _de

    high_entropy_domains = []
    for d in sorted(set(all_dom)):
        label = str(d).lower().split(".")[0]
        # CDN/描述性子域名：含连字符 → 不是随机生成
        if "-" in label:
            continue
        if _de(d) >= 3.5:
            high_entropy_domains.append(d)

    # DNS gap: 有 SNI/DNS 查询，但对应的流量中无 DNS 响应记录
    tls_count = _safe_int(f, "tls_clienthello_count")
    dns_count = sum(c for _, c in dns_top)
    sni_count = sum(c for _, c in sni_top)

    if dns_count < 5 and sni_count > 10 and tls_count > 0:
        return True, f"DNS 缺失：SNI 请求 {sni_count} 次但 DNS 查询仅 {dns_count} 次（IP 硬编码下发）"

    if high_entropy_domains and tls_count > 0 and dns_count < 3:
        return True, f"高熵随机域名 + TCP 可达（DNS={dns_count}）：{', '.join(high_entropy_domains[:3])}"
    return False, ""


def _detect_udp53_masquerade(f: Feature) -> Tuple[bool, str]:
    udp53_large = _safe_int(f, "udp53_large_count")
    malformed = _safe_int(f, "malformed_count")
    _, best_ratio = max_block_ratio(f)
    best_block, _ = max_block_ratio(f)

    if udp53_large > 10 and (best_block == 1344 or malformed > 0):
        return True, f"UDP 53 伪装：大载荷={udp53_large}, malformed={malformed}, best_block={best_block}（NordVPN 特征）"
    return False, ""


def _detect_nordvpn_dns_tunnel(f: Feature) -> Tuple[bool, str]:
    """NordVPN：UDP 53 独占 + 100% malformed DNS + 载荷固定（分析报告核心特征）。"""
    udp53_count = _safe_int(f, "udp53_count")
    udp53_large = _safe_int(f, "udp53_large_count")
    malformed = _safe_int(f, "malformed_count")
    total_packets = max(1, _safe_int(f, "total_packets"))
    tls_count = _safe_int(f, "tls_clienthello_count")
    dominant_size = _safe_int(f, "dominant_payload_size")
    dominant_ratio = _safe_float(f, "dominant_payload_ratio")

    # 条件1：UDP 53 占绝对主导（>80% 总包量）
    udp53_ratio = udp53_count / total_packets
    if udp53_ratio < 0.80:
        return False, ""

    # 条件2：malformed DNS 占比极高（>95% 的 UDP 53 包都是 malformed）
    if udp53_count == 0 or malformed < udp53_count * 0.95:
        return False, ""

    # 条件3：大载荷（>512 字节的 DNS 包）占比高
    if udp53_large < udp53_count * 0.50:
        return False, ""

    # 条件4：无 TLS（NordVPN 不伪装 TLS）
    # 条件5：主导载荷固定（>40% 的包是同一大小）
    if dominant_ratio < 0.40:
        return False, ""

    return True, (
        f"NordVPN DNS 混淆隧道：UDP53={udp53_count}({udp53_ratio:.0%})，"
        f"malformed={malformed}，大载荷={udp53_large}，"
        f"主导载荷={dominant_size}字节({dominant_ratio:.0%})，TLS={tls_count}"
    )


def _detect_doh_present(f: Feature) -> Tuple[bool, str]:
    sni_top = flatten_pairs(f.get("sni_top", []))
    doh_domains = {"doh.pub", "dns.alidns.com", "dns.google", "cloudflare-dns.com", "mozilla.cloudflare-dns.com"}
    hits = [sni for sni, _ in sni_top if str(sni).lower() in doh_domains]
    if hits:
        return True, f"DoH 存在：{', '.join(hits)}（隐私增强，常见于 VPN 环境）"
    return False, ""


# ── 流量行为 ──


def _detect_two_phase_connection(f: Feature) -> Tuple[bool, str]:
    ports = get_ports(f)
    if 65311 in ports and 5608 in ports:
        return True, f"两阶段连接模式：注册端口 65311 + 数据端口 5608（闪电VPN 独有）"
    return False, ""


def _detect_quic_tls_dual(f: Feature) -> Tuple[bool, str]:
    quic_count = _safe_int(f, "quic_frame_count")
    tls_count = _safe_int(f, "tls_clienthello_count")
    if quic_count > 10 and tls_count > 5:
        return True, f"QUIC + TLS 双协议隧道：QUIC={quic_count}, TLS ClientHello={tls_count}（UltraSurf 特征）"
    return False, ""


def _detect_extreme_flow_dominance(f: Feature) -> Tuple[bool, str]:
    single_flow = _safe_float(f, "single_flow_dominance")
    max_duration = _safe_float(f, "max_flow_duration")
    flow_count = _safe_int(f, "flow_count")

    if single_flow >= 0.98 and max_duration > 60 and flow_count < 10:
        return True, f"极端单流垄断：单流占比={single_flow:.1%}，时长={max_duration:.0f}s，总流数={flow_count}"
    return False, ""


# ── V2 新增规则检测函数 ──


def _detect_block_1378_cyberghost(f: Feature) -> Tuple[bool, str]:
    """CyberGhost IPsec ESP NAT-T 封装后的固定 MTU 1378 > 60%。"""
    ratio = _safe_float(f, "block_1378_ratio")
    if ratio >= 0.60:
        return True, f"1378 字节固定块占比={ratio:.1%}（CyberGhost IPsec NAT-T 独有 MTU）"
    return False, ""


def _detect_block_1344_nordvpn(f: Feature) -> Tuple[bool, str]:
    """NordVPN WireGuard+DNS 混淆后的满载块 1344 > 45%。"""
    ratio = _safe_float(f, "block_1344_ratio")
    malformed = _safe_int(f, "malformed_count")
    udp53_large = _safe_int(f, "udp53_large_count")
    if ratio >= 0.45 and (malformed > 0 or udp53_large > 0):
        return True, f"1344 字节固定块占比={ratio:.1%}，malformed={malformed}, udp53_large={udp53_large}（NordVPN NordLynx 特征）"
    return False, ""


def _detect_no_tls_encrypted_tcp(f: Feature) -> Tuple[bool, str]:
    """无 TLS ClientHello 但有大载荷加密 TCP + 固定块（SSR/VMess 特征）。"""
    tls_count = _safe_int(f, "tls_clienthello_count")
    nonstandard_tls = _safe_int(f, "nonstandard_tls_flow_count")
    best_block, best_ratio = max_block_ratio(f)
    total_payload = max(1, _safe_int(f, "total_payload_bytes"))

    # 条件：无 TLS 握手或 TLS 极少 + 有固定块 + 有实质性数据
    if tls_count <= 2 and nonstandard_tls == 0 and best_ratio >= 0.30 and total_payload > 10000:
        return True, f"无 TLS 加密 TCP + 固定块：block_{best_block}={best_ratio:.2f}，TLS ClientHello={tls_count}（SSR/VMess 特征）"
    return False, ""


def _detect_wizvpn_1452(f: Feature) -> Tuple[bool, str]:
    """WizVPN：wizvpn.net 域名 + 1452 固定块 > 50%（与 Hola 区分）。"""
    ratio = _safe_float(f, "block_1452_ratio")
    sni_top = flatten_pairs(f.get("sni_top", []))
    dns_top = flatten_pairs(f.get("dns_top", []))
    all_dom = [str(d[0]).lower() for d in sni_top + dns_top]

    if ratio >= 0.50 and any("wizvpn" in d for d in all_dom):
        return True, f"WizVPN：wizvpn.net 域名 + 1452 固定块占比={ratio:.1%}"
    return False, ""


def _detect_single_ja4_multi_sni(f: Feature) -> Tuple[bool, str]:
    """极光VPN：单一 JA4 指纹服务多个不同 SNI（22 个 SNI 用同一 JA4）。"""
    ja4_top = flatten_pairs(f.get("ja4_top", []))
    sni_top = flatten_pairs(f.get("sni_top", []))

    ja4_unique = len(ja4_top)
    sni_unique = len(sni_top)

    # 条件：JA4 指纹唯一 + SNI 种类 >= 10 + TLS ClientHello 存在
    tls_count = _safe_int(f, "tls_clienthello_count")
    if ja4_unique == 1 and sni_unique >= 10 and tls_count > 10:
        ja4 = ja4_top[0][0]
        return True, f"单一 JA4 ({ja4}) 服务 {sni_unique} 个不同 SNI（极光VPN 独有特征）"
    return False, ""


# ═══════════════════════════════════════════
# 规则注册表（所有规则）
# ═══════════════════════════════════════════

ALL_RULES: List[RuleDef] = [
    # L3 协议 (3)
    RuleDef("R_IPSEC_ESP", "L3_PROTOCOL", "IP proto 50 (ESP) 检测", 100, _detect_ipsec_esp),
    RuleDef("R_IPSEC_AH", "L3_PROTOCOL", "IP proto 51 (AH) 检测", 100, _detect_ipsec_ah),
    RuleDef("R_IPSEC_ESP_AH", "L3_PROTOCOL", "IP proto 50/51 (ESP/AH) 任一", 100, _detect_ipsec_esp_ah),

    # L4 UDP (5)
    RuleDef("R_IPSEC_IKE", "L4_UDP", "ISAKMP/IKE 协议解析", 98, _detect_ipsec_ike),
    RuleDef("R_IPSEC_NATT", "L4_UDP", "ESP-in-UDP NAT-T 检测", 98, _detect_ipsec_natt),
    RuleDef("R_WIREGUARD_PORT", "L4_UDP", "WireGuard UDP 51820 端口", 98, _detect_wireguard_port),
    RuleDef("R_WIREGUARD_PROTO", "L4_UDP", "WireGuard (wg) 协议识别", 98, _detect_wireguard_proto),
    RuleDef("R_OPENVPN", "L4_UDP", "OpenVPN UDP 1194/1195 端口", 95, _detect_openvpn),

    # L4 TCP (5)
    RuleDef("R_PORT_MISMATCH_3306", "L4_TCP", "TCP 3306 非 MySQL + 1428 固定块", 98, _detect_port_mismatch_3306),
    RuleDef("R_SPECIAL_PORT_ENCRYPTED", "L4_TCP", "专属端口 + 加密/固定块", 92, _detect_special_port_encrypted),
    RuleDef("R_SSH_KEEPALIVE_PROBE", "L4_TCP", "SSH 端口周期性 SYN 保活探测 (SSR)", 95, _detect_ssh_keepalive),
    RuleDef("R_P2P_DUAL_CHANNEL", "L4_TCP", "TLS控制 + 非TLS数据 双通道 (HolaVPN)", 95, _detect_p2p_dual_channel),
    RuleDef("R_NO_TLS_ENCRYPTED_TCP", "L4_TCP", "无 TLS + 加密 TCP + 固定块 (SSR/VMess)", 95, _detect_no_tls_encrypted_tcp),

    # TLS / JA4 指纹 (10)
    RuleDef("R_VPN_DOMAIN_SNI", "TLS_JA4", "DNS/SNI 命中 VPN 专属域名", 95, _detect_vpn_domain_sni),
    RuleDef("R_CHROME_JA4_NO_ALPN", "TLS_JA4", "Chrome JA4 + 全部无 ALPN (TLS指纹伪造)", 95, _detect_chrome_ja4_no_alpn),
    RuleDef("R_JA4_NON_BROWSER", "TLS_JA4", "JA4 非浏览器指纹 (密码套件数异常)", 85, _detect_ja4_non_browser),
    RuleDef("R_JA4_GOLANG", "TLS_JA4", "Go TLS 客户端指纹 (Clash)", 92, _detect_ja4_golang),
    RuleDef("R_SINGLE_CIPHER_SUITE", "TLS_JA4", "100% 单一密码套件 (硬编码VPN)", 95, _detect_single_cipher_suite),
    RuleDef("R_TLS_V1_0", "TLS_JA4", "TLS 1.0 版本 (快帆)", 95, _detect_tls_v1_0),
    RuleDef("R_SNI_IP_MISMATCH", "TLS_JA4", "SNI 知名企业域名 + IP 不匹配 (极光VPN)", 95, _detect_sni_ip_mismatch),
    RuleDef("R_SINGLE_SNI_MONOPOLY", "TLS_JA4", "单一 SNI 垄断 >90% + 无 ALPN", 92, _detect_single_sni_monopoly),
    RuleDef("R_REGIONAL_NODE_NAMING", "TLS_JA4", "SNI 区域化节点命名 (ISO国家码+编号)", 90, _detect_regional_node_naming),
    RuleDef("R_SINGLE_JA4_MULTI_SNI", "TLS_JA4", "单一 JA4 服务 10+ 不同 SNI (极光VPN)", 95, _detect_single_ja4_multi_sni),

    # TCP 载荷 (8)
    RuleDef("R_BLOCK_1300_SSR", "TCP_PAYLOAD", "1300 字节固定块 (SSR AEAD 密码)", 100, _make_block_detector(1300, 0.30, "SSR")),
    RuleDef("R_BLOCK_1370_VLESS_VMESS", "TCP_PAYLOAD", "1370 字节固定块 (VLess/VMess)", 95, _make_block_detector(1370, 0.30, "VLess/VMess")),
    RuleDef("R_BLOCK_1400_JIGUANG", "TCP_PAYLOAD", "1400 字节固定块 >80% (极光/天行VPN)", 100, _make_block_detector(1400, 0.80, "极光/天行VPN")),
    RuleDef("R_BLOCK_1448_SHANDIAN", "TCP_PAYLOAD", "1448 字节固定块 >90% (闪电VPN)", 100, _make_block_detector(1448, 0.90, "闪电VPN TLS MTU满载")),
    RuleDef("R_BLOCK_1452_HOLA", "TCP_PAYLOAD", "1452 字节固定块 >77% (HolaVPN P2P)", 100, _make_block_detector(1452, 0.77, "HolaVPN P2P")),
    RuleDef("R_BLOCK_1378_CYBERGHOST", "TCP_PAYLOAD", "1378 字节固定块 >60% (CyberGhost)", 100, _make_block_detector(1378, 0.60, "CyberGhost IPsec NAT-T")),
    RuleDef("R_BLOCK_1344_NORDVPN", "TCP_PAYLOAD", "1344 字节固定块 + malformed DNS (NordVPN)", 95, _detect_block_1344_nordvpn),
    RuleDef("R_WIZVPN_1452", "TCP_PAYLOAD", "wizvpn.net 域名 + 1452 固定块 >50% (WizVPN)", 100, _detect_wizvpn_1452),

    # DNS 行为 (8)
    RuleDef("R_MDNS_HOLA", "DNS", "mDNS __hola__ 自识别 (HolaVPN)", 100, _detect_mdns_hola),
    RuleDef("R_MDNS_RANDOM_LOCAL", "DNS", "随机 .local 域名 >5 (天行VPN)", 90, _detect_random_local_domains),
    RuleDef("R_WPAD_STORM", "DNS", "WPAD 查询风暴 >500 次 (仅组合评分参考)", 60, _detect_wpad_storm),
    RuleDef("R_CHEAP_TLD_CONCENTRATION", "DNS", "3+ 种廉价 TLD 集中", 90, _detect_cheap_tld_concentration),
    RuleDef("R_DNS_GAP_TCP_REACHABLE", "DNS", "DNS 缺失但 TCP 可达 (IP硬编码)", 90, _detect_dns_gap_tcp_reachable),
    RuleDef("R_UDP53_MASQUERADE", "DNS", "UDP 53 非 DNS 大载荷伪装 (NordVPN)", 95, _detect_udp53_masquerade),
    RuleDef("R_NORDVPN_DNS_TUNNEL", "DNS", "NordVPN DNS 混淆隧道 (UDP53独占+100%malformed+固定载荷)", 98, _detect_nordvpn_dns_tunnel),
    RuleDef("R_DOH_PRESENT", "DNS", "DoH 存在 (隐私增强)", 70, _detect_doh_present),

    # 流量行为 (3)
    RuleDef("R_TWO_PHASE_CONNECTION", "TRAFFIC", "两阶段连接：注册+数据端口 (闪电VPN)", 95, _detect_two_phase_connection),
    RuleDef("R_QUIC_TLS_DUAL", "TRAFFIC", "QUIC + TLS 双协议隧道 (仅组合评分)", 60, _detect_quic_tls_dual),
    RuleDef("R_EXTREME_FLOW_DOMINANCE", "TRAFFIC", "极端单流垄断 >98% + 长连接", 90, _detect_extreme_flow_dominance),
]


class RuleEngine:
    """数据驱动规则引擎。"""

    def __init__(self, rules: Optional[List[RuleDef]] = None):
        self.rules = rules or ALL_RULES

    def match(self, feature: Feature) -> List[RuleMatch]:
        """遍历所有启用的规则，返回命中的匹配列表。"""
        matches: List[RuleMatch] = []
        for rule in self.rules:
            if not rule.enabled:
                continue
            try:
                hit, evidence = rule.detect(feature)
                if hit:
                    matches.append(RuleMatch(
                        rule_id=rule.id,
                        category=rule.category,
                        confidence=rule.confidence,
                        evidence=evidence,
                    ))
            except Exception:
                continue
        return matches

    def get_max_confidence(self, matches: List[RuleMatch]) -> int:
        """获取命中规则的最高置信度。"""
        if not matches:
            return 0
        return max(m.confidence for m in matches)


class ComboScorer:
    """6 维度组合评分器。"""

    def score(self, feature: Feature) -> Tuple[ComboScores, List[str]]:
        s = ComboScores()
        evidence: List[str] = []
        self._add_evidence = evidence.append

        self._score_tls_spoof(feature, s)
        self._score_raw_encrypted(feature, s)
        self._score_endpoint_behavior(feature, s)
        self._score_dns_sni_anomaly(feature, s)
        self._score_ja4_fingerprint(feature, s)
        self._score_port_protocol(feature, s)

        return s, evidence

    def _add(self, e: List[str], msg: str) -> None:
        e.append(msg)

    def _score_tls_spoof(self, f: Feature, s: ComboScores) -> None:
        e: List[str] = []
        tls_count = _safe_int(f, "tls_clienthello_count")
        nonstandard_tls = _safe_int(f, "nonstandard_tls_flow_count")
        alpn_missing = _safe_float(f, "alpn_missing_ratio")
        top_ep_ratio = _safe_float(f, "top_endpoint_ratio")

        # 非标准端口 + 无 ALPN：仅在大量 TLS 流且端点集中时才算隧道特征
        # 排除邮件/聊天等正常应用（它们天然使用非标准端口 + 无 ALPN）
        if nonstandard_tls >= 5 and alpn_missing >= 0.90 and top_ep_ratio >= 0.70:
            s.tls_spoof += 3
            e.append(f"TLS 隧道特征：非标准端口={nonstandard_tls}, ALPN缺失={alpn_missing:.2f}, 端点集中={top_ep_ratio:.2f}")
        if tls_count > 0 and top_ep_ratio >= 0.80:
            s.tls_spoof += 1
            e.append(f"单一端点 TLS 承载={top_ep_ratio:.2f}")

        for msg in e:
            self._add_evidence(msg)

    def _score_raw_encrypted(self, f: Feature, s: ComboScores) -> None:
        e: List[str] = []
        no_tls_large = _safe_int(f, "no_tls_large_flow_count")
        best_block, best_ratio = max_block_ratio(f)
        ports = get_ports(f)

        if no_tls_large > 0:
            s.raw_encrypted += 2
            e.append(f"无 TLS 大载荷 TCP 流：{no_tls_large}")
        # 固定块：仅 VPN 专有块大小（1300/1370/1400/1452）计入，排除标准 TLS 1448
        if best_ratio >= 0.30 and best_block in (1300, 1370, 1400, 1452, 1310, 1344, 1428, 1378):
            pts = min(3, int(best_ratio / 0.15))
            s.raw_encrypted += pts
            e.append(f"固定块特征：block_{best_block}_ratio={best_ratio:.2f}")
        elif best_block == 1448 and best_ratio >= 0.80:
            s.raw_encrypted += 2
            e.append(f"TLS 1448 块极高占比：{best_ratio:.2f}")
        special_hits = sorted([p for p in ports if p in SPECIAL_PORTS])
        if special_hits:
            s.raw_encrypted += 2
            e.append(f"专属/非标准端口：{special_hits}")

        for msg in e:
            self._add_evidence(msg)

    def _score_endpoint_behavior(self, f: Feature, s: ComboScores) -> None:
        e: List[str] = []
        top_ep_ratio = _safe_float(f, "top_endpoint_ratio")
        single_flow = _safe_float(f, "single_flow_dominance")
        max_duration = _safe_float(f, "max_flow_duration")

        if top_ep_ratio >= 0.70:
            s.endpoint_behavior += 2
            e.append(f"单一端点集中：top_endpoint_ratio={top_ep_ratio:.2f}")
        if single_flow >= 0.95:
            s.endpoint_behavior += 2
            e.append(f"单流垄断：single_flow_dominance={single_flow:.2f}")
        elif single_flow >= 0.90:
            s.endpoint_behavior += 1
            e.append(f"单流主导：single_flow_dominance={single_flow:.2f}")
        if max_duration >= 3600:
            s.endpoint_behavior += 2
            e.append(f"超长连接>1h：max_duration={max_duration:.1f}s")
        elif max_duration >= 600:
            s.endpoint_behavior += 1
            e.append(f"长连接>10min：max_duration={max_duration:.1f}s")

        for msg in e:
            self._add_evidence(msg)

    def _score_dns_sni_anomaly(self, f: Feature, s: ComboScores) -> None:
        e: List[str] = []
        domains = all_domains(f)
        hits = match_domain_keywords(domains, _DOMAIN_RE)
        unique_tlds = count_unique_tlds(domains, RISK_TLDS)
        random_local = detect_random_local_domains(flatten_pairs(f.get("dns_top", [])))
        risk_tld_count = _safe_int(f, "risk_tld_count")

        if hits:
            s.dns_sni_anomaly += 3
            e.append("DNS/SNI 包含 VPN 语义关键词：" + ", ".join(sorted(set(hits))[:5]))
        if unique_tlds >= 3:
            s.dns_sni_anomaly += 3
            e.append(f"高风险 TLD 高度集中：{unique_tlds} 种")
        elif risk_tld_count >= 3:
            s.dns_sni_anomaly += 1
            e.append(f"高风险 TLD 域名={risk_tld_count} 个")
        if random_local >= 3:
            s.dns_sni_anomaly += 2
            e.append(f"随机 .local 域名：{random_local} 个")

        for msg in e:
            self._add_evidence(msg)

    def _score_ja4_fingerprint(self, f: Feature, s: ComboScores) -> None:
        e: List[str] = []
        ja4s = [str(x[0]) for x in flatten_pairs(f.get("ja4_top", []))]
        alpn_missing = _safe_float(f, "alpn_missing_ratio")
        tls_count = _safe_int(f, "tls_clienthello_count")
        unique_cipher = _safe_int(f, "cipher_suite_unique_count")
        single_cipher = f.get("single_cipher_suite", "")

        # Chrome JA4 + 无 ALPN（TLS 指纹伪造，VPN 铁证）
        if tls_count > 0 and alpn_missing >= 0.80:
            chrome_ja4 = any(re.match(CHROME_JA4_PREFIX, j) for j in ja4s)
            if chrome_ja4:
                s.ja4_fingerprint += 3
                e.append(f"Chrome JA4 + 无 ALPN（alpn_missing={alpn_missing:.2f}）")

        # 非浏览器 JA4 + 无 ALPN（VPN 自定义 TLS 栈）
        if alpn_missing >= 0.80:
            non_browser = False
            for ja4 in ja4s:
                cc = extract_ja4_cipher_count(ja4)
                if cc is not None and (cc >= 19 or cc <= 6):
                    non_browser = True
                    break
                if re.match(JA4_GOLANG_PATTERN, ja4):
                    non_browser = True
                    break
            if non_browser:
                s.ja4_fingerprint += 2
                e.append("非浏览器 JA4 + 无 ALPN")

        # 单一密码套件
        if unique_cipher == 1 and single_cipher and tls_count > 3:
            s.ja4_fingerprint += 2
            e.append(f"100% 单一密码套件 {single_cipher}")

        # Go 指纹（仅无 ALPN 时算分）
        if alpn_missing >= 0.80 and any(re.match(JA4_GOLANG_PATTERN, j) for j in ja4s):
            s.ja4_fingerprint += 1
            e.append("Go TLS 客户端指纹 + 无 ALPN")

        # TLS 1.0
        if any(re.match(r"^t10d", j) for j in ja4s):
            s.ja4_fingerprint += 2
            e.append("TLS 1.0 版本（快帆特征）")

        for msg in e:
            self._add_evidence(msg)

    def _score_port_protocol(self, f: Feature, s: ComboScores) -> None:
        e: List[str] = []
        ports = get_ports(f)
        prot = protocol_text(f)

        # 端口-协议错配
        if 3306 in ports and "mysql" not in prot:
            s.port_protocol += 2
            e.append("TCP 3306 非 MySQL 协议（端口伪装）")

        # 两阶段连接
        if 65311 in ports and 5608 in ports:
            s.port_protocol += 2
            e.append("两阶段连接模式：65311(注册) + 5608(数据)")

        # P2P 双通道
        hola_ports = {22225, 22226}
        if any(p in ports for p in hola_ports):
            s.port_protocol += 2
            e.append("Hola P2P 端口 22225/22226")

        for msg in e:
            self._add_evidence(msg)


# ── VPN Family 推断（数据驱动） ──


def infer_vpn_family(f: Feature, evidence_text: str = "") -> str:
    """根据特征 + 证据文本推断 VPN 类型。"""
    text = " ".join(all_domains(f)) + " " + protocol_text(f) + " " + evidence_text.lower()
    ports = get_ports(f)
    best_block, best_ratio = max_block_ratio(f)

    # 构建特征标记
    signals: set[str] = set()

    # 协议层
    if any(x in text for x in ["isakmp", "ike", "esp"]):
        signals.add("isakmp"); signals.add("ike"); signals.add("esp")
    if f.get("esp_in_udp_like") or _safe_int(f, "udp4500_count") > 100:
        signals.add("esp")
    if "wg" in text or 51820 in ports:
        signals.add("wg"); signals.add("wireguard")
    if "openvpn" in text.lower() or 1194 in ports or 1195 in ports:
        signals.add("openvpn")
    if 1194 in ports:
        signals.add("1194_port")

    # 域名关键词
    if "gosttwo" in text or "shdowsocks" in text:
        signals.add("gosttwo"); signals.add("shdowsocks")
    if "nodesni" in text or "kunlun04dns" in text or "sdv2-" in text:
        signals.add("nodesni"); signals.add("kunlun04dns"); signals.add("sdv2-")
    if "hola" in text or "zagent" in text:
        signals.add("hola"); signals.add("zagent")
    if "nord" in text:
        signals.add("nord")
    if "securepaidvpn" in text or "securepaid" in text:
        signals.add("securepaidvpn")
    if "clashverge" in text:
        signals.add("clashverge")
    if "ahahub" in text or "ahapivot" in text or "hubdhl" in text or "hubups" in text:
        signals.add("ahahub"); signals.add("ahapivot"); signals.add("hubdhl"); signals.add("hubups")
    if "skylinevpn" in text or "skylinenode" in text:
        signals.add("skylinevpn"); signals.add("skylinenode")
    if "wizvpn" in text:
        signals.add("wizvpn")
    if "kuaifan" in text or "wifiin.cn" in text:
        signals.add("kuaifan"); signals.add("wifiin.cn")
    if any(x in text for x in ["ultrasurf", "quic_tls_dual", "cheap_tld_storm"]):
        signals.add("ultrasurf")
    if "strongvpn" in text:
        signals.add("strongvpn")

    # 端口
    if 22225 in ports or 22226 in ports:
        signals.add("22225_port")
    if 11581 in ports or 11582 in ports or 11681 in ports:
        signals.add("11581_port"); signals.add("11582_port")
    if 3128 in ports:
        signals.add("3128_port")
    if 1428 == best_block and best_ratio >= 0.30:
        signals.add("1428_block")
    if 3306 in ports:
        signals.add("3306_port")
    if 5608 in ports:
        signals.add("5608_port")
    if 65311 in ports:
        signals.add("65311_port")
    if 1378 == best_block and best_ratio >= 0.60:
        signals.add("1378_block")

    # 固定块
    for n in [1300, 1370, 1400, 1448, 1452, 1310, 1344, 1428, 1378]:
        ratio = _safe_float(f, f"block_{n}_ratio")
        if ratio >= 0.30:
            signals.add(f"{n}_block")

    # TLS 存在性用于区分 VLess vs VMess
    # VLess: 非标准端口 TLS 或无 ALPN 的 TLS（VPN 特征）
    # VMess: 无 TLS（纯加密 TCP）或只有标准浏览器 TLS
    tls_count = _safe_int(f, "tls_clienthello_count")
    nonstandard_tls = _safe_int(f, "nonstandard_tls_flow_count")
    alpn_missing_ratio = _safe_float(f, "alpn_missing_ratio")
    if 1370 == best_block and best_ratio >= 0.30:
        if nonstandard_tls > 0 or (tls_count > 0 and alpn_missing_ratio >= 0.80):
            signals.add("1370_block_tls")
        else:
            signals.add("1370_block_no_tls")

    # SNI_IP_MISMATCH 是极光VPN 独有特征
    sni_top = flatten_pairs(f.get("sni_top", []))
    from .config import FAMOUS_ENTERPRISE_SNI
    for sni, _ in sni_top:
        if any(enterprise in str(sni).lower() for enterprise in FAMOUS_ENTERPRISE_SNI):
            signals.add("sni_ip_mismatch")
            break

    # 特殊
    udp53_large = _safe_int(f, "udp53_large_count")
    malformed = _safe_int(f, "malformed_count")
    if udp53_large > 10 and (best_block == 1344 or malformed > 0):
        signals.add("udp53_masquerade")

    # 按优先级匹配：每个元组 (required_signals, min_matches, family_name)
    # min_matches=None 表示全部需要；min_matches=N 表示至少需要 N 个
    family_rules: list[tuple[list[str], Optional[int], str]] = [
        (["isakmp", "ike", "esp"], None, "IPsec/CyberGhost"),
        # 极光VPN 优先于 WireGuard（SNI_IP_MISMATCH 是极光独有）
        (["sni_ip_mismatch"], None, "极光VPN"),
        (["wg", "wireguard"], None, "WireGuard/NordVPN/StrongVPN"),
        (["openvpn"], None, "OpenVPN"),
        (["gosttwo", "shdowsocks"], None, "番茄VPN/GOST"),
        # 闪电VPN
        (["nodesni", "kunlun04dns", "sdv2-", "1448_block", "5608_port", "65311_port"], 2, "闪电VPN"),
        # WizVPN 优先于 HolaVPN（避免 1452 块被 Hola 抢先匹配）
        (["wizvpn"], None, "WizVPN"),
        # HolaVPN
        (["hola", "zagent", "22225_port", "1452_block"], 2, "HolaVPN"),
        (["1378_block"], None, "CyberGhost/IPsec"),
        # NordVPN：UDP53 伪装 + malformed DNS + 1344 块，命中 1 个即可
        (["nord", "udp53_masquerade", "1344_block"], 1, "NordVPN"),
        (["securepaidvpn", "3128_port"], None, "SecurePaidVPN"),
        (["1300_block"], None, "ShadowsocksR/SSR"),
        (["1370_block_tls"], None, "VLess"),
        (["1370_block_no_tls"], None, "VMess"),
        (["clashverge"], None, "Clash"),
        # 老王VPN
        (["ahahub", "ahapivot", "hubdhl", "hubups", "1428_block"], 2, "老王VPN"),
        # 天行VPN
        (["skylinevpn", "skylinenode", "11581_port", "11582_port", "1400_block"], 2, "天行VPN"),
        (["1400_block"], None, "极光VPN/天行VPN"),
        # 快帆
        (["kuaifan", "wifiin.cn"], None, "快帆"),
        # UltraSurf 放最后（QUIC_TLS_DUAL 容易误触发）
        (["ultrasurf"], None, "UltraSurf"),
        (["strongvpn"], None, "StrongVPN"),
    ]

    for required, min_matches, family in family_rules:
        if min_matches is None:
            if signals.issuperset(required):
                return family
        else:
            hits = sum(1 for s in required if s in signals)
            if hits >= min_matches:
                return family

    # 部分匹配（至少命中 1 个关键信号）
    partial: list[tuple[list[str], str]] = [
        (["1310_block"], "番茄VPN/GOST"),
        (["1344_block"], "NordVPN"),
        (["1378_block"], "CyberGhost/IPsec"),
        (["1428_block"], "老王VPN"),
    ]
    for required, family in partial:
        if any(s in signals for s in required):
            return family

    return "unknown_vpn"
