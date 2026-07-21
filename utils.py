"""VPN Detector 共享工具函数。"""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

from .config import BLOCK_SIZES


def flatten_pairs(pairs: Any) -> List[Tuple[str, int]]:
    """将 [[k,v], ...] 格式转为 [(k, v), ...] 列表。"""
    out: List[Tuple[str, int]] = []
    if isinstance(pairs, list):
        for item in pairs:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                out.append((str(item[0]), int(item[1])))
    return out


def get_ports(f: Dict[str, Any]) -> Dict[int, int]:
    """从 port_counts_top 提取端口→计数映射。"""
    ports: Dict[int, int] = {}
    for p, c in flatten_pairs(f.get("port_counts_top", [])):
        try:
            ports[int(p)] = c
        except (ValueError, TypeError):
            continue
    return ports


def all_domains(f: Dict[str, Any]) -> List[str]:
    """提取所有 SNI 和 DNS 域名。"""
    domains: List[str] = []
    for k in ("sni_top", "dns_top"):
        for d, _ in flatten_pairs(f.get(k, [])):
            if d:
                domains.append(str(d).lower())
    return domains


def protocol_text(f: Dict[str, Any]) -> str:
    """获取协议计数的文本表示。"""
    pc = f.get("protocol_counts", {})
    if isinstance(pc, dict):
        return " ".join(str(k) for k in pc).lower()
    return str(pc).lower()


def max_block_ratio(f: Dict[str, Any]) -> Tuple[int, float]:
    """获取最大固定块大小及其占比。"""
    best_n, best_r = 0, 0.0
    for n in BLOCK_SIZES:
        r = float(f.get(f"block_{n}_ratio", 0) or 0)
        if r > best_r:
            best_n, best_r = n, r
    return best_n, best_r


def entropy_label(s: str) -> float:
    """计算字符串的香农熵。"""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def domain_entropy(domain: str) -> float:
    """计算域名标签的熵（仅取 TLD 之前的第一段）。"""
    if not domain:
        return 0.0
    label = domain.split(".")[0]
    return entropy_label(label)


def safe_key(parts: Tuple[Any, ...]) -> str:
    """生成稳定的短哈希 key。"""
    raw = "|".join(map(str, parts))
    return hashlib.md5(raw.encode("utf-8")).hexdigest()[:16]


def compile_domain_regex(keywords: List[str]) -> re.Pattern:
    """将域名关键词列表编译为正则。"""
    escaped = [re.escape(kw) for kw in keywords]
    return re.compile("|".join(escaped), re.IGNORECASE)


def match_domain_keywords(domains: List[str], pattern: re.Pattern) -> List[str]:
    """返回匹配关键词的域名列表。"""
    hits: List[str] = []
    for d in domains:
        if pattern.search(d):
            hits.append(d)
    return hits


def match_ja4_pattern(ja4: str, patterns: List[str]) -> bool:
    """检查 JA4 是否匹配任一模式。"""
    if not ja4:
        return False
    for pat in patterns:
        if re.match(pat, str(ja4)):
            return True
    return False


def extract_ja4_cipher_count(ja4: str) -> Optional[int]:
    """从 JA4 字符串中提取密码套件数量。

    JA4 格式: t{version}d{cipher_count}{extension_count}h{alpn}
    例如: t13d1516h2 → 15 个密码套件, 16 个扩展
    """
    if not ja4:
        return None
    m = re.match(r"^t\d+d(\d{1,2})", str(ja4))
    if m:
        return int(m.group(1))
    return None


def count_unique_tlds(domains: List[str], risk_tlds: List[str]) -> int:
    """统计域名中出现的不同高风险 TLD 种类数。"""
    found: set[str] = set()
    for d in domains:
        d_lower = str(d).lower()
        for tld in risk_tlds:
            if d_lower.endswith(tld):
                found.add(tld)
    return len(found)


def detect_regional_node_naming(domains: List[str]) -> bool:
    """检测 SNI/DNS 是否包含 ISO 国家码 + 数字编号的区域节点模式。"""
    from .config import ISO_COUNTRY_CODES

    pattern = re.compile(r"^([a-z]{2})\d+([-.]|$)", re.IGNORECASE)
    for d in domains:
        d_str = str(d).lower()
        label = d_str.split(".")[0]
        m = pattern.match(label)
        if m and m.group(1) in ISO_COUNTRY_CODES:
            return True
    return False


def detect_random_local_domains(dns_top: List[Tuple[str, int]]) -> int:
    """统计随机字符串 .local 域名数量（如 xxntypndvvgoo.local）。"""
    count = 0
    for d, _ in (dns_top or []):
        d_str = str(d).lower()
        if not d_str.endswith(".local"):
            continue
        label = d_str.split(".")[0]
        if len(label) >= 8 and entropy_label(label) >= 3.0:
            count += 1
    return count


def int_or_zero(x: Any) -> int:
    """安全转为 int，失败返回 0。"""
    if x is None:
        return 0
    s = str(x).strip()
    if not s:
        return 0
    if "," in s:
        s = s.split(",")[0]
    try:
        if s.startswith("0x"):
            return int(s, 16)
        return int(float(s))
    except (ValueError, TypeError):
        return 0


def float_or_none(x: Any) -> Optional[float]:
    """安全转为 float，失败返回 None。"""
    if x is None:
        return None
    s = str(x).strip()
    if not s:
        return None
    if "," in s:
        s = s.split(",")[0]
    try:
        return float(s)
    except (ValueError, TypeError):
        return None
