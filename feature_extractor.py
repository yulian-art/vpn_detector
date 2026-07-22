#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPN pcap 特征提取器 V2.0。

功能：
- 调用 tshark 解析 pcap/pcapng；
- 支持扫描目录、单文件、zip；
- 输出每个 pcap 的文件级特征和 top flow 特征；
- 新增 V2 字段：密码套件熵、QUIC 帧数、SSH SYN 周期性、随机.local、WPAD。

注意：
- 需要安装 Wireshark，并保证命令行能执行 tshark。
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import logging
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

from .config import BLOCK_SIZES, RISK_TLDS, STANDARD_TLS_PORTS
from .identity import make_capture_id, make_sample_id, make_split_group

logger = logging.getLogger(__name__)

PCAP_EXTS = {".pcap", ".pcapng", ".cap"}


def run_cmd(cmd: List[str], timeout: int = 120) -> str:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"命令超时：{' '.join(cmd)}") from e

    if proc.returncode != 0:
        raise RuntimeError(
            f"命令执行失败：{' '.join(cmd)}\nSTDERR:\n{proc.stderr[:2000]}"
        )
    return proc.stdout


def require_tshark() -> None:
    if shutil.which("tshark") is None:
        raise SystemExit(
            "未找到 tshark。请先安装 Wireshark，并将 tshark 所在目录加入 PATH。"
        )


def get_available_fields() -> set:
    try:
        out = run_cmd(["tshark", "-G", "fields"], timeout=60)
    except Exception:
        logger.warning("无法获取 tshark 字段列表，使用默认字段")
        return set()

    fields = set()
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3 and parts[0] == "F":
            fields.add(parts[2])
    fields.update({"_ws.col.Protocol", "_ws.col.Info"})
    return fields


def int_or_zero(x: Any) -> int:
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


def is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except Exception:
        return False


def entropy_label(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def domain_entropy(domain: str) -> float:
    if not domain:
        return 0.0
    label = domain.split(".")[0]
    return entropy_label(label)


def normalize_flow(
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    proto: str,
) -> Tuple[str, str, int, str, int, str]:
    src_private = is_private_ip(src_ip)
    dst_private = is_private_ip(dst_ip)

    if src_private and not dst_private:
        return (src_ip, src_ip, src_port, dst_ip, dst_port, proto)
    if dst_private and not src_private:
        return (dst_ip, dst_ip, dst_port, src_ip, src_port, proto)

    a = (src_ip, src_port)
    b = (dst_ip, dst_port)
    if a <= b:
        local_ip, local_port, remote_ip, remote_port = src_ip, src_port, dst_ip, dst_port
    else:
        local_ip, local_port, remote_ip, remote_port = dst_ip, dst_port, src_ip, src_port
    return (local_ip, local_ip, local_port, remote_ip, remote_port, proto)


def infer_direction(src_ip: str, dst_ip: str, local_ip: str) -> str:
    if src_ip == local_ip:
        return "outbound"
    if dst_ip == local_ip:
        return "inbound"
    return "unknown"


def safe_key(parts: Tuple[Any, ...]) -> str:
    raw = "|".join(map(str, parts))
    return hashlib.md5(raw.encode("utf-8")).hexdigest()[:16]


# ── FIXED: 临时目录不再在生成器内销毁 ──

def _extract_zip_members(zip_path: Path, source_name: str) -> Iterator[Tuple[str, str, Path, object]]:
    """解压 zip 中的 pcap，yield (source, member_name, temp_path, tmpdir)。调用方用完后清理。"""
    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            if Path(info.filename).suffix.lower() not in PCAP_EXTS:
                continue
            tmpdir = tempfile.TemporaryDirectory()
            out = Path(tmpdir.name) / Path(info.filename).name
            with zf.open(info, "r") as src, out.open("wb") as dst:
                shutil.copyfileobj(src, dst)
            yield str(zip_path), info.filename, out, tmpdir


def iter_input_pcaps(paths: List[Path]) -> Iterator[Tuple[str, str, Path]]:
    """
    Yield (source_archive, member_name, local_path)。
    内部管理临时目录生命周期。
    """
    for p in paths:
        if p.is_file() and p.suffix.lower() in PCAP_EXTS:
            yield "", str(p), p

        elif p.is_file() and p.suffix.lower() == ".zip":
            for source, name, tmp_path, tmpdir in _extract_zip_members(p, str(p)):
                try:
                    yield source, name, tmp_path
                finally:
                    tmpdir.cleanup()

        elif p.is_dir():
            for child in sorted(p.rglob("*")):
                if child.is_file() and child.suffix.lower() in PCAP_EXTS:
                    yield "", str(child), child
                elif child.is_file() and child.suffix.lower() == ".zip":
                    for source, name, tmp_path, tmpdir in _extract_zip_members(child, str(child)):
                        try:
                            yield source, name, tmp_path
                        finally:
                            tmpdir.cleanup()


def build_tshark_fields(available: set) -> List[str]:
    base = [
        "frame.number",
        "frame.time_epoch",
        "ip.src",
        "ip.dst",
        "ipv6.src",
        "ipv6.dst",
        "ip.proto",
        "tcp.srcport",
        "tcp.dstport",
        "udp.srcport",
        "udp.dstport",
        "tcp.len",
        "udp.length",
        "tcp.flags",
        "_ws.col.Protocol",
        "_ws.col.Info",
        "tls.handshake.type",
        "tls.handshake.extensions_server_name",
        "tls.handshake.extensions_alpn_str",
        "tls.handshake.ciphersuite",
        "tls.handshake.version",
        "dns.qry.name",
        "dns.flags.rcode",
        "_ws.malformed",
        "malformed",
    ]
    # V2 新增
    optional = [
        "tls.handshake.ja3",
        "tls.handshake.ja4",
        "quic.version",
    ]

    fields = []
    for f in base + optional:
        if f.startswith("_ws.") or not available or f in available:
            fields.append(f)
    # 去重保序
    seen: set[str] = set()
    out: List[str] = []
    for f in fields:
        if f not in seen:
            seen.add(f)
            out.append(f)
    return out


def tshark_rows(pcap_path: Path, fields: List[str], timeout: int) -> Iterator[Dict[str, str]]:
    """惰性生成器：逐行 yield tshark 输出，不一次性加载到内存。"""
    cmd = [
        "tshark",
        "-r", str(pcap_path),
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=\t",
        "-E", "quote=d",
        "-E", "occurrence=f",
    ]
    for f in fields:
        cmd += ["-e", f]

    out = run_cmd(cmd, timeout=timeout)
    if not out.strip():
        return

    reader = csv.DictReader(out.splitlines(), delimiter="\t")
    yield from reader


def analyze_udp4500_payloads(pcap_path: Path, timeout: int) -> Dict[str, Any]:
    """检查 UDP 4500 中是否存在 ESP-in-UDP 结构。"""
    result: Dict[str, Any] = {
        "udp4500_payload_checked": 0,
        "udp4500_non_esp_marker_count": 0,
        "udp4500_esp_like_count": 0,
        "udp4500_spi_top": [],
        "esp_in_udp_like": False,
    }

    cmd = [
        "tshark", "-r", str(pcap_path),
        "-Y", "udp.port == 4500",
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=\t",
        "-E", "quote=d",
        "-E", "occurrence=f",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "udp.payload",
    ]

    try:
        out = run_cmd(cmd, timeout=timeout)
    except Exception:
        return result

    if not out.strip():
        return result

    reader = csv.DictReader(out.splitlines(), delimiter="\t")
    spi_counter: Counter = Counter()
    seq_by_dir_spi: Dict[Tuple[str, str, str], List[int]] = defaultdict(list)

    for row in reader:
        payload = (row.get("udp.payload") or "").replace(":", "").lower()
        if len(payload) < 8:
            continue
        result["udp4500_payload_checked"] += 1

        if payload.startswith("00000000"):
            result["udp4500_non_esp_marker_count"] += 1
            continue

        if len(payload) >= 16:
            spi = payload[:8]
            seq_hex = payload[8:16]
            try:
                seq = int(seq_hex, 16)
            except (ValueError, TypeError):
                continue
            src = row.get("ip.src") or ""
            dst = row.get("ip.dst") or ""
            key = (src, dst, spi)
            seq_by_dir_spi[key].append(seq)
            spi_counter[spi] += 1

    esp_like = 0
    for key, seqs in seq_by_dir_spi.items():
        if len(seqs) < 5:
            continue
        inc = 0
        total = 0
        prev = None
        for s in seqs:
            if prev is not None:
                total += 1
                if s > prev:
                    inc += 1
            prev = s
        if total > 0 and inc / total >= 0.6:
            esp_like += len(seqs)

    result["udp4500_esp_like_count"] = esp_like
    result["udp4500_spi_top"] = spi_counter.most_common(5)
    result["esp_in_udp_like"] = esp_like >= 10
    return result


def _new_flow_dict(
    flow_id: str, local_ip: str, local_port: int,
    remote_ip: str, remote_port: int, proto: str,
) -> Dict[str, Any]:
    return {
        "flow_id": flow_id,
        "local_ip": local_ip,
        "local_port": local_port,
        "remote_ip": remote_ip,
        "remote_port": remote_port,
        "proto": proto,
        "start_ts": None,
        "end_ts": None,
        "packet_count": 0,
        "byte_count": 0,
        "out_bytes": 0,
        "in_bytes": 0,
        "payload_counter": Counter(),
        "data_payload_counter": Counter(),
        "protocols": Counter(),
        "sni": Counter(),
        "dns": Counter(),
        "ja3": Counter(),
        "ja4": Counter(),
        "alpn_present": False,
        "tls_handshake_count": 0,
        "tls_clienthello_count": 0,
        "tcp_rst_count": 0,
        "tcp_syn_count": 0,
        "iat_count": 0,
        "iat_under_1ms": 0,
        "last_ts": None,
    }


def _finalize_flow_dict(f: Dict[str, Any]) -> Dict[str, Any]:
    duration = 0.0
    if f["start_ts"] is not None and f["end_ts"] is not None:
        duration = max(0.0, f["end_ts"] - f["start_ts"])

    data_total = sum(f["data_payload_counter"].values())
    payload_total = sum(f["payload_counter"].values())

    def ratio_mod(n: int) -> float:
        if data_total <= 0:
            return 0.0
        hits = 0
        for length, count in f["data_payload_counter"].items():
            if length > 100 and length % n == 0:
                hits += count
        return hits / data_total

    dominant_payload_size = 0
    dominant_payload_ratio = 0.0
    if payload_total > 0:
        size, cnt = f["payload_counter"].most_common(1)[0]
        dominant_payload_size = size
        dominant_payload_ratio = cnt / payload_total

    mtu_hits = sum(cnt for length, cnt in f["data_payload_counter"].items() if 1400 <= length <= 1460)
    mtu_fill_ratio = mtu_hits / data_total if data_total else 0.0

    ul_dl_ratio = None
    if f["in_bytes"] > 0:
        ul_dl_ratio = f["out_bytes"] / f["in_bytes"]
    elif f["out_bytes"] > 0:
        ul_dl_ratio = float("inf")

    fixed = {f"block_{n}_ratio": ratio_mod(n) for n in BLOCK_SIZES}

    out = {
        "flow_id": f["flow_id"],
        "local_ip": f["local_ip"],
        "local_port": f["local_port"],
        "remote_ip": f["remote_ip"],
        "remote_port": f["remote_port"],
        "proto": f["proto"],
        "start_ts": f["start_ts"],
        "end_ts": f["end_ts"],
        "duration": duration,
        "packet_count": f["packet_count"],
        "byte_count": f["byte_count"],
        "out_bytes": f["out_bytes"],
        "in_bytes": f["in_bytes"],
        "ul_dl_ratio": ul_dl_ratio,
        "dominant_payload_size": dominant_payload_size,
        "dominant_payload_ratio": dominant_payload_ratio,
        "mtu_fill_ratio": mtu_fill_ratio,
        "iat_under_1ms_ratio": f["iat_under_1ms"] / f["iat_count"] if f["iat_count"] else 0.0,
        "rst_ratio": f["tcp_rst_count"] / f["packet_count"] if f["packet_count"] else 0.0,
        "syn_count": f["tcp_syn_count"],
        "has_tls_handshake": f["tls_handshake_count"] > 0,
        "tls_clienthello_count": f["tls_clienthello_count"],
        "alpn_present": f["alpn_present"],
        "top_sni": f["sni"].most_common(3),
        "top_dns": f["dns"].most_common(3),
        "top_protocols": f["protocols"].most_common(5),
        "top_ja3": f["ja3"].most_common(3),
        "top_ja4": f["ja4"].most_common(3),
    }
    out.update(fixed)
    return out


def extract_features_for_pcap(
    pcap_path: Path,
    source_archive: str,
    member_name: str,
    available_fields: set,
    timeout: int,
    max_flows: int,
) -> Dict[str, Any]:
    fields = build_tshark_fields(available_fields)

    flows: Dict[Tuple[str, int, str, int, str], Dict[str, Any]] = {}

    summary: Dict[str, Any] = {
        "source_archive": source_archive,
        "pcap_member": member_name,
        "file_name": Path(member_name).name,
        "file_size_bytes": pcap_path.stat().st_size if pcap_path.exists() else None,
        "total_packets": 0,
        "tcp_packets": 0,
        "udp_packets": 0,
        "ip_proto_counts": Counter(),
        "protocol_counts": Counter(),
        "port_counts": Counter(),
        "sni_counter": Counter(),
        "dns_counter": Counter(),
        "ja3_counter": Counter(),
        "ja4_counter": Counter(),
        "tls_clienthello_count": 0,
        "tls_alpn_present_count": 0,
        "tls_alpn_missing_count": 0,
        "nonstandard_tls_flow_count": 0,
        "udp500_count": 0,
        "udp4500_count": 0,
        "udp53_count": 0,
        "udp53_large_count": 0,
        "malformed_count": 0,
        "total_payload_bytes": 0,
        "endpoint_bytes": Counter(),
        "payload_counter": Counter(),
        "data_payload_counter": Counter(),
        # V2 新增计数器
        "cipher_suite_counter": Counter(),
        "quic_frame_count": 0,
        "ssh_syn_timestamps": [],  # 用于周期性检测
        "random_local_domain_count": 0,
        "wpad_query_count": 0,
    }

    ssh_syn_timestamps: List[float] = []

    for row in tshark_rows(pcap_path, fields, timeout=timeout):
        summary["total_packets"] += 1

        ip_src = row.get("ip.src") or row.get("ipv6.src") or ""
        ip_dst = row.get("ip.dst") or row.get("ipv6.dst") or ""
        if not ip_src or not ip_dst:
            continue

        ip_proto = row.get("ip.proto") or ""
        if ip_proto:
            summary["ip_proto_counts"][ip_proto] += 1

        proto_col = (row.get("_ws.col.Protocol") or "").strip()
        if proto_col:
            summary["protocol_counts"][proto_col] += 1

        tcp_sport = int_or_zero(row.get("tcp.srcport"))
        tcp_dport = int_or_zero(row.get("tcp.dstport"))
        udp_sport = int_or_zero(row.get("udp.srcport"))
        udp_dport = int_or_zero(row.get("udp.dstport"))

        if tcp_sport or tcp_dport:
            proto = "TCP"
            src_port, dst_port = tcp_sport, tcp_dport
            payload_len = int_or_zero(row.get("tcp.len"))
            summary["tcp_packets"] += 1
        elif udp_sport or udp_dport:
            proto = "UDP"
            src_port, dst_port = udp_sport, udp_dport
            udp_len = int_or_zero(row.get("udp.length"))
            payload_len = max(0, udp_len - 8) if udp_len else 0
            summary["udp_packets"] += 1
        else:
            proto = f"IPPROTO_{ip_proto}" if ip_proto else "OTHER"
            src_port = dst_port = 0
            payload_len = 0

        if src_port:
            summary["port_counts"][str(src_port)] += 1
        if dst_port:
            summary["port_counts"][str(dst_port)] += 1

        if proto == "UDP" and (src_port == 500 or dst_port == 500):
            summary["udp500_count"] += 1
        if proto == "UDP" and (src_port == 4500 or dst_port == 4500):
            summary["udp4500_count"] += 1
        if proto == "UDP" and (src_port == 53 or dst_port == 53):
            summary["udp53_count"] += 1
            if payload_len > 512:
                summary["udp53_large_count"] += 1

        if row.get("_ws.malformed") or row.get("malformed"):
            summary["malformed_count"] += 1

        summary["total_payload_bytes"] += payload_len
        if payload_len > 0:
            summary["payload_counter"][payload_len] += 1
        if payload_len > 100:
            summary["data_payload_counter"][payload_len] += 1

        # V2: QUIC 帧检测
        quic_ver = row.get("quic.version") or ""
        if quic_ver.strip():
            summary["quic_frame_count"] += 1

        # V2: SSH SYN 时序收集
        tcp_flags_raw = int_or_zero(row.get("tcp.flags"))
        ts_raw = float_or_none(row.get("frame.time_epoch"))
        if proto == "TCP" and (tcp_flags_raw & 0x02) and (src_port == 22 or dst_port == 22):
            if ts_raw is not None:
                ssh_syn_timestamps.append(ts_raw)

        # V2: DNS 行为检测
        dns_qry = (row.get("dns.qry.name") or "").strip().lower()
        if dns_qry:
            if dns_qry.endswith(".local"):
                label = dns_qry.split(".")[0]
                if len(label) >= 8 and entropy_label(label) >= 3.0:
                    summary["random_local_domain_count"] += 1
            if dns_qry.startswith("wpad") or dns_qry.startswith("wpad."):
                summary["wpad_query_count"] += 1

        local_ip, _, local_port, remote_ip, remote_port, proto_norm = normalize_flow(
            ip_src, src_port, ip_dst, dst_port, proto
        )
        direction = infer_direction(ip_src, ip_dst, local_ip)
        ep = f"{remote_ip}:{remote_port}/{proto_norm}"
        summary["endpoint_bytes"][ep] += payload_len

        flow_key = (local_ip, local_port, remote_ip, remote_port, proto_norm)
        flow_id = safe_key(flow_key)
        if flow_key not in flows:
            flows[flow_key] = _new_flow_dict(flow_id, local_ip, local_port, remote_ip, remote_port, proto_norm)
        f = flows[flow_key]

        ts = float_or_none(row.get("frame.time_epoch"))
        if ts is not None:
            if f["start_ts"] is None:
                f["start_ts"] = ts
            f["end_ts"] = ts
            if f["last_ts"] is not None:
                dt = ts - f["last_ts"]
                if dt >= 0:
                    f["iat_count"] += 1
                    if dt < 0.001:
                        f["iat_under_1ms"] += 1
            f["last_ts"] = ts

        f["packet_count"] += 1
        f["byte_count"] += payload_len
        if direction == "outbound":
            f["out_bytes"] += payload_len
        elif direction == "inbound":
            f["in_bytes"] += payload_len

        if payload_len > 0:
            f["payload_counter"][payload_len] += 1
        if payload_len > 100:
            f["data_payload_counter"][payload_len] += 1

        if proto_col:
            f["protocols"][proto_col] += 1

        sni = (row.get("tls.handshake.extensions_server_name") or "").strip()
        if sni:
            f["sni"][sni] += 1
            summary["sni_counter"][sni] += 1

        dns = (row.get("dns.qry.name") or "").strip()
        if dns:
            f["dns"][dns] += 1
            summary["dns_counter"][dns] += 1

        ja3 = (row.get("tls.handshake.ja3") or "").strip()
        if ja3:
            f["ja3"][ja3] += 1
            summary["ja3_counter"][ja3] += 1

        ja4 = (row.get("tls.handshake.ja4") or "").strip()
        if ja4:
            f["ja4"][ja4] += 1
            summary["ja4_counter"][ja4] += 1

        hs_type = str(row.get("tls.handshake.type") or "").strip()
        if hs_type:
            f["tls_handshake_count"] += 1
            if hs_type == "1" or hs_type.startswith("1,"):
                f["tls_clienthello_count"] += 1
                summary["tls_clienthello_count"] += 1
                alpn = (row.get("tls.handshake.extensions_alpn_str") or "").strip()
                if alpn:
                    f["alpn_present"] = True
                    summary["tls_alpn_present_count"] += 1
                else:
                    summary["tls_alpn_missing_count"] += 1

                # V2: 密码套件统计 (ClientHello)
                cs = (row.get("tls.handshake.ciphersuite") or "").strip()
                if cs:
                    summary["cipher_suite_counter"][cs] += 1

        # ServerHello 密码套件 (handshake.type == 2)
        if hs_type == "2" or hs_type.startswith("2,"):
            cs = (row.get("tls.handshake.ciphersuite") or "").strip()
            if cs:
                summary["cipher_suite_counter"][cs] += 1

        tcp_flags = int_or_zero(row.get("tcp.flags"))
        if tcp_flags:
            if tcp_flags & 0x04:
                f["tcp_rst_count"] += 1
            if tcp_flags & 0x02:
                f["tcp_syn_count"] += 1

    finalized = [_finalize_flow_dict(f) for f in flows.values()]
    finalized.sort(key=lambda x: x["byte_count"], reverse=True)

    # 非标准端口 TLS 流统计
    nonstandard_tls = 0
    no_tls_large_flows = 0
    long_flow_count = 0
    max_mtu_fill = 0.0
    max_iat_u1ms = 0.0
    max_single_flow_bytes = 0

    total_file_payload = max(1, summary["total_payload_bytes"])

    for f in finalized:
        if f["duration"] > 60:
            long_flow_count += 1
        max_mtu_fill = max(max_mtu_fill, f["mtu_fill_ratio"])
        max_iat_u1ms = max(max_iat_u1ms, f["iat_under_1ms_ratio"])
        max_single_flow_bytes = max(max_single_flow_bytes, f["byte_count"])

        if f["has_tls_handshake"] and f["remote_port"] not in STANDARD_TLS_PORTS:
            nonstandard_tls += 1
        if (not f["has_tls_handshake"]) and f["byte_count"] > 1024 * 1024 and f["proto"] == "TCP":
            no_tls_large_flows += 1

    data_total = sum(summary["data_payload_counter"].values())

    def file_block_ratio(n: int) -> float:
        if data_total <= 0:
            return 0.0
        hits = 0
        for length, count in summary["data_payload_counter"].items():
            if length > 100 and length % n == 0:
                hits += count
        return hits / data_total

    payload_total = sum(summary["payload_counter"].values())
    dominant_payload_size = 0
    dominant_payload_ratio = 0.0
    if payload_total:
        size, count = summary["payload_counter"].most_common(1)[0]
        dominant_payload_size = size
        dominant_payload_ratio = count / payload_total

    mtu_hits = sum(cnt for length, cnt in summary["data_payload_counter"].items() if 1400 <= length <= 1460)
    mtu_fill_ratio = mtu_hits / data_total if data_total else 0.0

    top_endpoint, top_endpoint_bytes = ("", 0)
    if summary["endpoint_bytes"]:
        top_endpoint, top_endpoint_bytes = summary["endpoint_bytes"].most_common(1)[0]
    top_endpoint_ratio = top_endpoint_bytes / total_file_payload if total_file_payload else 0.0
    single_flow_dominance = max_single_flow_bytes / total_file_payload

    # V2: SSH SYN 周期性检测
    ssh_syn_periodic = False
    if len(ssh_syn_timestamps) > 20:
        intervals = []
        sorted_ts = sorted(ssh_syn_timestamps)
        for i in range(1, len(sorted_ts)):
            intervals.append(sorted_ts[i] - sorted_ts[i-1])
        if intervals:
            mean_interval = sum(intervals) / len(intervals)
            # 计算标准差
            variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
            std = math.sqrt(variance)
            # 判断周期性：标准差 / 均值 < 0.3 且 均值在 2-15 秒范围
            if mean_interval > 0 and std / mean_interval < 0.3 and 2 < mean_interval < 15:
                ssh_syn_periodic = True

    # 密码套件统计
    cipher_suite_unique_count = len(summary["cipher_suite_counter"])
    single_cipher = ""
    if cipher_suite_unique_count == 1 and summary["tls_clienthello_count"] > 0:
        single_cipher = list(summary["cipher_suite_counter"].keys())[0]

    # UDP4500 ESP-in-UDP
    udp4500_payload_info = analyze_udp4500_payloads(pcap_path, timeout=timeout)

    final_summary: Dict[str, Any] = {
        "source_archive": source_archive,
        "pcap_member": member_name,
        "file_name": Path(member_name).name,
        "file_size_bytes": summary["file_size_bytes"],
        "total_packets": summary["total_packets"],
        "tcp_packets": summary["tcp_packets"],
        "udp_packets": summary["udp_packets"],
        "ip_proto_counts": dict(summary["ip_proto_counts"].most_common()),
        "protocol_counts": dict(summary["protocol_counts"].most_common(20)),
        "port_counts_top": summary["port_counts"].most_common(30),
        "sni_top": summary["sni_counter"].most_common(30),
        "dns_top": summary["dns_counter"].most_common(30),
        "ja3_top": summary["ja3_counter"].most_common(10),
        "ja4_top": summary["ja4_counter"].most_common(10),
        "tls_clienthello_count": summary["tls_clienthello_count"],
        "tls_alpn_present_count": summary["tls_alpn_present_count"],
        "tls_alpn_missing_count": summary["tls_alpn_missing_count"],
        "alpn_missing_ratio": (
            summary["tls_alpn_missing_count"] / summary["tls_clienthello_count"]
            if summary["tls_clienthello_count"] else 0.0
        ),
        "nonstandard_tls_flow_count": nonstandard_tls,
        "no_tls_large_flow_count": no_tls_large_flows,
        "udp500_count": summary["udp500_count"],
        "udp4500_count": summary["udp4500_count"],
        "udp53_count": summary["udp53_count"],
        "udp53_large_count": summary["udp53_large_count"],
        "malformed_count": summary["malformed_count"],
        "total_payload_bytes": summary["total_payload_bytes"],
        "top_endpoint": top_endpoint,
        "top_endpoint_ratio": top_endpoint_ratio,
        "single_flow_dominance": single_flow_dominance,
        "flow_count": len(finalized),
        "long_flow_count": long_flow_count,
        "dominant_payload_size": dominant_payload_size,
        "dominant_payload_ratio": dominant_payload_ratio,
        "mtu_fill_ratio": mtu_fill_ratio,
        "max_flow_mtu_fill_ratio": max_mtu_fill,
        "max_flow_iat_under_1ms_ratio": max_iat_u1ms,
        "max_flow_duration": max((f["duration"] for f in finalized), default=0.0),
        "risk_tld_count": sum(
            1 for d, _ in list(summary["dns_counter"].items()) + list(summary["sni_counter"].items())
            # 风险 TLD 统一从共享配置读取，避免提取阶段和检测阶段定义不一致。
            if any(str(d).lower().endswith(tld) for tld in RISK_TLDS)
        ),
        "max_domain_entropy": max(
            [domain_entropy(str(d)) for d in list(summary["dns_counter"].keys()) + list(summary["sni_counter"].keys())] or [0.0]
        ),
        # V2 新增字段
        "cipher_suite_unique_count": cipher_suite_unique_count,
        "single_cipher_suite": single_cipher,
        "quic_frame_count": summary["quic_frame_count"],
        "ssh_syn_count": sum(1 for _ in ssh_syn_timestamps),
        "ssh_syn_periodic": ssh_syn_periodic,
        "random_local_domain_count": summary["random_local_domain_count"],
        "wpad_query_count": summary["wpad_query_count"],
    }
    final_summary["sample_id"] = make_sample_id(source_archive, member_name, Path(member_name).name, summary["file_size_bytes"])
    final_summary["capture_id"] = make_capture_id(source_archive, member_name, Path(member_name).name)
    final_summary["split_group"] = make_split_group(source_archive, member_name, Path(member_name).name, final_summary["capture_id"])
    for n in BLOCK_SIZES:
        final_summary[f"block_{n}_ratio"] = file_block_ratio(n)

    final_summary.update(udp4500_payload_info)

    return {
        "file_feature": final_summary,
        "top_flows": finalized[:max_flows],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="VPN pcap 特征提取器 V2")
    parser.add_argument("--input", nargs="+", required=True, help="输入 pcap/目录/zip，可多个")
    parser.add_argument("--out", default="features.jsonl", help="输出 JSONL")
    parser.add_argument("--timeout", type=int, default=180, help="单个 tshark 命令超时时间")
    parser.add_argument("--max-flows", type=int, default=50, help="每个文件保留 top flow 数量")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

    require_tshark()
    available = get_available_fields()

    inputs = [Path(x) for x in args.input]
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    count = 0
    with out_path.open("w", encoding="utf-8") as f_out:
        for source_archive, member_name, local_path in iter_input_pcaps(inputs):
            count += 1
            logger.info(f"[{count}] 分析：{member_name}")
            try:
                rec = extract_features_for_pcap(
                    local_path,
                    source_archive=source_archive,
                    member_name=member_name,
                    available_fields=available,
                    timeout=args.timeout,
                    max_flows=args.max_flows,
                )
                f_out.write(json.dumps(rec, ensure_ascii=False) + "\n")
                f_out.flush()
            except Exception as e:
                err_rec = {
                    "file_feature": {
                        "source_archive": source_archive,
                        "pcap_member": member_name,
                        "file_name": Path(member_name).name,
                        "extract_error": str(e),
                    },
                    "top_flows": [],
                }
                f_out.write(json.dumps(err_rec, ensure_ascii=False) + "\n")
                f_out.flush()
                logger.error(f"{member_name}: {e}")

    logger.info(f"写入特征 JSONL：{out_path} ({count} 个文件)")


if __name__ == "__main__":
    main()
