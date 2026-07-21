#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build flow-level Phase 2 features from packet rows."""

from __future__ import annotations

import argparse
import hashlib
import logging
import math
from pathlib import Path
from statistics import mean, pstdev
from typing import Any, Dict, Iterable, List, Tuple

from .parquet_writer import write_table
from .tshark_packets import packet_rows_for_inputs

logger = logging.getLogger(__name__)


def canonical_flow_tuple(packet: Dict[str, Any]) -> Tuple[str, int, str, int, str]:
    """Return a direction-invariant five tuple for grouping packets."""

    src = str(packet.get("src_ip") or "")
    dst = str(packet.get("dst_ip") or "")
    src_port = int(packet.get("src_port") or 0)
    dst_port = int(packet.get("dst_port") or 0)
    transport = str(packet.get("transport") or "OTHER").upper()
    left = (src, src_port)
    right = (dst, dst_port)
    if left <= right:
        return src, src_port, dst, dst_port, transport
    return dst, dst_port, src, src_port, transport


def stable_flow_id(sample_id: str, flow_tuple: Tuple[str, int, str, int, str]) -> str:
    raw = "|".join([sample_id, *[str(x) for x in flow_tuple]])
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:20]


def packet_direction(packet: Dict[str, Any], flow_tuple: Tuple[str, int, str, int, str]) -> int:
    """Return 1 for canonical src->dst, -1 for reverse direction."""

    src = str(packet.get("src_ip") or "")
    src_port = int(packet.get("src_port") or 0)
    if src == flow_tuple[0] and src_port == flow_tuple[1]:
        return 1
    return -1


def directions_for_packets(
    packets: List[Dict[str, Any]],
    flow_tuple: Tuple[str, int, str, int, str],
    direction_mode: str = "first_packet",
) -> List[int]:
    """Return packet signs using first-packet semantics or legacy canonical semantics."""

    if direction_mode not in {"first_packet", "canonical"}:
        raise ValueError("direction_mode must be first_packet or canonical")
    canonical = [packet_direction(packet, flow_tuple) for packet in packets]
    if direction_mode == "canonical" or not canonical:
        return canonical
    first_sign = canonical[0]
    return [1 if sign == first_sign else -1 for sign in canonical]


def build_flow_features(packet_rows: Iterable[Dict[str, Any]], metadata: Dict[str, Any], direction_mode: str = "first_packet") -> List[Dict[str, Any]]:
    """Aggregate packet rows into one row per canonical flow."""

    flows: Dict[Tuple[str, int, str, int, str], List[Dict[str, Any]]] = {}
    for packet in packet_rows:
        if not packet.get("src_ip") or not packet.get("dst_ip"):
            continue
        flows.setdefault(canonical_flow_tuple(packet), []).append(packet)

    out: List[Dict[str, Any]] = []
    for flow_tuple, packets in sorted(flows.items(), key=lambda item: item[0]):
        packets = sorted(packets, key=lambda p: (float(p.get("timestamp") or 0.0), int(p.get("frame_number") or 0)))
        timestamps = [float(p["timestamp"]) for p in packets if p.get("timestamp") is not None]
        lengths = [int(p.get("packet_len") or 0) for p in packets]
        iats = [max(0.0, timestamps[i] - timestamps[i - 1]) for i in range(1, len(timestamps))]
        directions = directions_for_packets(packets, flow_tuple, direction_mode)
        up_lengths = [length for length, direction in zip(lengths, directions) if direction == 1]
        down_lengths = [length for length, direction in zip(lengths, directions) if direction == -1]
        up_bytes = sum(up_lengths)
        down_bytes = sum(down_lengths)
        first_seen = min(timestamps) if timestamps else None
        last_seen = max(timestamps) if timestamps else None
        duration = max(0.0, (last_seen - first_seen)) if first_seen is not None and last_seen is not None else 0.0
        row = {
            **metadata,
            "flow_id": stable_flow_id(str(metadata.get("sample_id", "")), flow_tuple),
            "src_ip": flow_tuple[0],
            "dst_ip": flow_tuple[2],
            "src_port": flow_tuple[1],
            "dst_port": flow_tuple[3],
            "transport": flow_tuple[4],
            "direction_mode": direction_mode,
            "packet_count": len(packets),
            "byte_count": sum(lengths),
            "duration": duration,
            "iat_mean": _safe_mean(iats),
            "iat_std": _safe_std(iats),
            "pkt_len_mean": _safe_mean(lengths),
            "pkt_len_std": _safe_std(lengths),
            "up_packets": len(up_lengths),
            "down_packets": len(down_lengths),
            "up_bytes": up_bytes,
            "down_bytes": down_bytes,
            "up_down_byte_ratio": _ratio(up_bytes, down_bytes),
            "first_seen": first_seen,
            "last_seen": last_seen,
        }
        out.append(row)
    return out


def extract_flow_features(input_paths: List[Path], out_path: Path, timeout: int, direction_mode: str = "first_packet") -> None:
    rows: List[Dict[str, Any]] = []
    for metadata, packet_rows in packet_rows_for_inputs(input_paths, timeout):
        rows.extend(build_flow_features(packet_rows, metadata, direction_mode=direction_mode))
    write_table(rows, out_path)
    logger.info("Wrote flow features: %s (%d rows)", out_path, len(rows))


def _safe_mean(values: List[float] | List[int]) -> float:
    return float(mean(values)) if values else 0.0


def _safe_std(values: List[float] | List[int]) -> float:
    return float(pstdev(values)) if len(values) > 1 else 0.0


def _ratio(up: int, down: int) -> float:
    if down > 0:
        return float(up / down)
    if up > 0:
        return math.inf
    return 0.0


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract Phase 2 flow-level features")
    parser.add_argument("--input", nargs="+", required=True, help="pcap/pcapng/cap files, zips, or directories")
    parser.add_argument("--out", default="results/flow_features.parquet")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--direction-mode", choices=["first_packet", "canonical"], default="first_packet")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    extract_flow_features([Path(x) for x in args.input], Path(args.out), args.timeout, args.direction_mode)


if __name__ == "__main__":
    main()
