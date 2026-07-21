#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build first-N packet sequence features for each flow."""

from __future__ import annotations

import argparse
import logging
import math
from pathlib import Path
from typing import Any, Dict, Iterable, List

from .flow_builder import canonical_flow_tuple, directions_for_packets, stable_flow_id
from .parquet_writer import write_table
from .tshark_packets import packet_rows_for_inputs

logger = logging.getLogger(__name__)


def build_sequence_features(packet_rows: Iterable[Dict[str, Any]], metadata: Dict[str, Any], first_n: int = 64, direction_mode: str = "first_packet") -> List[Dict[str, Any]]:
    """Build one first-N sequence row per canonical flow."""

    if first_n not in {32, 64}:
        raise ValueError("first_n must be 32 or 64 in Phase 2")
    flows: Dict[tuple, List[Dict[str, Any]]] = {}
    for packet in packet_rows:
        if not packet.get("src_ip") or not packet.get("dst_ip"):
            continue
        flows.setdefault(canonical_flow_tuple(packet), []).append(packet)

    out: List[Dict[str, Any]] = []
    for flow_tuple, packets in sorted(flows.items(), key=lambda item: item[0]):
        packets = sorted(packets, key=lambda p: (float(p.get("timestamp") or 0.0), int(p.get("frame_number") or 0)))[:first_n]
        lengths = [int(p.get("packet_len") or 0) for p in packets]
        directions = directions_for_packets(packets, flow_tuple, direction_mode)
        signed_lengths = [length * direction for length, direction in zip(lengths, directions)]
        timestamps = [p.get("timestamp") for p in packets]
        iat_ms: List[float] = []
        prev = None
        for ts in timestamps:
            if ts is None:
                iat_ms.append(0.0)
                continue
            current = float(ts)
            if prev is None:
                iat_ms.append(0.0)
            else:
                iat_ms.append(max(0.0, (current - prev) * 1000.0))
            prev = current
        out.append({
            **metadata,
            "flow_id": stable_flow_id(str(metadata.get("sample_id", "")), flow_tuple),
            "direction_mode": direction_mode,
            "seq_len": len(packets),
            "pkt_len_seq": lengths,
            "signed_len_seq": signed_lengths,
            "direction_seq": directions,
            "iat_ms_seq": iat_ms,
            "log1p_iat_seq": [math.log1p(x) for x in iat_ms],
        })
    return out


def extract_sequence_features(input_paths: List[Path], out_path: Path, first_n: int, timeout: int, direction_mode: str = "first_packet") -> None:
    rows: List[Dict[str, Any]] = []
    for metadata, packet_rows in packet_rows_for_inputs(input_paths, timeout):
        rows.extend(build_sequence_features(packet_rows, metadata, first_n=first_n, direction_mode=direction_mode))
    write_table(rows, out_path)
    logger.info("Wrote sequence features: %s (%d rows)", out_path, len(rows))


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract Phase 2 first-N packet sequence features")
    parser.add_argument("--input", nargs="+", required=True, help="pcap/pcapng/cap files, zips, or directories")
    parser.add_argument("--out", default="results/sequence_first64.parquet")
    parser.add_argument("--first-n", type=int, choices=[32, 64], default=64)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--direction-mode", choices=["first_packet", "canonical"], default="first_packet")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    extract_sequence_features([Path(x) for x in args.input], Path(args.out), args.first_n, args.timeout, args.direction_mode)


if __name__ == "__main__":
    main()
