#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Packet-row extraction for Phase 2 flow and sequence features."""

from __future__ import annotations

import argparse
import csv
import logging
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple

from vpn_detector.identity import make_capture_id, make_sample_id, make_split_group

logger = logging.getLogger(__name__)

PCAP_EXTS = {".pcap", ".pcapng", ".cap"}


def require_tshark() -> None:
    if shutil.which("tshark") is None:
        raise SystemExit("tshark not found. Install Wireshark and add tshark to PATH before using extract-flow/extract-seq.")


def run_cmd(cmd: List[str], timeout: int) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Command timed out: {' '.join(cmd)}") from exc
    if proc.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\nSTDERR:\n{proc.stderr[:2000]}")
    return proc.stdout


def _extract_zip_members(zip_path: Path) -> Iterator[Tuple[str, str, Path, tempfile.TemporaryDirectory]]:
    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            if info.is_dir() or Path(info.filename).suffix.lower() not in PCAP_EXTS:
                continue
            tmpdir = tempfile.TemporaryDirectory()
            out = Path(tmpdir.name) / Path(info.filename).name
            with zf.open(info, "r") as src, out.open("wb") as dst:
                shutil.copyfileobj(src, dst)
            yield str(zip_path), info.filename, out, tmpdir


def iter_input_pcaps(paths: List[Path]) -> Iterator[Tuple[str, str, Path]]:
    """Yield source_archive, pcap_member, and local pcap path."""

    for path in paths:
        if path.is_file() and path.suffix.lower() in PCAP_EXTS:
            yield "", str(path), path
        elif path.is_file() and path.suffix.lower() == ".zip":
            for source, member, local, tmpdir in _extract_zip_members(path):
                try:
                    yield source, member, local
                finally:
                    tmpdir.cleanup()
        elif path.is_dir():
            for child in sorted(path.rglob("*")):
                if child.is_file() and child.suffix.lower() in PCAP_EXTS:
                    yield "", str(child), child
                elif child.is_file() and child.suffix.lower() == ".zip":
                    for source, member, local, tmpdir in _extract_zip_members(child):
                        try:
                            yield source, member, local
                        finally:
                            tmpdir.cleanup()


def sample_metadata(source_archive: str, pcap_member: str, file_size_bytes: Any = "") -> Dict[str, str]:
    """Build Phase-1-compatible sample identity metadata."""

    file_name = Path(pcap_member).name
    sample_id = make_sample_id(source_archive, pcap_member, file_name, file_size_bytes)
    capture_id = make_capture_id(source_archive, pcap_member, file_name)
    return {
        "sample_id": sample_id,
        "capture_id": capture_id,
        "split_group": make_split_group(source_archive, pcap_member, file_name, capture_id),
        "source_archive": source_archive,
        "pcap_member": pcap_member,
        "file_name": file_name,
    }


def tshark_packet_rows(pcap_path: Path, timeout: int) -> Iterator[Dict[str, Any]]:
    """Run tshark and yield normalized packet rows."""

    fields = [
        "frame.number",
        "frame.time_epoch",
        "frame.len",
        "ip.src",
        "ip.dst",
        "ipv6.src",
        "ipv6.dst",
        "tcp.srcport",
        "tcp.dstport",
        "udp.srcport",
        "udp.dstport",
        "_ws.col.Protocol",
    ]
    cmd = [
        "tshark",
        "-r",
        str(pcap_path),
        "-T",
        "fields",
        "-E",
        "header=y",
        "-E",
        "separator=\t",
        "-E",
        "quote=d",
        "-E",
        "occurrence=f",
    ]
    for field in fields:
        cmd += ["-e", field]
    out = run_cmd(cmd, timeout)
    if not out.strip():
        return
    for raw in csv.DictReader(out.splitlines(), delimiter="\t"):
        yield normalize_packet_row(raw)


def normalize_packet_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a tshark row into the packet schema used by builders."""

    src_port = _int_or_none(row.get("tcp.srcport")) or _int_or_none(row.get("udp.srcport")) or 0
    dst_port = _int_or_none(row.get("tcp.dstport")) or _int_or_none(row.get("udp.dstport")) or 0
    transport = "TCP" if row.get("tcp.srcport") or row.get("tcp.dstport") else ("UDP" if row.get("udp.srcport") or row.get("udp.dstport") else str(row.get("_ws.col.Protocol") or "OTHER"))
    return {
        "frame_number": _int_or_none(row.get("frame.number")) or 0,
        "timestamp": _float_or_none(row.get("frame.time_epoch")),
        "packet_len": _int_or_none(row.get("frame.len")) or 0,
        "src_ip": row.get("ip.src") or row.get("ipv6.src") or "",
        "dst_ip": row.get("ip.dst") or row.get("ipv6.dst") or "",
        "src_port": src_port,
        "dst_port": dst_port,
        "transport": transport.upper(),
    }


def packet_rows_for_inputs(paths: List[Path], timeout: int) -> Iterator[Tuple[Dict[str, str], List[Dict[str, Any]]]]:
    """Yield metadata and packet rows for each pcap input."""

    require_tshark()
    for source_archive, pcap_member, local_path in iter_input_pcaps(paths):
        meta = sample_metadata(source_archive, pcap_member, local_path.stat().st_size if local_path.exists() else "")
        rows = list(tshark_packet_rows(local_path, timeout))
        yield meta, rows


def _int_or_none(value: Any) -> int | None:
    text = str(value or "").strip()
    if not text:
        return None
    if "," in text:
        text = text.split(",", 1)[0]
    try:
        return int(float(text))
    except Exception:
        return None


def _float_or_none(value: Any) -> float | None:
    text = str(value or "").strip()
    if not text:
        return None
    if "," in text:
        text = text.split(",", 1)[0]
    try:
        return float(text)
    except Exception:
        return None
