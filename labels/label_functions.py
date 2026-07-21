#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Labeling functions for strict labels.

The functions here emit votes only from observable inputs: directory roots,
manifest fields, rule results, or user-supplied review/analysis tables.
"""

from __future__ import annotations

import json
import logging
import zipfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import pandas as pd

from .schema import LabelConfidence, LabelVote, normalize_binary_label, normalize_confidence
from ..identity import make_capture_id, make_sample_id, make_split_group

logger = logging.getLogger(__name__)

PCAP_EXTS = {".pcap", ".pcapng", ".cap"}
NONVPN_HINTS = ("nonvpn", "non-vpn", "non_vpn", "normal", "benign", "novpn", "no-vpn")
VPN_HINTS = ("vpn", "proxy", "clash", "wireguard", "openvpn", "shadowsocks", "vless", "vmess")
VPN_VERDICTS = {"vpn_confirmed", "vpn_suspected", "weak_suspicious"}


def norm_path(path: Path) -> str:
    try:
        return str(path.resolve()).replace("\\", "/").lower()
    except Exception:
        return str(path).replace("\\", "/").lower()


def is_under(path_text: str, root: str | Path | None) -> bool:
    if not root:
        return False
    try:
        p = Path(path_text).resolve()
        r = Path(root).resolve()
        p.relative_to(r)
        return True
    except Exception:
        return norm_path(Path(path_text)).startswith(norm_path(Path(root)).rstrip("/") + "/")


def read_table(path: Path) -> pd.DataFrame:
    """Read CSV/XLSX/JSON/JSONL table input."""

    suffix = path.suffix.lower()
    if suffix in {".xlsx", ".xls"}:
        return pd.read_excel(path)
    if suffix == ".jsonl":
        rows = []
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
        return pd.DataFrame(rows)
    if suffix == ".json":
        with path.open("r", encoding="utf-8") as fh:
            obj = json.load(fh)
        return pd.DataFrame(obj if isinstance(obj, list) else obj.get("rows", []))
    return pd.read_csv(path, encoding="utf-8-sig")


def iter_input_samples(paths: Iterable[Path]) -> List[Dict[str, Any]]:
    """Scan pcaps/zips or load manifest-like rows as label entities."""

    rows: List[Dict[str, Any]] = []
    for path in paths:
        if path.is_dir():
            for child in sorted(path.rglob("*")):
                if child.is_file() and child.suffix.lower() in PCAP_EXTS:
                    rows.append(sample_from_path(child))
        elif path.is_file() and path.suffix.lower() in PCAP_EXTS:
            rows.append(sample_from_path(path))
        elif path.is_file() and path.suffix.lower() == ".zip":
            rows.extend(samples_from_zip(path))
        elif path.is_file() and path.suffix.lower() in {".csv", ".xlsx", ".xls", ".json", ".jsonl"}:
            for _, row in read_table(path).iterrows():
                rows.append(sample_from_manifest_row(row.to_dict()))
    return rows


def sample_from_path(path: Path) -> Dict[str, Any]:
    file_name = path.name
    pcap_member = str(path)
    size = path.stat().st_size if path.exists() else ""
    capture_id = make_capture_id("", pcap_member, file_name)
    return {
        "entity_level": "file",
        "sample_id": make_sample_id("", pcap_member, file_name, size),
        "capture_id": capture_id,
        "source_archive": "",
        "pcap_member": str(path),
        "file_name": path.name,
        "device_id": "unknown_device",
        "network_id": "unknown_network",
        "time_period": "unknown_time",
        "split_group": make_split_group("", pcap_member, file_name, capture_id),
        "note": "",
    }


def samples_from_zip(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    try:
        with zipfile.ZipFile(path, "r") as zf:
            for info in zf.infolist():
                if info.is_dir() or Path(info.filename).suffix.lower() not in PCAP_EXTS:
                    continue
                file_name = Path(info.filename).name
                capture_id = make_capture_id(str(path), info.filename, file_name)
                rows.append({
                    "entity_level": "file",
                    "sample_id": make_sample_id(str(path), info.filename, file_name, info.file_size),
                    "capture_id": capture_id,
                    "source_archive": str(path),
                    "pcap_member": info.filename,
                    "file_name": Path(info.filename).name,
                    "device_id": "unknown_device",
                    "network_id": "unknown_network",
                    "time_period": "unknown_time",
                    "split_group": make_split_group(str(path), info.filename, file_name, capture_id),
                    "note": "",
                })
    except zipfile.BadZipFile:
        logger.warning("Bad zip skipped: %s", path)
    return rows


def sample_from_manifest_row(row: Dict[str, Any]) -> Dict[str, Any]:
    file_name = str(row.get("file_name") or Path(str(row.get("pcap_member") or "")).name)
    pcap_member = str(row.get("pcap_member") or file_name)
    source_archive = str(row.get("source_archive") or "")
    file_size = row.get("file_size_bytes", row.get("size_bytes", ""))
    sample_id = str(row.get("sample_id") or make_sample_id(source_archive, pcap_member, file_name, file_size))
    capture_id = str(row.get("capture_id") or make_capture_id(source_archive, pcap_member, file_name))
    out = dict(row)
    out.update({
        "entity_level": row.get("entity_level", "file"),
        "sample_id": sample_id,
        "capture_id": capture_id,
        "source_archive": source_archive,
        "pcap_member": pcap_member,
        "file_name": file_name,
        "split_group": str(row.get("split_group") or make_split_group(source_archive, pcap_member, file_name, capture_id)),
    })
    return out


def sample_text(sample: Dict[str, Any]) -> str:
    return " ".join(str(sample.get(k, "")) for k in ("source_archive", "pcap_member", "file_name")).lower()


def sample_under_root(sample: Dict[str, Any], root: str | Path | None) -> bool:
    """Return true when a raw pcap or its source zip is under the given root."""

    if not root:
        return False
    return is_under(str(sample.get("pcap_member", "")), root) or is_under(str(sample.get("source_archive", "")), root)


def lf_from_vpn_root(sample: Dict[str, Any], vpn_root: str | Path | None = None) -> Optional[LabelVote]:
    if sample_under_root(sample, vpn_root):
        return LabelVote(
            "vpn_root",
            "binary",
            1,
            LabelConfidence.STRONG,
            evidence={"vpn_root": str(vpn_root), "source_archive": sample.get("source_archive", ""), "pcap_member": sample.get("pcap_member", "")},
            reason="pcap_or_source_archive_under_vpn_root",
        )
    return None


def lf_from_nonvpn_root(sample: Dict[str, Any], nonvpn_root: str | Path | None = None) -> Optional[LabelVote]:
    if sample_under_root(sample, nonvpn_root):
        return LabelVote(
            "nonvpn_root",
            "binary",
            0,
            LabelConfidence.STRONG,
            evidence={"nonvpn_root": str(nonvpn_root), "source_archive": sample.get("source_archive", ""), "pcap_member": sample.get("pcap_member", "")},
            reason="pcap_or_source_archive_under_nonvpn_root",
        )
    return None


def lf_from_path_keywords(sample: Dict[str, Any]) -> Optional[LabelVote]:
    text = sample_text(sample)
    if any(h in text for h in NONVPN_HINTS):
        return LabelVote("path_keywords", "binary", 0, LabelConfidence.MEDIUM, evidence={"matched": "nonvpn_hint"}, reason="path_contains_nonvpn_hint")
    if any(h in text for h in VPN_HINTS):
        return LabelVote("path_keywords", "binary", 1, LabelConfidence.WEAK, evidence={"matched": "vpn_hint"}, reason="path_contains_vpn_hint")
    return None


def lf_from_manifest_v4_fields(row: Dict[str, Any]) -> Optional[LabelVote]:
    value = normalize_binary_label(row.get("label_binary", row.get("is_vpn")))
    if value is None:
        return None
    status = str(row.get("label_status") or row.get("label_source") or "").lower()
    confidence = LabelConfidence.STRONG if "verified" in status or "dir_" in status else LabelConfidence.MEDIUM
    return LabelVote("manifest_v4", "binary", value, confidence, evidence={"row_file": row.get("file_name")}, reason="manifest_binary_field")


def lf_from_rule_results(row: Dict[str, Any]) -> Optional[LabelVote]:
    verdict = str(row.get("verdict") or row.get("rule_verdict") or "").strip()
    confidence = float(row.get("confidence", row.get("rule_confidence", 0)) or 0)
    if verdict in VPN_VERDICTS:
        level = LabelConfidence.MEDIUM if verdict == "vpn_confirmed" and confidence >= 85 else LabelConfidence.WEAK
        return LabelVote("rule_results", "binary", 1, level, evidence=row, reason=f"rule_verdict_{verdict}", family=str(row.get("vpn_family") or ""))
    if verdict == "no_vpn_evidence":
        return LabelVote("rule_results", "binary", 0, LabelConfidence.WEAK, evidence=row, reason="rule_no_vpn_evidence")
    return None


def lf_from_manual_review(row: Dict[str, Any]) -> Optional[LabelVote]:
    value = normalize_binary_label(row.get("label_binary", row.get("vote", row.get("is_vpn"))))
    if value is None:
        return None
    confidence = normalize_confidence(row.get("confidence") or "strong")
    if confidence == LabelConfidence.UNLABELED:
        confidence = LabelConfidence.STRONG
    return LabelVote("manual_review", "binary", value, confidence, evidence=row.get("evidence", ""), reason=str(row.get("note") or "manual_review"), family=str(row.get("label_family") or row.get("family") or ""))


def lf_from_analysis_doc_table(row: Dict[str, Any]) -> Optional[LabelVote]:
    value = normalize_binary_label(row.get("label_binary", row.get("vote", row.get("is_vpn"))))
    if value is None:
        return None
    confidence = normalize_confidence(row.get("confidence") or "medium")
    if confidence == LabelConfidence.STRONG:
        confidence = LabelConfidence.MEDIUM
    return LabelVote("analysis_doc_table", "binary", value, confidence, evidence=row.get("evidence", ""), reason=str(row.get("note") or "analysis_doc_table"), family=str(row.get("label_family") or row.get("family") or ""))


def metadata_votes(source: str, row: Dict[str, Any], confidence: LabelConfidence) -> List[LabelVote]:
    """Create optional protocol/tool/family/scenario votes from a table row."""

    votes: List[LabelVote] = []
    mappings = {
        "label_protocol": "protocol",
        "label_tool": "tool",
        "label_family": "family",
        "scenario": "scenario",
    }
    for col, task in mappings.items():
        value = row.get(col)
        if value is not None and str(value).strip() and str(value).strip().lower() not in {"nan", "unknown", "none"}:
            votes.append(LabelVote(source, task, str(value).strip(), confidence, evidence={"field": col}, reason=f"{source}_{col}"))
    return votes


def load_side_votes(paths: Iterable[str] | None, lf_name: str) -> Dict[str, List[LabelVote]]:
    """Load manual/analysis/rule side inputs and index votes by filename keys."""

    out: Dict[str, List[LabelVote]] = {}
    if not paths:
        return out
    for raw in paths:
        path = Path(raw)
        if not path.exists():
            raise FileNotFoundError(f"label side input not found: {path}")
        df = read_table(path)
        for _, series in df.iterrows():
            row = series.to_dict()
            if lf_name == "manual":
                vote = lf_from_manual_review(row)
                source = "manual_review"
                meta_conf = normalize_confidence(row.get("confidence") or "strong")
            elif lf_name == "analysis":
                vote = lf_from_analysis_doc_table(row)
                source = "analysis_doc_table"
                meta_conf = normalize_confidence(row.get("confidence") or "medium")
                if meta_conf == LabelConfidence.STRONG:
                    meta_conf = LabelConfidence.MEDIUM
            else:
                vote = lf_from_rule_results(row)
                source = "rule_results"
                meta_conf = LabelConfidence.WEAK
            votes = [vote] if vote else []
            votes.extend(metadata_votes(source, row, meta_conf))
            for key in row_keys(row):
                out.setdefault(key, []).extend(votes)
    return out


def row_keys(row: Dict[str, Any]) -> List[str]:
    keys = set()
    for col in ("sample_id", "pcap_member", "file_name"):
        val = row.get(col)
        if val is None:
            continue
        text = str(val)
        if text and text.lower() != "nan":
            keys.add(text.lower())
            keys.add(Path(text).name.lower())
    return [k for k in keys if k]


def votes_for_sample_from_index(sample: Dict[str, Any], index: Dict[str, List[LabelVote]]) -> List[LabelVote]:
    votes: List[LabelVote] = []
    seen = set()
    for key in row_keys(sample):
        for vote in index.get(key, []):
            marker = (vote.source, vote.task, str(vote.value), vote.reason)
            if marker not in seen:
                votes.append(vote)
                seen.add(marker)
    return votes
