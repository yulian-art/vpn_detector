#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Audit manifest labels with rule-detection results.

This does not blindly turn model/rule predictions into ground truth. It flags conflicts,
can auto-fill only unknown labels, and produces a smaller list that really needs manual review.
"""
from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd

logger = logging.getLogger(__name__)

VPN_VERDICTS = {"vpn_confirmed", "vpn_suspected", "weak_suspicious"}
CONFIRMED_VERDICTS = {"vpn_confirmed"}


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def read_manifest(path: Path) -> pd.DataFrame:
    if path.suffix.lower() in {".xlsx", ".xls"}:
        return pd.read_excel(path)
    return pd.read_csv(path, encoding="utf-8-sig")


def norm_binary(x: Any) -> Optional[int]:
    if pd.isna(x) or str(x).strip() == "":
        return None
    s = str(x).strip().lower()
    if s in {"1", "vpn", "true", "yes", "y"}:
        return 1
    if s in {"0", "nonvpn", "non-vpn", "normal", "false", "no", "n"}:
        return 0
    try:
        return int(float(s))
    except Exception:
        return None


def result_key(r: Dict[str, Any]) -> str:
    return Path(str(r.get("pcap_member") or r.get("file_name") or "")).name.lower()


def audit(manifest: pd.DataFrame, rule_results: List[Dict[str, Any]], apply_unknown: bool = False, override_conflicts: bool = False) -> pd.DataFrame:
    df = manifest.copy()
    result_map = {result_key(r): r for r in rule_results}

    audit_cols = []
    for _, row in df.iterrows():
        fname = Path(str(row.get("pcap_member") or row.get("file_name") or "")).name.lower()
        r = result_map.get(fname)
        label = norm_binary(row.get("label_binary", row.get("is_vpn", None)))

        if r is None:
            audit_cols.append({
                "rule_verdict": "missing_rule_result",
                "rule_confidence": 0,
                "rule_vpn_family": "",
                "auto_binary_suggestion": "",
                "audit_status": "need_review",
                "audit_reason": "no_matching_rule_result",
            })
            continue

        verdict = str(r.get("verdict", ""))
        conf = int(float(r.get("confidence", 0) or 0))
        fam = str(r.get("vpn_family", ""))
        suggestion = 1 if verdict in VPN_VERDICTS and conf >= 70 else 0

        status = "ok"
        reason = "consistent"
        if label is None:
            status = "auto_fill_possible" if conf >= 70 or verdict == "no_vpn_evidence" else "need_review"
            reason = "binary_label_missing"
        elif label == 0 and verdict in CONFIRMED_VERDICTS and conf >= 85:
            status = "conflict_critical"
            reason = "manifest_nonvpn_but_rules_confirm_vpn"
        elif label == 1 and verdict == "no_vpn_evidence":
            status = "conflict_warning"
            reason = "manifest_vpn_but_rules_find_no_vpn_evidence"
        elif label == 1 and fam and fam not in {"unknown_vpn", ""} and str(row.get("label_tool", "")).lower() in {"unknown", "unknown_vpn", "unknown_tool", "nan"}:
            status = "auto_fill_possible"
            reason = "tool_label_missing_rule_family_available"

        audit_cols.append({
            "rule_verdict": verdict,
            "rule_confidence": conf,
            "rule_vpn_family": fam,
            "auto_binary_suggestion": suggestion,
            "audit_status": status,
            "audit_reason": reason,
        })

    audit_df = pd.concat([df.reset_index(drop=True), pd.DataFrame(audit_cols)], axis=1)

    if apply_unknown:
        for idx, row in audit_df.iterrows():
            label = norm_binary(row.get("label_binary", None))
            if label is None and row["audit_status"] == "auto_fill_possible":
                audit_df.at[idx, "label_binary"] = int(row["auto_binary_suggestion"])
                if int(row["auto_binary_suggestion"]) == 0:
                    audit_df.at[idx, "label_protocol"] = "NonVPN"
                    audit_df.at[idx, "label_tool"] = "NonVPN"
                elif row.get("rule_vpn_family") and row.get("label_tool") in {"", "unknown", "unknown_vpn", "unknown_tool"}:
                    audit_df.at[idx, "label_tool"] = row["rule_vpn_family"]
                audit_df.at[idx, "need_review"] = "no"
        if override_conflicts:
            mask = audit_df["audit_status"].isin(["conflict_critical", "conflict_warning"])
            audit_df.loc[mask, "label_binary"] = audit_df.loc[mask, "auto_binary_suggestion"].astype(int)
            audit_df.loc[mask, "need_review"] = "yes"  # still review overrides

    # Put critical rows first.
    order = {"conflict_critical": 0, "conflict_warning": 1, "need_review": 2, "auto_fill_possible": 3, "ok": 4}
    audit_df["_audit_order"] = audit_df["audit_status"].map(order).fillna(9)
    audit_df = audit_df.sort_values(["_audit_order", "file_name" if "file_name" in audit_df.columns else "pcap_member"]).drop(columns=["_audit_order"])
    return audit_df


def main() -> None:
    ap = argparse.ArgumentParser(description="Audit manifest with rule results")
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--results", required=True, help="rule results JSONL from run.py detect")
    ap.add_argument("--out", default="manifest_audited.csv")
    ap.add_argument("--apply-unknown", action="store_true", help="auto-fill only missing/unknown labels when rule evidence is strong")
    ap.add_argument("--override-conflicts", action="store_true", help="override conflicts too; not recommended for ground-truth creation")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    out = audit(read_manifest(Path(args.manifest)), load_jsonl(Path(args.results)), args.apply_unknown, args.override_conflicts)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(out_path, index=False, encoding="utf-8-sig")
    logger.info("Wrote audited manifest: %s", out_path)
    logger.info("Audit counts: %s", out["audit_status"].value_counts(dropna=False).to_dict())


if __name__ == "__main__":
    main()
