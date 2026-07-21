#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fuse rule-detection results with ML predictions."""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd

logger = logging.getLogger(__name__)


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def read_predictions(path: Path) -> pd.DataFrame:
    if path.suffix.lower() == ".parquet":
        return pd.read_parquet(path)
    return pd.read_csv(path, encoding="utf-8-sig")


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


def ml_prob_vpn(row: Dict[str, Any]) -> float:
    for col in ("ml_prob_vpn", "ml_prob_1", "ml_prob_true", "ml_prob_VPN"):
        if col in row and pd.notna(row[col]):
            return float(row[col])
    label = str(row.get("ml_pred_label", "")).lower()
    if label in {"1", "vpn", "true"}:
        return float(row.get("ml_pred_prob_max", 0.5) or 0.5)
    if "ml_pred_prob_max" in row:
        return 1.0 - float(row.get("ml_pred_prob_max", 0.5) or 0.5)
    return 0.0


def fuse_one(rule: Dict[str, Any], ml: Dict[str, Any], dl: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    has_rule = bool(rule)
    has_ml = bool(ml)
    rule_verdict = str(rule.get("verdict") or rule.get("rule_verdict") or "missing_rule_result")
    rule_conf = float(rule.get("confidence", rule.get("rule_confidence", 0)) or 0)
    prob = ml_prob_vpn(ml) if has_ml else 0.0
    ml_label = str(ml.get("ml_pred_label", "")) if has_ml else ""
    has_dl = dl is not None
    dl_prob = float((dl or {}).get("dl_prob_vpn", 0.0) or 0.0)

    if rule_verdict == "vpn_confirmed" and rule_conf >= 85:
        final = "vpn_confirmed"
        final_conf = max(rule_conf / 100.0, 0.85)
        reason = "high_conf_rule_override"
        review = False
    elif has_dl and dl_prob >= 0.85 and rule_verdict not in {"vpn_confirmed", "vpn_suspected"} and prob < 0.55:
        final = "vpn_suspected"
        final_conf = dl_prob
        reason = "dl_high_rule_ml_low"
        review = True
    elif not has_rule and prob >= 0.85:
        final = "vpn_suspected"
        final_conf = prob
        reason = "ml_high_rule_missing"
        review = True
    elif rule_verdict in {"vpn_confirmed", "vpn_suspected"} and prob >= 0.55:
        final = "vpn_confirmed" if prob >= 0.8 or rule_conf >= 85 else "vpn_suspected"
        final_conf = max(rule_conf / 100.0, prob)
        reason = "rule_ml_agree"
        review = False
    elif prob >= 0.85:
        final = "vpn_suspected"
        final_conf = prob
        reason = "ml_high_rule_not_confirmed"
        review = True
    elif rule_verdict == "weak_suspicious" or prob >= 0.55:
        final = "weak_suspicious"
        final_conf = max(rule_conf / 100.0, prob)
        reason = "weak_rule_or_ml_signal"
        review = True
    else:
        final = "no_vpn_evidence"
        final_conf = max(rule_conf / 100.0, 1.0 - prob if prob else 0.0)
        reason = "no_strong_signal"
        review = False

    result = {
        "sample_id": ml.get("sample_id", rule.get("sample_id", "")) if has_ml else rule.get("sample_id", (dl or {}).get("sample_id", "")),
        "source_archive": rule.get("source_archive", ml.get("source_archive", "") if has_ml else (dl or {}).get("source_archive", "")),
        "pcap_member": rule.get("pcap_member", ml.get("pcap_member", "") if has_ml else (dl or {}).get("pcap_member", "")),
        "file_name": rule.get("file_name", ml.get("file_name", "") if has_ml else (dl or {}).get("file_name", "")),
        "final_verdict": final,
        "final_confidence": round(float(final_conf), 4),
        "rule_verdict": rule_verdict,
        "rule_confidence": rule_conf,
        "ml_prob_vpn": round(prob, 6),
        "ml_pred_label": ml_label,
        "matched_rules": json.dumps(rule.get("matched_rules", []), ensure_ascii=False),
        "evidence": json.dumps(rule.get("evidence", []), ensure_ascii=False),
        "top_sni": json.dumps(rule.get("top_sni", []), ensure_ascii=False),
        "top_dns": json.dumps(rule.get("top_dns", []), ensure_ascii=False),
        "best_block": rule.get("best_block", ""),
        "best_block_ratio": rule.get("best_block_ratio", ""),
        "decision_reason_code": reason,
        "review_recommended": bool(review),
    }
    if has_dl:
        result.update({
            "dl_pred_label": int((dl or {}).get("dl_pred_label", dl_prob >= 0.5)),
            "dl_prob_vpn": round(dl_prob, 6),
            "dl_evidence_count": int((dl or {}).get("dl_evidence_count", 0)),
            "dl_top_k_mean_prob_vpn": round(float((dl or {}).get("dl_top_k_mean_prob_vpn", dl_prob) or 0.0), 6),
            "dl_high_risk_flow_count": int((dl or {}).get("dl_high_risk_flow_count", 0)),
        })
    return result


def aggregate_dl_predictions(path: Path, top_k: int = 3, high_risk_threshold: float = 0.85) -> List[Dict[str, Any]]:
    frame = read_predictions(path)
    if "dl_prob_vpn" not in frame.columns:
        raise ValueError("DL predictions must contain dl_prob_vpn")
    key = "sample_id" if "sample_id" in frame.columns else None
    if key is None:
        raise ValueError("DL predictions must contain sample_id for sample-level aggregation")
    rows: List[Dict[str, Any]] = []
    for sample_id, group in frame.groupby(key, dropna=False):
        probs = pd.to_numeric(group["dl_prob_vpn"], errors="coerce").fillna(0.0).sort_values(ascending=False)
        maximum = float(probs.max()) if len(probs) else 0.0
        row = group.iloc[0].to_dict()
        row.update({
            "sample_id": sample_id,
            "dl_prob_vpn": maximum,
            "dl_pred_label": int(maximum >= 0.5),
            "dl_evidence_count": int(len(group)),
            "dl_top_k_mean_prob_vpn": float(probs.head(top_k).mean()) if len(probs) else 0.0,
            "dl_high_risk_flow_count": int((probs >= high_risk_threshold).sum()),
        })
        rows.append(row)
    return rows


def fuse_decisions(rule_results: Path, ml_predictions: Path, out_path: Path, csv_out: Optional[Path] = None, dl_predictions: Optional[Path] = None) -> pd.DataFrame:
    rules = load_jsonl(rule_results)
    preds_df = read_predictions(ml_predictions)
    pred_index: Dict[str, int] = {}
    pred_rows: List[Dict[str, Any]] = []
    for _, series in preds_df.iterrows():
        row = series.to_dict()
        pred_id = len(pred_rows)
        pred_rows.append(row)
        for key in row_keys(row):
            pred_index.setdefault(key, pred_id)

    dl_rows = aggregate_dl_predictions(dl_predictions) if dl_predictions else []
    dl_index: Dict[str, int] = {}
    for dl_id, row in enumerate(dl_rows):
        for key in row_keys(row):
            dl_index.setdefault(key, dl_id)

    rows = []
    matched_pred_ids = set()
    matched_dl_ids = set()
    for rule in rules:
        pred_id = None
        for key in row_keys(rule):
            if key in pred_index:
                pred_id = pred_index[key]
                matched_pred_ids.add(pred_id)
                break
        ml = pred_rows[pred_id] if pred_id is not None else {}
        dl_id = next((dl_index[key] for key in row_keys(rule) if key in dl_index), None)
        if dl_id is None and ml:
            dl_id = next((dl_index[key] for key in row_keys(ml) if key in dl_index), None)
        if dl_id is not None:
            matched_dl_ids.add(dl_id)
        rows.append(fuse_one(rule, ml, dl_rows[dl_id] if dl_id is not None else ({} if dl_predictions else None)))

    for pred_id, pred in enumerate(pred_rows):
        if pred_id not in matched_pred_ids:
            dl_id = next((dl_index[key] for key in row_keys(pred) if key in dl_index), None)
            if dl_id is not None:
                matched_dl_ids.add(dl_id)
            rows.append(fuse_one({}, pred, dl_rows[dl_id] if dl_id is not None else ({} if dl_predictions else None)))

    for dl_id, dl in enumerate(dl_rows):
        if dl_id not in matched_dl_ids:
            rows.append(fuse_one({}, {}, dl))

    out = pd.DataFrame(rows)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.suffix.lower() == ".parquet":
        out.to_parquet(out_path, index=False)
    else:
        out.to_csv(out_path, index=False, encoding="utf-8-sig")
    if csv_out:
        csv_out.parent.mkdir(parents=True, exist_ok=True)
        out.to_csv(csv_out, index=False, encoding="utf-8-sig")
    logger.info("Wrote fusion predictions: %s (%d rows)", out_path, len(out))
    return out


def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="Fuse rule results and ML predictions")
    parser.add_argument("--rule-results", required=True)
    parser.add_argument("--ml-predictions", required=True)
    parser.add_argument("--out", default="fusion_predictions.parquet")
    parser.add_argument("--csv-out")
    parser.add_argument("--dl-predictions")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    fuse_decisions(Path(args.rule_results), Path(args.ml_predictions), Path(args.out), Path(args.csv_out) if args.csv_out else None, Path(args.dl_predictions) if args.dl_predictions else None)


if __name__ == "__main__":
    main()
