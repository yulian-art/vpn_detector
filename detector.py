"""
VPN 检测器 — 编排规则引擎 + 组合评分。
替代原 vpn_detector_v1.py 中的 detect_one / main。
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import DOMAIN_KEYWORDS, RISK_TLDS, SPECIAL_PORTS
from .models import DetectionResult
from .rules_engine import (
    ComboScorer,
    Feature,
    RuleEngine,
    RuleMatch,
    infer_vpn_family,
)
from .utils import (
    all_domains,
    get_ports,
    max_block_ratio,
    protocol_text,
)

logger = logging.getLogger(__name__)

_engine = RuleEngine()
_scorer = ComboScorer()


def detect_one(rec: Dict[str, Any]) -> DetectionResult:
    """对单个 pcap 特征记录执行 VPN 检测。"""
    f: Feature = rec.get("file_feature", {})
    source_archive = str(f.get("source_archive", ""))
    pcap_member = str(f.get("pcap_member", ""))
    file_name = str(f.get("file_name", ""))

    # ── 一击命中规则 ──
    matches: List[RuleMatch] = _engine.match(f)
    matched_ids = [m.rule_id for m in matches]

    # 分离高置信规则 (>= 90) 和低置信规则
    high_conf_matches = [m for m in matches if m.confidence >= 90]
    low_conf_matches = [m for m in matches if m.confidence < 90]

    if high_conf_matches:
        # 高置信规则命中 → 直接确认
        verdict = "vpn_confirmed"
        confidence = max(m.confidence for m in high_conf_matches)
        combo_score = None
        combo_detail: Dict[str, int] = {}
        evidence = [m.evidence for m in high_conf_matches]
    elif matches:
        # 仅有低置信规则 → 转入组合评分，低置信规则作为加分项
        low_conf_evidence = [m.evidence for m in matches]
        scores, combo_evidence = _scorer.score(f)
        # 每条低置信规则额外 +1 分
        bonus = len(matches) * 1
        total = scores.total + bonus
        evidence = combo_evidence + low_conf_evidence

        if total >= 14:
            verdict = "vpn_confirmed"
            confidence = min(94, 85 + total)
        elif total >= 10:
            verdict = "vpn_suspected"
            confidence = min(84, 70 + total * 2)
        elif total >= 8:
            verdict = "weak_suspicious"
            confidence = min(69, 55 + total * 3)
        else:
            verdict = "no_vpn_evidence"
            confidence = 0

        combo_score = total
        combo_detail = scores.to_dict()
    else:
        # ── 组合评分 ──
        scores, combo_evidence = _scorer.score(f)
        total = scores.total
        evidence = combo_evidence

        if total >= 14:
            verdict = "vpn_confirmed"
            confidence = min(94, 85 + total)
        elif total >= 10:
            verdict = "vpn_suspected"
            confidence = min(84, 70 + total * 2)
        elif total >= 8:
            verdict = "weak_suspicious"
            confidence = min(69, 55 + total * 3)
        else:
            verdict = "no_vpn_evidence"
            confidence = 0

        combo_score = total
        combo_detail = scores.to_dict()

    # ── VPN 类型推断 ──
    family = infer_vpn_family(f, " ".join(evidence)) if verdict != "no_vpn_evidence" else ""

    best_block, best_block_ratio = max_block_ratio(f)

    return {
        "source_archive": source_archive,
        "pcap_member": pcap_member,
        "file_name": file_name,
        "verdict": verdict,
        "vpn_family": family,
        "confidence": confidence,
        "risk_score": round(confidence / 10, 2) if confidence else 0,
        "matched_rules": matched_ids,
        "combo_score": combo_score,
        "combo_detail": combo_detail,
        "evidence": evidence[:20],
        "top_endpoint": str(f.get("top_endpoint", "")),
        "top_endpoint_ratio": float(f.get("top_endpoint_ratio", 0) or 0),
        "top_sni": list(f.get("sni_top", [])[:5]),
        "top_dns": list(f.get("dns_top", [])[:5]),
        "dominant_payload_size": int(f.get("dominant_payload_size", 0) or 0),
        "dominant_payload_ratio": float(f.get("dominant_payload_ratio", 0) or 0),
        "best_block": best_block,
        "best_block_ratio": best_block_ratio,
        "notes": str(f.get("extract_error", "")),
    }


def run_detection(
    features_path: str,
    output_path: str,
    excel_path: Optional[str] = None,
) -> List[DetectionResult]:
    """从 features.jsonl 读取并检测，写入结果。"""
    features_file = Path(features_path)
    if not features_file.exists():
        raise FileNotFoundError(f"特征文件不存在：{features_path}")

    results: List[DetectionResult] = []
    with features_file.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            results.append(detect_one(rec))

    # 写入 JSONL
    out_path = Path(output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        for r in results:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    logger.info(f"写入 JSONL：{out_path} ({len(results)} 条)")

    # 写入 Excel
    if excel_path:
        _write_excel(results, Path(excel_path))

    return results


def _write_excel(results: List[DetectionResult], excel_path: Path) -> None:
    """写入 Excel 结果，fallback 到 CSV。"""
    rows = []
    for r in results:
        row = dict(r)
        row["matched_rules"] = json.dumps(row["matched_rules"], ensure_ascii=False)
        row["combo_detail"] = json.dumps(row["combo_detail"], ensure_ascii=False)
        row["evidence"] = "；".join(row["evidence"])
        row["top_sni"] = json.dumps(row["top_sni"], ensure_ascii=False)
        row["top_dns"] = json.dumps(row["top_dns"], ensure_ascii=False)
        rows.append(row)

    try:
        import pandas as pd
        pd.DataFrame(rows).to_excel(str(excel_path), index=False)
        logger.info(f"写入 Excel：{excel_path}")
    except Exception as e:
        # Fallback: 使用标准库 csv
        import csv
        csv_path = excel_path.with_suffix(".csv")
        if rows:
            fieldnames = list(rows[0].keys())
            with csv_path.open("w", newline="", encoding="utf-8-sig") as fh:
                writer = csv.DictWriter(fh, fieldnames=fieldnames)
                writer.writeheader()
                for row in rows:
                    writer.writerow(row)
        logger.warning(f"无法写入 xlsx，已写入 CSV：{csv_path}；原因：{e}")


def main() -> None:
    parser = argparse.ArgumentParser(description="VPN 检测器 V2")
    parser.add_argument("--features", required=True, help="features.jsonl 路径")
    parser.add_argument("--out", default="results.jsonl", help="输出 JSONL")
    parser.add_argument("--excel", default="results.xlsx", help="输出 Excel")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    run_detection(args.features, args.out, args.excel)


if __name__ == "__main__":
    main()
