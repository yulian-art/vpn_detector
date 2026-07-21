#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Aggregate labeling-function votes into labels_master."""

from __future__ import annotations

import argparse
import logging
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import pandas as pd

from .label_functions import (
    iter_input_samples,
    lf_from_manifest_v4_fields,
    lf_from_nonvpn_root,
    lf_from_path_keywords,
    lf_from_vpn_root,
    load_side_votes,
    metadata_votes,
    votes_for_sample_from_index,
)
from .review_exporter import export_review_workbook
from .schema import (
    LABELS_MASTER_COLUMNS,
    LabelConfidence,
    LabelVote,
    confidence_rank,
    evidence_to_json,
    normalize_binary_label,
    normalize_confidence,
)

logger = logging.getLogger(__name__)


def aggregate_votes(sample: Dict[str, Any], votes: Iterable[LabelVote]) -> Dict[str, Any]:
    """Aggregate votes for one sample into a labels_master row."""

    vote_list = [v for v in votes if v is not None]
    row = {col: "" for col in LABELS_MASTER_COLUMNS}
    for col in ("entity_level", "sample_id", "capture_id", "file_name", "pcap_member", "source_archive", "device_id", "network_id", "time_period", "split_group", "note"):
        row[col] = sample.get(col, row.get(col, ""))
    row["entity_level"] = row["entity_level"] or "file"
    row["split_group"] = row["split_group"] or row["capture_id"] or row["sample_id"]

    binary_votes = [v for v in vote_list if v.task == "binary" and normalize_binary_label(v.value) is not None]
    row["positive_votes"] = sum(1 for v in binary_votes if normalize_binary_label(v.value) == 1)
    row["negative_votes"] = sum(1 for v in binary_votes if normalize_binary_label(v.value) == 0)
    row["evidence_json"] = evidence_to_json([v.to_dict() for v in vote_list])

    conflicts: List[str] = []
    manual_binary = [v for v in binary_votes if v.source == "manual_review"]
    strong_values = {normalize_binary_label(v.value) for v in binary_votes if normalize_confidence(v.confidence) == LabelConfidence.STRONG}
    if len(strong_values) > 1:
        row.update({
            "label_binary": "",
            "label_confidence": LabelConfidence.UNLABELED.value,
            "label_score": 0.0,
            "label_status": "conflict",
            "review_status": "needs_conflict_review",
        })
        conflicts.append("strong_binary_conflict")
    elif manual_binary:
        chosen = sorted(manual_binary, key=lambda v: confidence_rank(v.confidence), reverse=True)[0]
        row["label_binary"] = normalize_binary_label(chosen.value)
        row["label_confidence"] = normalize_confidence(chosen.confidence).value
        row["label_score"] = float(chosen.weight or 0)
        row["label_status"] = "manual"
        row["review_status"] = "manual_reviewed"
    elif binary_votes:
        scores: Dict[int, float] = defaultdict(float)
        best_conf: Dict[int, LabelConfidence] = {}
        for vote in binary_votes:
            value = normalize_binary_label(vote.value)
            if value is None:
                continue
            scores[value] += float(vote.weight or 0)
            current = best_conf.get(value, LabelConfidence.UNLABELED)
            if confidence_rank(vote.confidence) > confidence_rank(current):
                best_conf[value] = normalize_confidence(vote.confidence)
        if scores.get(0, 0.0) == scores.get(1, 0.0):
            row["label_binary"] = ""
            row["label_confidence"] = LabelConfidence.UNLABELED.value
            row["label_score"] = max(scores.values()) if scores else 0.0
            row["label_status"] = "conflict"
            row["review_status"] = "needs_conflict_review"
            conflicts.append("binary_vote_tie")
        else:
            chosen_value = max(scores, key=scores.get)
            row["label_binary"] = chosen_value
            row["label_confidence"] = best_conf.get(chosen_value, LabelConfidence.UNLABELED).value
            row["label_score"] = round(scores[chosen_value], 4)
            row["label_status"] = "auto"
            row["review_status"] = "auto_labeled" if row["label_confidence"] != LabelConfidence.WEAK.value else "needs_review"
    else:
        row["label_binary"] = ""
        row["label_confidence"] = LabelConfidence.UNLABELED.value
        row["label_score"] = 0.0
        row["label_status"] = "unlabeled"
        row["review_status"] = "needs_label"

    for task, out_col in (("protocol", "label_protocol"), ("tool", "label_tool"), ("family", "label_family"), ("scenario", "scenario")):
        value, conflict = aggregate_metadata_task([v for v in vote_list if v.task == task])
        row[out_col] = value
        if conflict:
            conflicts.append(f"{task}_conflict")

    if row["label_binary"] == 0:
        row["label_protocol"] = row["label_protocol"] or "NonVPN"
        row["label_tool"] = row["label_tool"] or "NonVPN"
        row["label_family"] = row["label_family"] or "NonVPN"
    elif row["label_binary"] == 1:
        row["label_protocol"] = row["label_protocol"] or "unknown_protocol"
        row["label_tool"] = row["label_tool"] or "unknown_tool"

    if any(c in conflicts for c in ("tool_conflict", "family_conflict", "protocol_conflict")) and row["review_status"] == "auto_labeled":
        row["review_status"] = "needs_family_review"
        conflicts.append("family_tool_conflict")
    row["conflict_reasons"] = ";".join(dict.fromkeys(conflicts))
    return {col: row.get(col, "") for col in LABELS_MASTER_COLUMNS}


def aggregate_metadata_task(votes: List[LabelVote]) -> tuple[str, bool]:
    if not votes:
        return "", False
    manual = [v for v in votes if v.source == "manual_review"]
    if manual:
        return str(sorted(manual, key=lambda v: confidence_rank(v.confidence), reverse=True)[0].value), False
    counts: Counter[str] = Counter()
    best_rank: Dict[str, int] = {}
    for vote in votes:
        value = str(vote.value).strip()
        if not value:
            continue
        counts[value] += float(vote.weight or 0)
        best_rank[value] = max(best_rank.get(value, 0), confidence_rank(vote.confidence))
    if not counts:
        return "", False
    top_score = max(counts.values())
    top_values = [v for v, score in counts.items() if score == top_score]
    return sorted(top_values)[0], len(top_values) > 1


def build_labels_master(
    input_paths: Iterable[Path],
    out_parquet: Path,
    review_xlsx: Path,
    vpn_root: str | None = None,
    nonvpn_root: str | None = None,
    manual_review: Iterable[str] | None = None,
    analysis_docs: Iterable[str] | None = None,
    rule_results: Iterable[str] | None = None,
) -> pd.DataFrame:
    """Build labels_master.parquet and labels_review.xlsx from observable votes."""

    samples = iter_input_samples(input_paths)
    manual_index = load_side_votes(manual_review, "manual")
    analysis_index = load_side_votes(analysis_docs, "analysis")
    rule_index = load_side_votes(rule_results, "rule")
    rows: List[Dict[str, Any]] = []

    for sample in samples:
        votes: List[LabelVote] = []
        for vote in (
            lf_from_vpn_root(sample, vpn_root),
            lf_from_nonvpn_root(sample, nonvpn_root),
            lf_from_path_keywords(sample),
            lf_from_manifest_v4_fields(sample),
        ):
            if vote:
                votes.append(vote)
        votes.extend(metadata_votes("manifest_v4", sample, LabelConfidence.MEDIUM))
        votes.extend(votes_for_sample_from_index(sample, manual_index))
        votes.extend(votes_for_sample_from_index(sample, analysis_index))
        votes.extend(votes_for_sample_from_index(sample, rule_index))
        rows.append(aggregate_votes(sample, votes))

    df = pd.DataFrame(rows, columns=LABELS_MASTER_COLUMNS)
    out_parquet.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(out_parquet, index=False)
    export_review_workbook(df, review_xlsx)
    logger.info("Wrote labels master: %s (%d rows)", out_parquet, len(df))
    logger.info("Wrote labels review workbook: %s", review_xlsx)
    return df


def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="Build strict labels_master and review workbook")
    parser.add_argument("--input", nargs="+", required=True)
    parser.add_argument("--out-parquet", default="labels_master.parquet")
    parser.add_argument("--review-xlsx", default="labels_review.xlsx")
    parser.add_argument("--vpn-root")
    parser.add_argument("--nonvpn-root")
    parser.add_argument("--manual-review", nargs="*")
    parser.add_argument("--analysis-docs", nargs="*")
    parser.add_argument("--rule-results", nargs="*")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    build_labels_master(
        [Path(x) for x in args.input],
        Path(args.out_parquet),
        Path(args.review_xlsx),
        vpn_root=args.vpn_root,
        nonvpn_root=args.nonvpn_root,
        manual_review=args.manual_review,
        analysis_docs=args.analysis_docs,
        rule_results=args.rule_results,
    )


if __name__ == "__main__":
    main()
