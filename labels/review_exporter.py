#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Excel review export for labels_master."""

from __future__ import annotations

from pathlib import Path
from typing import Dict

import pandas as pd


SUMMARY_COLUMNS = ["label_binary", "label_confidence", "label_tool", "label_protocol", "scenario", "review_status"]


def build_summary_stats(df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for col in SUMMARY_COLUMNS:
        if col not in df.columns:
            continue
        counts = df[col].fillna("").astype(str).value_counts(dropna=False)
        for value, count in counts.items():
            rows.append({"field": col, "value": value, "count": int(count)})
    return pd.DataFrame(rows, columns=["field", "value", "count"])


def review_frames(df: pd.DataFrame) -> Dict[str, pd.DataFrame]:
    conflict_text = df.get("conflict_reasons", pd.Series([""] * len(df))).fillna("").astype(str)
    review = df.get("review_status", pd.Series([""] * len(df))).fillna("").astype(str)
    return {
        "need_review": df[review.ne("auto_labeled")].copy(),
        "strong_conflicts": df[review.eq("needs_conflict_review") | conflict_text.str.contains("strong_binary_conflict", na=False)].copy(),
        "family_conflicts": df[review.eq("needs_family_review") | conflict_text.str.contains("family_tool_conflict", na=False)].copy(),
        "auto_labeled": df[review.eq("auto_labeled")].copy(),
        "summary_stats": build_summary_stats(df),
    }


def export_review_workbook(df: pd.DataFrame, path: Path) -> None:
    """Write the review workbook with stable sheet names."""

    path.parent.mkdir(parents=True, exist_ok=True)
    frames = review_frames(df)
    with pd.ExcelWriter(path, engine="openpyxl") as writer:
        for sheet, frame in frames.items():
            frame.to_excel(writer, sheet_name=sheet[:31], index=False)
