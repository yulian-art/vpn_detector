#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apply a trained ML model bundle to features.jsonl or ML dataset CSV."""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Any, Dict, List

import joblib
import numpy as np
import pandas as pd

from .dataset_builder import build_dataset, flatten_feature_record, load_jsonl

logger = logging.getLogger(__name__)


def predict_dataframe(df: pd.DataFrame, model_path: Path) -> pd.DataFrame:
    bundle = joblib.load(model_path)
    model = bundle["model"]
    le = bundle["label_encoder"]
    cols: List[str] = bundle["feature_columns"]

    for c in cols:
        if c not in df.columns:
            df[c] = 0
    X = df[cols].replace([np.inf, -np.inf], np.nan)
    pred = model.predict(X)
    pred_label = le.inverse_transform(pred)
    out = df.copy()
    out["ml_pred_label"] = pred_label
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(X)
        out["ml_pred_prob_max"] = proba.max(axis=1)
        for i, cls in enumerate(le.classes_):
            out[f"ml_prob_{cls}"] = proba[:, i]
            if str(cls).lower() in {"1", "vpn", "true"}:
                out["ml_prob_vpn"] = proba[:, i]
        if "ml_prob_vpn" not in out.columns and len(le.classes_) == 2:
            positive_idx = list(le.classes_).index(sorted(le.classes_)[-1])
            out["ml_prob_vpn"] = proba[:, positive_idx]
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Predict using trained VPN ML model")
    parser.add_argument("--model", required=True, help="model .joblib")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--dataset", help="dataset csv/parquet")
    group.add_argument("--features", help="features.jsonl")
    parser.add_argument("--out", default="ml_predictions.csv")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

    if args.dataset:
        path = Path(args.dataset)
        df = pd.read_parquet(path) if path.suffix.lower() == ".parquet" else pd.read_csv(path, encoding="utf-8-sig")
    else:
        rows = [flatten_feature_record(rec) for rec in load_jsonl(Path(args.features))]
        df = pd.DataFrame(rows)
    pred = predict_dataframe(df, Path(args.model))
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.suffix.lower() == ".parquet":
        pred.to_parquet(out_path, index=False)
    else:
        pred.to_csv(out_path, index=False, encoding="utf-8-sig")
    logger.info("Wrote predictions: %s", args.out)


if __name__ == "__main__":
    main()
