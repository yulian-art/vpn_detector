#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Train tabular ML baselines for VPN detection.

Phase 1 intentionally uses traditional, inspectable models. Optional packages
such as xgboost, lightgbm, and shap are used only when installed.
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier, GradientBoostingClassifier, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit, StratifiedShuffleSplit, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder, StandardScaler

from .dataset_builder import feature_columns

logger = logging.getLogger(__name__)

TARGET_MAP = {
    "binary": "label_binary",
    "protocol": "label_protocol",
    "tool": "label_tool",
}


def read_dataset(path: Path) -> pd.DataFrame:
    if path.suffix.lower() == ".parquet":
        return pd.read_parquet(path)
    return pd.read_csv(path, encoding="utf-8-sig")


def make_models(random_state: int = 42) -> Dict[str, Pipeline]:
    models: Dict[str, Pipeline] = {
        "logreg": Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(max_iter=2000, class_weight="balanced")),
        ]),
        "rf": Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("clf", RandomForestClassifier(n_estimators=300, random_state=random_state, class_weight="balanced_subsample", n_jobs=-1, min_samples_leaf=1)),
        ]),
        "extra_trees": Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("clf", ExtraTreesClassifier(n_estimators=400, random_state=random_state, class_weight="balanced", n_jobs=-1, min_samples_leaf=1)),
        ]),
        "gbdt": Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("clf", GradientBoostingClassifier(random_state=random_state)),
        ]),
    }
    try:
        from xgboost import XGBClassifier  # type: ignore

        models["xgboost"] = Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("clf", XGBClassifier(random_state=random_state, eval_metric="logloss")),
        ])
    except Exception:
        logger.info("Optional model xgboost is not installed; skipping.")
    try:
        from lightgbm import LGBMClassifier  # type: ignore

        models["lightgbm"] = Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("clf", LGBMClassifier(random_state=random_state)),
        ])
    except Exception:
        logger.info("Optional model lightgbm is not installed; skipping.")
    return models


def split_data(
    df: pd.DataFrame,
    target_col: str,
    test_size: float,
    random_state: int,
) -> Tuple[np.ndarray, np.ndarray, str]:
    """Split data, preferring leakage-safe split_group then capture_id."""

    y = df[target_col].astype(str)
    idx = np.arange(len(df))
    for group_col in ("split_group", "capture_id"):
        if group_col in df.columns:
            groups = df[group_col].fillna("").astype(str)
            if groups.nunique() >= 2 and len(df) >= 4:
                splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=random_state)
                train_idx, test_idx = next(splitter.split(idx, y, groups))
                return train_idx, test_idx, group_col

    counts = y.value_counts()
    if len(counts) > 1 and counts.min() >= 2 and len(df) >= 4:
        splitter = StratifiedShuffleSplit(n_splits=1, test_size=test_size, random_state=random_state)
        train_idx, test_idx = next(splitter.split(idx, y))
        return train_idx, test_idx, "stratified"

    train_idx, test_idx = train_test_split(idx, test_size=test_size, random_state=random_state)
    return np.asarray(train_idx), np.asarray(test_idx), "random"


def binary_rates(y_true: np.ndarray, y_pred: np.ndarray) -> Dict[str, float]:
    labels = sorted(set(y_true) | set(y_pred))
    if len(labels) != 2:
        return {"fpr": 0.0, "fnr": 0.0}
    neg, pos = labels[0], labels[1]
    fp = int(((y_true == neg) & (y_pred == pos)).sum())
    tn = int(((y_true == neg) & (y_pred == neg)).sum())
    fn = int(((y_true == pos) & (y_pred == neg)).sum())
    tp = int(((y_true == pos) & (y_pred == pos)).sum())
    return {
        "fpr": float(fp / (fp + tn)) if fp + tn else 0.0,
        "fnr": float(fn / (fn + tp)) if fn + tp else 0.0,
    }


def compute_metrics(y_true: np.ndarray, y_pred: np.ndarray, proba: Any = None) -> Dict[str, Any]:
    precision, recall, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="weighted", zero_division=0)
    out: Dict[str, Any] = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "macro_precision": float(precision_score(y_true, y_pred, average="macro", zero_division=0)),
        "macro_recall": float(recall_score(y_true, y_pred, average="macro", zero_division=0)),
        "macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
        "classification_report": classification_report(y_true, y_pred, zero_division=0, output_dict=True),
        "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
    }
    out.update(binary_rates(y_true, y_pred))
    try:
        if proba is not None and proba.shape[1] == 2 and len(set(y_true)) == 2:
            out["roc_auc"] = float(roc_auc_score(y_true, proba[:, 1]))
            out["pr_auc"] = float(average_precision_score(y_true, proba[:, 1]))
            out["average_precision"] = out["pr_auc"]
    except Exception as exc:
        out["probability_metric_warning"] = str(exc)
    return out


def fit_pipeline(model: Pipeline, X: pd.DataFrame, y: np.ndarray, sample_weight: Optional[np.ndarray]) -> None:
    if sample_weight is not None:
        try:
            model.fit(X, y, clf__sample_weight=sample_weight)
            return
        except TypeError:
            logger.info("Model does not accept sample_weight; fitting without it.")
    model.fit(X, y)


def group_evaluation(test_df: pd.DataFrame, y_true: np.ndarray, y_pred: np.ndarray) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    tmp = test_df.copy()
    tmp["_y_true"] = y_true
    tmp["_y_pred"] = y_pred
    for col in ("label_tool", "label_protocol", "scenario", "label_confidence"):
        if col not in tmp.columns:
            continue
        rows = []
        for value, grp in tmp.groupby(col, dropna=False):
            rows.append({
                "value": str(value),
                "count": int(len(grp)),
                "accuracy": float(accuracy_score(grp["_y_true"], grp["_y_pred"])),
                "macro_f1": float(f1_score(grp["_y_true"], grp["_y_pred"], average="macro", zero_division=0)),
            })
        out[col] = rows
    return out


def threshold_sweep(y_true: np.ndarray, proba_pos: np.ndarray) -> pd.DataFrame:
    rows = []
    labels = sorted(set(y_true))
    if len(labels) != 2:
        return pd.DataFrame(columns=["threshold", "precision", "recall", "f1", "fpr", "fnr"])
    neg, pos = labels[0], labels[1]
    for threshold in np.linspace(0.05, 0.95, 19):
        pred = np.where(proba_pos >= threshold, pos, neg)
        rates = binary_rates(y_true, pred)
        rows.append({
            "threshold": round(float(threshold), 3),
            "precision": float(precision_score(y_true, pred, pos_label=pos, zero_division=0)),
            "recall": float(recall_score(y_true, pred, pos_label=pos, zero_division=0)),
            "f1": float(f1_score(y_true, pred, pos_label=pos, zero_division=0)),
            "fpr": rates["fpr"],
            "fnr": rates["fnr"],
        })
    return pd.DataFrame(rows)


def feature_importance_frame(model: Pipeline, columns: List[str]) -> pd.DataFrame:
    clf = model.named_steps.get("clf")
    if hasattr(clf, "feature_importances_"):
        values = np.asarray(clf.feature_importances_, dtype=float)
    elif hasattr(clf, "coef_"):
        values = np.abs(np.asarray(clf.coef_)).mean(axis=0)
    else:
        values = np.zeros(len(columns), dtype=float)
    return pd.DataFrame({"feature": columns, "importance": values}).sort_values("importance", ascending=False)


def maybe_write_shap_summary(model: Pipeline, X: pd.DataFrame, out_path: Path) -> None:
    try:
        import shap  # type: ignore

        clf = model.named_steps.get("clf")
        transformed = model.named_steps["imputer"].transform(X)
        explainer = shap.Explainer(clf, transformed)
        values = explainer(transformed[: min(len(X), 100)])
        arr = np.abs(values.values)
        if arr.ndim == 3:
            arr = arr.mean(axis=2)
        summary = pd.DataFrame({"feature": list(X.columns), "mean_abs_shap": arr.mean(axis=0)})
        summary.sort_values("mean_abs_shap", ascending=False).to_csv(out_path, index=False, encoding="utf-8-sig")
    except Exception as exc:
        logger.info("SHAP summary skipped: %s", exc)


def prepare_training_frame(df: pd.DataFrame, target: str, target_col: str) -> pd.DataFrame:
    df = df.copy()
    if "label_confidence" in df.columns:
        df = df[df["label_confidence"].fillna("unlabeled").astype(str) != "unlabeled"].copy()
    df = df[df[target_col].notna()].copy()
    if target == "binary":
        df = df[df[target_col].astype(str).str.strip() != ""].copy()
        df[target_col] = df[target_col].astype(int).astype(str)
    else:
        df[target_col] = df[target_col].astype(str)
        df = df[~df[target_col].str.lower().isin(["", "unknown", "unknown_tool", "unknown_protocol", "nan", "none"])]
    return df


def train(
    dataset_path: Path,
    target: str,
    feature_set: str,
    out_dir: Path,
    model_name: str = "rf",
    test_size: float = 0.25,
    random_state: int = 42,
) -> Dict[str, Any]:
    df = read_dataset(dataset_path)
    target_col = TARGET_MAP.get(target, target)
    if target_col not in df.columns:
        raise ValueError(f"Target column not found: {target_col}")

    df = prepare_training_frame(df, target, target_col)
    cols = feature_columns(df, feature_set)
    if not cols:
        raise ValueError(f"No numeric feature columns for feature_set={feature_set}")
    if df[target_col].nunique() < 2:
        raise ValueError(f"Need at least two classes for training; got {df[target_col].unique().tolist()}")

    train_idx, test_idx, split_method = split_data(df, target_col, test_size, random_state)
    X_train = df.iloc[train_idx][cols].replace([np.inf, -np.inf], np.nan)
    X_test = df.iloc[test_idx][cols].replace([np.inf, -np.inf], np.nan)
    y_train_raw = df.iloc[train_idx][target_col].astype(str).values
    y_test_raw = df.iloc[test_idx][target_col].astype(str).values
    sample_weight = None
    if "sample_weight" in df.columns:
        sample_weight = df.iloc[train_idx]["sample_weight"].fillna(1.0).astype(float).values

    le = LabelEncoder()
    y_train = le.fit_transform(y_train_raw)
    y_test = le.transform(y_test_raw)

    models = make_models(random_state)
    if model_name not in models:
        logger.warning("Model %s is unavailable; installed models are %s", model_name, sorted(models))
        return {"skipped": True, "reason": f"model_unavailable:{model_name}"}
    model = models[model_name]
    fit_pipeline(model, X_train, y_train, sample_weight)

    pred = model.predict(X_test)
    proba = model.predict_proba(X_test) if hasattr(model, "predict_proba") else None
    metrics = compute_metrics(y_test, pred, proba)
    metrics["group_evaluation"] = group_evaluation(df.iloc[test_idx], y_test, pred)

    out_dir.mkdir(parents=True, exist_ok=True)
    base = f"{target}_{feature_set}_{model_name}"
    model_path = out_dir / f"{base}.joblib"
    metrics_path = out_dir / f"{base}_metrics.json"
    threshold_path = out_dir / f"{base}_threshold_sweep.csv"
    importance_path = out_dir / f"{base}_feature_importance.csv"
    split_path = out_dir / f"{base}_split.csv"

    if proba is not None and proba.shape[1] == 2:
        threshold_sweep(y_test, proba[:, 1]).to_csv(threshold_path, index=False, encoding="utf-8-sig")
    else:
        pd.DataFrame(columns=["threshold", "precision", "recall", "f1", "fpr", "fnr"]).to_csv(threshold_path, index=False, encoding="utf-8-sig")
    feature_importance_frame(model, cols).to_csv(importance_path, index=False, encoding="utf-8-sig")
    maybe_write_shap_summary(model, X_test, out_dir / f"{base}_shap_summary.csv")

    split_df = df.iloc[np.concatenate([train_idx, test_idx])][[c for c in ["sample_id", "capture_id", "split_group", target_col] if c in df.columns]].copy()
    split_df["split"] = ["train"] * len(train_idx) + ["test"] * len(test_idx)
    split_df.to_csv(split_path, index=False, encoding="utf-8-sig")

    metadata = {
        "dataset_path": str(dataset_path),
        "row_count": int(len(df)),
        "train_rows": int(len(train_idx)),
        "test_rows": int(len(test_idx)),
        "split_method": split_method,
        "random_state": random_state,
        "model_name": model_name,
    }
    bundle = {
        "model": model,
        "label_encoder": le,
        "feature_columns": cols,
        "target": target,
        "target_col": target_col,
        "feature_set": feature_set,
        "metrics": metrics,
        "threshold_policy": {"default_threshold": 0.5, "positive_class": "1" if target == "binary" else None},
        "training_metadata": metadata,
        "model_name": model_name,
        "classes": list(le.classes_),
    }
    joblib.dump(bundle, model_path)
    with metrics_path.open("w", encoding="utf-8") as fh:
        json.dump(metrics, fh, ensure_ascii=False, indent=2)

    logger.info("Saved model: %s", model_path)
    logger.info("Metrics: accuracy=%.4f macro_f1=%.4f weighted_f1=%.4f", metrics["accuracy"], metrics["macro_f1"], metrics["weighted_f1"])
    return {
        "model_path": str(model_path),
        "metrics_path": str(metrics_path),
        "threshold_sweep_path": str(threshold_path),
        "feature_importance_path": str(importance_path),
        "split_path": str(split_path),
        "metrics": metrics,
        "training_metadata": metadata,
    }


def run_ablation(dataset: Path, target: str, out_dir: Path, model_name: str = "rf") -> pd.DataFrame:
    rows = []
    for fs in ["all", "no_identity", "behavior_only", "tls_only", "dns_only", "port_only"]:
        try:
            result = train(dataset, target, fs, out_dir / "ablation", model_name=model_name)
            if result.get("skipped"):
                rows.append({"feature_set": fs, "error": result.get("reason")})
            else:
                m = result["metrics"]
                rows.append({"feature_set": fs, "accuracy": m.get("accuracy"), "macro_f1": m.get("macro_f1"), "weighted_f1": m.get("weighted_f1"), "roc_auc": m.get("roc_auc")})
        except Exception as e:
            rows.append({"feature_set": fs, "error": str(e)})
            logger.warning("Ablation failed for %s: %s", fs, e)
    df = pd.DataFrame(rows)
    out_dir.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_dir / f"ablation_{target}_{model_name}.csv", index=False, encoding="utf-8-sig")
    return df


def main() -> None:
    parser = argparse.ArgumentParser(description="Train VPN ML baselines")
    parser.add_argument("--dataset", required=True, help="ML dataset .csv/.parquet")
    parser.add_argument("--target", choices=["binary", "protocol", "tool"], default="binary")
    parser.add_argument("--feature-set", choices=["all", "no_identity", "behavior_only", "tls_only", "dns_only", "port_only"], default="all")
    parser.add_argument("--model", choices=["logreg", "rf", "extra_trees", "gbdt", "xgboost", "lightgbm"], default="rf")
    parser.add_argument("--out-dir", default="models")
    parser.add_argument("--test-size", type=float, default=0.25)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--ablation", action="store_true", help="run all feature-set ablations")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

    if args.ablation:
        run_ablation(Path(args.dataset), args.target, Path(args.out_dir), args.model)
    else:
        result = train(Path(args.dataset), args.target, args.feature_set, Path(args.out_dir), args.model, args.test_size, args.random_state)
        if result.get("skipped"):
            logger.warning("Training skipped: %s", result.get("reason"))


if __name__ == "__main__":
    main()
