"""Build labeled sequence tables and expose them as padded PyTorch samples."""

from __future__ import annotations

import argparse
import ast
import json
import logging
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import numpy as np
import pandas as pd

from vpn_detector.dataset_builder import sample_weight_for_confidence

logger = logging.getLogger(__name__)

try:
    import torch
    from torch.utils.data import Dataset
except ImportError:  # build-seq-dataset remains usable without torch
    torch = None  # type: ignore
    Dataset = object  # type: ignore

SEQUENCE_COLUMNS = [
    "sample_id", "capture_id", "split_group", "source_archive", "pcap_member", "file_name",
    "flow_id", "seq_len", "pkt_len_seq", "signed_len_seq", "direction_seq", "iat_ms_seq",
    "log1p_iat_seq", "direction_mode",
]
LABEL_COLUMNS = [
    "label_binary", "label_protocol", "label_tool", "label_confidence", "sample_weight", "scenario",
]


def read_table(path: Path) -> pd.DataFrame:
    if path.suffix.lower() == ".parquet":
        return pd.read_parquet(path)
    return pd.read_csv(path, encoding="utf-8-sig")


def _valid_text(value: Any) -> bool:
    return pd.notna(value) and str(value).strip().lower() not in {"", "nan", "none"}


def build_sequence_dataset(sequences_path: Path, labels_path: Path, out_path: Path, target: str = "binary") -> pd.DataFrame:
    if target != "binary":
        raise ValueError("Phase 3 currently supports only --target binary")
    seq = read_table(sequences_path).copy()
    labels = read_table(labels_path).copy()
    required = {"flow_id", "seq_len", "signed_len_seq", "direction_seq", "log1p_iat_seq"}
    missing = sorted(required - set(seq.columns))
    if missing:
        raise ValueError(f"Sequence table missing required columns: {missing}")

    label_fields = [c for c in LABEL_COLUMNS if c in labels.columns]
    matched_parts: List[pd.DataFrame] = []
    remaining = seq.copy()
    if "sample_id" in seq.columns and "sample_id" in labels.columns:
        valid_labels = labels[labels["sample_id"].map(_valid_text)].drop_duplicates("sample_id")
        direct = remaining.merge(valid_labels[["sample_id", *label_fields]], on="sample_id", how="left", indicator=True, suffixes=("", "_label"))
        matched_parts.append(direct[direct["_merge"] == "both"].drop(columns="_merge"))
        remaining = direct[direct["_merge"] == "left_only"][seq.columns].copy()

    if not remaining.empty:
        fallback_keys = [c for c in ("pcap_member", "file_name") if c in remaining.columns and c in labels.columns]
        if not fallback_keys:
            logger.warning("%d sequence rows could not match labels by sample_id and no fallback keys are available", len(remaining))
        else:
            logger.warning("Falling back to label matching by %s for %d sequence rows", "+".join(fallback_keys), len(remaining))
            fallback_labels = labels.drop_duplicates(fallback_keys)
            extra = remaining.merge(fallback_labels[[*fallback_keys, *label_fields]], on=fallback_keys, how="left", suffixes=("", "_label"))
            matched_parts.append(extra)

    out = pd.concat(matched_parts, ignore_index=True) if matched_parts else seq.iloc[0:0].copy()
    if "label_confidence" not in out.columns:
        out["label_confidence"] = "unlabeled"
    if "sample_weight" not in out.columns:
        out["sample_weight"] = out["label_confidence"].map(sample_weight_for_confidence)
    else:
        computed = out["label_confidence"].map(sample_weight_for_confidence)
        out["sample_weight"] = pd.to_numeric(out["sample_weight"], errors="coerce").fillna(computed)
    if "label_binary" not in out.columns:
        out["label_binary"] = np.nan
    out = out[
        (out["label_confidence"].fillna("unlabeled").astype(str).str.lower() != "unlabeled")
        & out["label_binary"].notna()
        & (out["label_binary"].astype(str).str.strip() != "")
        & (out["sample_weight"].astype(float) > 0)
    ].copy()
    for col in SEQUENCE_COLUMNS + LABEL_COLUMNS:
        if col not in out.columns:
            out[col] = ""
    out = out[[*SEQUENCE_COLUMNS, *LABEL_COLUMNS]]
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.suffix.lower() == ".parquet":
        out.to_parquet(out_path, index=False)
    else:
        out.to_csv(out_path, index=False, encoding="utf-8-sig")
    logger.info("Wrote sequence dataset: %s (%d rows)", out_path, len(out))
    return out


def _as_list(value: Any) -> List[float]:
    if isinstance(value, np.ndarray):
        return value.astype(float).tolist()
    if isinstance(value, (list, tuple)):
        return [float(x) for x in value]
    if not _valid_text(value):
        return []
    text = str(value)
    try:
        parsed = json.loads(text)
    except Exception:
        parsed = ast.literal_eval(text)
    return [float(x) for x in parsed]


class PacketSequenceDataset(Dataset):
    """Three-channel packet sequence dataset with masks, padding, and truncation."""

    def __init__(self, data: Path | pd.DataFrame, max_len: int = 64, target_col: str = "label_binary") -> None:
        if torch is None:
            raise ImportError("PyTorch is required for PacketSequenceDataset; install torch separately")
        if max_len <= 0:
            raise ValueError("max_len must be positive")
        self.frame = read_table(data).reset_index(drop=True) if isinstance(data, Path) else data.reset_index(drop=True).copy()
        self.max_len = int(max_len)
        self.target_col = target_col

    def __len__(self) -> int:
        return len(self.frame)

    def __getitem__(self, index: int) -> Dict[str, Any]:
        row = self.frame.iloc[index]
        signed = _as_list(row.get("signed_len_seq"))
        iat = _as_list(row.get("log1p_iat_seq"))
        direction = _as_list(row.get("direction_seq"))
        actual = min(int(row.get("seq_len") or len(signed)), len(signed), len(iat), len(direction), self.max_len)
        features = np.zeros((3, self.max_len), dtype=np.float32)
        if actual:
            features[0, :actual] = np.asarray(signed[:actual], dtype=np.float32) / 1500.0
            features[1, :actual] = np.asarray(iat[:actual], dtype=np.float32) / 10.0
            features[2, :actual] = np.asarray(direction[:actual], dtype=np.float32)
        mask = np.zeros(self.max_len, dtype=np.bool_)
        mask[:actual] = True
        label = float(row.get(self.target_col, 0) or 0)
        weight = float(row.get("sample_weight", 1.0) or 0.0)
        return {
            "features": torch.from_numpy(features),
            "mask": torch.from_numpy(mask),
            "seq_len": torch.tensor(actual, dtype=torch.long),
            "label": torch.tensor(label, dtype=torch.float32),
            "sample_weight": torch.tensor(weight, dtype=torch.float32),
            "index": torch.tensor(index, dtype=torch.long),
        }


def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="Build a labeled packet-sequence dataset")
    parser.add_argument("--sequences", required=True)
    parser.add_argument("--labels", required=True)
    parser.add_argument("--out", default="datasets/seq_dataset.parquet")
    parser.add_argument("--target", choices=["binary"], default="binary")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    build_sequence_dataset(Path(args.sequences), Path(args.labels), Path(args.out), args.target)


if __name__ == "__main__":
    main()
