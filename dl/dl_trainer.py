"""CPU-friendly training for the Phase 3 sequence baselines."""

from __future__ import annotations

import argparse
import json
import logging
import random
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
import torch
from sklearn.model_selection import GroupShuffleSplit
from torch import nn
from torch.utils.data import DataLoader, Subset

from .metrics import binary_metrics
from .models_1dcnn import Packet1DCNN
from .models_transformer import PacketTinyTransformer
from .sequence_dataset import PacketSequenceDataset, read_table

logger = logging.getLogger(__name__)


def resolve_device(requested: str) -> torch.device:
    if requested == "auto":
        return torch.device("cuda" if torch.cuda.is_available() else "cpu")
    if requested == "cuda" and not torch.cuda.is_available():
        raise ValueError("--device cuda requested, but CUDA is not available")
    return torch.device(requested)


def group_split(frame: pd.DataFrame, test_size: float, random_state: int) -> Tuple[np.ndarray, np.ndarray]:
    if len(frame) < 4:
        raise ValueError("Sequence dataset is too small: need at least 4 rows")
    if "split_group" not in frame.columns or frame["split_group"].fillna("").astype(str).nunique() < 2:
        raise ValueError("Need at least two distinct split_group values for leakage-safe training")
    labels = frame["label_binary"].astype(int).to_numpy()
    if len(np.unique(labels)) < 2:
        raise ValueError("Need at least two label_binary classes for DL training")
    groups = frame["split_group"].fillna("").astype(str).to_numpy()
    indices = np.arange(len(frame))
    fallback: Optional[Tuple[np.ndarray, np.ndarray]] = None
    for offset in range(50):
        splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=random_state + offset)
        train_idx, test_idx = next(splitter.split(indices, labels, groups))
        fallback = (train_idx, test_idx)
        if len(np.unique(labels[train_idx])) == 2:
            return train_idx, test_idx
    assert fallback is not None
    raise ValueError("Unable to create a group split whose training set contains both classes; add more split_group diversity")


def make_model(model_name: str, max_len: int) -> nn.Module:
    if model_name == "cnn":
        return Packet1DCNN()
    if model_name == "transformer":
        return PacketTinyTransformer(max_len=max_len)
    raise ValueError(f"Unknown DL model: {model_name}")


def _evaluate(model: nn.Module, loader: DataLoader, device: torch.device, threshold: float) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    model.eval()
    all_indices: List[np.ndarray] = []
    all_labels: List[np.ndarray] = []
    all_probs: List[np.ndarray] = []
    with torch.no_grad():
        for batch in loader:
            logits = model(batch["features"].to(device), batch["mask"].to(device))
            probs = torch.softmax(logits, dim=1)[:, 1]
            all_indices.append(batch["index"].numpy())
            all_labels.append(batch["label"].numpy().astype(int))
            all_probs.append(probs.cpu().numpy())
    indices = np.concatenate(all_indices)
    labels = np.concatenate(all_labels)
    probs = np.concatenate(all_probs)
    preds = (probs >= threshold).astype(int)
    return indices, labels, preds, probs


def train_dl(
    dataset_path: Path,
    model_name: str,
    out_dir: Path,
    epochs: int = 10,
    batch_size: int = 64,
    lr: float = 1e-3,
    device_name: str = "auto",
    test_size: float = 0.25,
    random_state: int = 42,
    threshold: float = 0.5,
    max_len: int = 64,
) -> Dict[str, Any]:
    random.seed(random_state)
    np.random.seed(random_state)
    torch.manual_seed(random_state)
    frame = read_table(dataset_path)
    frame = frame[frame["label_binary"].notna()].reset_index(drop=True)
    train_idx, test_idx = group_split(frame, test_size, random_state)
    dataset = PacketSequenceDataset(frame, max_len=max_len)
    train_loader = DataLoader(Subset(dataset, train_idx.tolist()), batch_size=batch_size, shuffle=True)
    test_loader = DataLoader(Subset(dataset, test_idx.tolist()), batch_size=batch_size, shuffle=False)
    device = resolve_device(device_name)
    model = make_model(model_name, max_len).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    criterion = nn.CrossEntropyLoss(reduction="none")

    losses: List[float] = []
    for _ in range(epochs):
        model.train()
        epoch_loss = 0.0
        batches = 0
        for batch in train_loader:
            optimizer.zero_grad()
            logits = model(batch["features"].to(device), batch["mask"].to(device))
            labels = batch["label"].long().to(device)
            weights = batch["sample_weight"].to(device)
            raw_loss = criterion(logits, labels)
            loss = (raw_loss * weights).sum() / weights.sum().clamp_min(1e-8)
            loss.backward()
            optimizer.step()
            epoch_loss += float(loss.detach().cpu())
            batches += 1
        losses.append(epoch_loss / max(batches, 1))

    eval_indices, y_true, y_pred, probabilities = _evaluate(model, test_loader, device, threshold)
    metrics = binary_metrics(y_true, y_pred, probabilities)
    metrics.update({"train_loss_by_epoch": losses, "train_rows": int(len(train_idx)), "test_rows": int(len(test_idx)), "split_method": "split_group"})
    config = {
        "model": model_name, "target": "binary", "max_len": max_len, "input_channels": 3,
        "threshold": threshold, "epochs": epochs, "batch_size": batch_size, "lr": lr,
        "test_size": test_size, "random_state": random_state, "device_used": str(device),
    }
    base = f"dl_{model_name}_binary"
    out_dir.mkdir(parents=True, exist_ok=True)
    model_path = out_dir / f"{base}.pt"
    metrics_path = out_dir / f"{base}_metrics.json"
    predictions_path = out_dir / f"{base}_predictions.csv"
    config_path = out_dir / f"{base}_config.json"
    torch.save({"state_dict": model.state_dict(), "config": config}, model_path)
    metrics_path.write_text(json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8")
    config_path.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
    pred_frame = frame.iloc[eval_indices][[c for c in ("sample_id", "capture_id", "split_group", "flow_id", "seq_len") if c in frame.columns]].copy()
    pred_frame["dl_pred_label"] = y_pred
    pred_frame["dl_prob_vpn"] = probabilities
    pred_frame.to_csv(predictions_path, index=False, encoding="utf-8-sig")
    logger.info("Saved DL model: %s", model_path)
    return {"model_path": str(model_path), "metrics_path": str(metrics_path), "predictions_path": str(predictions_path), "config_path": str(config_path), "metrics": metrics}


def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="Train a lightweight packet-sequence model")
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--model", choices=["cnn", "transformer"], default="cnn")
    parser.add_argument("--out-dir", default="models_dl")
    parser.add_argument("--epochs", type=int, default=10)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--device", choices=["cpu", "cuda", "auto"], default="auto")
    parser.add_argument("--test-size", type=float, default=0.25)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--threshold", type=float, default=0.5)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    train_dl(Path(args.dataset), args.model, Path(args.out_dir), args.epochs, args.batch_size, args.lr, args.device, args.test_size, args.random_state, args.threshold)


if __name__ == "__main__":
    main()
