"""Inference for trained packet-sequence models."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import List, Optional

import pandas as pd
import torch
from torch.utils.data import DataLoader

from .dl_trainer import make_model, resolve_device
from .sequence_dataset import PacketSequenceDataset, read_table

logger = logging.getLogger(__name__)


def predict_dl(model_path: Path, dataset_path: Path, out_path: Path, device_name: str = "auto", batch_size: int = 256) -> pd.DataFrame:
    device = resolve_device(device_name)
    checkpoint = torch.load(model_path, map_location=device)
    config = checkpoint.get("config", {})
    max_len = int(config.get("max_len", 64))
    frame = read_table(dataset_path).reset_index(drop=True)
    dataset = PacketSequenceDataset(frame, max_len=max_len)
    loader = DataLoader(dataset, batch_size=batch_size, shuffle=False)
    model = make_model(str(config.get("model", "cnn")), max_len).to(device)
    model.load_state_dict(checkpoint["state_dict"])
    model.eval()
    probabilities = []
    with torch.no_grad():
        for batch in loader:
            logits = model(batch["features"].to(device), batch["mask"].to(device))
            probabilities.extend(torch.softmax(logits, dim=1)[:, 1].cpu().tolist())
    threshold = float(config.get("threshold", 0.5))
    out = frame[[c for c in ("sample_id", "capture_id", "split_group", "flow_id", "seq_len") if c in frame.columns]].copy()
    out["dl_pred_label"] = [int(prob >= threshold) for prob in probabilities]
    out["dl_prob_vpn"] = probabilities
    for col in ("sample_id", "capture_id", "split_group", "flow_id", "seq_len"):
        if col not in out.columns:
            out[col] = ""
    out = out[["sample_id", "capture_id", "split_group", "flow_id", "dl_pred_label", "dl_prob_vpn", "seq_len"]]
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.suffix.lower() == ".parquet":
        out.to_parquet(out_path, index=False)
    else:
        out.to_csv(out_path, index=False, encoding="utf-8-sig")
    logger.info("Wrote DL predictions: %s (%d rows)", out_path, len(out))
    return out


def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="Predict with a packet-sequence model")
    parser.add_argument("--model", required=True)
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--out", default="results/dl_predictions.csv")
    parser.add_argument("--device", choices=["cpu", "cuda", "auto"], default="auto")
    parser.add_argument("--batch-size", type=int, default=256)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    predict_dl(Path(args.model), Path(args.dataset), Path(args.out), args.device, args.batch_size)


if __name__ == "__main__":
    main()
