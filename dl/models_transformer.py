"""Tiny Transformer baseline for packet sequences."""

from __future__ import annotations

import torch
from torch import nn


class PacketTinyTransformer(nn.Module):
    def __init__(self, input_channels: int = 3, d_model: int = 64, nhead: int = 4, num_layers: int = 2, dropout: float = 0.1, max_len: int = 64) -> None:
        super().__init__()
        self.input_projection = nn.Linear(input_channels, d_model)
        self.position = nn.Parameter(torch.zeros(1, max_len, d_model))
        layer = nn.TransformerEncoderLayer(d_model=d_model, nhead=nhead, dim_feedforward=d_model * 2, dropout=dropout, batch_first=True)
        self.encoder = nn.TransformerEncoder(layer, num_layers=num_layers)
        self.classifier = nn.Linear(d_model, 2)

    def forward(self, features: torch.Tensor, mask: torch.Tensor | None = None) -> torch.Tensor:
        x = features.transpose(1, 2)
        x = self.input_projection(x) + self.position[:, : x.shape[1]]
        padding_mask = ~mask if mask is not None else None
        x = self.encoder(x, src_key_padding_mask=padding_mask)
        if mask is None:
            pooled = x.mean(dim=1)
        else:
            weights = mask.unsqueeze(-1).to(x.dtype)
            pooled = (x * weights).sum(dim=1) / weights.sum(dim=1).clamp_min(1.0)
        return self.classifier(pooled)
