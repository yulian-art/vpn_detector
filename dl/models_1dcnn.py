"""Small 1D-CNN packet sequence classifier."""

from __future__ import annotations

import torch
from torch import nn


class Packet1DCNN(nn.Module):
    def __init__(self, input_channels: int = 3, hidden_channels: int = 64, dropout: float = 0.2) -> None:
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Conv1d(input_channels, hidden_channels, kernel_size=5, padding=2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Conv1d(hidden_channels, hidden_channels, kernel_size=3, padding=1),
            nn.ReLU(),
        )
        self.dropout = nn.Dropout(dropout)
        self.classifier = nn.Linear(hidden_channels, 2)

    def forward(self, features: torch.Tensor, mask: torch.Tensor | None = None) -> torch.Tensor:
        encoded = self.encoder(features)
        if mask is not None:
            encoded = encoded.masked_fill(~mask.unsqueeze(1), torch.finfo(encoded.dtype).min)
        pooled = encoded.amax(dim=2)
        pooled = torch.where(torch.isfinite(pooled), pooled, torch.zeros_like(pooled))
        return self.classifier(self.dropout(pooled))
