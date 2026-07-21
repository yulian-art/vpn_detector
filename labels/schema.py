#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Shared schema and normalization helpers for strict labels."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class LabelConfidence(str, Enum):
    """Ground-truth confidence levels used by labels_master."""

    STRONG = "strong"
    MEDIUM = "medium"
    WEAK = "weak"
    UNLABELED = "unlabeled"


CONFIDENCE_WEIGHTS = {
    LabelConfidence.STRONG.value: 1.0,
    LabelConfidence.MEDIUM.value: 0.7,
    LabelConfidence.WEAK.value: 0.35,
    LabelConfidence.UNLABELED.value: 0.0,
}


@dataclass
class LabelVote:
    """One weak/strong supervision vote for one label task."""

    source: str
    task: str
    value: Any
    confidence: LabelConfidence | str
    weight: float | None = None
    evidence: Any = field(default_factory=dict)
    reason: str = ""
    family: str = ""

    def __post_init__(self) -> None:
        conf = normalize_confidence(self.confidence)
        self.confidence = conf
        if self.weight is None:
            self.weight = CONFIDENCE_WEIGHTS[conf.value]

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["confidence"] = normalize_confidence(self.confidence).value
        return data


LABELS_MASTER_COLUMNS = [
    "entity_level",
    "sample_id",
    "capture_id",
    "flow_id",
    "window_id",
    "file_name",
    "pcap_member",
    "source_archive",
    "label_binary",
    "label_protocol",
    "label_tool",
    "label_family",
    "scenario",
    "label_confidence",
    "label_score",
    "label_status",
    "review_status",
    "positive_votes",
    "negative_votes",
    "conflict_reasons",
    "evidence_json",
    "device_id",
    "network_id",
    "time_period",
    "split_group",
    "note",
]


def normalize_confidence(value: Any) -> LabelConfidence:
    """Return a safe LabelConfidence value."""

    if isinstance(value, LabelConfidence):
        return value
    text = str(value or "").strip().lower()
    aliases = {
        "high": "strong",
        "verified": "strong",
        "manual": "strong",
        "auto": "medium",
        "unknown": "unlabeled",
        "": "unlabeled",
    }
    text = aliases.get(text, text)
    try:
        return LabelConfidence(text)
    except ValueError:
        return LabelConfidence.UNLABELED


def normalize_binary_label(value: Any) -> Optional[int]:
    """Normalize a binary VPN label without treating unknown as VPN."""

    if value is None:
        return None
    text = str(value).strip().lower()
    if text in {"", "nan", "none", "unknown", "unlabeled", "null"}:
        return None
    if text in {"1", "true", "vpn", "yes", "y", "positive"}:
        return 1
    if text in {"0", "false", "nonvpn", "non-vpn", "non_vpn", "normal", "benign", "no", "n", "negative"}:
        return 0
    try:
        numeric = int(float(text))
        if numeric in {0, 1}:
            return numeric
    except Exception:
        pass
    return None


def evidence_to_json(value: Any) -> str:
    """Serialize evidence payloads for labels_master."""

    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except TypeError:
        return json.dumps(str(value), ensure_ascii=False)


def confidence_rank(value: Any) -> int:
    conf = normalize_confidence(value)
    return {
        LabelConfidence.UNLABELED: 0,
        LabelConfidence.WEAK: 1,
        LabelConfidence.MEDIUM: 2,
        LabelConfidence.STRONG: 3,
    }[conf]
