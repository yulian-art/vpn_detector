"""Stable sample and capture identities shared by every pipeline stage."""

from __future__ import annotations

import hashlib
from typing import Any


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).replace("\\", "/")


def _stable_id(*parts: Any) -> str:
    raw = "|".join(_text(part) for part in parts)
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:16]


def make_sample_id(
    source_archive: Any,
    pcap_member: Any,
    file_name: Any,
    file_size_bytes: Any = "",
) -> str:
    """Return the file-level identity used by labels and all feature tables."""

    return _stable_id(source_archive, pcap_member, file_name, file_size_bytes)


def make_capture_id(source_archive: Any, pcap_member: Any, file_name: Any = "") -> str:
    """Return a stable capture identity without using mutable label fields."""

    return _stable_id(source_archive, pcap_member, file_name)


def make_split_group(
    source_archive: Any,
    pcap_member: Any,
    file_name: Any = "",
    capture_id: Any = None,
) -> str:
    """Return the leakage-safe grouping key, reusing a supplied capture ID."""

    return _text(capture_id) if _text(capture_id) else make_capture_id(source_archive, pcap_member, file_name)


def stable_id(*parts: Any) -> str:
    """Compatibility helper for non-identity hashes in older modules."""

    return _stable_id(*parts)
