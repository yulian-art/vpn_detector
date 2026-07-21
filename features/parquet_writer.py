#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Small output helpers for Phase 2 feature tables."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List

import pandas as pd


def write_table(rows: Iterable[Dict[str, Any]], out_path: Path) -> pd.DataFrame:
    """Write rows to parquet or CSV based on suffix and return the DataFrame."""

    df = pd.DataFrame(list(rows))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.suffix.lower() == ".parquet":
        df.to_parquet(out_path, index=False)
    else:
        df.to_csv(out_path, index=False, encoding="utf-8-sig")
    return df
