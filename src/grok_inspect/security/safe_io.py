"""Bounded, safe file and YAML I/O."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from grok_inspect.security.paths import PathSecurityError, safe_readable_file


def read_text_bounded(path: Path | str, *, max_bytes: int = 1_000_000) -> str:
    p = safe_readable_file(path, max_bytes=max_bytes)
    data = p.read_bytes()
    if len(data) > max_bytes:
        raise PathSecurityError(f"File exceeds max size: {p}")
    return data.decode("utf-8", errors="replace")


def load_yaml_file(path: Path | str, *, max_bytes: int = 512_000) -> dict[str, Any]:
    """Load YAML with safe_load only; reject non-mapping roots and oversized files."""
    text = read_text_bounded(path, max_bytes=max_bytes)
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PathSecurityError(f"Invalid YAML: {path}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise PathSecurityError(f"YAML root must be a mapping: {path}")
    return data
