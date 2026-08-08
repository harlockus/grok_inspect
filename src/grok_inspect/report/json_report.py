"""JSON report serialization."""

from __future__ import annotations

import json

from grok_inspect.models import ScanResult


def to_json(result: ScanResult) -> str:
    return json.dumps(result.model_dump(mode="json"), indent=2, default=str)
