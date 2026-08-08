"""Mandatory redaction before Grok API payloads."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from grok_inspect.models import ScanResult

SECRET_PATTERNS = [
    re.compile(
        r"(?i)(api[_-]?key|token|password|secret|authorization)\s*[:=]\s*\S+"
    ),
    re.compile(r"(?i)bearer\s+[a-z0-9._\-]{20,}"),
    re.compile(r"xai-[A-Za-z0-9]{20,}"),
    re.compile(
        r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"
    ),
    re.compile(r"-----BEGIN[ A-Z]*PRIVATE KEY-----[\s\S]*?-----END[ A-Z]*PRIVATE KEY-----"),
    re.compile(r"(?i)(AKIA|ASIA)[0-9A-Z]{16}"),
    re.compile(r"(?i)ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"(?i)github_pat_[A-Za-z0-9_]{20,}"),
]


def redact_text(text: str) -> str:
    out = text
    for pat in SECRET_PATTERNS:
        out = pat.sub("[REDACTED]", out)
    return out


def normalize_path(path: str, home: str | None = None) -> str:
    if home and path.startswith(home):
        return "~" + path[len(home) :]
    return path


def _stable_hash(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:12]


def _redact_obj(obj: Any, home: str | None = None) -> Any:
    if isinstance(obj, str):
        s = redact_text(obj)
        if home:
            s = s.replace(home, "~")
        return s
    if isinstance(obj, dict):
        return {k: _redact_obj(v, home=home) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact_obj(v, home=home) for v in obj[:50]]
    return obj


def build_grok_payload(
    result: ScanResult,
    *,
    max_chars: int,
    home: str | None = None,
) -> str:
    """Serialize redacted JSON summary for the model."""
    open_findings = [f for f in result.findings if not f.acknowledged]
    open_findings.sort(key=lambda f: f.severity.rank, reverse=True)
    payload: dict[str, Any] = {
        "host": {
            "os_family": result.host.get("os_family"),
            "hostname_hash": _stable_hash(str(result.host.get("hostname", ""))),
            "elevated": result.elevated,
            "system": result.host.get("system"),
            "release": result.host.get("release"),
        },
        "score": result.score.model_dump(mode="json"),
        "coverage": [c.model_dump(mode="json") for c in result.coverage],
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "summary": redact_text(f.summary),
                "severity": f.severity.value,
                "category": f.category,
                "confidence": f.confidence,
                "evidence": _redact_obj(f.evidence, home=home),
                "remediation_hint": f.remediation_hint,
            }
            for f in open_findings
        ],
    }
    text = redact_text(json.dumps(payload, indent=2, default=str))
    while len(payload["findings"]) > 5 and len(text) > max_chars:
        payload["findings"].pop()
        text = redact_text(json.dumps(payload, indent=2, default=str))
    if len(text) > max_chars:
        text = text[: max_chars - 20] + "\n...[TRUNCATED]"
    return text
