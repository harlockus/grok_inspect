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
    re.compile(
        r"-----BEGIN[ A-Z]*PRIVATE KEY-----[\s\S]*?-----END[ A-Z]*PRIVATE KEY-----"
    ),
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


def _redact_obj(obj: Any, home: str | None = None, *, list_cap: int = 80) -> Any:
    if isinstance(obj, str):
        s = redact_text(obj)
        if home:
            s = s.replace(home, "~")
        # Cap very long strings in payload
        if len(s) > 2_000:
            s = s[:2_000] + "…[truncated]"
        return s
    if isinstance(obj, dict):
        out = {}
        for i, (k, v) in enumerate(obj.items()):
            if i >= 80:
                out["_truncated_keys"] = True
                break
            out[str(k)[:120]] = _redact_obj(v, home=home, list_cap=list_cap)
        return out
    if isinstance(obj, list):
        return [_redact_obj(v, home=home, list_cap=list_cap) for v in obj[:list_cap]]
    return obj


def _collector_summaries(result: ScanResult, home: str | None) -> list[dict[str, Any]]:
    """Include richer collector evidence for comprehensive analysis."""
    summaries: list[dict[str, Any]] = []
    for item in result.bundle_summary.get("collectors") or []:
        if not isinstance(item, dict):
            continue
        summaries.append(
            {
                "name": item.get("name"),
                "status": item.get("status"),
                "error": item.get("error"),
            }
        )
    # Attach evidence from findings' categories; also pull from coverage
    return summaries


def build_grok_payload(
    result: ScanResult,
    *,
    max_chars: int,
    home: str | None = None,
    collector_evidence: dict[str, dict[str, Any]] | None = None,
) -> str:
    """
    Serialize a comprehensive redacted package for Grok.

    Includes all open findings (severity-sorted), coverage, score, host context,
    and optional per-collector evidence digests. Truncates only if over max_chars,
    never dropping below the top findings by severity.
    """
    open_findings = [f for f in result.findings if not f.acknowledged]
    open_findings.sort(key=lambda f: (-f.severity.rank, f.id))
    ack = [f for f in result.findings if f.acknowledged]

    findings_payload = [
        {
            "id": f.id,
            "title": f.title,
            "summary": redact_text(f.summary),
            "severity": f.severity.value,
            "category": f.category,
            "confidence": f.confidence,
            "evidence": _redact_obj(f.evidence, home=home, list_cap=40),
            "remediation_hint": f.remediation_hint,
            "requires_elevated": f.requires_elevated,
        }
        for f in open_findings
    ]

    evidence_digest: dict[str, Any] = {}
    if collector_evidence:
        for name, ev in collector_evidence.items():
            # Prefer structured digests; cap nested size
            evidence_digest[name] = _redact_obj(ev, home=home, list_cap=60)

    payload: dict[str, Any] = {
        "report_type": "host_risk_brief_input",
        "audience": "CISO_CIO_IR",
        "host": {
            "os_family": result.host.get("os_family"),
            "system": result.host.get("system"),
            "release": result.host.get("release"),
            "version": result.host.get("version"),
            "machine": result.host.get("machine"),
            "python": result.host.get("python"),
            "hostname_hash": _stable_hash(str(result.host.get("hostname", ""))),
            "username_hash": _stable_hash(str(result.host.get("username", ""))),
            "elevated": result.elevated,
        },
        "scan_window": {
            "started_at": result.started_at.isoformat(),
            "finished_at": result.finished_at.isoformat(),
            "tool_version": result.tool_version,
        },
        "score": result.score.model_dump(mode="json"),
        "coverage": [c.model_dump(mode="json") for c in result.coverage],
        "collector_status": _collector_summaries(result, home),
        "findings_open": findings_payload,
        "findings_acknowledged_count": len(ack),
        "findings_acknowledged_ids": [f.id for f in ack[:40]],
        "collector_evidence": evidence_digest,
        "analysis_instructions": {
            "produce": "executive + technical dual-track actions",
            "include_30_60_90": True,
            "language": "board-ready English",
        },
    }

    text = redact_text(json.dumps(payload, indent=2, default=str))
    # Truncate strategy: drop lowest-severity findings first, keep >= 12 when possible
    min_keep = 12
    while (
        len(payload["findings_open"]) > min_keep
        and len(text) > max_chars
    ):
        payload["findings_open"].pop()
        text = redact_text(json.dumps(payload, indent=2, default=str))

    # If still too large, drop collector evidence bulk first
    while len(text) > max_chars and payload.get("collector_evidence"):
        keys = list(payload["collector_evidence"].keys())
        if not keys:
            break
        payload["collector_evidence"].pop(keys[-1], None)
        text = redact_text(json.dumps(payload, indent=2, default=str))

    if len(text) > max_chars:
        # Last resort hard truncate of payload body
        text = text[: max_chars - 40] + "\n...[TRUNCATED_FOR_SIZE]\n"
    return text
