"""Sanitize evidence and reports before persistence or display."""

from __future__ import annotations

import re
from typing import Any

from grok_inspect.models import Finding, GrokAnalysis, ScanResult
from grok_inspect.security.redact import redact_text

# Control characters that can break terminals / logs (keep tab/newline)
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# Extra secret shapes beyond redact_text
_PRIVATE_KEY = re.compile(
    r"-----BEGIN[ A-Z]*PRIVATE KEY-----[\s\S]*?-----END[ A-Z]*PRIVATE KEY-----"
)
_AWS = re.compile(r"(?i)(AKIA|ASIA)[0-9A-Z]{16}")
_PEM_LINE = re.compile(r"(?i)(aws_secret_access_key|private_key)\s*[:=]\s*\S+")


def scrub_control_chars(text: str, *, max_len: int = 50_000) -> str:
    s = _CTRL.sub("", text or "")
    if len(s) > max_len:
        s = s[: max_len - 20] + "…[truncated]"
    return s


def deep_sanitize(obj: Any, *, depth: int = 0, max_depth: int = 12) -> Any:
    """Recursively redact secrets and cap nested structures."""
    if depth > max_depth:
        return "[max_depth]"
    if obj is None or isinstance(obj, (bool, int, float)):
        return obj
    if isinstance(obj, str):
        s = scrub_control_chars(obj, max_len=4_000)
        s = _PRIVATE_KEY.sub("[REDACTED_PRIVATE_KEY]", s)
        s = _AWS.sub("[REDACTED_AWS_KEY]", s)
        s = _PEM_LINE.sub(r"\1=[REDACTED]", s)
        return redact_text(s)
    if isinstance(obj, dict):
        out = {}
        for i, (k, v) in enumerate(obj.items()):
            if i >= 200:
                out["…"] = "truncated_keys"
                break
            sk = scrub_control_chars(str(k), max_len=200)
            # Never keep raw secret field values
            if sk.lower() in {
                "password",
                "secret",
                "token",
                "api_key",
                "apikey",
                "authorization",
                "cookie",
                "set-cookie",
            }:
                out[sk] = "[REDACTED]"
            else:
                out[sk] = deep_sanitize(v, depth=depth + 1, max_depth=max_depth)
        return out
    if isinstance(obj, (list, tuple)):
        return [
            deep_sanitize(x, depth=depth + 1, max_depth=max_depth) for x in list(obj)[:100]
        ]
    return scrub_control_chars(str(obj), max_len=500)


def sanitize_finding(f: Finding) -> Finding:
    return f.model_copy(
        update={
            "title": scrub_control_chars(f.title, max_len=300),
            "summary": redact_text(scrub_control_chars(f.summary, max_len=2_000)),
            "remediation_hint": scrub_control_chars(f.remediation_hint, max_len=1_000),
            "evidence": deep_sanitize(f.evidence),
        }
    )


def sanitize_grok(g: GrokAnalysis) -> GrokAnalysis:
    # Drop raw model dump from persisted reports (may echo host evidence)
    return g.model_copy(
        update={
            "executive_summary": redact_text(
                scrub_control_chars(g.executive_summary, max_len=8_000)
            ),
            "threat_narrative": redact_text(
                scrub_control_chars(g.threat_narrative, max_len=20_000)
            ),
            "likely_attacker_goals": [
                scrub_control_chars(str(x), max_len=500)
                for x in (g.likely_attacker_goals or [])[:30]
            ],
            "remediation_plan": [
                scrub_control_chars(str(x), max_len=800)
                for x in (g.remediation_plan or [])[:40]
            ],
            "questions_for_operator": [
                scrub_control_chars(str(x), max_len=500)
                for x in (g.questions_for_operator or [])[:20]
            ],
            "prioritized_findings": deep_sanitize(g.prioritized_findings or [])[:50],
            "error": redact_text(scrub_control_chars(g.error or "", max_len=500)) or None,
            "raw_text": "",  # never persist raw model output
            "usage_summary": scrub_control_chars(g.usage_summary, max_len=200),
        }
    )


def sanitize_scan_result(result: ScanResult) -> ScanResult:
    """Return a copy safe to write to disk / display."""
    findings = [sanitize_finding(f) for f in result.findings]
    host = deep_sanitize(result.host)
    # Never put secrets in host dict
    if isinstance(host, dict):
        host.pop("api_key", None)
        host.pop("XAI_API_KEY", None)
    return result.model_copy(
        update={
            "host": host if isinstance(host, dict) else result.host,
            "findings": findings,
            "grok": sanitize_grok(result.grok),
            "bundle_summary": deep_sanitize(result.bundle_summary),
            "coverage": [
                c.model_copy(
                    update={
                        "detail": redact_text(
                            scrub_control_chars(c.detail, max_len=500)
                        )
                    }
                )
                for c in result.coverage
            ],
        }
    )


def validate_model_id(model_id: str) -> str:
    """
    Allow only safe Grok model id characters.

    Prevents odd injection into SDK/logging paths.
    """
    mid = (model_id or "").strip()
    if not mid:
        return "grok-4.5"
    if not re.fullmatch(r"[A-Za-z0-9._\-]{1,64}", mid):
        return "grok-4.5"
    # Prefer flagship; reject obvious non-flagship downgrades by policy name
    low = mid.lower()
    if any(x in low for x in ("mini", "fast-non-reasoning", "lite")):
        return "grok-4.5"
    return mid


def clamp_timeout(sec: int | float | None, *, default: int = 45) -> int:
    if sec is None:
        return default
    try:
        v = int(sec)
    except (TypeError, ValueError):
        return default
    return max(5, min(v, 300))
