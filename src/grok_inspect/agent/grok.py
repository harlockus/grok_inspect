"""Grok 4.5 analyst via official SpaceXAI xai-sdk (max reasoning)."""

from __future__ import annotations

import json
import re
import time
from typing import Any

from grok_inspect.agent.prompts import SYSTEM_CHARTER, build_user_message
from grok_inspect.config import Settings
from grok_inspect.models import GrokAnalysis, ScanResult
from grok_inspect.security.redact import build_grok_payload, redact_text
from grok_inspect.security.sanitize import scrub_control_chars, validate_model_id


def _parse_json_object(text: str) -> dict[str, Any]:
    text = scrub_control_chars(text.strip(), max_len=100_000)
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass
    m = re.search(r"\{[\s\S]*\}", text)
    if not m:
        return {
            "executive_summary": text[:2000],
            "threat_narrative": text[:8000],
        }
    try:
        data = json.loads(m.group(0))
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass
    return {
        "executive_summary": text[:2000],
        "threat_narrative": text[:8000],
    }


def _usage_summary(response: Any) -> str:
    usage = getattr(response, "usage", None)
    if usage is None:
        return ""
    parts = []
    for attr in (
        "input_tokens",
        "output_tokens",
        "reasoning_tokens",
        "total_tokens",
    ):
        val = getattr(usage, attr, None)
        if val is not None:
            parts.append(f"{attr}={val}")
    return ", ".join(parts)


def analyze_with_grok(
    result: ScanResult,
    settings: Settings,
    *,
    home: str | None = None,
) -> GrokAnalysis:
    """
    Call Grok 4.5 with reasoning_effort=high via xai-sdk.

    Never downgrades to mini/fast models on failure — returns heuristics-only
    GrokAnalysis(available=False) instead.
    Never stores raw model text in the returned analysis (report hygiene).
    """
    if not settings.grok_available:
        env_hint = settings.env_file or (settings.project_root / ".env")
        return GrokAnalysis(
            available=False,
            error=f"XAI_API_KEY not set — store it only in {env_hint}",
        )

    model_id = validate_model_id(settings.model.id or "grok-4.5")
    effort = "high"  # non-negotiable for analysis path

    try:
        payload = build_grok_payload(
            result,
            max_chars=settings.scan.payload_max_chars,
            home=home,
        )
    except Exception as exc:
        return GrokAnalysis(
            available=False,
            model_id=model_id,
            reasoning_effort=effort,
            error=f"redaction_failed: {type(exc).__name__}",
        )

    t0 = time.time()
    try:
        from xai_sdk import Client
        from xai_sdk.chat import system, user

        # Key passed only to SDK client — not logged
        client = Client(api_key=settings.api_key, timeout=3600)
        chat = client.chat.create(
            model=model_id,
            reasoning_effort=effort,
            messages=[system(SYSTEM_CHARTER)],
        )
        chat.append(
            user(
                build_user_message(
                    payload, str(result.host.get("os_family", "unknown"))
                )
            )
        )
        response = chat.sample()
        text = getattr(response, "content", None) or ""
        if not isinstance(text, str):
            text = str(text)
        parsed = _parse_json_object(text)
        latency = time.time() - t0
        conf = parsed.get("confidence")
        try:
            conf_f = float(conf) if conf is not None else None
            if conf_f is not None:
                conf_f = max(0.0, min(conf_f, 1.0))
        except (TypeError, ValueError):
            conf_f = None
        return GrokAnalysis(
            available=True,
            model_id=model_id,
            reasoning_effort=effort,
            executive_summary=redact_text(
                scrub_control_chars(str(parsed.get("executive_summary", "")), max_len=8_000)
            ),
            threat_narrative=redact_text(
                scrub_control_chars(str(parsed.get("threat_narrative", "")), max_len=20_000)
            ),
            prioritized_findings=list(parsed.get("prioritized_findings") or [])[:50],
            likely_attacker_goals=[
                scrub_control_chars(str(x), max_len=500)
                for x in (parsed.get("likely_attacker_goals") or [])[:30]
            ],
            remediation_plan=[
                scrub_control_chars(str(x), max_len=800)
                for x in (parsed.get("remediation_plan") or [])[:40]
            ],
            questions_for_operator=[
                scrub_control_chars(str(x), max_len=500)
                for x in (parsed.get("questions_for_operator") or [])[:20]
            ],
            confidence=conf_f,
            latency_s=latency,
            usage_summary=_usage_summary(response),
            raw_text="",  # never retain
        )
    except Exception as exc:
        return GrokAnalysis(
            available=False,
            model_id=model_id,
            reasoning_effort=effort,
            error=redact_text(
                scrub_control_chars(f"{type(exc).__name__}", max_len=200)
            ),
            latency_s=time.time() - t0,
        )
