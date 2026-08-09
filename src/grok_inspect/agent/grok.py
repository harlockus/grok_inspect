"""Grok 4.5 CISO analyst via official SpaceXAI xai-sdk (max reasoning)."""

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
    text = scrub_control_chars(text.strip(), max_len=200_000)
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass
    m = re.search(r"\{[\s\S]*\}", text)
    if not m:
        return {
            "executive_summary": text[:4000],
            "threat_narrative": text[:12_000],
        }
    try:
        data = json.loads(m.group(0))
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass
    return {
        "executive_summary": text[:4000],
        "threat_narrative": text[:12_000],
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


def _str_list(val: Any, *, max_items: int, max_len: int) -> list[str]:
    if not isinstance(val, list):
        return []
    out: list[str] = []
    for x in val[:max_items]:
        out.append(scrub_control_chars(str(x), max_len=max_len))
    return out


def _dict_list(val: Any, *, max_items: int) -> list[dict[str, Any]]:
    if not isinstance(val, list):
        return []
    out: list[dict[str, Any]] = []
    for x in val[:max_items]:
        if isinstance(x, dict):
            cleaned: dict[str, Any] = {}
            for k, v in list(x.items())[:40]:
                sk = scrub_control_chars(str(k), max_len=80)
                if isinstance(v, list):
                    cleaned[sk] = [
                        scrub_control_chars(str(i), max_len=800) for i in v[:40]
                    ]
                elif isinstance(v, dict):
                    cleaned[sk] = {
                        scrub_control_chars(str(kk), max_len=80): scrub_control_chars(
                            str(vv), max_len=800
                        )
                        for kk, vv in list(v.items())[:20]
                    }
                else:
                    cleaned[sk] = scrub_control_chars(str(v), max_len=2_000)
            out.append(cleaned)
        else:
            out.append({"value": scrub_control_chars(str(x), max_len=500)})
    return out


def _plan_306090(val: Any) -> dict[str, list[str]]:
    if not isinstance(val, dict):
        return {}
    out: dict[str, list[str]] = {}
    for key in ("0_30_days", "30_60_days", "60_90_days"):
        raw = val.get(key) or val.get(key.replace("_", "-")) or []
        out[key] = _str_list(raw, max_items=20, max_len=600)
    # accept alternate key names
    for alt, canon in (
        ("days_0_30", "0_30_days"),
        ("days_30_60", "30_60_days"),
        ("days_60_90", "60_90_days"),
        ("first_30_days", "0_30_days"),
    ):
        if alt in val and not out.get(canon):
            out[canon] = _str_list(val.get(alt), max_items=20, max_len=600)
    return out


def _analysis_from_parsed(
    parsed: dict[str, Any],
    *,
    model_id: str,
    effort: str,
    latency: float,
    usage: str,
) -> GrokAnalysis:
    conf = parsed.get("confidence")
    try:
        conf_f = float(conf) if conf is not None else None
        if conf_f is not None:
            conf_f = max(0.0, min(conf_f, 1.0))
    except (TypeError, ValueError):
        conf_f = None

    risk = scrub_control_chars(str(parsed.get("risk_rating", "") or ""), max_len=40)
    # normalize risk rating
    risk_l = risk.lower()
    for label in ("Critical", "High", "Medium", "Low", "Informational"):
        if risk_l.startswith(label.lower()[:4]) or risk_l == label.lower():
            risk = label
            break

    return GrokAnalysis(
        available=True,
        model_id=model_id,
        reasoning_effort=effort,
        executive_summary=redact_text(
            scrub_control_chars(str(parsed.get("executive_summary", "")), max_len=12_000)
        ),
        situation_overview=redact_text(
            scrub_control_chars(str(parsed.get("situation_overview", "")), max_len=6_000)
        ),
        risk_rating=risk,
        business_impact=redact_text(
            scrub_control_chars(str(parsed.get("business_impact", "")), max_len=8_000)
        ),
        board_talking_points=_str_list(
            parsed.get("board_talking_points"), max_items=12, max_len=500
        ),
        threat_narrative=redact_text(
            scrub_control_chars(str(parsed.get("threat_narrative", "")), max_len=40_000)
        ),
        attack_path=_str_list(parsed.get("attack_path"), max_items=20, max_len=600),
        likely_attacker_goals=_str_list(
            parsed.get("likely_attacker_goals"), max_items=20, max_len=500
        ),
        prioritized_findings=_dict_list(parsed.get("prioritized_findings"), max_items=40),
        executive_actions=_dict_list(parsed.get("executive_actions"), max_items=25),
        detailed_actions=_dict_list(parsed.get("detailed_actions"), max_items=40),
        remediation_plan=_str_list(
            parsed.get("remediation_plan"), max_items=25, max_len=800
        ),
        plan_30_60_90=_plan_306090(parsed.get("plan_30_60_90")),
        coverage_assessment=redact_text(
            scrub_control_chars(str(parsed.get("coverage_assessment", "")), max_len=6_000)
        ),
        residual_risk=redact_text(
            scrub_control_chars(str(parsed.get("residual_risk", "")), max_len=6_000)
        ),
        questions_for_operator=_str_list(
            parsed.get("questions_for_operator"), max_items=20, max_len=500
        ),
        assumptions_and_limits=_str_list(
            parsed.get("assumptions_and_limits"), max_items=20, max_len=500
        ),
        confidence=conf_f,
        latency_s=latency,
        usage_summary=usage,
        raw_text="",
    )


def analyze_with_grok(
    result: ScanResult,
    settings: Settings,
    *,
    home: str | None = None,
    collector_evidence: dict[str, dict] | None = None,
) -> GrokAnalysis:
    """
    Call Grok 4.5 with reasoning_effort=high via xai-sdk.

    Never downgrades to mini/fast models on failure.
    """
    if not settings.grok_available:
        env_hint = settings.env_file or (settings.project_root / ".env")
        return GrokAnalysis(
            available=False,
            error=f"XAI_API_KEY not set — store it only in {env_hint}",
        )

    model_id = validate_model_id(settings.model.id or "grok-4.5")
    effort = "high"

    try:
        payload = build_grok_payload(
            result,
            max_chars=settings.scan.payload_max_chars,
            home=home,
            collector_evidence=collector_evidence,
        )
    except Exception:
        return GrokAnalysis(
            available=False,
            model_id=model_id,
            reasoning_effort=effort,
            error="redaction_failed",
        )

    t0 = time.time()
    try:
        from xai_sdk import Client
        from xai_sdk.chat import system, user

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
        return _analysis_from_parsed(
            parsed,
            model_id=model_id,
            effort=effort,
            latency=time.time() - t0,
            usage=_usage_summary(response),
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
