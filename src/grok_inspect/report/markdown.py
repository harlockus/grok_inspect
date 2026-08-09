"""Executive Markdown report generation (CISO/CIO)."""

from __future__ import annotations

from typing import Any

from grok_inspect.models import ScanResult


def _kv_action(item: dict[str, Any], *keys: str, default: str = "") -> str:
    for k in keys:
        if k in item and item[k] is not None:
            return str(item[k])
    return default


def to_markdown(result: ScanResult) -> str:
    g = result.grok
    lines: list[str] = []

    # Cover
    lines.append("# Grok Inspect — Executive Host Risk Brief")
    lines.append("")
    lines.append(
        f"**Classification:** Internal use · Defensive inspection only  "
    )
    lines.append(
        f"**Host:** `{result.host.get('hostname')}` "
        f"({result.host.get('os_family')} {result.host.get('release')})  "
    )
    lines.append(f"**Elevated scan:** {'Yes' if result.elevated else 'No'}  ")
    lines.append(
        f"**Window:** {result.started_at.isoformat()} → {result.finished_at.isoformat()}  "
    )
    lines.append(
        f"**Heuristic max severity:** `{result.score.max_severity.value}` · "
        f"**Open findings:** {result.score.open_finding_count}  "
    )
    if g.available and g.risk_rating:
        lines.append(f"**Grok risk rating:** **{g.risk_rating}**  ")
    lines.append(f"**Tool:** grok-inspect {result.tool_version}  ")
    if g.available and g.model_id:
        lines.append(
            f"**Analyst model:** {g.model_id} · reasoning_effort={g.reasoning_effort}  "
        )
    lines.append("")
    lines.append("---")
    lines.append("")

    # Score strip
    lines.append("## 1. Severity scorecard")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|------:|")
    for sev in ("critical", "high", "medium", "low", "info"):
        lines.append(f"| {sev} | {result.score.counts.get(sev, 0)} |")
    lines.append("")

    # Grok executive block first for CISO reading path
    lines.append("## 2. Executive brief (Grok)")
    lines.append("")
    if g.available:
        if g.situation_overview:
            lines.append("### Situation overview")
            lines.append("")
            lines.append(g.situation_overview)
            lines.append("")
        lines.append("### Executive summary")
        lines.append("")
        lines.append(g.executive_summary or "_No summary returned._")
        lines.append("")
        if g.business_impact:
            lines.append("### Business impact")
            lines.append("")
            lines.append(g.business_impact)
            lines.append("")
        if g.board_talking_points:
            lines.append("### Board / leadership talking points")
            lines.append("")
            for bp in g.board_talking_points:
                lines.append(f"- {bp}")
            lines.append("")
    else:
        lines.append(
            f"_Grok analysis unavailable:_ {g.error or 'skipped / no API key'}"
        )
        lines.append("")
        lines.append(
            "Heuristic findings below remain valid for triage without Grok."
        )
        lines.append("")

    # Executive actions
    lines.append("## 3. Executive actions (decide & direct)")
    lines.append("")
    if g.available and g.executive_actions:
        lines.append(
            "| Priority | Owner | Timeline | Action | Success criteria |"
        )
        lines.append("|----------|-------|----------|--------|------------------|")
        for a in g.executive_actions:
            if not isinstance(a, dict):
                continue
            lines.append(
                "| "
                f"{_kv_action(a, 'priority', default='—')} | "
                f"{_kv_action(a, 'owner_role', 'owner', default='—')} | "
                f"{_kv_action(a, 'timeline', default='—')} | "
                f"{_kv_action(a, 'action', default='—').replace('|', '/')} | "
                f"{_kv_action(a, 'success_criteria', default='—').replace('|', '/')} |"
            )
        lines.append("")
    elif g.available and g.remediation_plan:
        for i, step in enumerate(g.remediation_plan, 1):
            lines.append(f"{i}. {step}")
        lines.append("")
    else:
        lines.append("_No executive actions generated._")
        lines.append("")

    # 30/60/90
    if g.available and g.plan_30_60_90:
        lines.append("## 4. 30 / 60 / 90 day plan")
        lines.append("")
        labels = (
            ("0_30_days", "0–30 days"),
            ("30_60_days", "30–60 days"),
            ("60_90_days", "60–90 days"),
        )
        for key, label in labels:
            items = g.plan_30_60_90.get(key) or []
            if not items:
                continue
            lines.append(f"### {label}")
            lines.append("")
            for it in items:
                lines.append(f"- {it}")
            lines.append("")

    # Detailed technical actions
    lines.append("## 5. Detailed technical actions")
    lines.append("")
    if g.available and g.detailed_actions:
        for i, a in enumerate(g.detailed_actions, 1):
            if not isinstance(a, dict):
                continue
            title = _kv_action(a, "title", default=f"Action {i}")
            phase = _kv_action(a, "phase", default="")
            owner = _kv_action(a, "owner_role", "owner", default="")
            effort = _kv_action(a, "effort", default="")
            header = f"### {i}. {title}"
            meta = " · ".join(x for x in (phase, owner, f"effort {effort}" if effort else "") if x)
            lines.append(header)
            lines.append("")
            if meta:
                lines.append(f"*{meta}*")
                lines.append("")
            steps = a.get("steps") or []
            if isinstance(steps, list) and steps:
                lines.append("**Steps**")
                lines.append("")
                for j, s in enumerate(steps, 1):
                    lines.append(f"{j}. {s}")
                lines.append("")
            ver = _kv_action(a, "verification")
            if ver:
                lines.append(f"**Verification:** {ver}")
                lines.append("")
            fids = a.get("related_finding_ids") or []
            if fids:
                lines.append(
                    "**Related findings:** "
                    + ", ".join(f"`{x}`" for x in fids[:20])
                )
                lines.append("")
    elif g.available and g.remediation_plan:
        lines.append("_See remediation list in §3 / flat plan below._")
        lines.append("")
    else:
        # Fallback: heuristic remediation hints
        open_f = [f for f in result.findings if not f.acknowledged]
        for f in open_f[:15]:
            if f.remediation_hint:
                lines.append(f"- **`{f.id}`** — {f.remediation_hint}")
        lines.append("")

    # Threat narrative
    if g.available and g.threat_narrative:
        lines.append("## 6. Threat narrative")
        lines.append("")
        lines.append(g.threat_narrative)
        lines.append("")
        if g.attack_path:
            lines.append("### Hypothesized attack path")
            lines.append("")
            for i, step in enumerate(g.attack_path, 1):
                lines.append(f"{i}. {step}")
            lines.append("")
        if g.likely_attacker_goals:
            lines.append("### Likely attacker goals")
            lines.append("")
            for goal in g.likely_attacker_goals:
                lines.append(f"- {goal}")
            lines.append("")

    # Prioritized findings from Grok
    if g.available and g.prioritized_findings:
        lines.append("## 7. Prioritized findings (Grok)")
        lines.append("")
        for pf in g.prioritized_findings:
            if not isinstance(pf, dict):
                continue
            rid = pf.get("id", "")
            title = pf.get("title", rid)
            rank = pf.get("rank", "")
            sev = pf.get("severity", "")
            lines.append(f"### #{rank} [{str(sev).upper()}] {title}")
            lines.append("")
            lines.append(f"- **Finding ID:** `{rid}`")
            if pf.get("rationale"):
                lines.append(f"- **Rationale:** {pf['rationale']}")
            if pf.get("business_relevance"):
                lines.append(f"- **Business relevance:** {pf['business_relevance']}")
            if pf.get("false_positive_notes"):
                lines.append(f"- **False-positive notes:** {pf['false_positive_notes']}")
            lines.append("")

    # Raw heuristic findings
    lines.append("## 8. Full finding catalog (heuristics)")
    lines.append("")
    open_f = [f for f in result.findings if not f.acknowledged]
    if not open_f:
        lines.append("_No open findings._")
        lines.append("")
    for f in open_f:
        lines.append(f"### [{f.severity.value.upper()}] {f.title}")
        lines.append("")
        lines.append(f"- **ID:** `{f.id}`")
        lines.append(f"- **Category:** {f.category}")
        lines.append(f"- **Confidence:** {f.confidence}")
        lines.append(f"- **Summary:** {f.summary}")
        if f.remediation_hint:
            lines.append(f"- **Local hint:** {f.remediation_hint}")
        if f.evidence:
            # compact evidence keys
            keys = ", ".join(f"`{k}`" for k in list(f.evidence.keys())[:12])
            lines.append(f"- **Evidence keys:** {keys}")
        lines.append("")

    ack = [f for f in result.findings if f.acknowledged]
    if ack:
        lines.append("### Acknowledged (allowlisted)")
        lines.append("")
        for f in ack:
            lines.append(f"- `{f.id}` — {f.title}")
        lines.append("")

    # Coverage
    lines.append("## 9. Coverage & residual risk")
    lines.append("")
    lines.append("### Collector coverage")
    lines.append("")
    for c in result.coverage:
        detail = f" — {c.detail}" if c.detail else ""
        lines.append(f"- `{c.collector}`: **{c.status.value}**{detail}")
    lines.append("")
    if g.available and g.coverage_assessment:
        lines.append("### Coverage assessment (Grok)")
        lines.append("")
        lines.append(g.coverage_assessment)
        lines.append("")
    if g.available and g.residual_risk:
        lines.append("### Residual risk")
        lines.append("")
        lines.append(g.residual_risk)
        lines.append("")
    if g.available and g.assumptions_and_limits:
        lines.append("### Assumptions & limits")
        lines.append("")
        for a in g.assumptions_and_limits:
            lines.append(f"- {a}")
        lines.append("")
    if g.available and g.questions_for_operator:
        lines.append("### Questions for the operator")
        lines.append("")
        for q in g.questions_for_operator:
            lines.append(f"- {q}")
        lines.append("")

    if g.available:
        lines.append("## 10. Analysis metadata")
        lines.append("")
        if g.confidence is not None:
            lines.append(f"- **Confidence:** {g.confidence}")
        if g.latency_s is not None:
            lines.append(f"- **Latency:** {g.latency_s:.1f}s")
        if g.usage_summary:
            lines.append(f"- **Usage:** {g.usage_summary}")
        lines.append("")

    lines.append("---")
    lines.append(
        "_Generated by **grok-inspect** · Defensive host inspection only · "
        "Protect this brief — it may contain sensitive host metadata._"
    )
    lines.append("")
    return "\n".join(lines)
