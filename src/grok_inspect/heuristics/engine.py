"""Heuristic engine: rule packs + chain boosts + dedupe."""

from __future__ import annotations

from grok_inspect.heuristics import (
    rules_network,
    rules_persistence,
    rules_posture,
    rules_process,
    rules_sniffing,
    rules_stealer,
)
from grok_inspect.heuristics.allowlist import Allowlist
from grok_inspect.models import Finding, ScanBundle, Severity


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str]] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.id, f.summary[:120])
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def _chain_boosts(findings: list[Finding], bundle: ScanBundle) -> list[Finding]:
    ids = {f.id for f in findings if not f.acknowledged}
    extra: list[Finding] = []
    os_family = bundle.host.get("os_family")

    has_proxy = "network.system_proxy_enabled" in ids or "network.proxy_env" in ids
    has_capture = "sniff.capture_process" in ids or "sniff.promisc_iface" in ids
    if has_proxy and has_capture:
        extra.append(
            Finding(
                id="sniff.mitm_chain",
                title="Possible MITM / sniffing chain",
                summary="Proxy configuration co-occurs with capture/promisc signals",
                severity=Severity.CRITICAL,
                category="sniffing",
                evidence={"linked": ["proxy", "capture_or_promisc"]},
                confidence=0.75,
                remediation_hint="Treat as high priority: verify proxy trust and active sniffers",
                os=os_family,
            )
        )

    has_stealer = any(i.startswith("stealer.") for i in ids)
    has_persist_temp = "persistence.temp_path" in ids
    if has_stealer and has_persist_temp:
        extra.append(
            Finding(
                id="stealer.persist_chain",
                title="Stealer indicators with suspicious persistence",
                summary="Stealer IoCs co-occur with temp/Downloads persistence",
                severity=Severity.CRITICAL,
                category="stealer",
                evidence={"linked": ["stealer", "persistence.temp_path"]},
                confidence=0.8,
                remediation_hint="Isolate host and perform full IR retention",
                os=os_family,
            )
        )

    return extra


def run_heuristics(
    bundle: ScanBundle,
    allowlist: Allowlist | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(rules_sniffing.apply(bundle))
    findings.extend(rules_network.apply(bundle))
    findings.extend(rules_process.apply(bundle))
    findings.extend(rules_persistence.apply(bundle))
    findings.extend(rules_stealer.apply(bundle))
    findings.extend(rules_posture.apply(bundle))
    findings.extend(_chain_boosts(findings, bundle))
    findings = _dedupe(findings)
    if allowlist:
        findings = allowlist.apply(findings)
    # Sort: severity desc, then id
    findings.sort(key=lambda f: (-f.severity.rank, f.id))
    return findings
