"""Stealer indicator heuristic rules."""

from __future__ import annotations

from grok_inspect.models import Finding, ScanBundle, Severity


def apply(bundle: ScanBundle) -> list[Finding]:
    out: list[Finding] = []
    os_family = bundle.host.get("os_family")
    st = bundle.evidence_for("stealer_indicators")

    for path in st.get("path_hits") or []:
        out.append(
            Finding(
                id="stealer.path_ioc",
                title="Path matches stealer IoC pattern",
                summary=f"Path resembles known stealer staging: {path}",
                severity=Severity.CRITICAL,
                category="stealer",
                evidence={"path": path},
                confidence=0.75,
                remediation_hint="Isolate host; do not open the file; collect offline for IR",
                os=os_family,
            )
        )

    for name in st.get("process_hits") or []:
        out.append(
            Finding(
                id="stealer.process_ioc",
                title="Process name matches stealer IoC",
                summary=f"Process name matches curated stealer indicator: {name}",
                severity=Severity.CRITICAL,
                category="stealer",
                evidence={"name": name},
                confidence=0.7,
                remediation_hint="Confirm legitimacy; if unknown, isolate and preserve memory/disk",
                os=os_family,
            )
        )

    auth = st.get("authorized_keys") or {}
    if auth.get("exists") and int(auth.get("key_count") or 0) > 5:
        out.append(
            Finding(
                id="stealer.many_authorized_keys",
                title="Many SSH authorized_keys entries",
                summary=f"authorized_keys has {auth.get('key_count')} keys",
                severity=Severity.MEDIUM,
                category="stealer",
                evidence=auth,
                confidence=0.6,
                remediation_hint="Audit keys; remove unknown public keys",
                os=os_family,
            )
        )

    mode = str(auth.get("mode") or "")
    if mode and mode not in {"0o600", "0o400", "600", "400", "0o644"}:
        # world-readable keys are bad; 644 still noisy
        if mode.endswith("77") or mode.endswith("66") or mode.endswith("7"):
            out.append(
                Finding(
                    id="stealer.authorized_keys_perms",
                    title="Weak authorized_keys permissions",
                    summary=f"authorized_keys mode is {mode}",
                    severity=Severity.MEDIUM,
                    category="stealer",
                    evidence=auth,
                    confidence=0.7,
                    remediation_hint="chmod 600 ~/.ssh/authorized_keys",
                    os=os_family,
                )
            )

    return out
