"""Persistence heuristic rules."""

from __future__ import annotations

from grok_inspect.models import Finding, ScanBundle, Severity


def apply(bundle: ScanBundle) -> list[Finding]:
    out: list[Finding] = []
    os_family = bundle.host.get("os_family")
    pers = bundle.evidence_for("persistence")

    for item in pers.get("risky_sample") or []:
        out.append(
            Finding(
                id="persistence.temp_path",
                title="Persistence references temp/Downloads path",
                summary=f"Persistence item may point at staging location: {item.get('path') or item.get('kind')}",
                severity=Severity.HIGH,
                category="persistence",
                evidence={"item": item},
                confidence=0.8,
                remediation_hint="Remove unauthorized persistence; investigate payload path",
                os=os_family,
            )
        )

    for item in pers.get("items") or []:
        if isinstance(item, dict) and item.get("kind") == "ld_so_preload":
            out.append(
                Finding(
                    id="persistence.ld_so_preload",
                    title="ld.so.preload is present",
                    summary="/etc/ld.so.preload exists — common rootkit/hijack technique",
                    severity=Severity.CRITICAL,
                    category="persistence",
                    evidence={"item": item},
                    confidence=0.9,
                    remediation_hint="Inspect preload contents immediately; remove if unexpected",
                    os=os_family,
                    requires_elevated=True,
                )
            )

    count = int(pers.get("count") or 0)
    if count > 40:
        out.append(
            Finding(
                id="persistence.high_volume",
                title="Large number of persistence items",
                summary=f"Observed {count} persistence entries (review for unknowns)",
                severity=Severity.LOW,
                category="persistence",
                evidence={"count": count},
                confidence=0.5,
                remediation_hint="Inventory and baseline known-good agents",
                os=os_family,
            )
        )

    return out
