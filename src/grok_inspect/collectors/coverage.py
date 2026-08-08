"""Coverage synthesis from collector results."""

from __future__ import annotations

from grok_inspect.models import (
    CollectorResult,
    CollectorStatus,
    CoverageEntry,
    Finding,
    Severity,
)


def build_coverage(
    results: list[CollectorResult],
    elevated: bool,
    os_family: str,
) -> tuple[list[CoverageEntry], list[Finding]]:
    entries: list[CoverageEntry] = []
    findings: list[Finding] = []
    for r in results:
        entries.append(
            CoverageEntry(
                collector=r.name,
                status=r.status,
                detail=r.detail or (r.error or ""),
                requires_elevated=False,
            )
        )
        if r.status in (
            CollectorStatus.LIMITED,
            CollectorStatus.SKIPPED,
            CollectorStatus.ERROR,
        ):
            findings.append(
                Finding(
                    id=f"coverage.{r.name}.{r.status.value}",
                    title=f"Collector {r.name}: {r.status.value}",
                    summary=r.error
                    or r.detail
                    or f"{r.name} did not run at full depth",
                    severity=Severity.INFO,
                    category="coverage",
                    evidence={"collector": r.name, "status": r.status.value},
                    confidence=1.0,
                    remediation_hint=(
                        "Re-run elevated (sudo / Administrator) for deeper coverage"
                        if not elevated
                        else "Check missing OS tools or permissions"
                    ),
                    os=os_family,
                )
            )
    if not elevated:
        findings.append(
            Finding(
                id="coverage.not_elevated",
                title="Scan not elevated",
                summary="Running without admin/root; some collectors are limited",
                severity=Severity.INFO,
                category="coverage",
                evidence={"elevated": False},
                confidence=1.0,
                remediation_hint="Re-run as root/Administrator for full comprehensive scan",
                os=os_family,
            )
        )
    return entries, findings
