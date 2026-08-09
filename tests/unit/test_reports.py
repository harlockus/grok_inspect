from pathlib import Path

from grok_inspect.models import (
    CoverageEntry,
    CollectorStatus,
    Finding,
    GrokAnalysis,
    ScanResult,
    ScanScore,
    Severity,
    utcnow,
)
from grok_inspect.report.writer import write_report_pack


def test_write_report_pack(tmp_path: Path):
    result = ScanResult(
        tool_version="0.1.0",
        started_at=utcnow(),
        finished_at=utcnow(),
        host={"hostname": "t", "os_family": "darwin", "release": "1"},
        elevated=False,
        coverage=[
            CoverageEntry(
                collector="env", status=CollectorStatus.FULL, detail=""
            )
        ],
        findings=[
            Finding(
                id="coverage.not_elevated",
                title="not elevated",
                summary="test",
                severity=Severity.INFO,
                category="coverage",
                evidence={},
            )
        ],
        score=ScanScore(max_severity=Severity.INFO, counts={"info": 1}, open_finding_count=1),
        grok=GrokAnalysis(
            available=True,
            model_id="grok-4.5",
            reasoning_effort="high",
            risk_rating="Medium",
            executive_summary="Host shows limited elevation; no critical compromise signals.",
            situation_overview="Non-elevated scan of a macOS workstation.",
            business_impact="Residual uncertainty on other-user processes.",
            board_talking_points=["No critical findings", "Re-run elevated for full coverage"],
            executive_actions=[
                {
                    "priority": "P1",
                    "owner_role": "IT Ops",
                    "action": "Re-run elevated scan",
                    "timeline": "24h",
                    "success_criteria": "Full collector coverage",
                }
            ],
            detailed_actions=[
                {
                    "phase": "Validate",
                    "title": "Elevated re-scan",
                    "owner_role": "IR",
                    "effort": "S",
                    "steps": ["sudo grok-inspect scan -v"],
                    "verification": "coverage shows full",
                }
            ],
            plan_30_60_90={
                "0_30_days": ["Complete elevated baseline"],
                "30_60_days": ["Baseline allowlist"],
                "60_90_days": ["Quarterly re-scan"],
            },
            threat_narrative="No strong compromise chain observed.",
            residual_risk="Visibility gaps without elevation.",
        ),
    )
    paths = write_report_pack(result, tmp_path)
    assert paths["json"].is_file()
    assert paths["md"].is_file()
    assert paths["html"].is_file()
    md = paths["md"].read_text(encoding="utf-8")
    assert "Executive Host Risk Brief" in md
    assert "Executive actions" in md
    assert "30 / 60 / 90" in md
    html = paths["html"].read_text(encoding="utf-8")
    assert "Executive Host Risk Brief" in html
    assert "Executive actions" in html
    assert (tmp_path / "latest.json").is_file()
    assert (tmp_path / "latest.md").is_file()
    assert (tmp_path / "latest.html").is_file()
