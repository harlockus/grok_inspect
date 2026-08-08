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
        grok=GrokAnalysis(available=False, error="test"),
    )
    paths = write_report_pack(result, tmp_path)
    assert paths["json"].is_file()
    assert paths["md"].is_file()
    assert paths["html"].is_file()
    assert (tmp_path / "latest.json").is_file()
    assert (tmp_path / "latest.md").is_file()
    assert (tmp_path / "latest.html").is_file()
