from grok_inspect.models import (
    Finding,
    GrokAnalysis,
    ScanResult,
    ScanScore,
    Severity,
    utcnow,
)
from grok_inspect.security.redact import build_grok_payload, redact_text


def test_redact_api_key_shape():
    s = "Authorization: Bearer xai-abcdefghijklmnopqrstuvwxyz0123456789"
    out = redact_text(s)
    assert "xai-abcdefghijklmnopqrstuvwxyz0123456789" not in out
    assert "REDACTED" in out


def test_build_payload_strips_home():
    home = "/Users/alice"
    result = ScanResult(
        tool_version="0.1.0",
        started_at=utcnow(),
        finished_at=utcnow(),
        host={"os_family": "darwin", "hostname": "h"},
        elevated=False,
        findings=[
            Finding(
                id="x",
                title="t",
                summary="path",
                severity=Severity.LOW,
                category="process",
                evidence={"path": f"{home}/secret/file"},
                confidence=1.0,
            )
        ],
        score=ScanScore.from_findings([]),
        grok=GrokAnalysis(),
    )
    # recompute score with finding
    result.score = ScanScore.from_findings(result.findings)
    text = build_grok_payload(result, max_chars=50_000, home=home)
    assert "/Users/alice" not in text
    assert "~/secret/file" in text
    assert "findings_open" in text
    assert "CISO_CIO_IR" in text

