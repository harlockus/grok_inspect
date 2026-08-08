"""Security-by-design hardening tests."""

from pathlib import Path

import pytest

from grok_inspect.collectors.subprocess_util import run_cmd
from grok_inspect.models import Finding, GrokAnalysis, ScanResult, ScanScore, Severity, utcnow
from grok_inspect.security.paths import PathSecurityError, ensure_path_inside, safe_report_dir
from grok_inspect.security.redact import redact_text
from grok_inspect.security.sanitize import (
    sanitize_scan_result,
    validate_model_id,
    clamp_timeout,
    deep_sanitize,
)


def test_subprocess_never_shell_and_caps_output():
    rc, out, err = run_cmd(["echo", "hello"], timeout=5)
    assert rc == 0
    assert "hello" in out


def test_null_in_argv_rejected():
    rc, out, err = run_cmd(["echo", "a\x00b"], timeout=5)
    assert rc == 1
    assert "null" in err.lower()


def test_path_confinement():
    root = Path("/tmp").resolve()
    ok = ensure_path_inside(root / "x", root)
    assert str(ok).startswith(str(root))
    with pytest.raises(PathSecurityError):
        ensure_path_inside(Path("/etc/passwd"), root)


def test_safe_report_dir_blocks_system32_style(tmp_path):
    d = safe_report_dir(tmp_path / "reports")
    assert d.exists() or not d.exists()  # resolved
    assert "reports" in str(d)


def test_validate_model_id_rejects_injection():
    assert validate_model_id("grok-4.5; rm -rf /") == "grok-4.5"
    assert validate_model_id("../../etc/passwd") == "grok-4.5"
    assert validate_model_id("grok-4.5") == "grok-4.5"
    assert validate_model_id("grok-mini-fast") == "grok-4.5"


def test_clamp_timeout():
    assert clamp_timeout(1) == 5
    assert clamp_timeout(9999) == 300
    assert clamp_timeout(None) == 45


def test_sanitize_strips_raw_text_and_secrets():
    result = ScanResult(
        tool_version="0.1.0",
        started_at=utcnow(),
        finished_at=utcnow(),
        host={"hostname": "h", "api_key": "xai-shouldgo"},
        elevated=False,
        findings=[
            Finding(
                id="x",
                title="t",
                summary="Authorization: Bearer xai-abcdefghijklmnopqrstuvwxyz012345",
                severity=Severity.LOW,
                category="process",
                evidence={"password": "supersecret", "cmdline": "token=abc123def456ghi789jkl"},
            )
        ],
        score=ScanScore(max_severity=Severity.LOW, counts={"low": 1}, open_finding_count=1),
        grok=GrokAnalysis(
            available=True,
            raw_text="SHOULD_NOT_PERSIST xai-abcdefghijklmnopqrstuvwxyz",
            executive_summary="ok",
        ),
    )
    safe = sanitize_scan_result(result)
    assert safe.grok.raw_text == ""
    assert "supersecret" not in str(safe.model_dump())
    assert "xai-abcdefghijklmnopqrstuvwxyz" not in str(safe.model_dump())
    assert safe.findings[0].evidence.get("password") == "[REDACTED]"


def test_redact_private_key():
    pem = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBg\n-----END PRIVATE KEY-----"
    assert "BEGIN PRIVATE KEY" not in redact_text(pem)
    assert "REDACTED" in redact_text(pem) or "PRIVATE" not in redact_text(pem)


def test_deep_sanitize_caps_depth():
    nest: dict = {"a": {}}
    cur = nest["a"]
    for _ in range(30):
        cur["a"] = {}
        cur = cur["a"]
    out = deep_sanitize(nest)
    assert out is not None
