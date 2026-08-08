from grok_inspect.models import Finding, ScanScore, Severity


def test_finding_defaults():
    f = Finding(
        id="sniff.promisc_iface",
        title="Promiscuous interface",
        summary="en0 is in promiscuous mode",
        severity=Severity.HIGH,
        category="sniffing",
        evidence={"iface": "en0"},
        confidence=0.9,
    )
    assert f.requires_elevated is False
    assert f.remediation_hint == ""


def test_scan_score_from_findings():
    findings = [
        Finding(
            id="a",
            title="a",
            summary="a",
            severity=Severity.INFO,
            category="coverage",
            evidence={},
            confidence=1.0,
        ),
        Finding(
            id="b",
            title="b",
            summary="b",
            severity=Severity.CRITICAL,
            category="stealer",
            evidence={},
            confidence=0.8,
        ),
    ]
    score = ScanScore.from_findings(findings)
    assert score.max_severity == Severity.CRITICAL
    assert score.counts["critical"] == 1
