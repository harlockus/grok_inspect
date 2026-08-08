import json
from pathlib import Path

from grok_inspect.heuristics.engine import run_heuristics
from grok_inspect.models import CollectorResult, CollectorStatus, ScanBundle, utcnow


def test_promisc_and_tcpdump_findings():
    raw = json.loads(
        Path("tests/fixtures/evidence/minimal_bundle.json").read_text(encoding="utf-8")
    )
    bundle = ScanBundle(
        started_at=utcnow(),
        host=raw["host"],
        elevated=raw["elevated"],
        results=[
            CollectorResult(
                name=r["name"],
                status=CollectorStatus(r["status"]),
                evidence=r["evidence"],
            )
            for r in raw["results"]
        ],
    )
    findings = run_heuristics(bundle)
    ids = {f.id for f in findings}
    assert "sniff.promisc_iface" in ids
    assert "sniff.capture_process" in ids
