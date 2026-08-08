import time

from grok_inspect.collectors.base import CollectorContext, run_collector
from grok_inspect.models import CollectorStatus


def test_run_collector_success():
    def coll(ctx: CollectorContext):
        return {"ok": True}

    r = run_collector(
        "demo", coll, CollectorContext(host={"elevated": False}, timeout_sec=5)
    )
    assert r.name == "demo"
    assert r.status == CollectorStatus.FULL
    assert r.evidence["ok"] is True


def test_run_collector_timeout():
    def coll(ctx: CollectorContext):
        time.sleep(2)
        return {}

    r = run_collector(
        "slow", coll, CollectorContext(host={}, timeout_sec=0.2)
    )
    assert r.status == CollectorStatus.ERROR
    assert r.error and "timeout" in r.error.lower()
