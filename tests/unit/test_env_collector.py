from grok_inspect.collectors.base import CollectorContext
from grok_inspect.collectors.env import collect_env


def test_collect_env_includes_host():
    ctx = CollectorContext(
        host={"os_family": "darwin", "elevated": False, "hostname": "t"}
    )
    ev = collect_env(ctx)
    assert "host" in ev
