from grok_inspect.platform import probe_host


def test_probe_host_has_os_family():
    h = probe_host()
    assert h["os_family"] in {"darwin", "linux", "windows"}
    assert "elevated" in h
    assert isinstance(h["elevated"], bool)
    assert h["hostname"]
