from grok_inspect.collectors.sniff_surface import match_capture_processes


def test_match_capture_processes():
    assert "tcpdump" in match_capture_processes(["tcpdump", "Safari"])
