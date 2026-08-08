from grok_inspect.collectors.process import looks_like_encoded_powershell


def test_encoded_powershell():
    cmd = "powershell -enc " + ("A" * 50)
    assert looks_like_encoded_powershell(cmd)
