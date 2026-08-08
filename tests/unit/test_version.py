from grok_inspect import __version__


def test_version_semver_shape():
    parts = __version__.split(".")
    assert len(parts) == 3
    assert all(p.isdigit() for p in parts)
