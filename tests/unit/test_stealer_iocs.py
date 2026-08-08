from pathlib import Path

from grok_inspect.collectors.stealer_indicators import load_iocs, path_matches_ioc


def test_path_ioc():
    root = Path(__file__).resolve().parents[2]
    iocs = load_iocs(root / "data" / "stealer_iocs.yaml")
    assert path_matches_ioc("/tmp/redline/payload.exe", iocs)
