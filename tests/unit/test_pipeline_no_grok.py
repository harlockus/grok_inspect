from pathlib import Path

from grok_inspect.config import load_settings
from grok_inspect.pipeline import run_scan


def test_run_scan_no_grok(tmp_path: Path):
    root = Path(__file__).resolve().parents[2]
    settings = load_settings(project_root=root)
    # Keep scan faster in CI
    settings.scan.collector_timeout_sec = 20
    result = run_scan(
        settings, use_grok=False, out_dir=tmp_path, verbose=False
    )
    assert result.finished_at >= result.started_at
    assert (tmp_path / "latest.json").exists()
    assert result.grok.available is False
    assert len(result.coverage) >= 1
