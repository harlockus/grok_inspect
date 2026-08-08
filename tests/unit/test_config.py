from pathlib import Path

from grok_inspect.config import load_settings


def test_default_model_is_flagship(monkeypatch):
    monkeypatch.delenv("XAI_API_KEY", raising=False)
    monkeypatch.delenv("XAI_MODEL", raising=False)
    monkeypatch.delenv("GROK_INSPECT_MODEL", raising=False)
    root = Path(__file__).resolve().parents[2]
    cfg = load_settings(project_root=root)
    assert cfg.model.id == "grok-4.5"
    assert cfg.model.reasoning_effort == "high"
    # Real project may or may not have .env; status string must never include a raw key
    status = cfg.api_key_status()
    assert "xai-" not in status or status.startswith("loaded")

