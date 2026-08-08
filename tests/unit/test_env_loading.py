"""API key must load from project .env and never from YAML."""

from pathlib import Path

from grok_inspect.config import load_settings, resolve_api_key


def test_api_key_from_dotenv_file(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("XAI_API_KEY", raising=False)
    (tmp_path / "pyproject.toml").write_text("[project]\nname='t'\n", encoding="utf-8")
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "default.yaml").write_text(
        "model:\n  id: grok-4.5\n  reasoning_effort: high\n",
        encoding="utf-8",
    )
    (tmp_path / ".env").write_text(
        'XAI_API_KEY="xai-testkeyfromdotenvfile123456"\n',
        encoding="utf-8",
    )
    settings = load_settings(project_root=tmp_path)
    assert settings.grok_available
    assert settings.api_key == "xai-testkeyfromdotenvfile123456"
    assert settings.api_key_source == "env_file"
    assert settings.env_file == (tmp_path / ".env").resolve()
    assert "dotenv" in settings.api_key_status() or str(tmp_path) in settings.api_key_status()


def test_yaml_cannot_supply_api_key(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("XAI_API_KEY", raising=False)
    (tmp_path / "pyproject.toml").write_text("[project]\nname='t'\n", encoding="utf-8")
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "default.yaml").write_text(
        "model:\n  id: grok-4.5\napi_key: xai-should-be-ignored\n"
        "xai_api_key: xai-also-ignored\n",
        encoding="utf-8",
    )
    settings = load_settings(project_root=tmp_path)
    assert settings.api_key == ""
    assert settings.api_key_source == "missing"
    assert not settings.grok_available


def test_env_file_overrides_process_env(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("XAI_API_KEY", "xai-from-shell-should-lose")
    (tmp_path / "pyproject.toml").write_text("[project]\nname='t'\n", encoding="utf-8")
    (tmp_path / ".env").write_text(
        "XAI_API_KEY=xai-from-dotenv-wins\n",
        encoding="utf-8",
    )
    key, source, path = resolve_api_key(tmp_path)
    assert key == "xai-from-dotenv-wins"
    assert source == "env_file"
    assert path == (tmp_path / ".env").resolve()


def test_placeholder_key_rejected(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("XAI_API_KEY", raising=False)
    (tmp_path / "pyproject.toml").write_text("[project]\nname='t'\n", encoding="utf-8")
    (tmp_path / ".env").write_text("XAI_API_KEY=your_key_here\n", encoding="utf-8")
    settings = load_settings(project_root=tmp_path)
    assert not settings.grok_available
