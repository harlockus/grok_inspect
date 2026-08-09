"""Settings loader for Grok Inspect.

API key policy:
  - Store ``XAI_API_KEY`` only in the project ``.env`` file (gitignored).
  - Never put the key in ``config/default.yaml``, code, or reports.
  - ``load_settings()`` reads ``.env`` from the project root, then uses
    ``XAI_API_KEY`` for Grok. Optional shell export still works for CI, but
    the supported operator path is project ``.env`` only.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal

from dotenv import dotenv_values, load_dotenv
from pydantic import BaseModel, Field

KeySource = Literal["env_file", "process_env", "missing"]


class ModelConfig(BaseModel):
    id: str = "grok-4.5"
    reasoning_effort: str = "high"
    temperature: float = 0.2


class ScanConfig(BaseModel):
    collector_timeout_sec: int = 45
    payload_max_chars: int = 350_000



class ReportsConfig(BaseModel):
    dir: str = "reports"


class Settings(BaseModel):
    model: ModelConfig = Field(default_factory=ModelConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)
    reports: ReportsConfig = Field(default_factory=ReportsConfig)
    api_key: str = ""
    api_key_source: KeySource = "missing"
    env_file: Path | None = None
    project_root: Path = Field(default_factory=Path.cwd)

    @property
    def grok_available(self) -> bool:
        return bool(self.api_key.strip())

    def api_key_status(self) -> str:
        """Human-safe status (never includes the key)."""
        if not self.grok_available:
            path = self.env_file or (self.project_root / ".env")
            return f"missing (set XAI_API_KEY in {path})"
        if self.api_key_source == "env_file":
            return f"loaded from {self.env_file}"
        if self.api_key_source == "process_env":
            return "loaded from process environment"
        return "missing"


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _looks_like_project(cur: Path) -> bool:
    return (cur / "pyproject.toml").is_file() or (
        cur / "config" / "default.yaml"
    ).is_file()


def find_project_root(start: Path | None = None) -> Path:
    """
    Locate the Grok Inspect project directory (where ``.env`` and config live).

    Order:
      1. ``GROK_INSPECT_ROOT`` env var
      2. Walk up from ``start`` / cwd
      3. Parent of active ``.venv`` (when using this project's virtualenv)
      4. Fall back to cwd
    """
    import sys

    env_root = os.getenv("GROK_INSPECT_ROOT", "").strip()
    if env_root:
        p = Path(env_root).expanduser().resolve()
        if p.is_dir():
            return p

    cur = (start or Path.cwd()).resolve()
    for _ in range(12):
        if _looks_like_project(cur):
            return cur
        if cur.parent == cur:
            break
        cur = cur.parent

    # If the active interpreter is .../GROK_INSPECT/.venv, use that project root
    try:
        prefix = Path(sys.prefix).resolve()
        if prefix.name in {".venv", "venv"} and _looks_like_project(prefix.parent):
            return prefix.parent
    except Exception:
        pass

    return (start or Path.cwd()).resolve()


def _strip_secret(value: str | None) -> str:
    if value is None:
        return ""
    s = str(value).strip()
    if not s:
        return ""
    # Common .env quoting: KEY="value" or KEY='value'
    if (s.startswith('"') and s.endswith('"')) or (
        s.startswith("'") and s.endswith("'")
    ):
        s = s[1:-1].strip()
    # Reject placeholder / empty-looking values
    if s.lower() in {"", "your_key_here", "changeme", "xxx", "todo"}:
        return ""
    return s


_SECRET_YAML_KEYS = frozenset(
    {
        "api_key",
        "xai_api_key",
        "apikey",
        "openai_api_key",
    }
)


def _purge_secrets_from_config_dict(data: dict[str, Any]) -> dict[str, Any]:
    """Never allow API keys to be supplied via YAML config files."""

    def walk(obj: Any) -> Any:
        if isinstance(obj, dict):
            return {
                k: walk(v)
                for k, v in obj.items()
                if str(k).lower() not in _SECRET_YAML_KEYS
            }
        if isinstance(obj, list):
            return [walk(x) for x in obj]
        return obj

    return walk(data)


def resolve_api_key(
    project_root: Path,
    *,
    env_file: Path | None = None,
) -> tuple[str, KeySource, Path]:
    """
    Resolve XAI_API_KEY with project ``.env`` as the primary storage location.

    Order:
      1. Values from project ``.env`` (``XAI_API_KEY``) — preferred / documented path
      2. Process environment (for CI / one-off exports) if .env has no key
    """
    path = (env_file or (project_root / ".env")).resolve()
    file_key = ""
    if path.is_file():
        # Parse file without mutating process env first (source of truth for storage)
        values = dotenv_values(path)
        file_key = _strip_secret(values.get("XAI_API_KEY"))
        # Load into process env so child tools / SDK helpers that read os.environ work
        # override=False: do not clobber an explicit shell export unless .env has the key
        # If .env has a key, we force-load it so the file is authoritative for this app.
        load_dotenv(path, override=bool(file_key))
        if file_key:
            # Ensure process env matches file when file is authoritative
            os.environ["XAI_API_KEY"] = file_key
            return file_key, "env_file", path

    # Fall back: process env only (not stored on disk by us)
    proc_key = _strip_secret(os.environ.get("XAI_API_KEY"))
    if proc_key:
        return proc_key, "process_env", path

    return "", "missing", path


def load_settings(
    project_root: Path | None = None,
    config_path: Path | None = None,
    env_file: Path | None = None,
) -> Settings:
    root = (
        find_project_root(project_root)
        if project_root is None
        else project_root.resolve()
    )
    data: dict[str, Any] = {}
    cfg_file = config_path or (root / "config" / "default.yaml")
    if cfg_file.is_file():
        try:
            from grok_inspect.security.safe_io import load_yaml_file

            loaded = load_yaml_file(cfg_file, max_bytes=256_000)
            data = _purge_secrets_from_config_dict(loaded)
        except Exception:
            # Fall back to empty defaults rather than crash on bad config
            data = {}


    # Model id may come from .env as well (non-secret)
    env_path = (env_file or (root / ".env")).resolve()
    if env_path.is_file():
        env_vals = dotenv_values(env_path)
        model_from_env = _strip_secret(
            env_vals.get("XAI_MODEL") or env_vals.get("GROK_INSPECT_MODEL")
        )
        if model_from_env:
            data = _deep_merge(data, {"model": {"id": model_from_env}})
        # Also load non-secret model overrides into os.environ for consistency
        load_dotenv(env_path, override=False)

    model_id = _strip_secret(
        os.getenv("XAI_MODEL") or os.getenv("GROK_INSPECT_MODEL")
    )
    if model_id:
        data = _deep_merge(data, {"model": {"id": model_id}})

    api_key, key_source, resolved_env = resolve_api_key(root, env_file=env_file)

    from grok_inspect.security.sanitize import clamp_timeout, validate_model_id

    # Validate / normalize model id from any source
    if isinstance(data.get("model"), dict) and data["model"].get("id"):
        data["model"]["id"] = validate_model_id(str(data["model"]["id"]))
    if isinstance(data.get("scan"), dict) and "collector_timeout_sec" in data["scan"]:
        data["scan"]["collector_timeout_sec"] = clamp_timeout(
            data["scan"]["collector_timeout_sec"]
        )

    settings = Settings.model_validate(
        {
            **data,
            "project_root": root,
            "api_key": api_key,
            "api_key_source": key_source,
            "env_file": resolved_env,
        }
    )
    settings.model.id = validate_model_id(settings.model.id)
    settings.scan.collector_timeout_sec = clamp_timeout(
        settings.scan.collector_timeout_sec
    )
    # Cap Grok payload size (allow comprehensive packages; still hard-capped)
    settings.scan.payload_max_chars = max(
        20_000, min(int(settings.scan.payload_max_chars or 350_000), 500_000)
    )

    if not settings.model.reasoning_effort:
        settings.model.reasoning_effort = "high"
    if settings.model.reasoning_effort.lower() not in {"high", "medium", "low"}:
        settings.model.reasoning_effort = "high"
    # Force high for analysis policy
    settings.model.reasoning_effort = "high"
    return settings

