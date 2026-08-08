# Grok Inspect v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `grok-inspect`, a cross-platform manual CLI that comprehensively inspects a host for sniffing/info-stealing indicators, scores findings with heuristics, analyzes via Grok 4.5 (`xai-sdk`, `reasoning_effort=high`) on redacted evidence, and writes CLI + Markdown + JSON + HTML reports.

**Architecture:** Modular Python package: OS-aware collectors → deterministic heuristic engine → mandatory redactor → SpaceXAI `xai-sdk` Grok analyst → report pack. Prefer elevated privileges; degrade gracefully with coverage findings. Spec: `docs/superpowers/specs/2026-08-08-grok-inspect-design.md`.

**Tech Stack:** Python ≥3.11, `xai-sdk`, typer, rich, pydantic, pydantic-settings, PyYAML, python-dotenv, Jinja2, pytest.

**Working directory:** `/Users/harlock/Documents/AI_PROJECTS/GROK_INSPECT`

---

## File structure (create)

| Path | Responsibility |
|------|----------------|
| `pyproject.toml` | Package metadata, deps, entry point `grok-inspect` |
| `.gitignore` | venv, reports, `.env`, caches |
| `.env.example` | `XAI_API_KEY=` |
| `config/default.yaml` | Model + scan defaults |
| `data/stealer_iocs.yaml` | Path/name IoC patterns |
| `data/allowlist.example.yaml` | Example suppressions |
| `src/grok_inspect/__init__.py` | Version |
| `src/grok_inspect/__main__.py` | `python -m grok_inspect` |
| `src/grok_inspect/models.py` | Pydantic models |
| `src/grok_inspect/config.py` | Settings loader |
| `src/grok_inspect/platform.py` | OS + privilege probe |
| `src/grok_inspect/pipeline.py` | End-to-end scan orchestration |
| `src/grok_inspect/cli.py` | Typer CLI |
| `src/grok_inspect/collectors/base.py` | Protocol, runner, timeouts |
| `src/grok_inspect/collectors/*.py` | Collectors A–K + coverage |
| `src/grok_inspect/heuristics/engine.py` | Rule runner |
| `src/grok_inspect/heuristics/rules_*.py` | Rule packs |
| `src/grok_inspect/security/redact.py` | Redaction + payload build |
| `src/grok_inspect/agent/grok.py` | `xai_sdk` client |
| `src/grok_inspect/agent/prompts.py` | System + user prompts |
| `src/grok_inspect/report/*` | Terminal, md, json, html |
| `tests/unit/*` | Unit tests |
| `tests/fixtures/evidence/*` | Canned bundles |
| `README.md`, `SECURITY.md`, `LICENSE` | Docs |

---

### Task 1: Project scaffold

**Files:**
- Create: `pyproject.toml`, `.gitignore`, `.env.example`, `config/default.yaml`
- Create: `src/grok_inspect/__init__.py`, `src/grok_inspect/__main__.py`
- Create: `tests/unit/test_version.py`

- [ ] **Step 1: Create `.gitignore`**

```gitignore
.venv/
__pycache__/
*.py[cod]
.pytest_cache/
.mypy_cache/
.ruff_cache/
*.egg-info/
dist/
build/
.env
reports/
*.pcap
.DS_Store
```

- [ ] **Step 2: Create `pyproject.toml`**

```toml
[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "grok-inspect"
version = "0.1.0"
description = "Cross-platform host inspection agent for sniffing and info-stealing detection with Grok 4.5 analysis"
readme = "README.md"
requires-python = ">=3.11"
license = { text = "MIT" }
authors = [{ name = "Grok Inspect" }]
dependencies = [
  "xai-sdk>=1.0.0",
  "typer>=0.12.0",
  "rich>=13.7.0",
  "pydantic>=2.7.0",
  "pydantic-settings>=2.3.0",
  "PyYAML>=6.0.1",
  "python-dotenv>=1.0.1",
  "Jinja2>=3.1.4",
]

[project.optional-dependencies]
dev = ["pytest>=8.2.0"]

[project.scripts]
grok-inspect = "grok_inspect.cli:app"

[tool.setuptools.packages.find]
where = ["src"]

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["src"]
```

- [ ] **Step 3: Create package stubs**

`src/grok_inspect/__init__.py`:

```python
"""Grok Inspect — host sniffing / stealer inspection agent."""

__version__ = "0.1.0"
```

`src/grok_inspect/__main__.py`:

```python
from grok_inspect.cli import app

if __name__ == "__main__":
    app()
```

Temporary `src/grok_inspect/cli.py` (expanded in Task 14):

```python
import typer

app = typer.Typer(name="grok-inspect", help="Host inspection agent", no_args_is_help=True)

@app.callback()
def main() -> None:
    """Grok Inspect CLI."""

@app.command("version")
def version_cmd() -> None:
    from grok_inspect import __version__
    typer.echo(f"grok-inspect {__version__}")
```

`.env.example`:

```
XAI_API_KEY=
# Optional flagship override (default grok-4.5):
# XAI_MODEL=grok-4.5
```

`config/default.yaml`:

```yaml
model:
  id: grok-4.5
  reasoning_effort: high
  temperature: 0.2

scan:
  collector_timeout_sec: 45
  payload_max_chars: 150000

reports:
  dir: reports
```

- [ ] **Step 4: Write version test**

`tests/unit/test_version.py`:

```python
from grok_inspect import __version__

def test_version_semver_shape():
    parts = __version__.split(".")
    assert len(parts) == 3
    assert all(p.isdigit() for p in parts)
```

- [ ] **Step 5: Install editable and run test**

```bash
cd /Users/harlock/Documents/AI_PROJECTS/GROK_INSPECT
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest tests/unit/test_version.py -v
grok-inspect version
```

Expected: tests PASS; CLI prints `grok-inspect 0.1.0`

- [ ] **Step 6: Commit** (if git repo exists / user wants commits)

```bash
git add pyproject.toml .gitignore .env.example config/default.yaml src tests
git commit -m "chore: scaffold grok-inspect package"
```

---

### Task 2: Core models

**Files:**
- Create: `src/grok_inspect/models.py`
- Create: `tests/unit/test_models.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/unit/test_models.py
from grok_inspect.models import (
    CollectorStatus,
    CoverageEntry,
    Finding,
    Severity,
    ScanScore,
    ScanResult,
)

def test_finding_defaults():
    f = Finding(
        id="sniff.promisc_iface",
        title="Promiscuous interface",
        summary="en0 is in promiscuous mode",
        severity=Severity.HIGH,
        category="sniffing",
        evidence={"iface": "en0"},
        confidence=0.9,
    )
    assert f.requires_elevated is False
    assert f.remediation_hint == ""

def test_scan_score_from_findings():
    findings = [
        Finding(id="a", title="a", summary="a", severity=Severity.INFO, category="coverage", evidence={}, confidence=1.0),
        Finding(id="b", title="b", summary="b", severity=Severity.CRITICAL, category="stealer", evidence={}, confidence=0.8),
    ]
    score = ScanScore.from_findings(findings)
    assert score.max_severity == Severity.CRITICAL
    assert score.counts["critical"] == 1
```

- [ ] **Step 2: Run tests — expect FAIL**

```bash
pytest tests/unit/test_models.py -v
```

- [ ] **Step 3: Implement models**

```python
# src/grok_inspect/models.py
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]


class CollectorStatus(str, Enum):
    FULL = "full"
    LIMITED = "limited"
    SKIPPED = "skipped"
    ERROR = "error"


class Finding(BaseModel):
    id: str
    title: str
    summary: str
    severity: Severity
    category: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    confidence: float = 1.0
    remediation_hint: str = ""
    os: str | None = None
    requires_elevated: bool = False
    acknowledged: bool = False  # allowlist suppressed from open risk


class CoverageEntry(BaseModel):
    collector: str
    status: CollectorStatus
    detail: str = ""
    requires_elevated: bool = False


class CollectorResult(BaseModel):
    name: str
    status: CollectorStatus
    evidence: dict[str, Any] = Field(default_factory=dict)
    detail: str = ""
    error: str | None = None


class ScanBundle(BaseModel):
    """Raw collector outputs before heuristics."""

    started_at: datetime
    host: dict[str, Any] = Field(default_factory=dict)
    elevated: bool = False
    results: list[CollectorResult] = Field(default_factory=list)


class ScanScore(BaseModel):
    max_severity: Severity = Severity.INFO
    counts: dict[str, int] = Field(default_factory=dict)
    open_finding_count: int = 0

    @classmethod
    def from_findings(cls, findings: list[Finding]) -> ScanScore:
        open_f = [f for f in findings if not f.acknowledged]
        counts = {s.value: 0 for s in Severity}
        max_sev = Severity.INFO
        for f in open_f:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
            if f.severity.rank > max_sev.rank:
                max_sev = f.severity
        return cls(max_severity=max_sev, counts=counts, open_finding_count=len(open_f))


class GrokAnalysis(BaseModel):
    available: bool = False
    model_id: str | None = None
    reasoning_effort: str | None = None
    executive_summary: str = ""
    threat_narrative: str = ""
    prioritized_findings: list[dict[str, Any]] = Field(default_factory=list)
    likely_attacker_goals: list[str] = Field(default_factory=list)
    remediation_plan: list[str] = Field(default_factory=list)
    questions_for_operator: list[str] = Field(default_factory=list)
    confidence: float | None = None
    latency_s: float | None = None
    usage_summary: str = ""
    error: str | None = None
    raw_text: str = ""


class ScanResult(BaseModel):
    version: str = "1"
    tool_version: str
    started_at: datetime
    finished_at: datetime
    host: dict[str, Any] = Field(default_factory=dict)
    elevated: bool = False
    coverage: list[CoverageEntry] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    score: ScanScore = Field(default_factory=ScanScore)
    grok: GrokAnalysis = Field(default_factory=GrokAnalysis)
    bundle_summary: dict[str, Any] = Field(default_factory=dict)

    def exit_code(self) -> int:
        if self.score.max_severity == Severity.CRITICAL:
            return 3
        if self.score.max_severity.rank >= Severity.MEDIUM.rank:
            return 1
        return 0


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
```

- [ ] **Step 4: Run tests — expect PASS**

```bash
pytest tests/unit/test_models.py -v
```

- [ ] **Step 5: Commit**

```bash
git add src/grok_inspect/models.py tests/unit/test_models.py
git commit -m "feat: add core scan models"
```

---

### Task 3: Config loader

**Files:**
- Create: `src/grok_inspect/config.py`
- Create: `tests/unit/test_config.py`

- [ ] **Step 1: Write failing test**

```python
# tests/unit/test_config.py
from pathlib import Path
from grok_inspect.config import load_settings

def test_default_model_is_flagship(tmp_path, monkeypatch):
    monkeypatch.delenv("XAI_API_KEY", raising=False)
    monkeypatch.delenv("XAI_MODEL", raising=False)
    cfg = load_settings(project_root=Path(__file__).resolve().parents[2])
    assert cfg.model.id == "grok-4.5"
    assert cfg.model.reasoning_effort == "high"
```

- [ ] **Step 2: Implement config**

```python
# src/grok_inspect/config.py
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, Field


class ModelConfig(BaseModel):
    id: str = "grok-4.5"
    reasoning_effort: str = "high"
    temperature: float = 0.2


class ScanConfig(BaseModel):
    collector_timeout_sec: int = 45
    payload_max_chars: int = 150_000


class ReportsConfig(BaseModel):
    dir: str = "reports"


class Settings(BaseModel):
    model: ModelConfig = Field(default_factory=ModelConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)
    reports: ReportsConfig = Field(default_factory=ReportsConfig)
    api_key: str = ""
    project_root: Path = Field(default_factory=Path.cwd)

    @property
    def grok_available(self) -> bool:
        return bool(self.api_key.strip())


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_settings(
    project_root: Path | None = None,
    config_path: Path | None = None,
) -> Settings:
    root = (project_root or Path.cwd()).resolve()
    load_dotenv(root / ".env")
    data: dict[str, Any] = {}
    cfg_file = config_path or (root / "config" / "default.yaml")
    if cfg_file.is_file():
        with cfg_file.open(encoding="utf-8") as f:
            loaded = yaml.safe_load(f) or {}
        if isinstance(loaded, dict):
            data = loaded
    model_id = os.getenv("XAI_MODEL") or os.getenv("GROK_INSPECT_MODEL")
    if model_id:
        data = _deep_merge(data, {"model": {"id": model_id.strip()}})
    settings = Settings.model_validate({**data, "project_root": root})
    settings.api_key = os.getenv("XAI_API_KEY", "") or ""
    # Enforce max-capability defaults if misconfigured empty
    if not settings.model.reasoning_effort:
        settings.model.reasoning_effort = "high"
    return settings
```

- [ ] **Step 3: Run tests**

```bash
pytest tests/unit/test_config.py -v
```

- [ ] **Step 4: Commit**

```bash
git add src/grok_inspect/config.py tests/unit/test_config.py
git commit -m "feat: add settings loader with grok-4.5 defaults"
```

---

### Task 4: Platform probe

**Files:**
- Create: `src/grok_inspect/platform.py`
- Create: `tests/unit/test_platform.py`

- [ ] **Step 1: Write tests (no root required)**

```python
# tests/unit/test_platform.py
from grok_inspect.platform import probe_host

def test_probe_host_has_os_family():
    h = probe_host()
    assert h["os_family"] in {"darwin", "linux", "windows"}
    assert "elevated" in h
    assert isinstance(h["elevated"], bool)
    assert h["hostname"]
```

- [ ] **Step 2: Implement platform probe**

```python
# src/grok_inspect/platform.py
from __future__ import annotations

import os
import platform
import sys
from typing import Any


def os_family() -> str:
    s = sys.platform
    if s.startswith("darwin"):
        return "darwin"
    if s.startswith("win"):
        return "windows"
    if s.startswith("linux"):
        return "linux"
    return s


def is_elevated() -> bool:
    family = os_family()
    if family == "windows":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            return False
    try:
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except AttributeError:
        return False


def probe_host() -> dict[str, Any]:
    return {
        "os_family": os_family(),
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "hostname": platform.node(),
        "python": platform.python_version(),
        "username": os.environ.get("USER") or os.environ.get("USERNAME") or "",
        "elevated": is_elevated(),
    }
```

- [ ] **Step 3: Run tests**

```bash
pytest tests/unit/test_platform.py -v
```

- [ ] **Step 4: Commit**

```bash
git add src/grok_inspect/platform.py tests/unit/test_platform.py
git commit -m "feat: add OS and privilege probe"
```

---

### Task 5: Collector base + runner

**Files:**
- Create: `src/grok_inspect/collectors/__init__.py`
- Create: `src/grok_inspect/collectors/base.py`
- Create: `tests/unit/test_collector_base.py`

- [ ] **Step 1: Write tests**

```python
# tests/unit/test_collector_base.py
import time
from grok_inspect.collectors.base import CollectorContext, run_collector
from grok_inspect.models import CollectorStatus

def test_run_collector_success():
    def coll(ctx: CollectorContext):
        return {"ok": True}

    r = run_collector("demo", coll, CollectorContext(host={"elevated": False}, timeout_sec=5))
    assert r.name == "demo"
    assert r.status == CollectorStatus.FULL
    assert r.evidence["ok"] is True

def test_run_collector_timeout():
    def coll(ctx: CollectorContext):
        time.sleep(2)
        return {}

    r = run_collector("slow", coll, CollectorContext(host={}, timeout_sec=0.2))
    assert r.status == CollectorStatus.ERROR
    assert r.error and "timeout" in r.error.lower()
```

- [ ] **Step 2: Implement base runner**

Use a thread + join timeout (cross-platform, no signals):

```python
# src/grok_inspect/collectors/base.py
from __future__ import annotations

import traceback
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

from grok_inspect.models import CollectorResult, CollectorStatus


@dataclass
class CollectorContext:
    host: dict[str, Any]
    timeout_sec: float = 45.0
    project_root: Any = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def elevated(self) -> bool:
        return bool(self.host.get("elevated"))

    @property
    def os_family(self) -> str:
        return str(self.host.get("os_family", ""))


CollectorFn = Callable[[CollectorContext], dict[str, Any] | CollectorResult]


class Collector(Protocol):
    name: str

    def collect(self, ctx: CollectorContext) -> dict[str, Any] | CollectorResult: ...


def run_collector(name: str, fn: CollectorFn, ctx: CollectorContext) -> CollectorResult:
    def _call() -> CollectorResult:
        try:
            out = fn(ctx)
            if isinstance(out, CollectorResult):
                return out
            status = CollectorStatus.FULL
            if isinstance(out, dict) and out.get("_status"):
                status = CollectorStatus(out.pop("_status"))
            detail = ""
            if isinstance(out, dict) and "_detail" in out:
                detail = str(out.pop("_detail") or "")
            return CollectorResult(name=name, status=status, evidence=out or {}, detail=detail)
        except Exception as exc:
            return CollectorResult(
                name=name,
                status=CollectorStatus.ERROR,
                evidence={},
                error=f"{type(exc).__name__}: {exc}",
                detail=traceback.format_exc()[-500:],
            )

    with ThreadPoolExecutor(max_workers=1) as pool:
        fut = pool.submit(_call)
        try:
            return fut.result(timeout=ctx.timeout_sec)
        except FuturesTimeout:
            return CollectorResult(
                name=name,
                status=CollectorStatus.ERROR,
                error=f"timeout after {ctx.timeout_sec}s",
            )
```

`src/grok_inspect/collectors/__init__.py`:

```python
"""Host evidence collectors."""
```

- [ ] **Step 3: Run tests**

```bash
pytest tests/unit/test_collector_base.py -v
```

- [ ] **Step 4: Commit**

```bash
git add src/grok_inspect/collectors tests/unit/test_collector_base.py
git commit -m "feat: collector protocol and timeout runner"
```

---

### Task 6: Env + coverage collectors + subprocess helper

**Files:**
- Create: `src/grok_inspect/collectors/subprocess_util.py`
- Create: `src/grok_inspect/collectors/env.py`
- Create: `src/grok_inspect/collectors/coverage.py`
- Create: `tests/unit/test_env_collector.py`

- [ ] **Step 1: Implement safe subprocess helper**

```python
# src/grok_inspect/collectors/subprocess_util.py
from __future__ import annotations

import subprocess
from typing import Sequence


def run_cmd(
    args: Sequence[str],
    *,
    timeout: float = 30.0,
    text: bool = True,
) -> tuple[int, str, str]:
    """Run command without shell. Returns (rc, stdout, stderr)."""
    try:
        p = subprocess.run(
            list(args),
            capture_output=True,
            text=text,
            timeout=timeout,
            check=False,
        )
        return p.returncode, p.stdout or "", p.stderr or ""
    except FileNotFoundError:
        return 127, "", f"not found: {args[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
```

- [ ] **Step 2: Env collector**

```python
# src/grok_inspect/collectors/env.py
from __future__ import annotations

from grok_inspect.collectors.base import CollectorContext
from grok_inspect.collectors.subprocess_util import run_cmd


def collect_env(ctx: CollectorContext) -> dict:
    evidence = {
        "host": dict(ctx.host),
        "proxy_env": {
            k: bool(v)
            for k, v in {
                "HTTP_PROXY": __import__("os").environ.get("HTTP_PROXY"),
                "HTTPS_PROXY": __import__("os").environ.get("HTTPS_PROXY"),
                "ALL_PROXY": __import__("os").environ.get("ALL_PROXY"),
                "http_proxy": __import__("os").environ.get("http_proxy"),
                "https_proxy": __import__("os").environ.get("https_proxy"),
            }.items()
            if v
        },
    }
    # Best-effort security posture flags
    family = ctx.os_family
    if family == "darwin":
        rc, out, _ = run_cmd(["csrutil", "status"], timeout=10)
        evidence["sip_status"] = out.strip() if rc == 0 else "unknown"
    elif family == "linux":
        rc, out, _ = run_cmd(["getenforce"], timeout=5)
        if rc == 0:
            evidence["selinux"] = out.strip()
    elif family == "windows":
        evidence["note"] = "windows_env_probe"
    evidence["_status"] = "full"
    return evidence
```

- [ ] **Step 3: Coverage synthesizer** (runs after all collectors)

```python
# src/grok_inspect/collectors/coverage.py
from __future__ import annotations

from grok_inspect.models import CollectorResult, CollectorStatus, CoverageEntry, Finding, Severity


def build_coverage(results: list[CollectorResult], elevated: bool, os_family: str) -> tuple[list[CoverageEntry], list[Finding]]:
    entries: list[CoverageEntry] = []
    findings: list[Finding] = []
    for r in results:
        entries.append(
            CoverageEntry(
                collector=r.name,
                status=r.status,
                detail=r.detail or (r.error or ""),
                requires_elevated=False,
            )
        )
        if r.status in (CollectorStatus.LIMITED, CollectorStatus.SKIPPED, CollectorStatus.ERROR):
            findings.append(
                Finding(
                    id=f"coverage.{r.name}.{r.status.value}",
                    title=f"Collector {r.name}: {r.status.value}",
                    summary=r.error or r.detail or f"{r.name} did not run at full depth",
                    severity=Severity.INFO,
                    category="coverage",
                    evidence={"collector": r.name, "status": r.status.value},
                    confidence=1.0,
                    remediation_hint=(
                        "Re-run elevated (sudo / Administrator) for deeper coverage"
                        if not elevated
                        else "Check missing OS tools or permissions"
                    ),
                    os=os_family,
                )
            )
    if not elevated:
        findings.append(
            Finding(
                id="coverage.not_elevated",
                title="Scan not elevated",
                summary="Running without admin/root; some collectors are limited",
                severity=Severity.INFO,
                category="coverage",
                evidence={"elevated": False},
                confidence=1.0,
                remediation_hint="Re-run as root/Administrator for full comprehensive scan",
                os=os_family,
            )
        )
    return entries, findings
```

- [ ] **Step 4: Test env collector**

```python
# tests/unit/test_env_collector.py
from grok_inspect.collectors.base import CollectorContext
from grok_inspect.collectors.env import collect_env

def test_collect_env_includes_host():
    ctx = CollectorContext(host={"os_family": "darwin", "elevated": False, "hostname": "t"})
    ev = collect_env(ctx)
    assert "host" in ev
```

```bash
pytest tests/unit/test_env_collector.py -v
```

- [ ] **Step 5: Commit**

```bash
git add src/grok_inspect/collectors tests/unit/test_env_collector.py
git commit -m "feat: env collector and coverage synthesis"
```

---

### Task 7: Network + sniff surface collectors

**Files:**
- Create: `src/grok_inspect/collectors/network.py`
- Create: `src/grok_inspect/collectors/sniff_surface.py`
- Create: `tests/unit/test_sniff_heuristics_input.py` (fixture-shaped evidence)

- [ ] **Step 1: Network collector (OS branches)**

Implement `collect_network(ctx)` that populates evidence keys (best-effort):

- `listeners`: list of `{proto, local, pid, process?}`
- `connections_sample`: up to 100 established non-local
- `interfaces`: name, flags, promisc if detectable
- `routes_default`: default gateway lines
- `hosts_file_suspicious`: non-comment lines that are not localhost
- `proxy`: system proxy best-effort

**macOS:** `lsof -nP -iTCP -sTCP:LISTEN`, `netstat -rn`, `ifconfig`, read `/etc/hosts`  
**Linux:** `ss -lptn`, `ss -tpn`, `ip -j link` or `ip link`, `ip route`, `/etc/hosts`  
**Windows:** `powershell -NoProfile -Command` with `Get-NetTCPConnection` (argument list, not shell string concatenation of user input)

Mark `_status` = `limited` if key commands missing or not elevated for PID ownership.

- [ ] **Step 2: Sniff surface collector**

```python
# Core idea in sniff_surface.py
CAPTURE_PROCESS_NAMES = {
    "tcpdump", "tshark", "dumpcap", "wireshark", "mitmproxy", "mitmdump",
    "charles", "fiddler", "bettercap", "ettercap", "npcap", "rawcap",
}
# Scan process list (from ps / tasklist) for name matches
# Check /dev/bpf* on darwin, npcap service on windows
# Note installed root CAs only as paths/counts — not private keys
```

Evidence keys: `capture_processes`, `capture_binaries_in_path`, `bpf_devices`, `promisc_interfaces`, `extra_root_cas_hint`

- [ ] **Step 3: Unit test with pure function for name matching**

Extract helper:

```python
def match_capture_processes(process_names: list[str]) -> list[str]:
    lower = {p.lower() for p in CAPTURE_PROCESS_NAMES}
    return sorted({n for n in process_names if n.lower() in lower or any(c in n.lower() for c in lower)})
```

```python
def test_match_capture_processes():
    from grok_inspect.collectors.sniff_surface import match_capture_processes
    assert "tcpdump" in match_capture_processes(["tcpdump", "Safari"])
```

- [ ] **Step 4: Commit**

```bash
git commit -m "feat: network and sniff surface collectors"
```

---

### Task 8: Process + persistence + stealer collectors

**Files:**
- Create: `src/grok_inspect/collectors/process.py`
- Create: `src/grok_inspect/collectors/persistence.py`
- Create: `src/grok_inspect/collectors/stealer_indicators.py`
- Create: `data/stealer_iocs.yaml`
- Create: `tests/unit/test_process_patterns.py`
- Create: `tests/unit/test_stealer_iocs.py`

- [ ] **Step 1: `data/stealer_iocs.yaml`**

```yaml
version: 1
path_substrings:
  - "stealers"
  - "racoon"
  - "redline"
  - "vidar"
  - "lumma"
  - "metastealer"
process_names:
  - "stealer"
  - "clipper"
suspicious_cmdline_regex:
  - '(?i)powershell.*-enc\s+[A-Za-z0-9+/=]{40,}'
  - '(?i)(curl|wget).*\|\s*(sh|bash|powershell)'
```

- [ ] **Step 2: Process collector**

Collect processes: pid, ppid, user, name, path, cmdline (truncate 500 chars).  
Detect LOLBin patterns via regex from IoC file.  
Detect system binary names from non-system paths (OS-specific prefixes).

- [ ] **Step 3: Persistence collector**

| OS | Paths / sources |
|----|-----------------|
| darwin | `~/Library/LaunchAgents`, `/Library/LaunchAgents`, `/Library/LaunchDaemons`, crontab |
| linux | `~/.config/systemd/user`, `/etc/systemd/system`, crontab, `~/.config/autostart`, `/etc/ld.so.preload` if exists |
| windows | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` via `reg query`, Startup folder |

Evidence: list of persistence items with path, command, mtime if available.

- [ ] **Step 4: Stealer indicators**

Load `data/stealer_iocs.yaml`. Match paths and process names. Check browser profile dirs exist; if `lsof`/`handle` available, note non-browser PIDs (best-effort). Never open cookie DBs.

- [ ] **Step 5: Tests**

```python
# tests/unit/test_process_patterns.py
from grok_inspect.collectors.process import looks_like_encoded_powershell

def test_encoded_powershell():
    cmd = "powershell -enc " + ("A" * 50)
    assert looks_like_encoded_powershell(cmd)
```

```python
# tests/unit/test_stealer_iocs.py
from pathlib import Path
from grok_inspect.collectors.stealer_indicators import load_iocs, path_matches_ioc

def test_path_ioc(project_root=None):
    root = Path(__file__).resolve().parents[2]
    iocs = load_iocs(root / "data" / "stealer_iocs.yaml")
    assert path_matches_ioc("/tmp/redline/payload.exe", iocs)
```

- [ ] **Step 6: Commit**

```bash
git commit -m "feat: process, persistence, and stealer collectors"
```

---

### Task 9: Remaining collectors (accounts, filesystem, kernel, logs, peripheral)

**Files:**
- Create: `src/grok_inspect/collectors/accounts_access.py`
- Create: `src/grok_inspect/collectors/filesystem_hotspots.py`
- Create: `src/grok_inspect/collectors/kernel_posture.py`
- Create: `src/grok_inspect/collectors/logs_sample.py`
- Create: `src/grok_inspect/collectors/peripheral.py`

- [ ] **Step 1: Implement each with best-effort OS branches**

Minimum evidence each must return even if limited:

| Collector | Minimum keys |
|-----------|----------------|
| accounts_access | `users_sample`, `ssh_listening` (bool/unknown), `admin_hint` |
| filesystem_hotspots | `recent_exec_sample` (list, max 50), `suid_sample` (unix), `world_writable_hits` |
| kernel_posture | `firewall_hint`, `extensions_or_modules_sample` |
| logs_sample | `auth_lines` (max 30 strings, truncated) |
| peripheral | `usb_hint` or `_status: skipped` if unsupported |

Every collector must catch permission errors and return `_status: limited` rather than raising.

- [ ] **Step 2: Smoke import test**

```python
# tests/unit/test_collectors_import.py
from grok_inspect.collectors import env, network, sniff_surface, process
from grok_inspect.collectors import persistence, stealer_indicators
from grok_inspect.collectors import accounts_access, filesystem_hotspots
from grok_inspect.collectors import kernel_posture, logs_sample, peripheral

def test_imports():
    assert callable(env.collect_env)
```

- [ ] **Step 3: Commit**

```bash
git commit -m "feat: remaining host collectors"
```

---

### Task 10: Heuristic engine + rule packs

**Files:**
- Create: `src/grok_inspect/heuristics/__init__.py`
- Create: `src/grok_inspect/heuristics/engine.py`
- Create: `src/grok_inspect/heuristics/rules_sniffing.py`
- Create: `src/grok_inspect/heuristics/rules_stealer.py`
- Create: `src/grok_inspect/heuristics/rules_process.py`
- Create: `src/grok_inspect/heuristics/rules_network.py`
- Create: `src/grok_inspect/heuristics/rules_persistence.py`
- Create: `src/grok_inspect/heuristics/rules_posture.py`
- Create: `src/grok_inspect/heuristics/allowlist.py`
- Create: `data/allowlist.example.yaml`
- Create: `tests/unit/test_heuristics.py`
- Create: `tests/fixtures/evidence/minimal_bundle.json`

- [ ] **Step 1: Fixture**

```json
{
  "elevated": false,
  "host": {"os_family": "darwin", "hostname": "test-host"},
  "results": [
    {
      "name": "sniff_surface",
      "status": "full",
      "evidence": {
        "capture_processes": [{"name": "tcpdump", "pid": 999}],
        "promisc_interfaces": ["en0"]
      }
    },
    {
      "name": "process",
      "status": "full",
      "evidence": {
        "processes": [
          {"pid": 1, "name": "launchd", "path": "/sbin/launchd", "cmdline": "launchd"}
        ]
      }
    }
  ]
}
```

- [ ] **Step 2: Engine API**

```python
# heuristics/engine.py
def run_heuristics(bundle: ScanBundle, allowlist: Allowlist | None = None) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(rules_sniffing.apply(bundle))
    findings.extend(rules_network.apply(bundle))
    findings.extend(rules_process.apply(bundle))
    findings.extend(rules_persistence.apply(bundle))
    findings.extend(rules_stealer.apply(bundle))
    findings.extend(rules_posture.apply(bundle))
    if allowlist:
        findings = allowlist.apply(findings)
    return _dedupe(findings)
```

- [ ] **Step 3: Sniffing rules (example complete)**

```python
# rules_sniffing.py
from grok_inspect.models import Finding, ScanBundle, Severity

def apply(bundle: ScanBundle) -> list[Finding]:
    out: list[Finding] = []
    ev = _evidence(bundle, "sniff_surface")
    for iface in ev.get("promisc_interfaces") or []:
        out.append(Finding(
            id="sniff.promisc_iface",
            title="Interface in promiscuous mode",
            summary=f"Interface {iface} appears promiscuous (strong sniffing signal)",
            severity=Severity.HIGH,
            category="sniffing",
            evidence={"iface": iface},
            confidence=0.85,
            remediation_hint="Identify process using the interface; disable promisc if unexpected",
            os=bundle.host.get("os_family"),
        ))
    for proc in ev.get("capture_processes") or []:
        name = proc.get("name") if isinstance(proc, dict) else str(proc)
        out.append(Finding(
            id="sniff.capture_process",
            title="Packet capture process running",
            summary=f"Capture-related process observed: {name}",
            severity=Severity.MEDIUM,
            category="sniffing",
            evidence={"process": proc},
            confidence=0.8,
            remediation_hint="Verify this is authorized troubleshooting or security tooling",
            os=bundle.host.get("os_family"),
        ))
    return out

def _evidence(bundle: ScanBundle, name: str) -> dict:
    for r in bundle.results:
        if r.name == name:
            return r.evidence or {}
    return {}
```

Implement analogous `apply(bundle)` in other rule modules:

- **network:** many listeners on high ports by unknown processes; suspicious hosts file entries  
- **process:** encoded powershell; masquerade paths  
- **persistence:** persistence pointing at temp/Downloads  
- **stealer:** IoC path hits  
- **posture:** firewall off / SIP disabled if present in env evidence  

- [ ] **Step 4: Chain boost in engine after base rules**

If findings include both `sniff` root-CA-like and proxy anomalies, append or escalate a `sniff.mitm_chain` HIGH/CRITICAL finding.

- [ ] **Step 5: Tests**

```python
def test_promisc_and_tcpdump_findings():
    from pathlib import Path
    import json
    from grok_inspect.models import ScanBundle, CollectorResult, CollectorStatus, utcnow
    from grok_inspect.heuristics.engine import run_heuristics

    raw = json.loads(Path("tests/fixtures/evidence/minimal_bundle.json").read_text())
    bundle = ScanBundle(
        started_at=utcnow(),
        host=raw["host"],
        elevated=raw["elevated"],
        results=[CollectorResult(name=r["name"], status=CollectorStatus(r["status"]), evidence=r["evidence"]) for r in raw["results"]],
    )
    findings = run_heuristics(bundle)
    ids = {f.id for f in findings}
    assert "sniff.promisc_iface" in ids
    assert "sniff.capture_process" in ids
```

- [ ] **Step 6: Commit**

```bash
git commit -m "feat: heuristic engine and rule packs"
```

---

### Task 11: Redaction

**Files:**
- Create: `src/grok_inspect/security/__init__.py`
- Create: `src/grok_inspect/security/redact.py`
- Create: `tests/unit/test_redact.py`

- [ ] **Step 1: Failing tests**

```python
from grok_inspect.security.redact import redact_text, build_grok_payload
from grok_inspect.models import Finding, Severity, ScanResult, ScanScore, utcnow, GrokAnalysis

def test_redact_api_key_shape():
    s = "Authorization: Bearer xai-abcdefghijklmnopqrstuvwxyz0123456789"
    assert "xai-abcdefghijklmnopqrstuvwxyz0123456789" not in redact_text(s)
    assert "REDACTED" in redact_text(s)

def test_build_payload_strips_home(monkeypatch):
    # include a finding with evidence path under /Users/alice/secret
    ...
```

- [ ] **Step 2: Implement**

```python
# security/redact.py
import re
from typing import Any
from grok_inspect.models import ScanResult

SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|token|password|secret|authorization)\s*[:=]\s*\S+"),
    re.compile(r"(?i)bearer\s+[a-z0-9._\-]{20,}"),
    re.compile(r"xai-[A-Za-z0-9]{20,}"),
    re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),  # JWT-ish
]

def redact_text(text: str) -> str:
    out = text
    for pat in SECRET_PATTERNS:
        out = pat.sub("[REDACTED]", out)
    return out

def normalize_path(path: str, home: str | None = None) -> str:
    if home and path.startswith(home):
        return "~" + path[len(home):]
    return path

def build_grok_payload(result: ScanResult, *, max_chars: int, home: str | None = None) -> str:
    """Serialize redacted JSON-ish summary for the model."""
    open_findings = [f for f in result.findings if not f.acknowledged]
    open_findings.sort(key=lambda f: f.severity.rank, reverse=True)
    payload = {
        "host": {
            "os_family": result.host.get("os_family"),
            "hostname_hash": _stable_hash(str(result.host.get("hostname", ""))),
            "elevated": result.elevated,
            "system": result.host.get("system"),
            "release": result.host.get("release"),
        },
        "score": result.score.model_dump(),
        "coverage": [c.model_dump() for c in result.coverage],
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "summary": redact_text(f.summary),
                "severity": f.severity.value,
                "category": f.category,
                "confidence": f.confidence,
                "evidence": _redact_obj(f.evidence, home=home),
                "remediation_hint": f.remediation_hint,
            }
            for f in open_findings
        ],
    }
    import json
    text = json.dumps(payload, indent=2, default=str)
    text = redact_text(text)
    if len(text) > max_chars:
        # Truncate findings list until under cap
        while len(payload["findings"]) > 5 and len(text) > max_chars:
            payload["findings"].pop()
            text = redact_text(json.dumps(payload, indent=2, default=str))
        if len(text) > max_chars:
            text = text[: max_chars - 20] + "\n...[TRUNCATED]"
    return text

def _redact_obj(obj: Any, home: str | None = None) -> Any:
    if isinstance(obj, str):
        s = redact_text(obj)
        if home:
            s = s.replace(home, "~")
        return s
    if isinstance(obj, dict):
        return {k: _redact_obj(v, home=home) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact_obj(v, home=home) for v in obj[:50]]
    return obj

def _stable_hash(s: str) -> str:
    import hashlib
    return hashlib.sha256(s.encode()).hexdigest()[:12]
```

- [ ] **Step 3: Run tests**

```bash
pytest tests/unit/test_redact.py -v
```

- [ ] **Step 4: Commit**

```bash
git commit -m "feat: mandatory redaction for Grok payloads"
```

---

### Task 12: Report pack (terminal, md, json, html)

**Files:**
- Create: `src/grok_inspect/report/__init__.py`
- Create: `src/grok_inspect/report/json_report.py`
- Create: `src/grok_inspect/report/markdown.py`
- Create: `src/grok_inspect/report/html.py`
- Create: `src/grok_inspect/report/terminal.py`
- Create: `src/grok_inspect/report/templates/brief.html.j2`
- Create: `src/grok_inspect/report/writer.py`
- Create: `tests/unit/test_reports.py`

- [ ] **Step 1: Writer API**

```python
# report/writer.py
from pathlib import Path
from grok_inspect.models import ScanResult

def write_report_pack(result: ScanResult, out_dir: Path) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = result.finished_at.strftime("%Y%m%dT%H%M%SZ")
    base = f"grok-inspect-{stamp}"
    paths = {}
    paths["json"] = out_dir / f"{base}.json"
    paths["md"] = out_dir / f"{base}.md"
    paths["html"] = out_dir / f"{base}.html"
    paths["json"].write_text(to_json(result), encoding="utf-8")
    paths["md"].write_text(to_markdown(result), encoding="utf-8")
    paths["html"].write_text(to_html(result), encoding="utf-8")
    for ext in ("json", "md", "html"):
        latest = out_dir / f"latest.{ext}"
        latest.write_text(paths[ext].read_text(encoding="utf-8"), encoding="utf-8")
    return paths
```

- [ ] **Step 2: JSON** = `result.model_dump(mode="json")` via pydantic  
- [ ] **Step 3: Markdown** sections: Host, Coverage, Score, Findings table, Grok analysis, Remediation  
- [ ] **Step 4: HTML** Jinja2 template with severity colors  
- [ ] **Step 5: Terminal** Rich table of top findings + paths  

- [ ] **Step 6: Test**

```python
def test_write_report_pack(tmp_path):
    # build minimal ScanResult, write, assert three files + latest.*
```

- [ ] **Step 7: Commit**

```bash
git commit -m "feat: markdown json html and terminal reports"
```

---

### Task 13: Pipeline orchestration (`--no-grok` path)

**Files:**
- Create: `src/grok_inspect/pipeline.py`
- Create: `src/grok_inspect/collectors/registry.py`
- Create: `tests/unit/test_pipeline_no_grok.py`

- [ ] **Step 1: Registry of collectors in order**

```python
# collectors/registry.py
from grok_inspect.collectors.env import collect_env
from grok_inspect.collectors.network import collect_network
from grok_inspect.collectors.sniff_surface import collect_sniff_surface
from grok_inspect.collectors.process import collect_process
from grok_inspect.collectors.persistence import collect_persistence
from grok_inspect.collectors.stealer_indicators import collect_stealer
from grok_inspect.collectors.accounts_access import collect_accounts
from grok_inspect.collectors.filesystem_hotspots import collect_filesystem
from grok_inspect.collectors.kernel_posture import collect_kernel
from grok_inspect.collectors.logs_sample import collect_logs
from grok_inspect.collectors.peripheral import collect_peripheral

COLLECTORS: list[tuple[str, callable]] = [
    ("env", collect_env),
    ("network", collect_network),
    ("sniff_surface", collect_sniff_surface),
    ("process", collect_process),
    ("persistence", collect_persistence),
    ("stealer_indicators", collect_stealer),
    ("accounts_access", collect_accounts),
    ("filesystem_hotspots", collect_filesystem),
    ("kernel_posture", collect_kernel),
    ("logs_sample", collect_logs),
    ("peripheral", collect_peripheral),
]
```

- [ ] **Step 2: `run_scan(settings, *, use_grok: bool, out_dir, allowlist_path, verbose) -> ScanResult`**

1. `probe_host()`  
2. For each collector: `run_collector` with timeout from settings  
3. `build_coverage`  
4. Build `ScanBundle`  
5. `run_heuristics` + merge coverage findings  
6. `ScanScore.from_findings`  
7. If `use_grok` and key present: redact + Grok (Task 14) else empty `GrokAnalysis(available=False, error=...)`  
8. `write_report_pack`  
9. Return result  

- [ ] **Step 3: Integration-style unit test**

```python
def test_run_scan_no_grok(tmp_path):
    from grok_inspect.config import load_settings
    from grok_inspect.pipeline import run_scan
    settings = load_settings(project_root=Path("/Users/harlock/Documents/AI_PROJECTS/GROK_INSPECT"))
    result = run_scan(settings, use_grok=False, out_dir=tmp_path, verbose=False)
    assert result.finished_at >= result.started_at
    assert (tmp_path / "latest.json").exists()
    assert result.grok.available is False
```

- [ ] **Step 4: Commit**

```bash
git commit -m "feat: scan pipeline without Grok"
```

---

### Task 14: Grok agent via SpaceXAI `xai-sdk`

**Files:**
- Create: `src/grok_inspect/agent/__init__.py`
- Create: `src/grok_inspect/agent/prompts.py`
- Create: `src/grok_inspect/agent/grok.py`
- Create: `tests/unit/test_grok_parse.py`

- [ ] **Step 1: Prompts**

```python
# agent/prompts.py
SYSTEM_CHARTER = """You are Grok Inspect's host IR analyst (defensive only).
You receive REDACTED host inspection findings about possible sniffing, info-stealing,
persistence, and related malicious presence.
Rules:
- Do not invent detections not supported by findings; you may chain and prioritize.
- No exploit instructions or credential dumping guidance.
- Distinguish legitimate admin/security tools from malice.
- Respect coverage limits (not elevated / skipped collectors).
- Output a single JSON object with keys:
  executive_summary (string),
  threat_narrative (string),
  prioritized_findings (array of {id, rank, rationale}),
  likely_attacker_goals (array of strings),
  remediation_plan (array of ordered strings),
  questions_for_operator (array of strings),
  confidence (number 0-1).
"""

def build_user_message(redacted_payload: str, os_family: str) -> str:
    return (
        f"OS family: {os_family}\n"
        "Analyze this redacted scan payload and return ONLY the JSON object.\n\n"
        f"{redacted_payload}"
    )
```

- [ ] **Step 2: Grok client**

```python
# agent/grok.py
from __future__ import annotations

import json
import re
import time
from typing import Any

from grok_inspect.config import Settings
from grok_inspect.models import GrokAnalysis, ScanResult
from grok_inspect.security.redact import build_grok_payload
from grok_inspect.agent.prompts import SYSTEM_CHARTER, build_user_message


def analyze_with_grok(result: ScanResult, settings: Settings, *, home: str | None = None) -> GrokAnalysis:
    if not settings.grok_available:
        return GrokAnalysis(available=False, error="XAI_API_KEY not set")

    payload = build_grok_payload(result, max_chars=settings.scan.payload_max_chars, home=home)
    t0 = time.time()
    try:
        from xai_sdk import Client
        from xai_sdk.chat import system, user

        client = Client(api_key=settings.api_key, timeout=3600)
        chat = client.chat.create(
            model=settings.model.id,
            reasoning_effort=settings.model.reasoning_effort,  # must be "high"
            messages=[system(SYSTEM_CHARTER)],
        )
        chat.append(user(build_user_message(payload, str(result.host.get("os_family", "unknown")))))
        response = chat.sample()
        text = getattr(response, "content", None) or ""
        if not isinstance(text, str):
            text = str(text)
        parsed = _parse_json_object(text)
        latency = time.time() - t0
        usage = _usage_summary(response)
        return GrokAnalysis(
            available=True,
            model_id=settings.model.id,
            reasoning_effort=settings.model.reasoning_effort,
            executive_summary=str(parsed.get("executive_summary", "")),
            threat_narrative=str(parsed.get("threat_narrative", "")),
            prioritized_findings=list(parsed.get("prioritized_findings") or []),
            likely_attacker_goals=[str(x) for x in (parsed.get("likely_attacker_goals") or [])],
            remediation_plan=[str(x) for x in (parsed.get("remediation_plan") or [])],
            questions_for_operator=[str(x) for x in (parsed.get("questions_for_operator") or [])],
            confidence=parsed.get("confidence"),
            latency_s=latency,
            usage_summary=usage,
            raw_text=text[:50_000],
        )
    except Exception as exc:
        return GrokAnalysis(
            available=False,
            model_id=settings.model.id,
            reasoning_effort=settings.model.reasoning_effort,
            error=f"{type(exc).__name__}: {exc}",
            latency_s=time.time() - t0,
        )


def _parse_json_object(text: str) -> dict[str, Any]:
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{[\s\S]*\}", text)
        if not m:
            return {"executive_summary": text[:2000], "threat_narrative": text[:8000]}
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            return {"executive_summary": text[:2000], "threat_narrative": text[:8000]}


def _usage_summary(response: Any) -> str:
    usage = getattr(response, "usage", None)
    if usage is None:
        return ""
    parts = []
    for attr in ("input_tokens", "output_tokens", "reasoning_tokens", "total_tokens"):
        val = getattr(usage, attr, None)
        if val is not None:
            parts.append(f"{attr}={val}")
    return ", ".join(parts)
```

**Hard rules in code comments + config:** never set `reasoning_effort` below `high` by default; never swap model to fast/mini on failure.

- [ ] **Step 3: Parse unit tests (no API)**

```python
from grok_inspect.agent.grok import _parse_json_object

def test_parse_fenced_json():
    text = 'Here you go:\n{"executive_summary": "ok", "threat_narrative": "n", "prioritized_findings": [], "likely_attacker_goals": [], "remediation_plan": [], "questions_for_operator": [], "confidence": 0.5}'
    d = _parse_json_object(text)
    assert d["executive_summary"] == "ok"
```

- [ ] **Step 4: Wire into pipeline when `use_grok=True`**

- [ ] **Step 5: Commit**

```bash
git commit -m "feat: Grok 4.5 analyst via xai-sdk with high reasoning"
```

---

### Task 15: Full CLI

**Files:**
- Modify: `src/grok_inspect/cli.py`
- Create: `tests/unit/test_cli_version.py`

- [ ] **Step 1: Implement CLI**

```python
# cli.py — key structure
import typer
from rich.console import Console
from pathlib import Path
from grok_inspect import __version__
from grok_inspect.config import load_settings
from grok_inspect.pipeline import run_scan
from grok_inspect.report.terminal import print_summary

app = typer.Typer(name="grok-inspect", help="Host sniffing/stealer inspection with Grok 4.5", no_args_is_help=True)
console = Console(stderr=True)

@app.command("version")
def version_cmd() -> None:
    typer.echo(f"grok-inspect {__version__}")

@app.command("scan")
def scan_cmd(
    out: Path = typer.Option(None, "--out", help="Report directory"),
    no_grok: bool = typer.Option(False, "--no-grok", help="Heuristics only"),
    allowlist: Path = typer.Option(None, "--allowlist", help="Allowlist YAML"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
    timeout: int = typer.Option(None, "--timeout", help="Per-collector timeout seconds"),
) -> None:
    settings = load_settings()
    if timeout:
        settings.scan.collector_timeout_sec = timeout
    out_dir = out or (Path.cwd() / settings.reports.dir)
    try:
        result = run_scan(
            settings,
            use_grok=not no_grok,
            out_dir=out_dir,
            allowlist_path=allowlist,
            verbose=verbose,
        )
    except Exception as exc:
        console.print(f"[red]Scan failed:[/red] {exc}")
        raise typer.Exit(2) from exc
    print_summary(result, out_dir)
    raise typer.Exit(result.exit_code())
```

- [ ] **Step 2: Manual smoke**

```bash
cd /Users/harlock/Documents/AI_PROJECTS/GROK_INSPECT
source .venv/bin/activate
grok-inspect scan --no-grok -v --out ./reports
echo $?
ls -la reports/
```

Expected: reports written; exit 0/1/3 depending on host findings (not 2).

- [ ] **Step 3: Optional live Grok smoke (requires key)**

```bash
export XAI_API_KEY=...
grok-inspect scan -v --out ./reports
# latest.md should include Grok executive_summary; model_id grok-4.5
```

- [ ] **Step 4: Commit**

```bash
git commit -m "feat: CLI scan command with exit codes"
```

---

### Task 16: Docs and packaging polish

**Files:**
- Create: `README.md`
- Create: `SECURITY.md`
- Create: `LICENSE` (MIT)
- Create: `data/allowlist.example.yaml`

- [ ] **Step 1: README sections**

- What it is / is not  
- Install: `python -m venv .venv && pip install -e ".[dev]"`  
- `export XAI_API_KEY=...`  
- `grok-inspect scan` / `--no-grok` / elevated re-run  
- Report locations  
- Model policy: grok-4.5 + high reasoning via xai-sdk  
- Cross-platform notes  

- [ ] **Step 2: SECURITY.md**

- Defensive use only  
- Never collects passwords/cookies/key material  
- Reports may contain sensitive metadata — protect `reports/`  
- Redaction before API  
- No automatic remediation  

- [ ] **Step 3: Full test suite**

```bash
pytest -v
```

Expected: all PASS

- [ ] **Step 4: Final commit**

```bash
git commit -m "docs: README and SECURITY for grok-inspect v1"
```

---

## Spec coverage checklist (self-review)

| Spec requirement | Task(s) |
|------------------|---------|
| Manual CLI scan | 15 |
| macOS / Linux / Windows collectors | 7–9 |
| Comprehensive modules A–K | 6–9 |
| Prefer elevated, degrade gracefully | 4, 6, 10 |
| Heuristics ground truth | 10 |
| Mandatory redaction | 11 |
| Grok 4.5 + high via xai-sdk | 14 |
| No model downgrade | 14 |
| CLI + md + json + html | 12 |
| Exit codes 0/1/2/3 | 2, 15 |
| Allowlist | 10 |
| Tests | throughout |
| README / SECURITY | 16 |

## Placeholder scan

Plan uses concrete files, APIs, and commands. Collector OS command details are specified by platform tables; implementers must still choose exact argv lists per OS without shell injection.

## Type consistency

Canonical types live in `models.py`: `Finding`, `Severity`, `CollectorResult`, `CollectorStatus`, `ScanBundle`, `ScanScore`, `GrokAnalysis`, `ScanResult`, `CoverageEntry`. Pipeline returns `ScanResult`. Grok returns `GrokAnalysis`.

---

## Execution handoff

Plan complete and saved to:

`docs/superpowers/plans/2026-08-08-grok-inspect-implementation.md`

**Two execution options:**

1. **Subagent-Driven (recommended)** — Fresh subagent per task, review between tasks, fast iteration  
2. **Inline Execution** — Execute tasks in this session with checkpoints  

Which approach?
