# Grok Inspect

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Cross-platform host inspection agent** for **sniffing**, **info-stealing**, and related malicious presence — with **Grok 4.5** analysis via the official SpaceXAI **`xai-sdk`** (`reasoning_effort=high`).

| | |
|--|--|
| **Trigger** | Manual CLI (`grok-inspect scan`) |
| **Platforms** | macOS · Linux · Windows |
| **AI** | Grok 4.5 (flagship, high reasoning) — optional with `--no-grok` |
| **Output** | Terminal + Markdown + JSON + HTML |
| **Security** | Secrets only in `.env`; redaction; path confinement; no auto-remediation |

> **Full guide:** [docs/USER_GUIDE.md](docs/USER_GUIDE.md) · **Security:** [SECURITY.md](SECURITY.md)

---

## What it does

1. Collects local host evidence (network, capture tools, processes, persistence, stealer IoCs, accounts, filesystem hotspots, posture, logs, peripherals)  
2. Scores findings with **deterministic heuristics**  
3. Optionally analyzes a **redacted** pack with **Grok 4.5** (high reasoning)  
4. Writes reports under `reports/`  

It does **not** dump passwords/cookies/keys, capture live packets, or kill processes.

---

## Quick start

```bash
# 1. Install
git clone <your-repo-url> GROK_INSPECT
cd GROK_INSPECT
bash scripts/install.sh
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# 2. API key (Grok) — only in .env
cp .env.example .env
# Edit .env → XAI_API_KEY=xai-...

# 3. Verify
grok-inspect doctor

# 4. Scan
grok-inspect scan -v
```

Open results:

- `reports/latest.md`  
- `reports/latest.html`  
- `reports/latest.json`  

---

## Install notes

**Preferred:** `bash scripts/install.sh` (plain `pip install`, not editable).

**Avoid on macOS + Python 3.14:** `pip install -e .`  
Setuptools creates a hidden `__editable__.*.pth` that Python 3.14 skips → `ModuleNotFoundError: grok_inspect`. Fix: re-run `bash scripts/install.sh`.

Manual:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install ".[dev]"
```

---

## Common commands

| Command | Purpose |
|---------|---------|
| `grok-inspect doctor` | Check `.env` / key / model (never prints full key) |
| `grok-inspect scan -v` | Full scan + Grok if key set |
| `grok-inspect scan --no-grok -v` | Local heuristics only |
| `grok-inspect scan --out ./reports` | Custom report dir |
| `grok-inspect version` | Version |

### Elevated (deeper coverage)

```bash
# macOS / Linux — use the venv binary
sudo .venv/bin/grok-inspect scan -v

# Windows — run terminal as Administrator, then:
grok-inspect scan -v
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Clean / info–low |
| 1 | Medium or high findings |
| 2 | Scan error |
| 3 | Critical findings |

---

## Configuration

| Item | Where |
|------|--------|
| **API key** | Project `.env` only (`XAI_API_KEY=...`) — **gitignored** |
| Defaults | `config/default.yaml` (no secrets) |
| Example env | `.env.example` |
| Allowlist example | `data/allowlist.example.yaml` |

Model policy: **`grok-4.5`** + **`reasoning_effort=high`**. No mini/fast fallback. Cost control = `--no-grok` or omit key.

---

## Secure by design (summary)

| Control | Behavior |
|---------|----------|
| API key storage | `.env` only; stripped from YAML |
| Subprocess | `shell=False`; secrets scrubbed from child env |
| Redaction | Before Grok **and** before report write |
| Path safety | Blocks report writes under system roots |
| Safe YAML | Size-capped `safe_load` |
| No raw model dump | `raw_text` cleared from reports |
| Read-only intent | No kill / quarantine / config mutation |

Details and threat model: **[SECURITY.md](SECURITY.md)**.

---

## Project layout

```text
GROK_INSPECT/
  src/grok_inspect/     # Package (collectors, heuristics, agent, reports, security)
  config/default.yaml   # Non-secret defaults
  data/                 # IoCs + allowlist example
  docs/USER_GUIDE.md    # Full operator guide
  docs/superpowers/     # Design + implementation plan
  scripts/install.sh    # Reliable installer
  tests/                # Unit tests
  reports/              # Scan output (gitignored except placeholder)
  .env.example          # Template — copy to .env
```

---

## Development

```bash
source .venv/bin/activate
pytest -q
```

Design: [docs/superpowers/specs/2026-08-08-grok-inspect-design.md](docs/superpowers/specs/2026-08-08-grok-inspect-design.md)

---

## Responsible use

For **defensive** inspection of systems you own or are authorized to assess. Unauthorized scanning may be illegal.

## License

[MIT](LICENSE)
