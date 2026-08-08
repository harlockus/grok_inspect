# Grok Inspect — User Guide

Complete guide for installing, configuring, running, and interpreting results.

## Table of contents

1. [What it is](#1-what-it-is)
2. [Requirements](#2-requirements)
3. [Install](#3-install)
4. [API key setup](#4-api-key-setup-spacexai)
5. [Commands](#5-commands)
6. [Running scans](#6-running-scans)
7. [Elevated (sudo) scans](#7-elevated-sudo-scans)
8. [Reading reports](#8-reading-reports)
9. [Allowlists](#9-allowlists)
10. [Exit codes](#10-exit-codes)
11. [Troubleshooting](#11-troubleshooting)
12. [Security practices](#12-security-practices)
13. [Architecture overview](#13-architecture-overview)

---

## 1. What it is

**Grok Inspect** (`grok-inspect`) is a **manual CLI** that inspects a local Mac, Windows, or Linux host for:

- Network sniffing / packet-capture surface  
- Info-stealing indicators  
- Suspicious processes, persistence, posture, accounts, and more  

It:

1. Collects host evidence locally  
2. Scores findings with **deterministic heuristics**  
3. Optionally sends a **redacted** summary to **Grok 4.5** (`reasoning_effort=high`) via the official SpaceXAI **`xai-sdk`**  
4. Writes **CLI + Markdown + JSON + HTML** reports  

It does **not** kill processes, dump passwords, or auto-remediate.

---

## 2. Requirements

| Item | Requirement |
|------|-------------|
| OS | macOS, Linux, or Windows |
| Python | 3.11+ (3.12–3.14 tested) |
| Network | Only if using Grok analysis |
| API key | `XAI_API_KEY` from [console.x.ai](https://console.x.ai/) for Grok mode |
| Privileges | User-level works; **admin/root** for deeper coverage |

---

## 3. Install

### Recommended (all platforms with bash)

```bash
cd /path/to/GROK_INSPECT
bash scripts/install.sh
source .venv/bin/activate    # Windows: .venv\Scripts\activate
```

### Manual

```bash
cd /path/to/GROK_INSPECT
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install ".[dev]"
```

### Important: do not use editable install on macOS + Python 3.14

```bash
# BAD on macOS/Python 3.14 — often breaks with ModuleNotFoundError
pip install -e .
```

Use `scripts/install.sh` or plain `pip install .` instead.  
Root cause: setuptools creates a hidden `__editable__.*.pth` that Python 3.14 skips (`UF_HIDDEN`).

### Verify install

```bash
grok-inspect version
# → grok-inspect 0.1.0
```

---

## 4. API key setup (SpaceXAI)

**Store the key only in project `.env` (gitignored).**

```bash
cp .env.example .env
# Edit .env:
#   XAI_API_KEY=xai-your-real-key
```

Never put the key in:

- `config/*.yaml`  
- source code  
- Git commits  
- chat / tickets  

Check without printing the full key:

```bash
grok-inspect doctor
```

Expected when ready:

```text
.env file: found
XAI_API_KEY: present
Source: loaded from .../GROK_INSPECT/.env
Grok analysis ready for `grok-inspect scan`
```

Optional in `.env`:

```bash
# XAI_MODEL=grok-4.5
```

**Model policy:** analysis uses **`grok-4.5`** with **`reasoning_effort=high`**. No silent fallback to mini/fast models. Use `--no-grok` to skip the API.

If both shell `export XAI_API_KEY=...` and `.env` have a key, **`.env` wins**.

---

## 5. Commands

| Command | Purpose |
|---------|---------|
| `grok-inspect doctor` | Verify project root, `.env`, key, model |
| `grok-inspect scan` | Run a full host inspection |
| `grok-inspect version` | Print version |
| `grok-inspect --help` | Top-level help |
| `grok-inspect scan --help` | Scan flags |

Also:

```bash
python -m grok_inspect scan -v
```

---

## 6. Running scans

### Everyday full scan (heuristics + Grok)

```bash
cd /path/to/GROK_INSPECT
source .venv/bin/activate
grok-inspect scan -v
```

### Offline / no API

```bash
grok-inspect scan --no-grok -v
```

### Custom report directory

```bash
grok-inspect scan -v --out ./reports
```

### Allowlist known-good tools

```bash
cp data/allowlist.example.yaml data/allowlist.yaml
# edit allowlist.yaml
grok-inspect scan -v --allowlist data/allowlist.yaml
```

(`data/allowlist.yaml` is gitignored so private paths stay local.)

### Timeout

```bash
grok-inspect scan --timeout 60 -v
```

### All scan flags

| Flag | Meaning |
|------|---------|
| `-v` / `--verbose` | Collector progress |
| `--no-grok` | Heuristics only |
| `--out DIR` | Report directory |
| `--allowlist PATH` | Allowlist YAML |
| `--timeout SEC` | Per-collector timeout (5–300) |

---

## 7. Elevated (sudo) scans

Many signals need admin/root (other users’ processes, some services, deeper network ownership).

### macOS / Linux

Use the **venv binary** (so root uses the right package):

```bash
cd /path/to/GROK_INSPECT
sudo .venv/bin/grok-inspect scan -v
```

Heuristics only:

```bash
sudo .venv/bin/grok-inspect scan --no-grok -v
```

### Windows

Run PowerShell or Terminal **as Administrator**, activate the venv, then:

```powershell
grok-inspect scan -v
```

Without elevation the report still works and lists **coverage** findings explaining what was limited.

---

## 8. Reading reports

After a scan, open:

| File | Use |
|------|-----|
| `reports/latest.md` | Human-readable narrative |
| `reports/latest.html` | Browser-friendly brief |
| `reports/latest.json` | Automation / SIEM pipelines |
| `reports/grok-inspect-<timestamp>.*` | Archived run |

### Report sections

1. **Host / elevation / score**  
2. **Coverage** — which collectors ran full / limited / skipped  
3. **Findings** — severity, rule id, summary, remediation hint  
4. **Grok analysis** (if enabled) — executive summary, narrative, ordered remediation  

### Severity guide

| Severity | Meaning (approx.) |
|----------|-------------------|
| critical | Strong compromise / stealer / MITM chain indicators |
| high | Promisc mode, dangerous process patterns, weak posture |
| medium | Suspicious hosts/proxy, notable anomalies |
| low | Weaker signals, volume/noise |
| info | Coverage notes, installed tools presence |

Findings are **heuristics**, not courtroom proof. Grok prioritizes and explains; it does not invent new detections.

---

## 9. Allowlists

Use when legitimate tools (corp proxy, Wireshark lab, remote support) create expected noise.

```yaml
# data/allowlist.yaml
version: 1
rule_ids:
  - sniff.capture_process
path_substrings:
  - /Applications/Wireshark.app
process_names:
  - Wireshark
```

Allowlisted findings are **acknowledged** (still visible, not open risk).

---

## 10. Exit codes

| Code | Meaning |
|------|---------|
| `0` | Completed; max severity info/low (or clean) |
| `1` | Completed; medium or high findings |
| `2` | Scan error (bad path, crash) |
| `3` | Completed; one or more **critical** findings |

Useful in scripts:

```bash
grok-inspect scan --no-grok
echo $?
```

---

## 11. Troubleshooting

### `ModuleNotFoundError: No module named 'grok_inspect'`

```bash
bash scripts/install.sh
source .venv/bin/activate
grok-inspect version
```

Do **not** use `pip install -e .` on macOS Python 3.14+.

### `doctor` says key missing

1. `cp .env.example .env`  
2. Set `XAI_API_KEY=xai-...` (no quotes required; placeholders like `your_key_here` are rejected)  
3. `grok-inspect doctor`  

### Grok section says unavailable

- Missing key → add to `.env`  
- Or you used `--no-grok`  
- Or API/network error (heuristics reports still written)

### sudo can’t find `grok-inspect`

```bash
sudo /full/path/to/GROK_INSPECT/.venv/bin/grok-inspect scan -v
```

### Coverage mostly “limited”

Re-run elevated (section 7).

### Permission errors under `reports/`

Ensure the output directory is writable; avoid writing under system paths (tool blocks `/etc`, `/System`, etc.).

---

## 12. Security practices

- **Defensive use only** — systems you own or are authorized to assess  
- **Key only in `.env`** — never commit  
- **Protect `reports/`** — host metadata  
- **No secret dumping** by design  
- **No auto-remediation** — operator acts on recommendations  
- See [SECURITY.md](../SECURITY.md) for threat model and controls  

---

## 13. Architecture overview

```text
scan
  → privilege / host probe
  → collectors (network, sniff, process, persistence, stealer, …)
  → heuristic rules + chain boosts
  → redaction
  → Grok 4.5 high reasoning (optional)
  → sanitize + write reports
```

Design details: [docs/superpowers/specs/2026-08-08-grok-inspect-design.md](superpowers/specs/2026-08-08-grok-inspect-design.md)

---

## Quick reference card

```bash
# Setup
bash scripts/install.sh && source .venv/bin/activate
cp .env.example .env   # add XAI_API_KEY
grok-inspect doctor

# Scan
grok-inspect scan -v
grok-inspect scan --no-grok -v
sudo .venv/bin/grok-inspect scan -v

# Results
open reports/latest.html   # or: less reports/latest.md
```
