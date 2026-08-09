# Grok Inspect — Comprehensive User Guide

Professional documentation for operators, IR leads, and security leadership.

## Table of contents

1. [Product overview](#1-product-overview)  
2. [Requirements](#2-requirements)  
3. [Installation](#3-installation)  
4. [API key & Grok configuration](#4-api-key--grok-configuration)  
5. [Operating modes (Standard vs Pro)](#5-operating-modes-standard-vs-pro)  
6. [Command reference](#6-command-reference)  
7. [Running scans](#7-running-scans)  
8. [Elevated / Pro mode (sudo)](#8-elevated--pro-mode-sudo)  
9. [Executive reports (CISO / CIO)](#9-executive-reports-ciso--cio)  
10. [Interpreting findings](#10-interpreting-findings)  
11. [Allowlists](#11-allowlists)  
12. [Exit codes & automation](#12-exit-codes--automation)  
13. [Troubleshooting](#13-troubleshooting)  
14. [Security practices](#14-security-practices)  
15. [Architecture](#15-architecture)  

---

## 1. Product overview

**Grok Inspect** is an **on-demand host inspection agent**. On each run it:

1. Probes OS and privilege level  
2. Executes cross-platform **collectors** (network, sniff surface, process, persistence, stealer indicators, accounts, filesystem, posture, logs, peripherals)  
3. Scores **findings** with deterministic **heuristics**  
4. Optionally escalates a **redacted**, comprehensive package to **Grok 4.5** (`reasoning_effort=high`) via SpaceXAI **`xai-sdk`**  
5. Writes a **CISO/CIO-grade brief** (Markdown + HTML + JSON) plus a terminal summary  

### Design principles

| Principle | Meaning |
|-----------|---------|
| Ground truth in heuristics | Grok prioritizes and narrates; it does not invent detections |
| Dual-track actions | Leadership decisions **and** engineer-executable steps |
| Honest coverage | Limited collectors are reported, not hidden |
| Secure by design | Redaction, no secret dumps, no auto-remediation |

### Not in scope

- Continuous monitoring / EDR replacement  
- Live packet capture pipelines  
- Password, cookie, keychain, or LSASS extraction  
- Automatic process kill or quarantine  

---

## 2. Requirements

| Item | Requirement |
|------|-------------|
| OS | macOS, Linux, or Windows |
| Python | **3.11+** (3.12–3.14 supported) |
| Network | Required only for Grok analysis |
| API key | `XAI_API_KEY` from [console.x.ai](https://console.x.ai/) for Grok mode |
| Privileges | User for **Standard**; admin/root for **Pro** depth |

---

## 3. Installation

### Recommended (production-reliable)

```bash
git clone https://github.com/harlockus/grok_inspect.git
cd grok_inspect
bash scripts/install.sh
source .venv/bin/activate          # Windows: .venv\Scripts\activate
grok-inspect version
```

### Manual

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install ".[dev]"
```

### Critical note — macOS + Python 3.14

**Do not** use:

```bash
pip install -e .
```

Editable installs may create a **hidden** `__editable__.*.pth` that Python 3.14 **skips**, causing:

```text
ModuleNotFoundError: No module named 'grok_inspect'
```

**Fix:**

```bash
bash scripts/install.sh
# or: pip install .
```

### After `git pull`

Reinstall so the CLI entry point matches source:

```bash
source .venv/bin/activate
pip install .
```

---

## 4. API key & Grok configuration

### Policy

| Location | Allowed |
|----------|---------|
| Project `.env` | **Yes — only supported secret store** |
| `config/*.yaml` | **No** (stripped if present) |
| Git commits / reports | **No** |

### Setup

```bash
cp .env.example .env
```

Edit `.env`:

```bash
XAI_API_KEY=xai-your-real-key
# Optional:
# XAI_MODEL=grok-4.5
```

### Verify (never prints full key)

```bash
grok-inspect doctor
```

Healthy output includes:

```text
.env file: found
XAI_API_KEY: present
Grok analysis ready for `grok-inspect scan`
```

### Model policy

| Setting | Value |
|---------|--------|
| Model | `grok-4.5` (flagship) |
| Reasoning | `high` (always for analysis) |
| Fallback model | **None** — failure → heuristics-only report |
| Offline | `--no-grok` |

If both shell `export XAI_API_KEY` and `.env` define a key, **`.env` wins**.

---

## 5. Operating modes (Standard vs Pro)

```text
┌──────────────────────┐     ┌──────────────────────────────┐
│   STANDARD MODE      │     │   PRO MODE (ELEVATED)        │
│   User context       │     │   root / Administrator       │
│   Fast triage        │     │   Maximum collector depth    │
│   Honest “limited”   │     │   Prefer for CISO briefs     │
│   coverage notes     │     │   sudo .venv/bin/grok-inspect│
└──────────────────────┘     └──────────────────────────────┘
```

| Dimension | Standard | **Pro (Elevated)** |
|-----------|----------|---------------------|
| Invocation | `grok-inspect scan -v` | `sudo .venv/bin/grok-inspect scan -v` |
| Process enumeration | Best-effort | Deeper (other users, services) |
| Drivers / deep posture | Partial | Stronger where OS allows |
| Report field `Elevated` | `No` | `Yes` |
| Recommendation | Day-to-day | Pre-board / IR evidence packs |

---

## 6. Command reference

| Command | Description |
|---------|-------------|
| `grok-inspect doctor` | Health check: project root, `.env`, key, model |
| `grok-inspect scan` | Full host scan |
| `grok-inspect scan -v` | Verbose collector progress |
| `grok-inspect scan --no-grok` | Heuristics only (no API) |
| `grok-inspect scan --out DIR` | Report directory |
| `grok-inspect scan --allowlist PATH` | Allowlist YAML |
| `grok-inspect scan --timeout SEC` | Per-collector timeout (5–300) |
| `grok-inspect version` | Print version |
| `python -m grok_inspect scan -v` | Module invocation |

---

## 7. Running scans

### Standard + Grok (default professional path)

```bash
cd /path/to/grok_inspect
source .venv/bin/activate
grok-inspect scan -v
```

### Offline / air-gapped heuristics

```bash
grok-inspect scan --no-grok -v --out ./reports
```

### Custom output directory

```bash
grok-inspect scan -v --out /secure/ir/cases/2026-08-09
```

### Allowlist known-good tools

```bash
cp data/allowlist.example.yaml data/allowlist.yaml
# edit rule_ids / paths / process_names
grok-inspect scan -v --allowlist data/allowlist.yaml
```

(`data/allowlist.yaml` is gitignored.)

---

## 8. Elevated / Pro mode (sudo)

### macOS / Linux

Always call the **venv executable** so privileges and package path stay aligned:

```bash
cd /path/to/grok_inspect

# Pro mode — full scan + Grok CISO brief
sudo .venv/bin/grok-inspect scan -v

# Pro mode — offline
sudo .venv/bin/grok-inspect scan --no-grok -v
```

**Avoid** `sudo grok-inspect` unless that name is on root’s `PATH` (often it is not).

### Windows

1. Start **PowerShell** or **Windows Terminal** as **Administrator**  
2. Activate the project venv  
3. Run:

```powershell
grok-inspect scan -v
```

### Confirm elevation

In CLI or report cover:

- **Elevated scan: Yes**  
- Fewer `coverage.not_elevated` / `*.limited` entries  

---

## 9. Executive reports (CISO / CIO)

### Artifacts

| File | Use |
|------|-----|
| `reports/latest.html` | Preferred executive view — browser / PDF print |
| `reports/latest.md` | Shareable brief in tickets / email |
| `reports/latest.json` | Machine-readable full object |
| `reports/grok-inspect-<timestamp>.*` | Immutable run archive |

### Brief structure

1. **Cover** — host, elevation, heuristic max severity, **Grok risk rating**  
2. **Severity scorecard** — critical → info  
3. **Executive brief** — situation, summary, business impact, board talking points  
4. **Executive actions** — P0–P3, owner role, timeline, success criteria  
5. **30 / 60 / 90 day plan**  
6. **Detailed technical actions** — phase, steps, verification, related finding IDs  
7. **Threat narrative** — attack path, goals  
8. **Prioritized findings (Grok)**  
9. **Full heuristic catalog**  
10. **Coverage & residual risk**  

### What Grok receives

A **comprehensive redacted package**: open findings (severity-sorted), coverage, collector status, and collector evidence digests — not passwords, cookies, or private keys. Payload size defaults to a large CISO-oriented budget (`payload_max_chars` in `config/default.yaml`).

---

## 10. Interpreting findings

| Severity | Guidance |
|----------|----------|
| **critical** | Immediate leadership attention; possible active compromise path |
| **high** | Urgent validation (e.g. promisc interfaces, dangerous process patterns) |
| **medium** | Investigate; may be misconfig or weak signal |
| **low** | Hygiene / volume signals |
| **info** | Coverage and inventory presence |

Grok may mark authorized tools (e.g. Wireshark) as **authorized-but-risky** — leadership still owns policy.

---

## 11. Allowlists

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

Allowlisted items become **acknowledged** (visible, not open risk).

---

## 12. Exit codes & automation

| Code | Meaning |
|------|---------|
| `0` | Completed; max severity info/low |
| `1` | Medium or high findings |
| `2` | Error (config/path/crash) |
| `3` | Critical findings |

Example:

```bash
grok-inspect scan --no-grok -v
code=$?
if [ "$code" -ge 3 ]; then echo "CRITICAL"; fi
```

---

## 13. Troubleshooting

### `ModuleNotFoundError: grok_inspect`

```bash
bash scripts/install.sh
source .venv/bin/activate
grok-inspect version
```

### `doctor` — key missing

1. Ensure `.env` exists in the project root  
2. Set `XAI_API_KEY=xai-...` (placeholders like `your_key_here` are rejected)  
3. Re-run `grok-inspect doctor`  

### Grok unavailable in report

- Missing key, `--no-grok`, or API/network failure  
- Heuristic findings and local remediation hints still ship  

### `sudo` cannot find the CLI

```bash
sudo /full/path/to/grok_inspect/.venv/bin/grok-inspect scan -v
```

### Many collectors limited

Re-run in **Pro mode** (section 8).

---

## 14. Security practices

- Defensive use only; authorized systems only  
- Never commit `.env` or real `reports/*`  
- Protect report storage (host metadata)  
- Prefer Pro elevated scans for executive decision packs  
- See [SECURITY.md](../SECURITY.md)  

---

## 15. Architecture

```text
scan
  → privilege / host probe
  → collectors (parallel-safe sequential runner + timeouts)
  → heuristics + chain boosts + allowlist
  → redaction
  → Grok 4.5 high (optional, comprehensive package)
  → sanitize
  → write CLI + MD + JSON + HTML
```

Design detail: [docs/superpowers/specs/2026-08-08-grok-inspect-design.md](superpowers/specs/2026-08-08-grok-inspect-design.md)

---

## Quick reference card

```bash
# Install
git clone https://github.com/harlockus/grok_inspect.git && cd grok_inspect
bash scripts/install.sh && source .venv/bin/activate
cp .env.example .env   # set XAI_API_KEY
grok-inspect doctor

# Standard
grok-inspect scan -v

# Pro (elevated)
sudo .venv/bin/grok-inspect scan -v

# Reports
open reports/latest.html
```
