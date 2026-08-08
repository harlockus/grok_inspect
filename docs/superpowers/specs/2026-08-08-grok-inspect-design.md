# Grok Inspect — Design Spec (v1)

**Date:** 2026-08-08  
**Project path:** `/Users/harlock/Documents/AI_PROJECTS/GROK_INSPECT`  
**Status:** Draft for user review (pre-implementation)

## 1. Purpose

**Grok Inspect** (`grok-inspect`) is a **manual CLI host inspection agent** that, when triggered, examines a local Mac, Windows, or Linux machine for **sniffing**, **info-stealing**, and related **malicious presence**. It collects host evidence locally, scores findings with deterministic heuristics, sends a **redacted** evidence pack to **Grok 4.5** via the official **SpaceXAI / xAI SDK** (`xai-sdk`) at **maximum reasoning**, and writes a full report pack (CLI + Markdown + JSON + HTML).

It is **defensive inspection only**: detect and explain, not exploit, dump secrets, or auto-remediate.

### 1.1 Relationship to neighboring projects

| Project | Role vs Grok Inspect |
|---------|----------------------|
| **FIREWALL / Aegis** | Live / PCAP network capture and traffic IDS. Grok Inspect is **on-demand host forensics**, not continuous packet capture. |
| **CISO Advisory** | External threat intel briefs. Grok Inspect is **local host** triage with the same SpaceXAI SDK family. |

## 2. Goals and non-goals

### 2.1 Goals (v1)

- Manual CLI scan: `grok-inspect scan`
- Cross-platform: **macOS, Linux, Windows**
- **Comprehensive** host coverage: network, sniffing surface, process/LOLBins, persistence, stealer indicators, accounts/access, filesystem hotspots, kernel/posture, log samples, peripherals (best-effort)
- Prefer elevated privileges; **degrade gracefully** with explicit coverage notes
- Local collectors + heuristics; **mandatory redaction** before Grok
- **Grok 4.5** + `reasoning_effort: high` via **`xai-sdk`** — no mini/fast downgrade
- Report pack: terminal (Rich) + `.md` + `.json` + `.html`
- Safe defaults: read-only intent, no secret extraction, no process kill

### 2.2 Non-goals (v1)

- Always-on daemon or scheduled monitoring
- Live packet capture / PCAP (Aegis territory)
- Reading or exporting passwords, cookies, keychain/LSASS contents, private keys
- Full-disk antivirus hash of every file
- Automatic quarantine, kill, or persistence removal
- Multi-host fleet / cloud console
- Silent fallback to weaker LLM models

## 3. Architecture

### 3.1 High-level flow

```
grok-inspect scan
       │
       ▼
┌──────────────────┐
│  Privilege probe │  admin/root? → full modules; else limited + coverage notes
└────────┬─────────┘
         ▼
┌──────────────────┐
│   Collectors     │  OS-aware modules (darwin / linux / windows)
│  A–K + coverage  │  sequential, per-collector timeouts
└────────┬─────────┘
         ▼
┌──────────────────┐
│ Heuristic engine │  deterministic rules → Finding[] + ScanScore
└────────┬─────────┘
         ▼
┌──────────────────┐
│    Redactor      │  secrets stripped; paths normalized; size caps
└────────┬─────────┘
         ▼
┌──────────────────┐
│  Grok analyst    │  xai-sdk Client · grok-4.5 · reasoning_effort=high
│                  │  narrative, prioritization, remediation
└────────┬─────────┘
         ▼
┌──────────────────┐
│  Report writers  │  terminal · .md · .json · .html → reports/
└──────────────────┘
```

### 3.2 Design principles

1. **Collectors never call Grok** — pure local evidence.
2. **Heuristics are deterministic and tested** — Grok adds judgment, not raw detection ground truth.
3. **Redaction is mandatory** before any API payload; redaction failure blocks Grok, not local reports.
4. **Degrade gracefully** — missing privileges → fewer signals + explicit coverage gaps.
5. **Cross-platform via adapters** — shared finding schema; OS-specific paths inside collectors.
6. **Max Grok capability** — flagship model + high reasoning; cost control is `--no-grok` or missing key, not a weaker model.

### 3.3 Package layout

```
GROK_INSPECT/
  pyproject.toml
  README.md
  SECURITY.md
  LICENSE
  .env.example
  .gitignore
  config/
    default.yaml
  data/
    stealer_iocs.yaml          # curated path/filename patterns (versioned)
    allowlist.example.yaml
  docs/
    superpowers/
      specs/
        2026-08-08-grok-inspect-design.md
  src/grok_inspect/
    __init__.py
    __main__.py
    cli.py
    config.py
    models.py
    platform.py                # OS detect + privilege probe
    pipeline.py                # orchestrates scan end-to-end
    collectors/
      __init__.py
      base.py                  # Collector protocol + runner
      env.py
      network.py
      sniff_surface.py
      process.py
      persistence.py
      stealer_indicators.py
      accounts_access.py
      filesystem_hotspots.py
      kernel_posture.py
      logs_sample.py
      peripheral.py
      coverage.py
    heuristics/
      __init__.py
      engine.py
      rules_sniffing.py
      rules_stealer.py
      rules_process.py
      rules_network.py
      rules_persistence.py
      rules_posture.py
    security/
      __init__.py
      redact.py
    agent/
      __init__.py
      grok.py                  # xai_sdk.Client wrapper
      prompts.py
    report/
      __init__.py
      terminal.py
      markdown.py
      json_report.py
      html.py
      templates/
        brief.html.j2
  tests/
    unit/
    fixtures/
      evidence/                # canned collector bundles per OS
  reports/                     # gitignored scan outputs
```

## 4. Collectors (comprehensive)

Each collector returns **raw evidence** (structured facts), not verdicts. Status: `full` | `limited` | `skipped`.

### 4.1 Shared finding shape

| Field | Purpose |
|--------|---------|
| `id` | Stable rule id (e.g. `sniff.promisc_iface`) |
| `title` / `summary` | Human-readable |
| `severity` | `info` · `low` · `medium` · `high` · `critical` |
| `category` | `sniffing` · `stealer` · `process` · `network` · `persistence` · `posture` · `coverage` · `accounts` · `filesystem` |
| `evidence` | Key facts (redacted before Grok) |
| `confidence` | Heuristic confidence 0–1 |
| `remediation_hint` | Short local hint (Grok expands) |
| `os` / `requires_elevated` | Metadata for coverage |

### 4.2 Module inventory

| ID | Module | Collects |
|----|--------|----------|
| A | `env` | OS, arch, kernel, hostname, user (hashable), elevated?, SIP / Secure Boot / SELinux / AppArmor (when queryable), firewall on/off |
| B | `network` | Listeners + owners, established externals, interfaces, routes, DNS/hosts, system proxy / PAC / proxy env, unexpected remote-access listeners |
| C | `sniff_surface` | Capture tools (running + installed), libpcap/Npcap/BPF, promisc/monitor mode, MITM helpers, eBPF/probe tooling when visible, user-installed root CAs |
| D | `process` | Process inventory, masquerade, LOLBins, secret-shaped argv (flag only), parent/child anomalies, signature best-effort, simple enumeration discrepancies when elevated |
| E | `persistence` | macOS LaunchAgents/Daemons, Login Items, cron; Linux systemd/cron/autostart/ld.so.preload; Windows Run keys, Startup, services, tasks, WMI/IFEO/Winlogon hotspots (best-effort) |
| F | `stealer_indicators` | Path IoCs, non-browser PIDs on browser profiles, wallet path openers, clipboard/keylogger-adjacent names, credential-tool **names** only, authorized_keys metadata, exfil CLI presence |
| G | `accounts_access` | Unexpected admins, guest, sudoers anomalies, sshd, shares/RDP, recent logons (sample) |
| H | `filesystem_hotspots` | World-writable PATH-sensitive paths, SUID/SGID/capabilities, recent executables in temp/Downloads/startup-adjacent dirs, browser extensions metadata, staging binaries in temp |
| I | `kernel_posture` | Drivers/kexts/system extensions (best-effort), security features disabled, docker socket exposure |
| J | `logs_sample` | Bounded auth/security log samples (size-capped) |
| K | `peripheral` | Recent USB/HID when OS APIs expose history (low confidence) |
| — | `coverage` | Per-collector status, failures, elevation re-run hint |

### 4.3 Hard collection rules

- **Never** read or export passwords, cookies, private keys, keychain dumps, or LSASS memory.
- Prefer argument-vector subprocesses / OS APIs over `shell=True`.
- Per-collector **timeout** (default 30–60s; configurable).
- Sequential execution by default (simpler, safer).
- Legitimate security tools are **flagged as present**, not auto-labeled malware; allowlist + Grok disambiguate.

### 4.4 Still out of scope for collectors

- Continuous PCAP
- Full-disk AV
- Secret material extraction
- Automatic remediation actions

## 5. Heuristics

### 5.1 Pipeline

```
ScanBundle → match rules → merge/dedupe → severity adjust → sort → ScanResult
```

### 5.2 Rule packs

| Pack | Examples |
|------|----------|
| `sniffing` | promisc iface, capture tool running, unexpected root CA + proxy combo |
| `stealer` | path IoC, non-browser holding browser profile handles, wallet + odd process |
| `process` | LOLBin encoded cmd, masquerade path, secrets-shaped argv (value stripped) |
| `network` | sensitive listener by unknown owner, reverse-shell-ish patterns |
| `persistence` | LaunchAgent → temp binary, Run key → Downloads, ld.so.preload set |
| `posture` | firewall off, SIP off, Defender disabled, world-writable SUID |
| `coverage` | collector skipped / limited |

### 5.3 Scoring

- Finding severity: `info` · `low` · `medium` · `high` · `critical`
- Overall risk: max severity + weighted counts + **chain boosts** (e.g. unexpected CA + system proxy + capture tool)
- Optional local `allowlist.yaml`: suppress known-good by path/publisher/rule-id; suppressed items remain in inventory as “acknowledged,” not open findings

### 5.4 Grok boundary

**Grok does not invent detections.** It ranks, explains, chains, and recommends. Heuristics own ground truth.

## 6. Redaction

`security/redact.py` builds `GrokPayload` from `ScanResult` before any network call.

| Data | Treatment |
|------|-----------|
| API keys, tokens, JWTs, passwords in text | `[REDACTED]` |
| Home directory absolute paths | `~/…` or hash middle segments |
| Usernames | optional stable hash per scan |
| Cmdlines with secret-shaped tokens | structure kept, token body redacted |
| Full environment dumps | never; flags only (e.g. `has_http_proxy=true`) |
| File contents / binary / memory | never |
| Payload size | cap ~100–200 KB: prioritize high-severity findings; always include coverage |

If redaction fails → **do not call Grok**; still write local heuristic reports.

## 7. Grok analyst (SpaceXAI SDK)

### 7.1 SDK and model policy

| Setting | v1 default | Rule |
|---------|------------|------|
| SDK | **`xai-sdk`** (`from xai_sdk import Client`) | Official SpaceXAI / xAI Python SDK; primary path |
| Model | `grok-4.5` | Flagship only |
| Reasoning | `reasoning_effort="high"` | Maximum intelligence; never default lower |
| Fallback model | **None** | Failure → heuristics-only section in reports |
| Temperature | low/stable (e.g. `0.2`) if supported alongside reasoning | Prefer accurate triage |
| Auth | `XAI_API_KEY` | No invented `SPACEXAI_*` vars |
| Client timeout | long (up to 3600s) | High reasoning can be slow |
| OpenAI-compat client | Not primary | Documented escape hatch only if SDK gap blocks shipping |
| Server-side tools | Not required for v1 | Host evidence is local; optional later |
| Escalation | Full redacted finding pack when Grok enabled | On-demand scan, not live rate-limited IDS |

### 7.2 Client pattern

```python
from xai_sdk import Client
from xai_sdk.chat import system, user

client = Client(api_key=os.getenv("XAI_API_KEY"), timeout=3600)
chat = client.chat.create(
    model="grok-4.5",
    reasoning_effort="high",
    messages=[system(HOST_IR_CHARTER)],
)
chat.append(user(redacted_scan_payload))
response = chat.sample()  # or stream for CLI progress
```

### 7.3 Analyst output (structured)

- `executive_summary`
- `threat_narrative`
- `prioritized_findings[]` (map back to heuristic rule ids)
- `likely_attacker_goals`
- `remediation_plan[]` (ordered)
- `questions_for_operator`
- `confidence`
- Report meta: `model_id`, `reasoning_effort`, latency, token usage when available

### 7.4 Prompt constraints

- Defensive IR only; no exploit or credential-theft how-to
- Distinguish legitimate admin/security tools from malice
- Respect allowlist and coverage limits
- Prefer actionable operator steps for the current OS

### 7.5 Offline / failure

- `--no-grok` or missing `XAI_API_KEY` → complete local reports, banner that Grok was skipped
- API/parse failure → same; never silent weaker model

## 8. CLI

```text
grok-inspect scan [options]
grok-inspect version
```

### 8.1 `scan` options (v1)

| Flag | Meaning |
|------|---------|
| `--out DIR` | Report directory (default `./reports`) |
| `--no-grok` | Heuristics only |
| `--allowlist PATH` | Extra allowlist file |
| `--verbose` / `-v` | Collector progress on stderr |
| `--timeout SEC` | Per-collector timeout override |

Optional later: `--json-only` to skip md/html (default remains full pack).

### 8.2 Exit codes

| Code | Meaning |
|------|---------|
| `0` | Completed; max severity info/low only (or clean) |
| `1` | Completed; medium or high findings present |
| `2` | Scan error (collector crash / invalid config) |
| `3` | Completed; one or more **critical** findings |

### 8.3 Terminal UX

Rich progress by collector → severity table → top findings → paths to report files → elevation hint if limited.

## 9. Reports

Timestamped basename, e.g. `grok-inspect-2026-08-08T100530Z`:

| Artifact | Contents |
|----------|----------|
| `*.md` | Coverage, findings, Grok section, remediation |
| `*.json` | Machine-readable `ScanResult` + `GrokAnalysis` + meta |
| `*.html` | Single-file brief (Jinja2 template) |
| CLI | Live summary |

Also update `reports/latest.{md,json,html}`.

### 9.1 JSON top-level schema

`version`, `started_at`, `finished_at`, `host`, `coverage`, `findings[]`, `score`, `grok`, `tool_version`, `model_meta` (when Grok ran).

`reports/` is **gitignored**. README warns reports may contain sensitive host metadata (even when Grok payload is redacted).

## 10. Config and secrets

| Source | Examples |
|--------|----------|
| Env | `XAI_API_KEY`, optional `XAI_MODEL` / `GROK_INSPECT_MODEL` (flagship override only) |
| `config/default.yaml` | model id, reasoning_effort, timeouts, severity thresholds, report dir, redaction mode |
| `.env` | via python-dotenv; never committed |

No product telemetry. Network egress for analysis is only the SpaceXAI API when Grok is enabled.

### 10.1 Config sketch

```yaml
model:
  id: grok-4.5
  reasoning_effort: high
  temperature: 0.2
  # no fallback_model

scan:
  collector_timeout_sec: 45
  payload_max_chars: 150000

reports:
  dir: reports
```

## 11. Dependencies (v1)

- Python **≥ 3.11**
- `xai-sdk` (SpaceXAI official SDK)
- `typer`, `rich`, `pydantic`, `pydantic-settings`
- `PyYAML`, `python-dotenv`, `Jinja2`
- Dev: `pytest`

OS tooling invoked best-effort when present (`ss`, `lsof`, `ip`, PowerShell cmdlets, etc.); missing tools → limited coverage, not hard failure of entire scan.

## 12. Testing strategy

| Layer | What |
|-------|------|
| Unit | redaction, rule matching, severity/chains, path normalization, exit codes |
| Fixtures | canned `ScanBundle` JSON per OS → expected findings |
| Integration | `scan --no-grok` smoke on developer machine |
| Agent contract | mock/fake `xai_sdk` responses; parse + failure fallback |

## 13. Security of the tool

- Read-only inspection intent (no kill, no quarantine, no installing persistence)
- No shell injection patterns where avoidable
- Mandatory redaction before SpaceXAI calls
- Minimal dependency surface
- `SECURITY.md` documents responsible use and secret handling
- Reports may be sensitive; operator responsibility for storage

## 14. End-to-end sequence (one scan)

1. Probe env/privileges  
2. Run collectors A–K + coverage (timeouts, status tags)  
3. Heuristics → findings + score  
4. Write local draft artifacts (heuristics complete)  
5. Redact → Grok via `xai-sdk` (unless `--no-grok` / no key)  
6. Merge Grok into reports  
7. Print CLI summary + exit code  

## 15. Implementation phases (for planning)

Suggested order after this spec is approved:

1. Scaffold package, config, models, CLI shell  
2. Platform probe + collector base + env/coverage  
3. Network + sniff surface collectors  
4. Process + persistence + stealer  
5. Accounts, filesystem, kernel, logs, peripheral  
6. Heuristic engine + rule packs + allowlist  
7. Redaction + report pack (md/json/html/terminal)  
8. Grok agent (`xai-sdk`, high reasoning)  
9. Tests, README, SECURITY, smoke run  

## 16. Success criteria (v1)

- `pip install -e .` works on macOS, Linux, Windows (Python 3.11+)  
- `grok-inspect scan --no-grok` completes and writes full report pack  
- Elevated vs non-elevated coverage differences are visible in reports  
- With `XAI_API_KEY`, scan uses **grok-4.5** + **reasoning_effort=high** via **xai-sdk**  
- No secret material intentionally collected or sent to the API  
- Unit tests cover redaction and core rules without network  

---

## Appendix A — Decisions log

| Decision | Choice |
|----------|--------|
| Trigger | Manual CLI scan |
| Scope | Comprehensive balanced host inspection |
| Privileges | Prefer elevated; degrade gracefully |
| AI data path | Local collect + redacted Grok analysis |
| Output | CLI + Markdown + JSON + HTML |
| Architecture | Modular Python collectors + heuristics + Grok |
| Grok model | `grok-4.5`, `reasoning_effort=high`, no downgrade |
| Grok SDK | Official SpaceXAI `xai-sdk` |

## Appendix B — References

- SpaceXAI quickstart: https://docs.x.ai/developers/quickstart  
- Reasoning / `reasoning_effort`: https://docs.x.ai/developers/model-capabilities/text/reasoning  
- Models: https://docs.x.ai/developers/models  
- Sibling patterns: Aegis (FIREWALL), CISO Advisory (`xai_sdk` agent)
