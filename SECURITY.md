# Security Policy

## Purpose

Grok Inspect is a **defensive** host inspection tool. Use it only on machines you own or are explicitly authorized to assess.

**No tool is “unhackable.”** This project is engineered **secure by design** against realistic threats to a local CLI security scanner.

## Secure-by-design controls

| Control | Implementation |
|---------|----------------|
| No shell injection | Collectors use `subprocess` with `shell=False` and fixed argv lists |
| Secret-scrubbed children | `XAI_API_KEY` and other secrets are **removed** from collector subprocess environments |
| Path confinement | Report dirs validated; writes refused under system roots (`/etc`, `/System`, …) |
| Safe YAML | `yaml.safe_load` only; size-capped; non-mapping roots rejected |
| Config cannot hold API keys | `api_key` / `xai_api_key` keys stripped from YAML |
| API key storage | **Only** project `.env` (gitignored); never in reports |
| Redaction | Secrets redacted before Grok payloads **and** before report writes |
| No raw model dump | `GrokAnalysis.raw_text` cleared before persistence |
| Model id allowlist | Only safe characters; rejects mini/fast downgrade names |
| Timeouts | Per-command and per-collector caps |
| Output caps | Stdout/evidence size limits |
| Jinja2 | Fixed template name, autoescape on |
| Errors | No full tracebacks in reports; exception text redacted |
| Read-only intent | No kill / quarantine / config mutation features |

## Threat model (v1)

**In scope (we harden against):**

- Malicious or malformed local config / allowlist YAML  
- Accidental secret inclusion in process command lines or evidence  
- Operator typo writing reports into system directories  
- Log/report leakage of `XAI_API_KEY`  
- Resource exhaustion from hung OS tools  

**Out of scope / residual risk:**

- Fully compromised root/admin already on the host  
- Kernel rootkits that lie to userland APIs  
- Supply-chain compromise of PyPI dependencies  
- Physical / side-channel attacks  
- Prompt injection changing only Grok’s **text** (the tool cannot act on Grok output automatically)  

## What we collect

- Process metadata, network listeners, persistence paths, posture flags  
- Stealer/sniffing **indicators** (paths, process names) — not stolen data  

## What we never intentionally collect

- Passwords, cookies, session tokens from browsers  
- Keychain / credential store contents  
- Private keys (PEM material is redacted if seen in text)  
- LSASS or process memory dumps  
- Full packet captures  

## API key storage (required)

| Location | Allowed? |
|----------|----------|
| Project `.env` (gitignored) | **Yes — only supported storage** |
| `config/*.yaml` | **No** (stripped if present) |
| Source / reports / commits | **No** |
| Shell export (ephemeral CI) | OK for one-off; prefer `.env` |

```bash
cp .env.example .env
# XAI_API_KEY=xai-...
grok-inspect doctor
```

## GitHub / publish hygiene

Before every push:

- [ ] `.env` is **not** staged (`git status` / `git check-ignore -v .env`)  
- [ ] No real reports under `reports/` staged (gitignored)  
- [ ] No API keys in docs or tests (use fakes only)  
- [ ] `pytest -q` passes  

## Reports

`reports/` may still contain **sensitive host metadata**. Protect it. Do not commit scan outputs.

## No automatic remediation

Grok Inspect does **not** kill processes, quarantine files, or change system configuration based on findings or Grok output.

## Reporting vulnerabilities

If you discover a vulnerability in Grok Inspect itself (e.g. secret leakage, injection), please report it privately to the repository maintainers before public disclosure.
