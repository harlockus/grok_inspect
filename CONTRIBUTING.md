# Contributing to Grok Inspect

Thanks for helping improve a defensive host inspection tool.

## Ground rules

1. **Defensive only** — no exploit development, credential dumping, or offensive modules.  
2. **No secrets in git** — never commit `.env`, keys, or real scan reports.  
3. **Secure by design** — prefer `shell=False`, redaction, path checks, size limits.  
4. **Tests** — add or update unit tests for new rules and security helpers.  

## Setup

```bash
bash scripts/install.sh
source .venv/bin/activate
pytest -q
```

Do **not** use `pip install -e .` on macOS + Python 3.14 (see README). After code changes, reinstall with:

```bash
pip install .
# or
bash scripts/install.sh
```

## Development tips

- Collectors return **facts**; heuristics return **findings**.  
- Never send unredacted evidence to Grok.  
- Do not log or print `XAI_API_KEY`.  
- Keep OS-specific commands as static argv lists (no user-controlled shell strings).  

## Pull requests

- Clear description of what and why  
- Tests green (`pytest -q`)  
- Update docs if behavior or CLI changes  

## Reporting security issues

See [SECURITY.md](SECURITY.md). Prefer private disclosure for vulnerabilities in the tool itself.
