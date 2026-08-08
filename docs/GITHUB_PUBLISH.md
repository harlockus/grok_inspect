# Publishing this repo to GitHub

## Pre-push checklist

- [ ] No `.env` file staged (must stay local)  
- [ ] No `reports/grok-inspect-*` or `latest.*` scan files staged  
- [ ] `git status` looks clean of secrets  
- [ ] `pytest -q` passes  
- [ ] README + USER_GUIDE accurate  

## First-time publish

```bash
cd /path/to/GROK_INSPECT

# Confirm secrets ignored
git check-ignore -v .env
# → .gitignore:… .env

# Create GitHub repo (example with gh CLI)
gh repo create GROK_INSPECT --private --source=. --remote=origin

# Or: create empty repo on GitHub, then:
# git remote add origin git@github.com:YOU/GROK_INSPECT.git

git push -u origin main
```

Prefer **private** first if the repo is still experimental.

## After clone (users)

```bash
git clone <url>
cd GROK_INSPECT
bash scripts/install.sh
source .venv/bin/activate
cp .env.example .env
# add XAI_API_KEY
grok-inspect doctor
grok-inspect scan -v
```

## Never push

| Path | Why |
|------|-----|
| `.env` | API keys |
| `reports/*` (scan outputs) | Host metadata |
| `.venv/` | Local environment |
| `data/allowlist.yaml` | May contain private paths |
