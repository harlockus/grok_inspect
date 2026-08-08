#!/usr/bin/env bash
# Reliable install for Grok Inspect (macOS / Linux / Windows Git Bash).
# Avoids broken setuptools "editable" installs on macOS Python 3.14+
# where __editable__.*.pth is UF_HIDDEN and ignored by site.py.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate

python -m pip install --upgrade pip setuptools wheel
# Non-editable install: package copied into site-packages (reliable imports)
python -m pip uninstall -y grok-inspect >/dev/null 2>&1 || true
python -m pip install ".[dev]"

# Clear any leftover broken editable pth files
rm -f .venv/lib/python*/site-packages/__editable__.*grok* 2>/dev/null || true
rm -f .venv/lib/python*/site-packages/grok_inspect_src.pth 2>/dev/null || true

echo ""
echo "Verifying import…"
python -c "import grok_inspect; print('  grok_inspect OK:', grok_inspect.__file__)"
echo "Verifying CLI…"
grok-inspect version
echo ""
echo "Install complete. Next:"
echo "  source .venv/bin/activate"
echo "  cp -n .env.example .env   # then set XAI_API_KEY (never commit .env)"
echo "  grok-inspect doctor"
echo "  grok-inspect scan -v"
echo "  sudo .venv/bin/grok-inspect scan -v   # elevated (optional)"
echo ""
echo "Docs: README.md · docs/USER_GUIDE.md · SECURITY.md"

