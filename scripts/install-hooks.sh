#!/usr/bin/env bash
# Install and activate git pre-commit hooks for docker-platform.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "==> Installing pre-commit hooks"
if ! command -v pre-commit >/dev/null 2>&1; then
    echo "pre-commit not found. Install it first:"
    echo "  pipx install pre-commit   # or: pip install --user pre-commit"
    echo "  (macOS) brew install pre-commit"
    exit 1
fi

pre-commit install --install-hooks
pre-commit install --hook-type commit-msg || true

echo "==> Hooks installed. Running once against all files (non-fatal)…"
pre-commit run --all-files || {
    echo "Some hooks reported issues. Fix them before committing."
    exit 0
}

echo "==> Done."
