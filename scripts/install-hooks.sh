#!/usr/bin/env bash
# self-test: waived (thin wrapper; exercised by make init / make hooks on every dev bootstrap)
# Install local git hooks for zenchron-foundry.
# Installs the custom hooks in scripts/git-hooks/ into .git/hooks, and (if the
# pre-commit framework is available) wires up pre-commit too.
#
# These are COMPENSATING CONTROLS, not equivalent to enforced GitHub branch
# protection — they are local and bypassable, and only prevent accidents.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

HOOK_SRC="scripts/git-hooks"
HOOK_DST=".git/hooks"

if [ ! -d "$HOOK_DST" ]; then
    echo "Not a git working tree (no $HOOK_DST). Run from the repo root." >&2
    exit 1
fi

echo "==> Installing custom hooks from $HOOK_SRC -> $HOOK_DST"
for src in "$HOOK_SRC"/*; do
    [ -f "$src" ] || continue
    name="$(basename "$src")"
    cp "$src" "$HOOK_DST/$name"
    chmod +x "$HOOK_DST/$name"
    echo "    installed $name"
done

# Optional: pre-commit framework manages .git/hooks/pre-commit (overrides the
# copied fallback with the richer config-driven hook). pre-push stays custom.
if command -v pre-commit >/dev/null 2>&1; then
    echo "==> pre-commit framework found — installing managed hooks"
    pre-commit install --install-hooks
    pre-commit install --hook-type commit-msg || true
else
    echo "==> pre-commit framework not installed (optional)."
    echo "    The copied scripts/git-hooks/pre-commit fallback is active."
    echo "    For the full hook set: pipx install pre-commit  (or brew install pre-commit)"
fi

echo "==> Done. Active hooks:"
for h in "$HOOK_DST"/*; do
    case "$h" in *.sample) continue ;; esac
    [ -f "$h" ] && printf '    %s\n' "$(basename "$h")"
done
echo
echo "Reminder: local hooks are advisory and bypassable"
echo "(ZENCHRON_ALLOW_PROTECTED_PUSH=1). They prevent accidents, not attackers."
