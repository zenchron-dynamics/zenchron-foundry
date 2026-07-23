#!/usr/bin/env bash
# self-test: waived (thin wrapper; exercised by the "no wolfi/apk guard" gate in scripts/macro-validate.sh and the ci.yml static-gates job)
# =============================================================================
# Zenchron Dynamics — supply-chain guard: no Wolfi / Chainguard / apk.
# Fails CI if ACTIVE (operational) files reintroduce a dependency we removed in
# the Debian-first migration (ADR-0001). Historical references are allowed ONLY
# in documentation (docs/**, CHANGELOG.md) and in this script's own patterns.
#
# Scanned (operational) paths: Dockerfiles, scripts, CI workflows, compose
# profiles/examples, Makefile, policies. Docs are intentionally NOT scanned so
# the ADR/migration guides can describe what was removed.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Forbidden patterns in active code (extended regex).
PATTERN='cgr\.dev|chainguard|wolfi-base|wolfi|melange|apko|apk[[:space:]]+add|apk[[:space:]]+upgrade|shyim/wolfi-php'

# Operational files to scan (tracked files only; docs are intentionally excluded).
# Portable: no `mapfile` (bash 3.2 on macOS lacks it).
rc=0
while IFS= read -r f; do
    [ -f "$f" ] || continue
    case "$f" in scripts/assert-no-wolfi.sh) continue ;; esac
    # Exclude references to our own internal filenames that legitimately contain
    # "wolfi" (this guard, and the migration doc referenced from READMEs/CI).
    hits="$(grep -InE "$PATTERN" "$f" 2>/dev/null | grep -vE 'assert-no-wolfi|wolfi-to-debian' || true)"
    if [ -n "$hits" ]; then
        echo "FORBIDDEN Wolfi/Chainguard/apk reference in active file: $f"
        printf '%s\n' "$hits" | sed 's/^/    /'
        rc=1
    fi
done < <(git ls-files -- 'images' 'scripts' '.github' 'profiles' 'examples' 'Makefile' 'policies')

if [ "$rc" -eq 0 ]; then
    echo "==> assert-no-wolfi: clean (no Wolfi/Chainguard/apk in active code)."
else
    echo "==> assert-no-wolfi: FAILED. Remove the references above or, if this is"
    echo "    historical documentation, move it under docs/ (see ADR-0001)."
fi
exit "$rc"
