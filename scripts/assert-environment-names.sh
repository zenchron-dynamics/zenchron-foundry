#!/usr/bin/env bash
# self-test: waived (thin wrapper; exercised by the "environment names" gate in scripts/macro-validate.sh and the ci.yml static-gates job)
# =============================================================================
# Zenchron Dynamics — release-environment name guard.
# Fails CI if any workflow pins a deployment `environment:` that is not one of
# the approved, protected release environments. This is the tripwire that stops
# a workflow from quietly resurrecting the old generic `rc` / `release` names
# (which have NO protection rules) or inventing an unapproved environment name
# that GitHub would auto-create *unprotected* on first run.
#
# Approved release environment names are EXACTLY:
#     foundry-rc
#     foundry-production
#
# Any other `environment:` value (rc, release, prod, staging, a typo, …) fails.
# Both the inline form (`environment: foundry-rc`) and the block form
# (`environment:` then `name: foundry-rc`) are checked. A computed value
# (a `${{ … }}` expression) is refused: a release environment must be a literal.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Scan tracked workflow files. `git ls-files` keeps us to committed sources and
# stays portable (no mapfile — macOS bash 3.2).
files="$(git ls-files -- '.github/workflows/*.yml' '.github/workflows/*.yaml')"
# SC-28: fail closed — this repo always has workflows, so an empty glob means
# the file discovery itself regressed and MUST NOT vacuous-pass the gate.
[ -n "$files" ] || { echo "==> assert-environment-names: FAIL — zero workflow files found (glob/discovery regression; the repo always has workflows)." >&2; exit 1; }

# All the real work is one awk pass per file: emit "file:line:VALUE" for every
# deployment environment name it can resolve.
findings="$(printf '%s\n' "$files" | while IFS= read -r f; do
    [ -f "$f" ] || continue
    awk -v F="$f" '
        # inline:  environment: <value>
        match($0, /^[[:space:]]*environment:[[:space:]]*[^[:space:]#]/) {
            v = $0
            sub(/^[[:space:]]*environment:[[:space:]]*/, "", v)
            sub(/[[:space:]]*#.*$/, "", v); gsub(/["'"'"']/, "", v)
            sub(/[[:space:]]+$/, "", v)
            if (v != "") { print F ":" NR ":" v; next }
        }
        # block:   environment:\n    name: <value>
        /^[[:space:]]*environment:[[:space:]]*$/ { inblk = 1; next }
        inblk && match($0, /^[[:space:]]*name:[[:space:]]*[^[:space:]#]/) {
            v = $0
            sub(/^[[:space:]]*name:[[:space:]]*/, "", v)
            sub(/[[:space:]]*#.*$/, "", v); gsub(/["'"'"']/, "", v)
            sub(/[[:space:]]+$/, "", v)
            inblk = 0
            if (v != "") { print F ":" NR ":" v }
            next
        }
        # any other non-blank line closes an open environment block
        inblk && /[^[:space:]]/ { inblk = 0 }
    ' "$f"
done)"

rc=0
count=0
if [ -n "$findings" ]; then
    while IFS= read -r hit; do
        [ -n "$hit" ] || continue
        count=$((count + 1))
        val="${hit##*:}"
        loc="${hit%:*}"
        case "$val" in
            foundry-rc|foundry-production) : ;;
            *)
                echo "FORBIDDEN environment name at $loc -> '$val'"
                echo "    (only 'foundry-rc' and 'foundry-production' are approved)"
                rc=1
                ;;
        esac
    done <<EOF
$findings
EOF
fi

if [ "$rc" -eq 0 ]; then
    echo "==> assert-environment-names: clean ($count deployment environment reference(s), all approved)."
else
    echo "==> assert-environment-names: FAILED. Rename the environments above to one of:"
    echo "    foundry-rc, foundry-production — and create them protected (see"
    echo "    scripts/check-release-environments.sh)."
fi
exit "$rc"
