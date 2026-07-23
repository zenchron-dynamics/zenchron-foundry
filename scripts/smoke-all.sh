#!/usr/bin/env bash
# =============================================================================
# Zenchron Dynamics — run the full runtime smoke matrix.
#
# Builds (on demand) and smoke-tests all 10 runtime images:
#   php-cli, php-fpm, php-worker, php-frankenphp  x  {8.3, 8.4}
#   nginx, caddy
#
# Aggregates per-image results and prints a final roll-up. Exits nonzero if any
# check failed, any image failed to run, or ZERO images were tested.
#
# CI sharding: set SMOKE_FAMILIES to a space-separated subset of family names to
# restrict the matrix, e.g. SMOKE_FAMILIES="php-fpm nginx".
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
# shellcheck source=lib/common.sh
. "$ROOT/scripts/lib/common.sh"

DISPATCH="${ROOT}/scripts/smoke-test.sh"

# Full matrix, derived from MATRIX_IMAGES in lib/common.sh (SC-15): one
# "<family> <version>" pair per line, version empty for the versionless "prod"
# edge images (nginx/caddy) — the shape smoke-test.sh dispatches on.
smoke_matrix() {
    local t fam sel
    for t in $MATRIX_IMAGES; do
        fam="${t%:*}"; sel="${t#*:}"
        case "$sel" in
            prod) printf '%s\n' "$fam" ;;
            *)    printf '%s %s\n' "$fam" "$sel" ;;
        esac
    done
}

FAMILIES_FILTER="${SMOKE_FAMILIES:-}"

images_tested=0
images_failed=0
total_pass=0
total_fail=0

want_family() {  # $1=family -> 0 if it should run
    [ -z "$FAMILIES_FILTER" ] && return 0
    for _f in $FAMILIES_FILTER; do
        [ "$_f" = "$1" ] && return 0
    done
    return 1
}

while read -r family version; do
    [ -z "$family" ] && continue
    want_family "$family" || continue

    label="$family${version:+ $version}"
    printf '\n############################################################\n'
    printf '# smoke-all: %s\n' "$label"
    printf '############################################################\n'

    # Capture output while still streaming it to the console.
    out="$("$DISPATCH" "$family" "$version" 2>&1 || true)"
    printf '%s\n' "$out"

    summary="$(printf '%s\n' "$out" | grep -E '^SMOKE SUMMARY: ' | tail -n1 || true)"
    if [ -z "$summary" ]; then
        printf '!! %s produced no summary (build/run failure)\n' "$label" >&2
        images_failed=$((images_failed + 1))
        continue
    fi

    # Parse "SMOKE SUMMARY: <p> passed, <f> failed, <t> checks".
    p="$(printf '%s\n' "$summary" | sed -E 's/^SMOKE SUMMARY: ([0-9]+) passed.*/\1/')"
    f="$(printf '%s\n' "$summary" | sed -E 's/.* ([0-9]+) failed.*/\1/')"
    total_pass=$((total_pass + p))
    total_fail=$((total_fail + f))
    images_tested=$((images_tested + 1))
    [ "$f" -gt 0 ] && images_failed=$((images_failed + 1))
done <<EOF
$(smoke_matrix)
EOF

# Denominator derived from the authoritative matrix (no hardcoded /10).
printf '\n############################################################\n'
printf 'SMOKE-ALL: %d/%d images, %d checks passed, %d failed\n' \
    "$images_tested" "$MATRIX_COUNT" "$total_pass" "$total_fail"
printf '############################################################\n'

if [ "$images_tested" -eq 0 ]; then
    printf 'SMOKE-ALL ERROR: zero images tested (treated as failure)\n' >&2
    exit 3
fi
if [ "$images_failed" -gt 0 ] || [ "$total_fail" -gt 0 ]; then
    exit 1
fi
exit 0
