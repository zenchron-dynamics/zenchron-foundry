#!/usr/bin/env bash
# =============================================================================
# scripts/lib/common.sh
# -----------------------------------------------------------------------------
# Single source of truth for the release toolchain: logging, the canonical
# validation regexes, and the authoritative 10-image matrix. Every release
# script sources this instead of re-declaring the matrix or re-implementing
# CalVer/revision checks.
#
# Portable to bash 3.2 (macOS system bash): no associative arrays, no ${x,,}.
#
# Usage:
#   . "$(dirname "$0")/lib/common.sh"      # from scripts/
#   scripts/lib/common.sh --self-test      # run the self-check
# =============================================================================
set -euo pipefail

# --- logging -----------------------------------------------------------------
log()  { printf '%s\n' "$*"; }
warn() { printf '%s\n' "$*" >&2; }
die()  { printf 'REFUSE: %s\n' "$*" >&2; exit 1; }

# --- canonical formats -------------------------------------------------------
# CalVer release tag: vYYYY.MM.DD with an optional .N hotfix ordinal.
CALVER_RE='^v[0-9]{4}\.[0-9]{2}\.[0-9]{2}(\.[0-9]+)?$'
# Strict CalVer (no hotfix ordinal) — used where a bare date is required.
CALVER_STRICT_RE='^v[0-9]{4}\.[0-9]{2}\.[0-9]{2}$'
# RC identifier: rc1, rc2, ... — never rc0, never leading-zero.
RC_RE='^rc[1-9][0-9]*$'
# Full git revision: exactly 40 lowercase hex.
HEX40_RE='^[0-9a-f]{40}$'
# OCI image digest.
DIGEST_RE='^sha256:[0-9a-f]{64}$'

is_calver()        { printf '%s' "${1:-}" | grep -Eq "$CALVER_RE"; }
is_calver_strict() { printf '%s' "${1:-}" | grep -Eq "$CALVER_STRICT_RE"; }
is_rc()            { printf '%s' "${1:-}" | grep -Eq "$RC_RE"; }
is_hex40()         { printf '%s' "${1:-}" | grep -Eq "$HEX40_RE"; }
is_digest()        { printf '%s' "${1:-}" | grep -Eq "$DIGEST_RE"; }

# require_* variants die() with a clear message; use in gate paths.
require_calver()  { is_calver  "${1:-}" || die "version '${1:-}' is not vYYYY.MM.DD[.N]"; }
require_rc()      { is_rc      "${1:-}" || die "rc '${1:-}' must match rc[1-9][0-9]*"; }
require_hex40()   { is_hex40   "${1:-}" || die "revision '${1:-}' is not 40 lowercase hex"; }

# --- authoritative image matrix ----------------------------------------------
# Ten images. Token form <family>:<selector>, where selector is the PHP minor
# for PHP families, or "prod" for the versionless edge images. This is the ONE
# place the matrix is defined; assert-image-matrix.sh, smoke-all.sh, ci.yml and
# the manifest/promotion tooling all derive from it.
MATRIX_IMAGES="php-cli:8.3 php-cli:8.4 php-fpm:8.3 php-fpm:8.4 php-worker:8.3 php-worker:8.4 php-frankenphp:8.3 php-frankenphp:8.4 nginx:prod caddy:prod"
MATRIX_COUNT=10

matrix_images() { printf '%s\n' $MATRIX_IMAGES; }   # one token per line
matrix_families() { for t in $MATRIX_IMAGES; do printf '%s\n' "${t%:*}"; done | sort -u; }

# image_label <family> [version] -> the ONE canonical label for an image.
#
# Every consumer of per-image reconciliation evidence pairs records by this
# string, so it has to have a single definition. It did not: the reconciler
# built `family + "/" + version` from whatever the caller passed, scan-images.yml
# passes `prod` for the edge images (matching MATRIX_IMAGES) while
# trusted-validation.yml passed an empty version, and the stale-exception
# aggregate stripped `prod` off entirely. The same nginx image was therefore
# "nginx/prod" in one path, "nginx" in another, and "nginx" in the canonical
# set — so the aggregate reported nginx and caddy as BOTH missing and
# unexpected on a run where all ten scans succeeded.
#
# Canonical form is `family/version`, mirroring the `family:version` spelling of
# MATRIX_IMAGES. An empty version means the versionless edge images, which
# MATRIX_IMAGES spells `prod`, so both spellings collapse to the same label.
image_label() {
  local fam="${1:?image_label: family required}" ver="${2:-}"
  case "$ver" in
    ""|prod) printf '%s/prod\n' "$fam" ;;
    *)       printf '%s/%s\n' "$fam" "$ver" ;;
  esac
}

# Every canonical image label, derived from MATRIX_IMAGES.
matrix_image_labels() {
  local t
  while read -r t; do image_label "${t%:*}" "${t##*:}"; done < <(matrix_images)
}

# Assert a counter hit the full matrix; used by every 10/10 gate.
assert_full_matrix() {
  test "${1:-0}" -eq "$MATRIX_COUNT" \
    || die "expected $MATRIX_COUNT images, got ${1:-0}"
}

# --- self-test ---------------------------------------------------------------
_common_self_test() {
  local fail=0
  _t() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }
  # positive
  _t "CalVer v2026.07.03"          'is_calver v2026.07.03'
  _t "CalVer hotfix v2026.07.03.1" 'is_calver v2026.07.03.1'
  _t "rc1 valid"                   'is_rc rc1'
  _t "40-hex valid"                'is_hex40 7b4985a1234567890abcdef1234567890abcdef1'
  # negative
  _t "empty version rejected"      '! is_calver ""'
  _t "malformed CalVer rejected"   '! is_calver 2026.7.3'
  _t "rc0 rejected"                '! is_rc rc0'
  _t "empty rc rejected"           '! is_rc ""'
  _t "abbreviated revision reject" '! is_hex40 7b4985a'
  _t "uppercase revision reject"   '! is_hex40 7B4985A1234567890ABCDEF1234567890ABCDEF1'
  _t "39-char revision rejected"   '! is_hex40 7b4985a1234567890abcdef1234567890abcde'
  # matrix
  _t "matrix has 10 images"        'test "$(matrix_images | wc -l | tr -d " ")" = 10'
  _t "matrix has 6 families"       'test "$(matrix_families | wc -l | tr -d " ")" = 6'
  _t "assert_full_matrix(10) ok"   'assert_full_matrix 10'
  _t "assert_full_matrix(9) fails" '! ( assert_full_matrix 9 ) 2>/dev/null'
  return $fail
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-}" in
    --self-test) _common_self_test && echo "common.sh: SELF-TEST OK" ;;
    *) echo "usage: common.sh --self-test" >&2; exit 2 ;;
  esac
fi
