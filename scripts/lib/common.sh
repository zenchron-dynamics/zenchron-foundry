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
# PHP 8.5 IS DELIBERATELY ABSENT FROM THE LIVE MATRIX, and its absence is now a
# POSITION rather than a blocker. The images DO build on linux/amd64 — the
# opcache and php-redis root causes were found and fixed, and four amd64
# children have been built, smoked, SBOM'd and scanned (evidence:
# docs/audits/experimental-php-8.5-linux-amd64/).
#
# They stay out of THIS list because production is MATRIX_COUNT images and 8.5
# has not earned that: no runtime contract in contracts/, no extension contract,
# no support commitment, no governance decisions, and no arm64 child at all.
# Adding them here would put eight extra children into a ~10-hour acceptance run
# whose expected count is derived from MATRIX_COUNT.
#
# They are NOT dead configuration either. They are an ENUMERATED experimental
# cohort with its own canonical plan and its own bounded capabilities:
#   policies/experimental-cohorts.yaml
#   scripts/experimental/experimental-plan.sh
#   scripts/experimental/assert-experimental-isolation.sh
# That plan REFUSES production acceptance, release manifests, promotion,
# sealing, signing, publication and the 8.3/8.4 governance selectors, and the
# isolation gate refuses the reverse from this side. Promoting 8.5 requires a
# lifecycle authorization change in policies/lifecycle.yaml, not an edit here.
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
  # Shape, not a count: a literal here has to be edited every time the matrix
  # grows, and it silently became wrong when PHP 8.5 landed. Assert the invariant
  # that actually matters — every entry is family:version and the set is unique.
  _t "matrix entries are all family:version" \
     'test -z "$(matrix_images | grep -vE "^[a-z0-9-]+:[a-z0-9.]+$" || true)"'
  _t "matrix entries are unique"    'test "$(matrix_images | wc -l)" = "$(matrix_images | sort -u | wc -l)"'
  _t "matrix is non-empty"          'test "$(matrix_images | wc -l | tr -d " ")" -gt 0'
  _t "matrix has 6 families"       'test "$(matrix_families | wc -l | tr -d " ")" = 6'
  _t "assert_full_matrix(MATRIX_COUNT) ok" 'assert_full_matrix "$MATRIX_COUNT"'
  _t "assert_full_matrix(short) fails"     '! ( assert_full_matrix "$((MATRIX_COUNT - 1))" ) 2>/dev/null'
  # MATRIX_COUNT is a deliberate tripwire for accidental MATRIX_IMAGES edits
  # (see assert-image-matrix.sh). It must agree with the list it guards.
  _t "MATRIX_COUNT matches MATRIX_IMAGES" \
     'test "$(matrix_images | wc -l | tr -d " ")" = "$MATRIX_COUNT"'
  # --- child + SBOM identity, the ONE derivation both sides call ------------
  _t "child_slug keeps the platform in the identity" \
     '[ "$(child_slug php-fpm 8.3 linux/amd64)" != "$(child_slug php-fpm 8.3 linux/arm64)" ]'
  _t "sbom_basename IS child_slug (no second spelling)" \
     '[ "$(sbom_basename php-fpm 8.3 linux/amd64)" = "$(child_slug php-fpm 8.3 linux/amd64)" ]'
  _t "sbom_filename is child_slug + the format extension" \
     '[ "$(sbom_filename php-fpm 8.3 linux/amd64 spdx-json)" = "php-fpm-8.3-linux-amd64.spdx.json" ]'
  _t "sbom_filename spells the edge images with their prod selector" \
     '[ "$(sbom_filename nginx prod linux/arm64 cdx-json)" = "nginx-prod-linux-arm64.cdx.json" ]'
  _t "an undeclared SBOM format is REFUSED, never guessed" \
     '! ( sbom_format_ext spdx-xml ) 2>/dev/null'
  _t "sbom_path joins without a double separator" \
     '[ "$(sbom_path /tmp/s caddy prod linux/amd64 spdx-json)" = "/tmp/s/caddy-prod-linux-amd64.spdx.json" ]'
  _t "sbom_filenames_for_child emits one name per declared format" \
     '[ "$(sbom_filenames_for_child caddy prod linux/amd64 | wc -l | tr -d " ")" = "$(printf "%s\\n" $SBOM_FORMATS | wc -l | tr -d " ")" ]'
  # NO TWO CHILDREN COLLIDE. The whole matrix on both platforms, in both
  # formats, must produce exactly as many distinct filenames as there are
  # (child, format) pairs. A blind character substitution fails this.
  _t "no two children collide onto one SBOM filename across the whole matrix" \
     'n=0; out=""
      for t in $MATRIX_IMAGES; do
        for p in linux/amd64 linux/arm64; do
          for f in $SBOM_FORMATS; do
            out="$out$(sbom_filename "${t%:*}" "${t##*:}" "$p" "$f")
"; n=$((n+1))
          done
        done
      done
      [ "$(printf %s "$out" | sort -u | wc -l | tr -d " ")" = "$n" ]'
  return $fail
}

# --- canonical child identity (platform-bound) -------------------------------
# ONE definition of what identifies an acceptance child, used by the workflow,
# the authorizer and the tests.
#
# WHY. image_label() answers "which image" — php-fpm/8.3 — and is correct for
# that. It is NOT an identity for a CHILD, because one image produces one child
# per platform. When the platform axis was added, the artifact name and the
# evidence filename kept using the image label, so php-fpm/8.3 on amd64 and on
# arm64 both wrote `php-fpm-8.3.json` and both uploaded
# `child-php-fpm-8.3-<run>-<attempt>`. With `merge-multiple: true` the second
# overwrites the first: 20 planned children could yield at most 10 distinct
# evidence records, and the authorizer would refuse for a defect rather than a
# finding. Cancelled run 32123758374 is the record of that.
#
# child_key  <fam> <ver> <platform>  -> php-fpm/8.3/linux/amd64   (canonical)
# child_slug <fam> <ver> <platform>  -> php-fpm-8.3-linux-amd64   (fs/artifact safe)
#
# The slug is deliberately NOT a blind character substitution: it is built from
# validated components, so two different keys cannot normalise onto one slug.
child_key() {
  local fam="${1:?child_key: family required}" ver="${2:-}" plat="${3:?child_key: platform required}"
  printf '%s/%s\n' "$(image_label "$fam" "$ver")" "$plat"
}

child_slug() {
  local fam="${1:?child_slug: family required}" ver="${2:-}" plat="${3:?child_slug: platform required}"
  # Refuse anything that could collide or escape a path. A slug is an identity,
  # and an identity that can be produced two ways is not one.
  case "$fam" in ""|*[!a-zA-Z0-9._-]*) die "child_slug: invalid family '$fam'" ;; esac
  case "$ver" in *[!a-zA-Z0-9._-]*)    die "child_slug: invalid selector '$ver'" ;; esac
  case "$plat" in
    linux/*) : ;;
    *) die "child_slug: platform must be linux/<arch>, got '$plat'" ;;
  esac
  local arch="${plat#linux/}"
  case "$arch" in ""|*[!a-zA-Z0-9]*) die "child_slug: invalid architecture '$arch'" ;; esac
  local label; label="$(image_label "$fam" "$ver")"
  printf '%s-linux-%s\n' "${label//\//-}" "$arch"
}

# --- canonical SBOM identity (producer AND consumer) -------------------------
# ONE derivation of an SBOM's filename, called by the producer
# (scripts/generate-sbom.sh) and by every consumer (the evidence bundle, the
# licence inventory, the release seal).
#
# WHY. The producer derived its filename by blind character substitution on the
# image reference — NAME=$(echo "$IMAGE" | tr '/:@' '___') — while the evidence
# bundle looked up <child_slug>.spdx.json. The two sets never intersected, so a
# complete SBOM directory produced `sbom.present: false` with exit 0: a release
# whose bill of materials was silently absent, reported as a clean build. That
# is the same second-derivation defect child_slug() was introduced to remove
# (see the child_key note above), reappearing one layer out.
#
# A blind substitution is also not an identity: `a/b:c` and `a_b_c` and `a:b/c`
# all normalise onto one name, so two different images can claim one SBOM. The
# derivation below is built from the SAME validated components as child_slug(),
# so platform stays part of the identity and two distinct children cannot
# collide onto one filename.
#
# The formats are closed. An SBOM in a format nobody declared is not a bill of
# materials the release path can reason about, so asking for one REFUSES rather
# than inventing an extension.
SBOM_FORMATS="spdx-json cdx-json"

# sbom_format_ext <format> -> the ONE extension for that format
sbom_format_ext() {
  case "${1:?sbom_format_ext: format required}" in
    spdx-json) printf '.spdx.json\n' ;;
    cdx-json)  printf '.cdx.json\n' ;;
    *) die "sbom_format_ext: unknown SBOM format '$1' (declared: $SBOM_FORMATS)" ;;
  esac
}

# sbom_basename <fam> <ver> <platform> -> php-fpm-8.3-linux-amd64
# Deliberately child_slug() itself rather than a parallel spelling: an SBOM
# names a CHILD, and a child has exactly one identity in this repository.
sbom_basename() { child_slug "${1:-}" "${2:-}" "${3:-}"; }

# sbom_filename <fam> <ver> <platform> <format> -> php-fpm-8.3-linux-amd64.spdx.json
sbom_filename() {
  local base ext
  base="$(child_slug "${1:-}" "${2:-}" "${3:-}")" || return 1
  ext="$(sbom_format_ext "${4:?sbom_filename: format required}")" || return 1
  printf '%s%s\n' "$base" "$ext"
}

# sbom_path <dir> <fam> <ver> <platform> <format>
sbom_path() {
  local dir="${1:?sbom_path: directory required}" name
  shift
  name="$(sbom_filename "$@")" || return 1
  printf '%s/%s\n' "${dir%/}" "$name"
}

# Every filename the closed format set can produce for one child, one per line.
# The consumer uses this to decide whether a file in an SBOM directory is bound
# to a child at all — an unbound file is refused rather than ignored.
sbom_filenames_for_child() {
  local f
  for f in $SBOM_FORMATS; do sbom_filename "${1:-}" "${2:-}" "${3:-}" "$f"; done
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-}" in
    --self-test) _common_self_test && echo "common.sh: SELF-TEST OK" ;;
    *) echo "usage: common.sh --self-test" >&2; exit 2 ;;
  esac
fi
