#!/usr/bin/env bash
# =============================================================================
# scripts/release/build-acceptance-matrix.sh <platform-list>
# -----------------------------------------------------------------------------
# THE single enumeration of acceptance children. Emits the GitHub Actions matrix
# as JSON: one entry per (image, platform), each carrying exactly ONE platform.
#
# WHY THIS EXISTS.
#
# The pinned acceptance basis asked for 20 children — 10 images on two platforms
# in one run, under one frozen vulnerability database. That was unreachable. The
# stage matrix had no platform axis: it hardcoded ten image entries and took the
# platform from `inputs.platforms` verbatim, and every child then refused with
#
#     REFUSE: stage one platform per run; got 'linux/amd64,linux/arm64'
#
# so a two-platform dispatch produced ten immediate refusals, zero children and
# zero evidence, while the authorizer computed expected_children = 10 x 2 = 20
# and refused for finding none. Removing the comma guard would have been the
# wrong fix: it exists so a comma-separated build cannot emit a multi-platform
# INDEX whose digest names the wrong object. The guard was right; the
# enumeration was missing.
#
# It also removes a second source of truth. The workflow's ten hardcoded entries
# duplicated MATRIX_IMAGES in scripts/lib/common.sh with nothing asserting they
# agreed, so the shipping matrix could drift between the release workflow and
# every tool that derives from the library.
#
# Contexts are DERIVED, not listed: images/<fam> for a `prod` selector,
# images/<fam>/<ver> otherwise. Verified total against the previous hardcoded
# list before that list was deleted.
#
# FAILS CLOSED. An empty, malformed, duplicated or non-linux platform list is a
# refusal, and this runs in the cheap guard job — before any builder starts —
# so a typo costs seconds instead of a matrix.
#
# NOTE ON AUTHORIZATION. This deliberately does NOT check platform
# authorization. That check lives in the authorizer, after the matrix, so an
# unevidenced architecture still builds and records ten children before being
# refused — which is exactly how #139's arm64 evidence was acquired. Validating
# shape early and authority late is intentional.
#
# Usage:
#   build-acceptance-matrix.sh "linux/amd64,linux/arm64"   # -> {"include":[...]}
#   build-acceptance-matrix.sh --count "linux/amd64"       # -> 10
#   build-acceptance-matrix.sh --self-test
# =============================================================================
set -uo pipefail
_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
. "$_d/../lib/common.sh"

# validate_platforms <list> -> normalised newline list on stdout, or refuse
validate_platforms() {
  local raw="${1-}" seen="" p
  [ -n "$raw" ] || { echo "REFUSE: no platforms requested" >&2; return 1; }
  case "$raw" in
    *,,*|,*|*,) echo "REFUSE: malformed platform list '$raw' (empty element)" >&2; return 1 ;;
  esac
  local out=""
  for p in ${raw//,/ }; do
    case "$p" in
      linux/*)
        [ "$p" != "linux/" ] || { echo "REFUSE: '$p' names no architecture" >&2; return 1; }
        ;;
      *) echo "REFUSE: '$p' is not a linux/<arch> platform" >&2; return 1 ;;
    esac
    case " $seen " in
      *" $p "*) echo "REFUSE: platform '$p' requested twice" >&2; return 1 ;;
    esac
    seen="$seen $p"
    out="${out}${p}"$'\n'
  done
  [ -n "$out" ] || { echo "REFUSE: no platforms requested" >&2; return 1; }
  printf '%s' "$out"
}

build_matrix() {
  local plats; plats="$(validate_platforms "${1-}")" || return 1
  command -v jq >/dev/null || { echo "REFUSE: jq required" >&2; return 1; }

  local entries="" tok fam ver ctx plat
  while IFS= read -r plat; do
    [ -n "$plat" ] || continue
    while IFS= read -r tok; do
      [ -n "$tok" ] || continue
      fam="${tok%:*}"; ver="${tok##*:}"
      # Context derivation, not a second list to maintain.
      if [ "$ver" = prod ]; then ctx="images/${fam}"; else ctx="images/${fam}/${ver}"; fi
      entries="${entries}$(jq -nc --arg f "$fam" --arg v "$ver" --arg c "$ctx" --arg p "$plat" \
        '{fam:$f, ver:$v, ctx:$c, platform:$p}')"$'\n'
    done < <(matrix_images)
  done <<< "$plats"

  printf '%s' "$entries" | jq -sc '{include: .}'
}

matrix_count() {
  local m; m="$(build_matrix "${1-}")" || return 1
  printf '%s' "$m" | jq '.include|length'
}

self_test() {
  local pass=0 fail=0 out
  ck() { if eval "$2"; then pass=$((pass+1)); echo "ok   - $1"; else fail=$((fail+1)); echo "FAIL - $1"; fi; }

  # --- shape ---------------------------------------------------------------
  ck "one platform yields exactly MATRIX_COUNT children" \
     "[ \"\$(matrix_count 'linux/amd64')\" = '$MATRIX_COUNT' ]"
  ck "two platforms yield exactly 2 x MATRIX_COUNT children" \
     "[ \"\$(matrix_count 'linux/amd64,linux/arm64')\" = '$((MATRIX_COUNT * 2))' ]"
  ck "three platforms scale linearly" \
     "[ \"\$(matrix_count 'linux/amd64,linux/arm64,linux/riscv64')\" = '$((MATRIX_COUNT * 3))' ]"

  out="$(build_matrix 'linux/amd64,linux/arm64')"

  # --- every child carries exactly ONE platform ---------------------------
  ck "no child receives a comma-separated platform" \
     "! printf '%s' \"\$out\" | jq -e '.include[]|select(.platform|contains(\",\"))' >/dev/null"
  ck "every child platform is linux/<arch>" \
     "printf '%s' \"\$out\" | jq -e 'all(.include[]; .platform|test(\"^linux/[a-z0-9]+\$\"))' >/dev/null"
  ck "both requested platforms are present" \
     "[ \"\$(printf '%s' \"\$out\" | jq -r '[.include[].platform]|unique|length')\" = 2 ]"
  ck "each platform carries the full image set" \
     "[ \"\$(printf '%s' \"\$out\" | jq -r '[.include[]|select(.platform==\"linux/arm64\")]|length')\" = '$MATRIX_COUNT' ]"

  # --- identity uniqueness ------------------------------------------------
  ck "(fam,ver,platform) triples are unique" \
     "[ \"\$(printf '%s' \"\$out\" | jq -r '[.include[]|\"\\(.fam):\\(.ver):\\(.platform)\"]|unique|length')\" = '$((MATRIX_COUNT * 2))' ]"
  ck "image identity alone is NOT unique across platforms (cross product is real)" \
     "[ \"\$(printf '%s' \"\$out\" | jq -r '[.include[]|\"\\(.fam):\\(.ver)\"]|unique|length')\" = '$MATRIX_COUNT' ]"

  # --- derived from the library, not a second list ------------------------
  ck "families come from MATRIX_IMAGES" \
     "[ \"\$(printf '%s' \"\$out\" | jq -r '[.include[].fam]|unique|sort|join(\",\")')\" = \"\$(matrix_families | sort | paste -sd, -)\" ]"
  ck "every context exists on disk" \
     "printf '%s' \"\$out\" | jq -r '.include[].ctx' | sort -u | while read -r c; do [ -d \"\$c\" ] || { echo \"missing \$c\" >&2; exit 1; }; done"

  # --- refusals, each for its own reason ----------------------------------
  ck "an empty list refuses"                  "! build_matrix '' >/dev/null 2>&1"
  ck "a non-linux platform refuses"           "! build_matrix 'darwin/arm64' >/dev/null 2>&1"
  ck "a bare 'linux/' refuses"                "! build_matrix 'linux/' >/dev/null 2>&1"
  ck "a duplicate platform refuses"           "! build_matrix 'linux/amd64,linux/amd64' >/dev/null 2>&1"
  ck "a trailing comma refuses"               "! build_matrix 'linux/amd64,' >/dev/null 2>&1"
  ck "a leading comma refuses"                "! build_matrix ',linux/amd64' >/dev/null 2>&1"
  ck "an empty middle element refuses"        "! build_matrix 'linux/amd64,,linux/arm64' >/dev/null 2>&1"

  # Refusal DIAGNOSTICS, so a refusal cannot pass for the wrong reason.
  #
  # Output is CAPTURED first. `build_matrix ... | grep` under `set -o pipefail`
  # reports build_matrix's status, and build_matrix fails here ON PURPOSE, so a
  # matching grep would still read as a failed assertion. This is the fourth
  # place in this repository that trap has bitten; the shape is always an
  # assertion about a deliberately-failing command.
  why() { build_matrix "$1" 2>&1 || true; }
  ck "the duplicate refusal names the duplicate" \
     "why 'linux/amd64,linux/amd64' | grep -q 'requested twice'"
  ck "the non-linux refusal names the platform" \
     "why 'darwin/arm64' | grep -q 'not a linux/<arch> platform'"
  ck "the empty refusal says nothing was requested" \
     "why '' | grep -q 'no platforms requested'"

  echo "----"
  printf 'self-test: %d ok, %d failed\n' "$pass" "$fail"
  [ "$fail" -eq 0 ]
}

# NO ARGUMENT is a usage error; an EMPTY argument is a refusal. Those are
# different: the workflow passes "$PLATFORMS" positionally, so an empty dispatch
# input arrives as an empty string and must produce the refusal reason rather
# than a usage banner that says nothing about what was wrong.
if [ "$#" -eq 0 ]; then
  echo "usage: $(basename "$0") <platform-list> | --count <list> | --self-test" >&2
  exit 64
fi
case "$1" in
  --self-test) self_test ;;
  --count)     shift; matrix_count "${1-}" ;;
  *)           build_matrix "$1" ;;
esac
