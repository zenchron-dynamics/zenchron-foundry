#!/usr/bin/env bash
# =============================================================================
# scripts/verify-platforms.sh <image-ref>
# -----------------------------------------------------------------------------
# Asserts a published image is a manifest LIST advertising BOTH linux/amd64 and
# linux/arm64, with no duplicate platform records. Used by the RC certification
# workflow over each published digest.
#
# Env: REQUIRED_PLATFORMS (default linux/amd64,linux/arm64), FETCH_INDEX_FN
#      (injectable; default docker buildx / crane) for offline tests.
# =============================================================================
set -euo pipefail
_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
. "$_d/lib/common.sh"
REQUIRED_PLATFORMS="${REQUIRED_PLATFORMS:-linux/amd64,linux/arm64}"

_default_index() { crane manifest "$1" 2>/dev/null || docker buildx imagetools inspect "$1" --format '{{json .Manifest}}' 2>/dev/null; }

# count_platform <index-json> <os/arch> -> number of manifest entries for it
count_platform() {
  local os="${2%%/*}" arch="${2##*/}"
  jq --arg os "$os" --arg arch "$arch" '[ (.manifests // [])[] | select(.platform.os==$os and .platform.architecture==$arch) ] | length' <<<"$1" 2>/dev/null || echo 0
}

verify_platforms() {
  local ref="$1" fetch="${FETCH_INDEX_FN:-_default_index}"
  command -v jq >/dev/null || die "jq required"
  local idx; idx="$("$fetch" "$ref")"; [ -n "$idx" ] || die "could not fetch image index for $ref"
  jq -e '.manifests' >/dev/null 2>&1 <<<"$idx" || die "$ref is not a manifest list (no .manifests)"
  local p n
  IFS=',' read -r -a _plats <<<"$REQUIRED_PLATFORMS"
  for p in "${_plats[@]}"; do
    n="$(count_platform "$idx" "$p")"
    [ "$n" -ge 1 ] || die "$ref missing platform $p"
    [ "$n" -le 1 ] || die "$ref has duplicate platform record for $p ($n)"
  done
  echo "PLATFORMS OK [$ref]: $REQUIRED_PLATFORMS"
}

_vp_self_test() {
  command -v jq >/dev/null || { echo "SKIP - jq absent"; return 0; }
  local fail=0
  local good='{"manifests":[{"platform":{"os":"linux","architecture":"amd64"}},{"platform":{"os":"linux","architecture":"arm64"}}]}'
  local single='{"manifests":[{"platform":{"os":"linux","architecture":"amd64"}}]}'
  local dup='{"manifests":[{"platform":{"os":"linux","architecture":"amd64"}},{"platform":{"os":"linux","architecture":"amd64"}},{"platform":{"os":"linux","architecture":"arm64"}}]}'
  local notlist='{"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{}}'
  _run() { ( FETCH_INDEX_FN=_mk verify_platforms x ) >/dev/null 2>&1; }  # subshell: die()->exit contained
  _mk() { printf '%s' "$_M"; }
  _ok() { _M="$2"; if _run; then echo "ok   - $1"; else echo "FAIL - $1 (want pass)"; fail=1; fi; }
  _no() { _M="$2"; if _run; then echo "FAIL - $1 (want reject)"; fail=1; else echo "ok   - $1"; fi; }
  _ok "amd64+arm64 index passes"   "$good"
  _no "single-arch rejected"       "$single"
  _no "duplicate platform rejected" "$dup"
  _no "non-manifest-list rejected" "$notlist"
  return $fail
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-}" in
    --self-test) _vp_self_test && echo "verify-platforms.sh: SELF-TEST OK" ;;
    "") echo "usage: verify-platforms.sh <image-ref> | --self-test" >&2; exit 2 ;;
    *) verify_platforms "$1" ;;
  esac
fi
