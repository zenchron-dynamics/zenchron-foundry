#!/usr/bin/env bash
# =============================================================================
# scripts/lib/registry-probe.sh
# -----------------------------------------------------------------------------
# Pre-publish immutability guard for an immutable RC tag. The tag name already
# embeds the source SHA, so a DIFFERENT commit can never collide; this guards
# the remaining case — the SAME immutable tag already present — and decides
# between an idempotent resume and a hard conflict.
#
# probe_immutable_tag <ref> <expected_revision>  ->  echoes a verdict + returns:
#     ABSENT   (0)  tag does not exist            -> publish
#     RESUME   (10) present, same revision label  -> idempotent resume allowed
#     CONFLICT (20) present, different revision    -> fail permanently
#     UNAVAIL  (30) registry lookup failed         -> fail closed
#
# Resolvers are injectable so this is testable offline:
#     PROBE_EXISTS_FN <ref>   -> exit 0 if the tag exists, 1 if absent, 2 if the
#                                lookup itself failed (network/registry down)
#     PROBE_REV_FN    <ref>   -> echo the image's org.opencontainers.image.revision
# Defaults use `docker buildx imagetools inspect`.
# =============================================================================
set -euo pipefail
_rp_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
[ -n "${_COMMON_SOURCED:-}" ] || . "$_rp_dir/common.sh"
_COMMON_SOURCED=1

_default_exists() {
  # 0 exists, 1 absent, 2 lookup failed. imagetools distinguishes "not found"
  # (absent) from other errors (treat as lookup failure -> fail closed).
  local out; out="$(docker buildx imagetools inspect "$1" 2>&1)" && return 0
  printf '%s' "$out" | grep -qiE 'not found|no such manifest|manifest unknown|404' && return 1
  return 2
}
_default_rev() {
  # Read org.opencontainers.image.revision. For a multi-arch image the ref is an
  # OCI index whose `.Image.Config` is empty (the label lives on each platform
  # child), so a direct read returns "" and would spuriously CONFLICT on resume.
  # Resolve one linux platform child manifest first, then read the label off it.
  # A single-arch image has no `.Manifest.Manifests`, so child is empty and we
  # read the ref directly.
  local ref="$1" child target="$1" repo
  child="$(docker buildx imagetools inspect "$ref" \
    --format '{{ range .Manifest.Manifests }}{{ if eq .Platform.OS "linux" }}{{ println .Digest }}{{ end }}{{ end }}' 2>/dev/null \
    | grep -m1 '^sha256:')"
  if [ -n "$child" ]; then
    repo="${ref%%@*}"; repo="${repo%:*}"; target="$repo@$child"
  fi
  docker buildx imagetools inspect "$target" \
    --format '{{ index .Image.Config.Labels "org.opencontainers.image.revision" }}' 2>/dev/null
}

probe_immutable_tag() {
  local ref="$1" expected="$2"
  local exists_fn="${PROBE_EXISTS_FN:-_default_exists}"
  local rev_fn="${PROBE_REV_FN:-_default_rev}"

  local rc; "$exists_fn" "$ref"; rc=$?
  case "$rc" in
    1) echo "ABSENT $ref"; return 0 ;;
    2) echo "UNAVAIL $ref"; return 30 ;;   # fail closed
  esac
  # present: compare revision label
  local got; got="$("$rev_fn" "$ref")"
  if [ -n "$got" ] && [ "$got" = "$expected" ]; then
    echo "RESUME $ref (revision $got)"; return 10
  fi
  echo "CONFLICT $ref (present revision '${got:-<none>}' != expected '$expected')"; return 20
}

# --- self-test (mocked resolvers) --------------------------------------------
_rp_self_test() {
  local fail=0 R=7b4985a1234567890abcdef1234567890abcdef1
  # mock resolvers read _M_EXISTS (0/1/2) and _M_REV from the environment
  _m_exists() { return "${_M_EXISTS:-1}"; }
  _m_rev()    { printf '%s' "${_M_REV:-}"; }
  _case() { # name  exists-rc  rev  expected-revision  want-verdict  want-code
    local out code
    out="$(PROBE_EXISTS_FN=_m_exists PROBE_REV_FN=_m_rev _M_EXISTS="$2" _M_REV="$3" \
           probe_immutable_tag ghcr.io/x/php-cli:t "$4" 2>&1)"; code=$?
    if printf '%s' "$out" | grep -q "^$5 " && [ "$code" = "$6" ]; then
      echo "ok   - $1"; else echo "FAIL - $1: '$out' code=$code (want $5/$6)"; fail=1; fi
  }
  _case "absent -> publish"          1 ""  "$R" ABSENT   0
  _case "present same rev -> resume" 0 "$R" "$R" RESUME   10
  _case "present diff rev -> conflict" 0 aaaa "$R" CONFLICT 20
  _case "present no label -> conflict" 0 ""  "$R" CONFLICT 20
  _case "lookup failed -> fail closed" 2 ""  "$R" UNAVAIL  30
  return $fail
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-}" in
    --self-test) _rp_self_test && echo "registry-probe.sh: SELF-TEST OK" ;;
    *) echo "usage: registry-probe.sh --self-test" >&2; exit 2 ;;
  esac
fi
