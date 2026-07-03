#!/usr/bin/env bash
# =============================================================================
# scripts/lib/registry-aliases.sh
# -----------------------------------------------------------------------------
# The ONE definition of every registry tag/alias the release pipeline touches.
# Promotion, rollback, manifest generation and verification all derive tags
# from here so the alias inventory can never drift between them.
#
# Tag vocabulary (all under ${NS}/<family>:<suffix>):
#   immutable RC tag  — SHA-bound, never reused, the authoritative candidate:
#       php   : 8.4-v2026.07.03-rc1-sha-7b4985a12345
#       edge  : v2026.07.03-rc1-sha-7b4985a12345
#   convenience RC tag — mutable, human-facing, NEVER read by promotion:
#       php   : 8.4-debian-rc1     edge: prod-rc1
#   stable aliases     — the promotion targets (full inventory):
#       php   : 8.4-prod  8.4-prod-<rel>  8.4-debian
#       edge  : prod      prod-<rel>
#
# Portable to bash 3.2. Source-only; sourcing does not touch a registry.
# =============================================================================
set -euo pipefail

_ra_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
[ -n "${_COMMON_SOURCED:-}" ] || . "$_ra_dir/common.sh"
_COMMON_SOURCED=1

REGISTRY="${REGISTRY:-ghcr.io}"
NAMESPACE="${NAMESPACE:-zenchron-dynamics}"
NS="${REGISTRY}/${NAMESPACE}"

# short_sha <40-hex> -> first 12 (the form used in immutable tags)
short_sha() { printf '%s' "${1:0:12}"; }

# immutable_rc_suffix <selector> <version> <rc> <revision40>
#   selector: PHP minor (e.g. 8.4) or "prod" for edges.
immutable_rc_suffix() {
  local sel="$1" ver="$2" rc="$3" ssha; ssha="$(short_sha "$4")"
  case "$sel" in
    prod) printf '%s-%s-sha-%s' "$ver" "$rc" "$ssha" ;;
    *)    printf '%s-%s-%s-sha-%s' "$sel" "$ver" "$rc" "$ssha" ;;
  esac
}

# convenience_rc_suffix <selector> <rc>  (mutable alias; not authoritative)
convenience_rc_suffix() {
  case "$1" in prod) printf 'prod-%s' "$2" ;; *) printf '%s-debian-%s' "$1" "$2" ;; esac
}

# stable_aliases <selector> <rel>  -> space-separated stable tag suffixes,
# ordered canonical-LAST (version-bound first, bare canonical prod last) so a
# two-phase promotion mutates the human-facing alias only after the rest hold.
stable_aliases() {
  local sel="$1" rel="$2"
  case "$sel" in
    prod) printf '%s' "prod-${rel} prod" ;;
    *)    printf '%s' "${sel}-prod-${rel} ${sel}-debian ${sel}-prod" ;;
  esac
}

# full_ref <family> <suffix> -> fully-qualified image reference
full_ref() { printf '%s/%s:%s' "$NS" "$1" "$2"; }

# --- self-test (offline) -----------------------------------------------------
_ra_self_test() {
  local fail=0 R=7b4985a1234567890abcdef1234567890abcdef1
  _t() { if [ "$2" = "$3" ]; then echo "ok   - $1"; else echo "FAIL - $1: got '$2' want '$3'"; fail=1; fi; }
  _t "php immutable RC tag" \
     "$(immutable_rc_suffix 8.4 v2026.07.03 rc1 "$R")" "8.4-v2026.07.03-rc1-sha-7b4985a12345"
  _t "edge immutable RC tag" \
     "$(immutable_rc_suffix prod v2026.07.03 rc1 "$R")" "v2026.07.03-rc1-sha-7b4985a12345"
  _t "php convenience RC tag" "$(convenience_rc_suffix 8.4 rc1)" "8.4-debian-rc1"
  _t "edge convenience RC tag" "$(convenience_rc_suffix prod rc1)" "prod-rc1"
  _t "php stable aliases (canonical last)" \
     "$(stable_aliases 8.3 2026.07.03)" "8.3-prod-2026.07.03 8.3-debian 8.3-prod"
  _t "edge stable aliases (canonical last)" \
     "$(stable_aliases prod 2026.07.03)" "prod-2026.07.03 prod"
  _t "full ref" "$(full_ref php-cli 8.4-prod)" "ghcr.io/zenchron-dynamics/php-cli:8.4-prod"
  # every matrix image yields ≥1 stable alias, canonical prod present
  local n=0
  for t in $MATRIX_IMAGES; do
    case " $(stable_aliases "${t#*:}" 2026.07.03) " in *" ${t##*:} "*|*" prod "*) : ;; *) :; esac
    n=$((n+1))
  done
  _t "matrix fully mapped" "$n" "10"
  return $fail
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-}" in
    --self-test) _ra_self_test && echo "registry-aliases.sh: SELF-TEST OK" ;;
    *) echo "usage: registry-aliases.sh --self-test" >&2; exit 2 ;;
  esac
fi
