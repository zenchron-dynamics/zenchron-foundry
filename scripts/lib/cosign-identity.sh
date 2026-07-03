#!/usr/bin/env bash
# =============================================================================
# scripts/lib/cosign-identity.sh
# -----------------------------------------------------------------------------
# Resolves the explicit cosign identity regexp for a signing ROLE from
# policies/cosign-identities.yaml. Replaces the repo-wide `…/.*` wildcard: each
# role is anchored to one workflow file, so a scheduled-rebuild signature can
# never satisfy the rc-publisher / release identity.
#
#   identity_re_for_role <role> [policy]  -> echoes the anchored regexp
#   issuer_from_policy [policy]           -> echoes the pinned OIDC issuer
# =============================================================================
set -euo pipefail
_ci_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
[ -n "${_COMMON_SOURCED:-}" ] || . "$_ci_dir/common.sh"
_COMMON_SOURCED=1

_ci_policy_default="$_ci_dir/../../policies/cosign-identities.yaml"

identity_re_for_role() {
  local role="$1" policy="${2:-$_ci_policy_default}"
  command -v yq >/dev/null 2>&1 || die "yq required to read cosign-identities.yaml"
  [ -f "$policy" ] || die "cosign identity policy not found: $policy"
  local re; re="$(yq -r ".roles.\"$role\".identity_regexp // \"\"" "$policy")"
  [ -n "$re" ] && [ "$re" != "null" ] || die "unknown cosign role '$role' in $policy"
  printf '%s' "$re"
}

issuer_from_policy() {
  local policy="${1:-$_ci_policy_default}"
  yq -r '.issuer' "$policy"
}

# --- self-test ---------------------------------------------------------------
_ci_self_test() {
  command -v yq >/dev/null 2>&1 || { echo "SKIP - yq absent"; return 0; }
  local fail=0
  # shellcheck disable=SC2034  # consumed inside the single-quoted eval assertions below
  local RC_ID='https://github.com/zenchron-dynamics/zenchron-foundry/.github/workflows/publish-ghcr.yml@refs/heads/master'
  # shellcheck disable=SC2034
  local SR_ID='https://github.com/zenchron-dynamics/zenchron-foundry/.github/workflows/scheduled-rebuild.yml@refs/heads/master'
  _t() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }
  _rcre() { identity_re_for_role rc-publisher; }   # recomputed per assertion
  _t "rc-publisher regexp resolves"           '[ -n "$(_rcre)" ]'
  _t "rc regexp matches publish-ghcr identity" 'printf "%s" "$RC_ID" | grep -Eq "$(_rcre)"'
  _t "rc regexp REJECTS scheduled-rebuild"     '! printf "%s" "$SR_ID" | grep -Eq "$(_rcre)"'
  _t "rc regexp is not a bare wildcard"        '! _rcre | grep -q "/\\.\\*"'
  _t "scheduled-rebuild role resolves"         'identity_re_for_role scheduled-rebuild >/dev/null'
  _t "unknown role rejected"                   '! ( identity_re_for_role no-such-role ) 2>/dev/null'
  _t "issuer is GitHub Actions"                '[ "$(issuer_from_policy)" = "https://token.actions.githubusercontent.com" ]'
  return $fail
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-}" in
    --self-test) _ci_self_test && echo "cosign-identity.sh: SELF-TEST OK" ;;
    role) shift; identity_re_for_role "$@" ;;
    *) echo "usage: cosign-identity.sh --self-test | role <name>" >&2; exit 2 ;;
  esac
fi
