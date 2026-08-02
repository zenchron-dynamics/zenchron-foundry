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

# COSIGN_IDENTITY_POLICY overrides the policy path (self-tests point it at
# fixture/unreadable policies to prove callers fail closed).
_ci_policy_default="${COSIGN_IDENTITY_POLICY:-$_ci_dir/../../policies/cosign-identities.yaml}"

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
  command -v yq >/dev/null 2>&1 || die "yq required to read cosign-identities.yaml"
  [ -f "$policy" ] || die "cosign identity policy not found: $policy"
  local iss; iss="$(yq -r '.issuer // ""' "$policy")"
  [ -n "$iss" ] && [ "$iss" != "null" ] || die "no issuer pinned in $policy"
  printf '%s' "$iss"
}

# Every identity regexp the policy declares, one per line.
policy_identity_regexps() {
  local policy="${1:-$_ci_policy_default}"
  command -v yq >/dev/null 2>&1 || die "yq required to read cosign-identities.yaml"
  [ -f "$policy" ] || die "cosign identity policy not found: $policy"
  local out; out="$(yq -r '.roles[].identity_regexp' "$policy" | grep -v '^null$')"
  [ -n "$out" ] || die "no role identity_regexp declared in $policy"
  printf '%s\n' "$out"
}

# assert_identity_re_in_policy <regexp> [policy]
#
# A regexp is accepted only if it is EXACTLY one the policy declares. Two
# regexps cannot be compared for "is at least as strict as", so anything else —
# including a hand-written pattern that merely looks similar — is refused.
#
# This exists because IDENTITY_RE and EXPECTED_IDENTITY are read from the
# ENVIRONMENT. Resolving them from the policy when EXPECTED_ROLE is set did not
# constrain the case where the caller supplies them directly, so the strict
# verifier could be pointed at any identity by exporting one variable.
assert_identity_re_in_policy() {
  local re="$1" policy="${2:-$_ci_policy_default}"
  [ -n "$re" ] || die "empty cosign identity regexp"
  grep -qxF -- "$re" <<<"$(policy_identity_regexps "$policy")" \
    || die "cosign identity regexp is not declared in $(basename "$policy"): $re"
}

# assert_identity_literal_in_policy <identity> [policy]
#
# An exact identity is accepted only if some declared role's regexp matches it,
# so --certificate-identity cannot name a workflow the policy never authorised.
assert_identity_literal_in_policy() {
  local id="$1" policy="${2:-$_ci_policy_default}" re
  [ -n "$id" ] || die "empty cosign identity"
  while IFS= read -r re; do
    [ -n "$re" ] || continue
    if printf '%s' "$id" | grep -Eq -- "$re"; then return 0; fi
  done <<<"$(policy_identity_regexps "$policy")"
  die "cosign identity is not authorised by any role in $(basename "$policy"): $id"
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
  # release role: anchored to release.yml on a STRICT CalVer tag (PT-06)
  # shellcheck disable=SC2034  # consumed inside the single-quoted eval assertions below
  local REL_ID='https://github.com/zenchron-dynamics/zenchron-foundry/.github/workflows/release.yml@refs/tags/v2026.07.04'
  _relre() { identity_re_for_role release; }
  _t "release regexp matches CalVer tag identity" 'printf "%s" "$REL_ID" | grep -Eq "$(_relre)"'
  _t "release regexp matches hotfix CalVer tag"   'printf "%s" "$REL_ID.1" | grep -Eq "$(_relre)"'
  _t "release regexp REJECTS non-CalVer v-tag"    '! printf "%s" "${REL_ID%v2026.07.04}vNext" | grep -Eq "$(_relre)"'
  _t "release regexp REJECTS master-ref identity" '! printf "%s" "$RC_ID" | grep -Eq "$(_relre)"'
  _t "unknown role rejected"                   '! ( identity_re_for_role no-such-role ) 2>/dev/null'

  # --- policy membership -----------------------------------------------------
  # IDENTITY_RE and EXPECTED_IDENTITY are read from the ENVIRONMENT, so
  # resolving them from the policy in the EXPECTED_ROLE branch did not constrain
  # a caller who supplies them directly. These assertions are what closes that.
  _t "a declared regexp is accepted" \
    'assert_identity_re_in_policy "$(identity_re_for_role rc-publisher)"'
  _t "a repo-wide wildcard regexp is REFUSED" \
    '! ( assert_identity_re_in_policy "^https://github\.com/zenchron-dynamics/zenchron-foundry/.*$" ) 2>/dev/null'
  _t "a near-miss regexp is REFUSED (no partial credit)" \
    '! ( assert_identity_re_in_policy "^https://github\.com/zenchron-dynamics/zenchron-foundry/\.github/workflows/.*@refs/heads/master$" ) 2>/dev/null'
  _t "an empty regexp is REFUSED" \
    '! ( assert_identity_re_in_policy "" ) 2>/dev/null'
  _t "an authorised exact identity is accepted" \
    'assert_identity_literal_in_policy "$RC_ID"'
  _t "a scheduled-rebuild identity is accepted (it is a declared role)" \
    'assert_identity_literal_in_policy "$SR_ID"'
  _t "an identity from another repository is REFUSED" \
    '! ( assert_identity_literal_in_policy "https://github.com/evil/repo/.github/workflows/x.yml@refs/heads/master" ) 2>/dev/null'
  _t "an identity on an unauthorised ref is REFUSED" \
    '! ( assert_identity_literal_in_policy "https://github.com/zenchron-dynamics/zenchron-foundry/.github/workflows/publish-ghcr.yml@refs/heads/attacker" ) 2>/dev/null'
  _t "an empty identity is REFUSED" \
    '! ( assert_identity_literal_in_policy "" ) 2>/dev/null'
  _t "an unreadable policy is a FAILURE, not an empty allowlist" \
    '! ( COSIGN_IDENTITY_POLICY=/nonexistent policy_identity_regexps /nonexistent ) 2>/dev/null'
  _t "every declared role is listed" \
    '[ "$(policy_identity_regexps | grep -c .)" = 3 ]'
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
