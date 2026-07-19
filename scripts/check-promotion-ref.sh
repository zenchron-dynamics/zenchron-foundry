#!/usr/bin/env bash
# =============================================================================
# scripts/check-promotion-ref.sh <github-ref> <version>
# -----------------------------------------------------------------------------
# Stable promotion and release sealing may run ONLY from the stable release tag
# for the version being released:
#
#   github.ref == refs/tags/<version>   and   <version> is CalVer vYYYY.MM.DD[.N]
#
# Why: the `foundry-production` environment admits stable tags only. Running
# promotion from a branch is refused by the environment (correctly) and would
# also decouple the promoted digests from the commit the release seals. RC tags
# (v2026.07.04-rc1) are not stable tags and are refused here too.
# =============================================================================
set -euo pipefail
_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
. "$_d/lib/common.sh"

check_promotion_ref() {
  local ref="${1:-}" version="${2:-}"
  require_calver "$version"
  case "$ref" in
    refs/tags/*) ;;
    *) die "ref '${ref}' is not a tag — promotion/sealing must run from refs/tags/${version}" ;;
  esac
  local tag="${ref#refs/tags/}"
  is_calver "$tag" || die "tag '${tag}' is not a stable release tag (vYYYY.MM.DD[.N])"
  [ "$tag" = "$version" ] || die "tag '${tag}' != version input '${version}'"
  log "REF OK: ${ref} is the stable release tag for ${version}"
}

# --- self-test ---------------------------------------------------------------
_cpr_self_test() {
  local fail=0
  _ok() { if ( check_promotion_ref "$2" "$3" ) >/dev/null 2>&1; then echo "ok   - $1"; else echo "FAIL - $1 (want pass)"; fail=1; fi; }
  _no() { if ( check_promotion_ref "$2" "$3" ) >/dev/null 2>&1; then echo "FAIL - $1 (want reject)"; fail=1; else echo "ok   - $1"; fi; }

  _ok "stable tag passes"          refs/tags/v2026.07.04    v2026.07.04
  _ok "hotfix stable tag passes"   refs/tags/v2026.07.04.1  v2026.07.04.1
  _no "master branch rejected"     refs/heads/master        v2026.07.04
  _no "feature branch rejected"    refs/heads/release/fix   v2026.07.04
  _no "rc tag rejected"            refs/tags/v2026.07.04-rc1 v2026.07.04
  _no "tag != version rejected"    refs/tags/v2026.07.03    v2026.07.04
  _no "non-calver tag rejected"    refs/tags/latest         v2026.07.04
  _no "empty ref rejected"         ""                       v2026.07.04
  _no "bad version rejected"       refs/tags/v2026.07.04    2026.7.4
  return $fail
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-}" in
    --self-test) _cpr_self_test && echo "check-promotion-ref.sh: SELF-TEST OK" ;;
    "") echo "usage: check-promotion-ref.sh <github-ref> <version> | --self-test" >&2; exit 2 ;;
    *) check_promotion_ref "$@" ;;
  esac
fi
