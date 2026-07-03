#!/usr/bin/env bash
# =============================================================================
# scripts/validate-release-version.sh
# -----------------------------------------------------------------------------
# The RC-publication input gate. Binds a candidate to exactly one version, one
# rc, one 40-hex revision, one confirmation string, and one allowed source ref.
# Called by publish-rc.yml's gate job; also runnable with --self-test.
#
# Inputs (env):
#   VERSION            vYYYY.MM.DD[.N]
#   RC                 rc[1-9][0-9]*
#   EXPECTED_REVISION  40 lowercase hex; MUST equal GITHUB_SHA
#   GITHUB_SHA         the commit the workflow is running on
#   CONFIRMATION       PUBLISH-<VERSION>-<RC>-<EXPECTED_REVISION>
#   GITHUB_REF         refs/heads/master or an allowed protected release ref
#   ALLOWED_REFS       space-separated extra allowed refs (optional)
#   SKIP_ANCESTRY=1    skip the git merge-base check (self-test / no checkout)
# =============================================================================
set -euo pipefail
_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
. "$_d/lib/common.sh"

# Reachable-from-master check. Fails CLOSED: if the commit is not an ancestor of
# origin/master, refuse. Requires a full-history checkout (fetch-depth: 0).
_ancestry_ok() {
  local sha="$1"
  [ "${SKIP_ANCESTRY:-0}" = "1" ] && return 0
  git fetch --quiet origin master 2>/dev/null || die "cannot fetch origin/master (ancestry check fails closed)"
  git merge-base --is-ancestor "$sha" origin/master 2>/dev/null \
    || die "revision $sha is not reachable from origin/master"
}

validate_rc_publication() {
  local version="${VERSION:-}" rc="${RC:-}" rev="${EXPECTED_REVISION:-}"
  local sha="${GITHUB_SHA:-}" conf="${CONFIRMATION:-}" ref="${GITHUB_REF:-}"

  require_calver "$version"
  require_rc "$rc"
  require_hex40 "$rev"
  require_hex40 "$sha"
  [ "$rev" = "$sha" ] || die "expected_revision ($rev) != github.sha ($sha)"

  local want="PUBLISH-${version}-${rc}-${rev}"
  [ "$conf" = "$want" ] || die "confirmation mismatch: expected '$want'"

  # Allowed source refs: master by default, plus any ALLOWED_REFS.
  local ok=0
  case "$ref" in refs/heads/master) ok=1 ;; esac
  for a in ${ALLOWED_REFS:-}; do [ "$ref" = "$a" ] && ok=1; done
  [ "$ok" = 1 ] || die "source ref '$ref' is not master or an allowed protected release ref"

  _ancestry_ok "$sha"
  log "release-version gate OK: $version $rc @ $rev (ref $ref)"
}

# --- self-test ---------------------------------------------------------------
_vrv_self_test() {
  local fail=0
  local R=7b4985a1234567890abcdef1234567890abcdef1
  # run validate in a subshell with a given env; expect pass(0) or fail(!=0)
  _run() { ( eval "$1"; SKIP_ANCESTRY=1; export SKIP_ANCESTRY; validate_rc_publication ) >/dev/null 2>&1; }
  _ok()  { if _run "$2"; then echo "ok   - $1"; else echo "FAIL - $1 (expected pass)"; fail=1; fi; }
  _no()  { if _run "$2"; then echo "FAIL - $1 (expected reject)"; fail=1; else echo "ok   - $1"; fi; }

  local GOOD="VERSION=v2026.07.03 RC=rc1 EXPECTED_REVISION=$R GITHUB_SHA=$R CONFIRMATION=PUBLISH-v2026.07.03-rc1-$R GITHUB_REF=refs/heads/master"
  _ok "valid RC publication"        "$GOOD"
  _no "empty version"               "VERSION= RC=rc1 EXPECTED_REVISION=$R GITHUB_SHA=$R CONFIRMATION=PUBLISH--rc1-$R GITHUB_REF=refs/heads/master"
  _no "malformed CalVer"            "VERSION=2026.7.3 RC=rc1 EXPECTED_REVISION=$R GITHUB_SHA=$R CONFIRMATION=PUBLISH-2026.7.3-rc1-$R GITHUB_REF=refs/heads/master"
  _no "empty rc"                    "VERSION=v2026.07.03 RC= EXPECTED_REVISION=$R GITHUB_SHA=$R CONFIRMATION=x GITHUB_REF=refs/heads/master"
  _no "rc0"                         "VERSION=v2026.07.03 RC=rc0 EXPECTED_REVISION=$R GITHUB_SHA=$R CONFIRMATION=PUBLISH-v2026.07.03-rc0-$R GITHUB_REF=refs/heads/master"
  _no "abbreviated revision"        "VERSION=v2026.07.03 RC=rc1 EXPECTED_REVISION=7b4985a GITHUB_SHA=7b4985a CONFIRMATION=PUBLISH-v2026.07.03-rc1-7b4985a GITHUB_REF=refs/heads/master"
  _no "revision != github.sha"      "VERSION=v2026.07.03 RC=rc1 EXPECTED_REVISION=$R GITHUB_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa CONFIRMATION=PUBLISH-v2026.07.03-rc1-$R GITHUB_REF=refs/heads/master"
  _no "wrong confirmation"          "VERSION=v2026.07.03 RC=rc1 EXPECTED_REVISION=$R GITHUB_SHA=$R CONFIRMATION=PUBLISH-WRONG GITHUB_REF=refs/heads/master"
  _no "off-master branch"           "VERSION=v2026.07.03 RC=rc1 EXPECTED_REVISION=$R GITHUB_SHA=$R CONFIRMATION=PUBLISH-v2026.07.03-rc1-$R GITHUB_REF=refs/heads/feature-x"
  return $fail
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-}" in
    --self-test) _vrv_self_test && echo "validate-release-version.sh: SELF-TEST OK" ;;
    *) validate_rc_publication ;;
  esac
fi
