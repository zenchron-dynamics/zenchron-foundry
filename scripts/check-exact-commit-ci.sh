#!/usr/bin/env bash
# =============================================================================
# scripts/check-exact-commit-ci.sh <commit-sha>
# -----------------------------------------------------------------------------
# Requires that EVERY check named in policies/required-release-checks.yaml has
# concluded `success` on the EXACT tagged commit — via the GitHub Checks +
# Statuses API. "Latest successful master run" is never accepted for another
# commit. Skipped / neutral / cancelled / stale / timed-out / failed / missing
# all REJECT. Checks still running are polled up to the policy timeout.
#
# Injectable for offline tests:
#   CHECKS_FIXTURE=<file>  read the combined checks JSON from a file instead of
#                          calling `gh api`. Disables polling (single read).
# JSON shape (both real gh output and fixtures):
#   { "checks": [ {"name": <str>, "status": <queued|in_progress|completed>,
#                  "conclusion": <success|failure|skipped|...|null> }, ... ] }
# =============================================================================
set -euo pipefail
_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
. "$_d/lib/common.sh"
POLICY="${POLICY:-$_d/../policies/required-release-checks.yaml}"
REPO="${REPO:-zenchron-dynamics/zenchron-foundry}"

required_checks() { yq -r '.required_checks[]' "$POLICY"; }
accept_conclusions() { yq -r '.accept_conclusions[]' "$POLICY" | tr '\n' ' '; }
poll_timeout() { yq -r '.poll.timeout_seconds // 1800' "$POLICY"; }
poll_interval() { yq -r '.poll.interval_seconds // 30' "$POLICY"; }

# Fetch combined check-runs + commit-statuses for a SHA as our normalized JSON.
fetch_checks() { # <sha> -> {checks:[{name,status,conclusion}]}
  local sha="$1"
  if [ -n "${CHECKS_FIXTURE:-}" ]; then cat "$CHECKS_FIXTURE"; return 0; fi
  # check-runs (GitHub Actions) + legacy commit statuses, merged.
  local cr st
  cr="$(gh api "repos/$REPO/commits/$sha/check-runs" --paginate 2>/dev/null || echo '{}')"
  st="$(gh api "repos/$REPO/commits/$sha/status" 2>/dev/null || echo '{}')"
  jq -n --argjson cr "$cr" --argjson st "$st" '
    { checks:
      ( ($cr.check_runs // [] | map({name:.name, status:.status, conclusion:.conclusion}))
      + ($st.statuses    // [] | map({name:.context, status:"completed",
            conclusion:(if .state=="success" then "success" else .state end)})) ) }'
}

# Evaluate one snapshot. Echoes PENDING if any required check is still running,
# PASS if all required are accepted, FAIL otherwise (with reasons on stderr).
evaluate() { # <checks-json>
  local json="$1" accept; accept=" $(accept_conclusions) "
  local pending=0 failed=0
  while IFS= read -r name; do
    [ -n "$name" ] || continue
    local row status concl
    row="$(jq -c --arg n "$name" '.checks[] | select(.name==$n)' <<<"$json" | tail -1)"
    if [ -z "$row" ]; then echo "  missing: $name" >&2; failed=1; continue; fi
    status="$(jq -r '.status' <<<"$row")"; concl="$(jq -r '.conclusion // "null"' <<<"$row")"
    if [ "$status" != "completed" ]; then echo "  pending: $name ($status)" >&2; pending=1; continue; fi
    case "$accept" in *" $concl "*) : ;; *) echo "  rejected: $name -> $concl" >&2; failed=1 ;; esac
  done < <(required_checks)
  if [ "$failed" = 1 ]; then echo FAIL; elif [ "$pending" = 1 ]; then echo PENDING; else echo PASS; fi
}

check_commit() {
  local sha="$1"; require_hex40 "$sha"
  command -v yq >/dev/null || die "yq required"
  command -v jq >/dev/null || die "jq required"
  local interval; interval="$(poll_interval)"
  # No wall-clock in fixtures; single evaluation when CHECKS_FIXTURE set.
  local verdict json
  json="$(fetch_checks "$sha")"
  verdict="$(evaluate "$json")"
  if [ -n "${CHECKS_FIXTURE:-}" ]; then
    [ "$verdict" = PASS ] || die "required checks not all green on $sha ($verdict)"
    log "exact-commit CI OK: all required checks succeeded on $sha"; return 0
  fi
  # Live: bounded polling while PENDING.
  local waited=0 timeout; timeout="$(poll_timeout)"
  while [ "$verdict" = PENDING ] && [ "$waited" -lt "$timeout" ]; do
    log "checks still running on $sha; waiting ${interval}s (${waited}/${timeout})"
    sleep "$interval"; waited=$((waited+interval))
    json="$(fetch_checks "$sha")"; verdict="$(evaluate "$json")"
  done
  [ "$verdict" = PASS ] || die "exact-commit CI gate failed on $sha: $verdict"
  log "exact-commit CI OK: all required checks succeeded on $sha"
}

# --- self-test (fixtures) ----------------------------------------------------
_ci_self_test() {
  command -v jq >/dev/null && command -v yq >/dev/null || { echo "SKIP - jq/yq absent"; return 0; }
  local fail=0 tmp; tmp="$(mktemp -d)"
  local SHA=1111111111111111111111111111111111111111
  # Build an all-green fixture from the policy's required list.
  _fixture() { # <mutator-jq>
    local names; names="$(required_checks | jq -R . | jq -s .)"
    jq -n --argjson names "$names" '{checks: ($names | map({name:., status:"completed", conclusion:"success"}))}' \
      | jq "${1:-.}"
  }
  # subshell: check_commit calls die()->exit on FAIL; contain it so one failing
  # case does not terminate the whole self-test.
  _run() { ( CHECKS_FIXTURE="$1" check_commit "$SHA" ) >/dev/null 2>&1; }
  _ok() { _fixture "$2" > "$tmp/f.json"; if _run "$tmp/f.json"; then echo "ok   - $1"; else echo "FAIL - $1 (want pass)"; fail=1; fi; }
  _no() { _fixture "$2" > "$tmp/f.json"; if _run "$tmp/f.json"; then echo "FAIL - $1 (want reject)"; fail=1; else echo "ok   - $1"; fi; }

  _ok "all green passes"            '.'
  _no "one skipped rejects"         '.checks[0].conclusion="skipped"'
  _no "one failure rejects"         '.checks[1].conclusion="failure"'
  _no "one cancelled rejects"       '.checks[2].conclusion="cancelled"'
  _no "one null-conclusion rejects" '.checks[3].conclusion=null'
  _no "missing check rejects"       'del(.checks[4])'
  _no "one still-running rejects (fixture=no-poll)" '.checks[5].status="in_progress" | .checks[5].conclusion=null'
  rm -rf "$tmp"; return $fail
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-}" in
    --self-test) _ci_self_test && echo "check-exact-commit-ci.sh: SELF-TEST OK" ;;
    "") echo "usage: check-exact-commit-ci.sh <commit-sha> | --self-test" >&2; exit 2 ;;
    *) check_commit "$1" ;;
  esac
fi
