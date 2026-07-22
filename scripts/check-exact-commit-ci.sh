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
  #
  # FAIL CLOSED on an API error. `gh api` prints the error BODY to stdout and
  # exits non-zero, so the old `$(gh api ... || echo '{}')` concatenated two JSON
  # documents ({"message":"Resource not accessible by integration"}{}) and jq
  # --argjson died with exit 2 — an unreadable crash for what is really "the
  # token cannot read checks". Assign first, test the exit status separately,
  # and refuse with the actual API response. Never silently treat an
  # unreadable check list as an empty one: that would make a gate whose whole
  # job is "prove CI is green" pass vacuously if it could not see CI at all.
  #
  # Read via TEMP FILES, never `--argjson`. A busy release commit accumulates
  # dozens of check-runs (~180 KB across pages); passing that as a jq
  # command-line argument overflows ARG_MAX and jq dies with "Argument list too
  # long" (exit 126). Files have no such limit. `--paginate` (no --slurp) may
  # emit several concatenated top-level objects; jq's `--slurpfile` reads them
  # all into an array, so every page is collected — this also fixes a latent
  # multi-page bug the old single-`$cr` capture had.
  local tmp; tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" RETURN
  if ! gh api "repos/$REPO/commits/$sha/check-runs" --paginate > "$tmp/cr.json" 2>"$tmp/cr.err"; then
    echo "REFUSE: cannot read check-runs for $sha (needs 'checks: read')." >&2
    cat "$tmp/cr.err" >&2; cat "$tmp/cr.json" >&2
    return 1
  fi
  if ! gh api "repos/$REPO/commits/$sha/status" > "$tmp/st.json" 2>"$tmp/st.err"; then
    echo "REFUSE: cannot read commit statuses for $sha (needs 'statuses: read')." >&2
    cat "$tmp/st.err" >&2; cat "$tmp/st.json" >&2
    return 1
  fi
  jq -n \
    --slurpfile cr "$tmp/cr.json" \
    --slurpfile st "$tmp/st.json" '
    { checks:
      ( ($cr | map(.check_runs // []) | add // []
             | map({name:.name, status:.status, conclusion:.conclusion}))
      + ($st | map(.statuses    // []) | add // []
             | map({name:.context, status:"completed",
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

  # --- independent-policy positive (SC-05) -----------------------------------
  # Every other case builds its fixture FROM the live policy, which cannot
  # prove the gate actually reads policy names. This one uses a HARDCODED
  # fixture policy with 3 invented names + a matching fixture snapshot: if the
  # gate merely echoed the live policy (or ignored POLICY), it would fail here.
  cat > "$tmp/pol.yaml" <<'POL'
schema_version: 1
accept_conclusions: [success]
required_checks:
  - fixture check alpha
  - fixture check beta
  - fixture check gamma
POL
  jq -n '{checks: [
    {name:"fixture check alpha", status:"completed", conclusion:"success"},
    {name:"fixture check beta",  status:"completed", conclusion:"success"},
    {name:"fixture check gamma", status:"completed", conclusion:"success"}]}' > "$tmp/pol-fx.json"
  if ( POLICY="$tmp/pol.yaml" CHECKS_FIXTURE="$tmp/pol-fx.json" check_commit "$SHA" ) >/dev/null 2>&1; then
    echo "ok   - hardcoded fixture policy passes (gate reads POLICY names)"
  else
    echo "FAIL - hardcoded fixture policy passes (gate reads POLICY names)"; fail=1
  fi
  # same fixture snapshot, but the policy demands a 4th name -> must reject
  printf '  - fixture check delta\n' >> "$tmp/pol.yaml"
  if ( POLICY="$tmp/pol.yaml" CHECKS_FIXTURE="$tmp/pol-fx.json" check_commit "$SHA" ) >/dev/null 2>&1; then
    echo "FAIL - extra policy name must reject (gate reads POLICY names)"; fail=1
  else
    echo "ok   - extra policy name rejects (gate reads POLICY names)"
  fi

  _ok "all green passes"            '.'
  _no "one skipped rejects"         '.checks[0].conclusion="skipped"'
  _no "one failure rejects"         '.checks[1].conclusion="failure"'
  _no "one cancelled rejects"       '.checks[2].conclusion="cancelled"'
  _no "one null-conclusion rejects" '.checks[3].conclusion=null'
  _no "missing check rejects"       'del(.checks[4])'
  _no "one still-running rejects (fixture=no-poll)" '.checks[5].status="in_progress" | .checks[5].conclusion=null'

  # --- fetch_checks error path (regression: v2026.07.04 seal) ----------------
  # `gh api` prints the error BODY to stdout and exits non-zero. The old
  # `$(gh api ... || echo '{}')` glued two JSON docs together and jq --argjson
  # exited 2. A gate that proves CI is green must REFUSE when it cannot read
  # CI — never crash cryptically, never treat unreadable as empty/green.
  # CHECKS_FIXTURE bypasses fetch_checks, so this stubs `gh` on PATH instead.
  local stub="$tmp/bin"; mkdir -p "$stub"
  cat > "$stub/gh" <<'STUB'
#!/usr/bin/env bash
echo '{"message":"Resource not accessible by integration","status":"403"}'
exit 1
STUB
  chmod +x "$stub/gh"
  if ( PATH="$stub:$PATH"; unset CHECKS_FIXTURE; fetch_checks "$SHA" ) >/dev/null 2>&1; then
    echo "FAIL - unreadable checks must refuse (want reject)"; fail=1
  else
    echo "ok   - unreadable checks refuse (no vacuous pass, no jq crash)"
  fi

  # --- large multi-page payload (regression: v2026.07.21 seal, E2BIG) --------
  # A busy release commit's check-runs are ~180 KB across pages. The old
  # `--argjson "$cr"` passed that on argv and jq died "Argument list too long"
  # (exit 126). fetch_checks must handle a big MULTI-PAGE response — two
  # concatenated {check_runs:[...]} objects, hundreds of runs — via files.
  cat > "$stub/gh" <<'STUB'
#!/usr/bin/env bash
# Emit two pages (as --paginate does): concatenated top-level objects, 1500
# check-runs total with long names to blow a command-line ARG_MAX.
pad="$(printf 'x%.0s' {1..400})"
page() { jq -cn --arg pad "$pad" '{check_runs: [range(750) | {name:("chk-\(.)-"+$pad), status:"completed", conclusion:"success"}]}'; }
case "$*" in
  *check-runs*) page; page ;;
  *status*)     echo '{"statuses":[]}' ;;
  *)            echo '{}' ;;
esac
STUB
  chmod +x "$stub/gh"
  local out
  if out="$( PATH="$stub:$PATH"; unset CHECKS_FIXTURE; fetch_checks "$SHA" 2>&1 )" \
     && printf '%s' "$out" | jq -e '.checks | length == 1500' >/dev/null 2>&1; then
    echo "ok   - large multi-page payload handled (no ARG_MAX overflow, pages merged)"
  else
    echo "FAIL - large multi-page payload (want 1500 merged checks)"; fail=1
  fi

  rm -rf "$tmp"; return $fail
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-}" in
    --self-test) _ci_self_test && echo "check-exact-commit-ci.sh: SELF-TEST OK" ;;
    "") echo "usage: check-exact-commit-ci.sh <commit-sha> | --self-test" >&2; exit 2 ;;
    *) check_commit "$1" ;;
  esac
fi
