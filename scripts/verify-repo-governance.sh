#!/usr/bin/env bash
# =============================================================================
# scripts/verify-repo-governance.sh
# -----------------------------------------------------------------------------
# Proves that the repository's LIVE GitHub configuration equals the governance
# declared in policies/repository-governance.yaml. Fails closed on any
# divergence, in BOTH directions:
#
#   declared but missing live -> a document claims a control that does not exist
#   live but not declared     -> undocumented configuration drift
#
# Why this exists (issue #97): four documents asserted that branch protection,
# rulesets and tag protection were unavailable and therefore compensated by
# local hooks. The premise ("GitHub Free + PRIVATE repo") was false — the
# repository is public — and the live configuration had ZERO protections. A
# governance claim that nothing checks is not a control; this script is what
# turns docs/repository-security.md from an aspiration into evidence.
#
# Required-check NAMES are read from policies/required-release-checks.yaml, the
# same file the release gate uses, so the merge gate and the release gate cannot
# drift apart.
#
# Usage:
#   verify-repo-governance.sh [--evidence <file.json>]
#   LOCAL=1 verify-repo-governance.sh     # skip (exit 0) when gh/jq/network absent
#   verify-repo-governance.sh --self-test # offline fixture checks of the comparators
#
# Exit: 0 = verified, 1 = divergence or missing prerequisite (unless LOCAL=1).
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCAL="${LOCAL:-0}"
POLICY="${POLICY:-${ROOT}/policies/repository-governance.yaml}"
CHECKS_POLICY="${CHECKS_POLICY:-${ROOT}/policies/required-release-checks.yaml}"
REPO="${REPO:-zenchron-dynamics/zenchron-foundry}"

fails=0
pass() { printf 'PASS: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; fails=$((fails + 1)); }

# --- comparators (pure, self-testable offline) -------------------------------

# set_equal <newline-set-a> <newline-set-b> — order-insensitive exact equality.
set_equal() {
  local a b
  a="$(printf '%s\n' "$1" | grep -v '^$' | LC_ALL=C sort -u)"
  b="$(printf '%s\n' "$2" | grep -v '^$' | LC_ALL=C sort -u)"
  [ "$a" = "$b" ]
}

# set_missing <required> <actual> — elements of <required> absent from <actual>.
set_missing() {
  LC_ALL=C comm -23 \
    <(printf '%s\n' "$1" | grep -v '^$' | LC_ALL=C sort -u) \
    <(printf '%s\n' "$2" | grep -v '^$' | LC_ALL=C sort -u)
}

# --- prerequisites -----------------------------------------------------------

need() {
  command -v "$1" >/dev/null 2>&1 && return 0
  if [ "$LOCAL" = "1" ]; then
    echo "SKIPPED: '$1' not available (LOCAL=1)"
    exit 0
  fi
  echo "FAIL: '$1' is required to verify live governance (set LOCAL=1 to skip outside CI)" >&2
  exit 1
}

# api <path> [jq-filter] — a failed call is a FAILURE, never an empty success.
api() {
  local path="$1" out
  if ! out="$(gh api "$path" 2>&1)"; then
    echo "FAIL: GitHub API call failed for '${path}': ${out}" >&2
    exit 1
  fi
  printf '%s' "$out"
}

# --- policy readers ----------------------------------------------------------

pol() { # pol <yq-style dotted path> -> value via python (no yq dependency)
  PYPATH="$1" POLICY="$POLICY" python3 - <<'PY'
import os, sys, yaml
doc = yaml.safe_load(open(os.environ["POLICY"]))
cur = doc
for part in os.environ["PYPATH"].split("."):
    if isinstance(cur, dict) and part in cur:
        cur = cur[part]
    else:
        sys.exit(3)
if isinstance(cur, bool):
    print("true" if cur else "false")
elif isinstance(cur, list):
    print("\n".join(str(x) for x in cur))
else:
    print(cur)
PY
}

required_check_names() {
  CHECKS_POLICY="$CHECKS_POLICY" python3 - <<'PY'
import os, yaml
print("\n".join(yaml.safe_load(open(os.environ["CHECKS_POLICY"]))["required_checks"]))
PY
}

# --- ruleset verification ----------------------------------------------------

# verify_ruleset <policy-key> <expected-target>
verify_ruleset() {
  local key="$1" want_target="$2" name enforcement rs id
  name="$(pol "${key}.name")"

  id="$(printf '%s' "$RULESETS" | jq -r --arg n "$name" '.[] | select(.name==$n) | .id' | head -1)"
  if [ -z "$id" ] || [ "$id" = "null" ]; then
    fail "ruleset '${name}' does not exist on ${REPO} (declared in $(basename "$POLICY"))"
    return
  fi
  rs="$(api "repos/${REPO}/rulesets/${id}")"

  [ "$(jq -r '.target' <<<"$rs")" = "$want_target" ] \
    && pass "ruleset '${name}' targets ${want_target}" \
    || fail "ruleset '${name}' targets '$(jq -r '.target' <<<"$rs")', declared '${want_target}'"

  enforcement="$(pol "${key}.enforcement")"
  [ "$(jq -r '.enforcement' <<<"$rs")" = "$enforcement" ] \
    && pass "ruleset '${name}' enforcement=${enforcement}" \
    || fail "ruleset '${name}' enforcement='$(jq -r '.enforcement' <<<"$rs")', declared '${enforcement}'"

  # Include-refs must match exactly: a widened or narrowed scope is drift.
  if set_equal "$(pol "${key}.include_refs")" "$(jq -r '.conditions.ref_name.include[]' <<<"$rs")"; then
    pass "ruleset '${name}' ref scope matches"
  else
    fail "ruleset '${name}' ref scope drifted: live [$(jq -r '.conditions.ref_name.include|join(",")' <<<"$rs")]"
  fi

  # bypass_actors: declared empty means NOBODY bypasses, admins included.
  # Checked in BOTH directions. A non-empty declaration is refused outright
  # rather than approximated: this verifier does not model actor identities, and
  # silently "passing" an unmodelled declaration is exactly the aspiration-read-
  # as-control failure this script exists to prevent.
  local n_bypass declared_bypass
  n_bypass="$(jq -r '.bypass_actors | length' <<<"$rs")"
  declared_bypass="$(pol "${key}.bypass_actors" 2>/dev/null || true)"
  if [ -n "$declared_bypass" ]; then
    fail "ruleset '${name}': policy declares bypass actors, which this verifier does not model — keep bypass_actors empty (see issue #112) or extend the verifier before declaring them"
  elif [ "$n_bypass" -ne 0 ]; then
    fail "ruleset '${name}' has ${n_bypass} bypass actor(s) but the policy declares none — enforcement is escapable"
  else
    pass "ruleset '${name}' has no bypass actors (admins included)"
  fi

  # Every declared rule type must be live.
  local missing
  missing="$(set_missing "$(pol "${key}.required_rules")" "$(jq -r '.rules[].type' <<<"$rs")")"
  if [ -z "$missing" ]; then
    pass "ruleset '${name}' carries every declared rule"
  else
    fail "ruleset '${name}' is missing rule(s): $(tr '\n' ' ' <<<"$missing")"
  fi

  RULESET_JSON="$rs"
}

# --- main --------------------------------------------------------------------

verify_all() {
  need gh; need jq; need python3
  [ -f "$POLICY" ] || { echo "FAIL: policy file not found: ${POLICY}" >&2; exit 1; }
  [ -f "$CHECKS_POLICY" ] || { echo "FAIL: checks policy not found: ${CHECKS_POLICY}" >&2; exit 1; }

  echo "=== Repository governance verification — ${REPO} ==="
  echo "policy: $(basename "$POLICY")   checked: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo

  local repo_json want_vis want_branch
  repo_json="$(api "repos/${REPO}")"

  want_vis="$(pol repository.visibility)"
  [ "$(jq -r '.visibility' <<<"$repo_json")" = "$want_vis" ] \
    && pass "visibility is '${want_vis}' as declared" \
    || fail "visibility is '$(jq -r '.visibility' <<<"$repo_json")', declared '${want_vis}'"

  want_branch="$(pol repository.default_branch)"
  [ "$(jq -r '.default_branch' <<<"$repo_json")" = "$want_branch" ] \
    && pass "default branch is '${want_branch}'" \
    || fail "default branch is '$(jq -r '.default_branch' <<<"$repo_json")', declared '${want_branch}'"

  # Actions defaults.
  local wf_json
  wf_json="$(api "repos/${REPO}/actions/permissions/workflow")"
  [ "$(jq -r '.default_workflow_permissions' <<<"$wf_json")" = "$(pol repository.actions.default_workflow_permissions)" ] \
    && pass "default GITHUB_TOKEN permissions are read-only" \
    || fail "default_workflow_permissions='$(jq -r '.default_workflow_permissions' <<<"$wf_json")', declared '$(pol repository.actions.default_workflow_permissions)'"
  [ "$(jq -r '.can_approve_pull_request_reviews' <<<"$wf_json")" = "$(pol repository.actions.can_approve_pull_request_reviews)" ] \
    && pass "Actions cannot approve pull requests" \
    || fail "can_approve_pull_request_reviews='$(jq -r '.can_approve_pull_request_reviews' <<<"$wf_json")' diverges from policy"

  RULESETS="$(api "repos/${REPO}/rulesets")"

  # --- branch ruleset -------------------------------------------------------
  verify_ruleset branch_ruleset branch
  local branch_rs="${RULESET_JSON:-}"

  if [ -n "$branch_rs" ]; then
    local pr_params sc_params live_checks want_checks
    pr_params="$(jq -r '.rules[] | select(.type=="pull_request") | .parameters' <<<"$branch_rs")"
    if [ -n "$pr_params" ] && [ "$pr_params" != "null" ]; then
      local k
      for k in required_approving_review_count dismiss_stale_reviews_on_push \
               required_review_thread_resolution require_code_owner_review \
               require_last_push_approval; do
        local live want
        live="$(jq -r --arg k "$k" '.[$k]' <<<"$pr_params")"
        want="$(pol "branch_ruleset.pull_request.${k}")"
        [ "$live" = "$want" ] \
          && pass "pull_request.${k} = ${want}" \
          || fail "pull_request.${k} is '${live}', declared '${want}'"
      done
    else
      fail "branch ruleset has no pull_request rule parameters"
    fi

    sc_params="$(jq -r '.rules[] | select(.type=="required_status_checks") | .parameters' <<<"$branch_rs")"
    if [ -n "$sc_params" ] && [ "$sc_params" != "null" ]; then
      [ "$(jq -r '.strict_required_status_checks_policy' <<<"$sc_params")" = "$(pol branch_ruleset.required_status_checks.strict)" ] \
        && pass "required_status_checks.strict = $(pol branch_ruleset.required_status_checks.strict)" \
        || fail "strict_required_status_checks_policy is '$(jq -r '.strict_required_status_checks_policy' <<<"$sc_params")', declared '$(pol branch_ruleset.required_status_checks.strict)'"

      live_checks="$(jq -r '.required_status_checks[].context' <<<"$sc_params")"
      want_checks="$(required_check_names)"
      if set_equal "$want_checks" "$live_checks"; then
        pass "required status checks match $(basename "$CHECKS_POLICY") exactly ($(grep -c . <<<"$want_checks") checks)"
      else
        fail "required status checks diverge from $(basename "$CHECKS_POLICY")"
        local m
        m="$(set_missing "$want_checks" "$live_checks")"; [ -n "$m" ] && printf '      not required live: %s\n' "$(tr '\n' '|' <<<"$m")" >&2
        m="$(set_missing "$live_checks" "$want_checks")"; [ -n "$m" ] && printf '      required live but not in policy: %s\n' "$(tr '\n' '|' <<<"$m")" >&2
      fi
    else
      fail "branch ruleset has no required_status_checks parameters"
    fi
  fi

  # The ruleset must actually APPLY to the default branch — a ruleset that
  # exists but matches no ref protects nothing.
  local applied missing_applied
  applied="$(api "repos/${REPO}/rules/branches/${want_branch}" | jq -r '.[].type' | LC_ALL=C sort -u)"
  missing_applied="$(set_missing "$(pol branch_ruleset.required_rules)" "$applied")"
  if [ -z "$missing_applied" ]; then
    pass "all declared rules are LIVE on refs/heads/${want_branch}"
  else
    fail "rules declared but NOT applying to refs/heads/${want_branch}: $(tr '\n' ' ' <<<"$missing_applied")"
  fi

  # --- tag ruleset ----------------------------------------------------------
  verify_ruleset tag_ruleset tag

  # --- pending items must be ABSENT ----------------------------------------
  # A `pending` declaration is a promise that the control is NOT in place; if it
  # silently appears, the docs are stale in the other direction.
  local env_json envs_with_reviewers
  env_json="$(api "repos/${REPO}/environments")"
  envs_with_reviewers="$(jq -r '[.environments[]? | select([.protection_rules[]?.type] | index("required_reviewers")) | .name] | join(",")' <<<"$env_json")"
  if [ "$(pol pending.environment_required_reviewers)" = "pending" ]; then
    [ -z "$envs_with_reviewers" ] \
      && pass "environment required-reviewers absent, as declared pending (gap, not a control)" \
      || fail "environments now HAVE required reviewers (${envs_with_reviewers}) but the policy still says 'pending' — promote it to 'required'"
  else
    [ -n "$envs_with_reviewers" ] \
      && pass "environment required reviewers active on: ${envs_with_reviewers}" \
      || fail "policy requires environment reviewers but none are configured"
  fi

  echo
  if [ "$fails" -gt 0 ]; then
    printf 'RESULT: FAIL (%d governance divergence(s))\n' "$fails" >&2
    return 1
  fi
  echo "RESULT: PASS (live configuration equals $(basename "$POLICY"))"
}

write_evidence() { # write_evidence <path> <verdict>
  local out="$1" verdict="$2"
  jq -n \
    --arg repo "$REPO" \
    --arg checked_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg verdict "$verdict" \
    --arg revision "$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)" \
    --argjson repo_json "$(api "repos/${REPO}" | jq '{visibility,private,default_branch,allow_forking,license:.license.spdx_id}')" \
    --argjson rulesets "$(api "repos/${REPO}/rulesets")" \
    --argjson applied_to_default "$(api "repos/${REPO}/rules/branches/$(pol repository.default_branch)")" \
    --argjson environments "$(api "repos/${REPO}/environments" | jq '[.environments[]? | {name, protection_rules: [.protection_rules[]?.type]}]')" \
    '{repository:$repo, checked_at:$checked_at, source_revision:$revision, verdict:$verdict,
      settings:$repo_json, rulesets:$rulesets, rules_applied_to_default_branch:$applied_to_default,
      environments:$environments}' > "$out"
  echo "evidence written: ${out}"
}

self_test() {
  local ok=0 bad=0
  t() { if eval "$2"; then ok=$((ok+1)); echo "  ok   $1"; else bad=$((bad+1)); echo "  FAIL $1"; fi; }
  t "set_equal is order-insensitive"        'set_equal "$(printf "b\na")" "$(printf "a\nb")"'
  t "set_equal rejects a missing element"   '! set_equal "$(printf "a\nb")" "$(printf "a")"'
  t "set_equal rejects an extra element"    '! set_equal "$(printf "a")" "$(printf "a\nb")"'
  t "set_equal tolerates blank lines"       'set_equal "$(printf "a\n\nb")" "$(printf "b\na")"'
  t "set_equal handles names with spaces"   'set_equal "$(printf "build+smoke nginx")" "$(printf "build+smoke nginx")"'
  t "set_missing reports what is absent"    '[ "$(set_missing "$(printf "a\nb")" "$(printf "a")")" = "b" ]'
  t "set_missing is empty when covered"     '[ -z "$(set_missing "$(printf "a")" "$(printf "a\nb")")" ]'
  t "policy file parses"                    '[ "$(pol repository.visibility)" = "public" ]'
  t "policy declares no bypass actors"      '[ -z "$(pol branch_ruleset.bypass_actors || true)" ]'
  t "required check names load (26)"        '[ "$(required_check_names | grep -c .)" = "26" ]'
  echo "self-test: $ok ok, $bad failed"
  [ "$bad" -eq 0 ]
}

main() {
  local evidence=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --self-test) self_test; return $? ;;
      --evidence)  evidence="${2:?--evidence needs a path}"; shift 2 ;;
      *) echo "usage: $(basename "$0") [--evidence <file.json>] [--self-test]" >&2; return 1 ;;
    esac
  done
  local verdict=PASS rc=0
  verify_all || { verdict=FAIL; rc=1; }
  [ -n "$evidence" ] && write_evidence "$evidence" "$verdict"
  return $rc
}

main "$@"
