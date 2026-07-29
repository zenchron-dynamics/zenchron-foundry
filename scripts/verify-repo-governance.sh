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


class StrictLoader(yaml.SafeLoader):
    """Reject duplicate mapping keys.

    PyYAML silently keeps the LAST duplicate, so a policy could declare a key
    twice with different values and the verifier would enforce only one of them
    — which is exactly how a duplicated `release_environments:` block survived
    into this file. A policy that says two different things is not a policy.
    """


def _no_duplicates(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping", node.start_mark,
                "duplicate key %r — the policy declares it twice" % (key,),
                key_node.start_mark)
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _no_duplicates)

try:
    doc = yaml.load(open(os.environ["POLICY"]), Loader=StrictLoader)
except yaml.YAMLError as exc:
    print("POLICY ERROR: %s" % exc, file=sys.stderr)
    sys.exit(4)
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

  # Rule types must match EXACTLY, both directions. Checking only that every
  # declared rule is live let an undocumented rule appear unnoticed — an
  # unexpected `creation` restriction on the tag ruleset would silently break the
  # normal release path, and an added `required_signatures` would block merges.
  local declared_rules live_rules missing extra
  declared_rules="$(pol "${key}.required_rules")"
  live_rules="$(jq -r '.rules[].type' <<<"$rs")"
  missing="$(set_missing "$declared_rules" "$live_rules")"
  extra="$(set_missing "$live_rules" "$declared_rules")"
  if [ -z "$missing" ] && [ -z "$extra" ]; then
    pass "ruleset '${name}' rule set matches the policy exactly"
  else
    [ -n "$missing" ] && fail "ruleset '${name}' is missing rule(s): $(tr '\n' ' ' <<<"$missing")"
    [ -n "$extra" ] && fail "ruleset '${name}' has UNDECLARED live rule(s): $(tr '\n' ' ' <<<"$extra") — declare them or remove them"
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

  # The policy claims this verifier warns past review_interval_days and fails
  # after a grace period. It did not evaluate the dates at all.
  local rev_date review_date interval today grace
  rev_date="$(pol review.decision_date)"; review_date="$(pol review.review_date)"
  interval="$(pol review.review_interval_days)"; today="${TODAY:-$(date -u +%F)}"
  if [ -z "$review_date" ] || [ -z "$rev_date" ] || [ -z "$interval" ]; then
    fail "policy review block is incomplete (decision_date, review_date, review_interval_days all required)"
  else
    # Grace period: one quarter of the interval, minimum 7 days.
    grace="$(( interval / 4 )); "; grace="$(( interval / 4 ))"; [ "$grace" -lt 7 ] && grace=7
    local overdue_by
    overdue_by="$(python3 -c "
import datetime, sys
rd = datetime.date.fromisoformat('${review_date}')
td = datetime.date.fromisoformat('${today}')
print((td - rd).days)")"
    if [ "$overdue_by" -gt "$grace" ]; then
      fail "governance review is ${overdue_by} days past ${review_date} (grace ${grace}d) — re-review and re-date the policy"
    elif [ "$overdue_by" -gt 0 ]; then
      echo "WARN: governance review is ${overdue_by} day(s) overdue (due ${review_date}, grace ${grace}d)" >&2
      pass "governance review overdue but inside the grace period"
    else
      pass "governance review is current (due ${review_date})"
    fi
  fi

  # --- organization runner group -------------------------------------------
  # This is the control that silently broke CI for two days: with
  # allows_public_repositories=false on a PUBLIC repo, GitHub creates jobs and
  # never dispatches them. It needs admin:org, which is why it sat in
  # not_api_verifiable — but "we cannot read it" is not the same as "it is
  # fine", so it is now checked and a read failure is a FAILURE, not a skip.
  local grp_name grp_id want_public org_json live_public
  grp_name="$(pol org_runner_group.name)"
  grp_id="$(pol org_runner_group.id)"
  want_public="$(pol org_runner_group.allows_public_repositories)"

  if org_json="$(gh api "orgs/${REPO%%/*}/actions/runner-groups" 2>/dev/null)"; then
    live_public="$(jq -r --arg n "$grp_name" \
      '.runner_groups[]? | select(.name==$n) | .allows_public_repositories' <<<"$org_json")"
    if [ -z "$live_public" ] || [ "$live_public" = "null" ]; then
      fail "org runner group '${grp_name}' (id ${grp_id}) not found — the runners' group was renamed or removed"
    elif [ "$live_public" = "$want_public" ]; then
      pass "org runner group '${grp_name}' allows_public_repositories=${live_public} as declared"
    else
      fail "org runner group '${grp_name}' allows_public_repositories=${live_public}, declared ${want_public}"
      [ "$live_public" = "false" ] && \
        echo "      -> with a PUBLIC repo this silently stops job dispatch: jobs queue, no runner is assigned, and they are cancelled at the 24h timeout" >&2
    fi
  else
    fail "cannot read orgs/${REPO%%/*}/actions/runner-groups — needs the admin:org scope (\`gh auth refresh -h github.com -s admin:org\`). A control that cannot be read cannot be claimed."
  fi

  # The flag above is only safe because fork PRs cannot reach the privileged
  # pool. Verify that boundary EXISTS and is wired, not merely that it once did.
  # EXECUTE the boundary gate rather than grepping for its filename. A
  # file-exists + Makefile-grep check proves only that a string appears; it
  # would pass for a gate that is present, wired, and broken.
  local boundary
  boundary="$(pol org_runner_group.requires_fork_pr_boundary)"
  if [ ! -x "${ROOT}/${boundary}" ] && [ ! -f "${ROOT}/${boundary}" ]; then
    fail "fork-PR boundary '${boundary}' is missing — allows_public_repositories must NOT be true without it"
  elif ! bash "${ROOT}/${boundary}" >/dev/null 2>&1; then
    fail "fork-PR boundary '${boundary}' FAILS when executed — allows_public_repositories must NOT be true while it is red"
  elif ! make -C "$ROOT" -n validate 2>/dev/null | grep -q "$(basename "$boundary")"; then
    # `make -n validate` expands the REAL target, so this proves the gate is in
    # the recipe rather than merely mentioned somewhere in the Makefile.
    fail "fork-PR boundary '${boundary}' is not part of the real 'make validate' target"
  else
    pass "fork-PR trust boundary executes clean and is in the validate target (${boundary})"
  fi

  RULESETS="$(api "repos/${REPO}/rulesets")"

  # An extra ACTIVE ruleset touching a protected scope is undeclared
  # configuration, which the stated invariant ("live but not declared -> FAIL")
  # must catch. Looking up only the two named rulesets missed it entirely.
  local declared_names undeclared
  declared_names="$(printf '%s\n%s\n' "$(pol branch_ruleset.name)" "$(pol tag_ruleset.name)")"
  undeclared="$(jq -r '.[] | select(.enforcement=="active") | .name' <<<"$RULESETS" \
                | grep -vxF -f <(printf '%s\n' "$declared_names") || true)"
  if [ -n "$undeclared" ]; then
    while IFS= read -r extra_name; do
      [ -n "$extra_name" ] || continue
      fail "undeclared ACTIVE ruleset '${extra_name}' exists — declare it in $(basename "$POLICY") or remove it"
    done <<<"$undeclared"
  else
    pass "no undeclared active rulesets"
  fi

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
  #
  # EVERY declared pending key must be evaluated. Leaving one silently unused
  # recreates the aspiration-as-control problem this file exists to solve, so an
  # unrecognised key is a hard failure rather than a no-op.
  local pending_keys key
  pending_keys="$(POLICY="$POLICY" python3 -c "
import os, yaml
d = yaml.safe_load(open(os.environ['POLICY'])) or {}
print('\n'.join((d.get('pending') or {}).keys()))")"

  local env_json envs_with_reviewers required_envs missing_envs
  env_json="$(api "repos/${REPO}/environments")"
  envs_with_reviewers="$(jq -r '[.environments[]? | select([.protection_rules[]?.type] | index("required_reviewers")) | .name] | sort | join(",")' <<<"$env_json")"
  # The intended release environments, by NAME. "any environment has reviewers"
  # proved nothing about whether the RELEASE environments are protected.
  required_envs="$(pol release_environments 2>/dev/null || printf 'foundry-rc\nfoundry-production\n')"

  while IFS= read -r key; do
    [ -n "$key" ] || continue
    case "$key" in
      environment_required_reviewers)
        if [ "$(pol pending.environment_required_reviewers)" = "pending" ]; then
          [ -z "$envs_with_reviewers" ] \
            && pass "environment required-reviewers absent on every environment, as declared pending (gap, not a control)" \
            || fail "environments now HAVE required reviewers (${envs_with_reviewers}) but the policy still says 'pending' — promote it to 'required'"
        else
          # Named check: each required release environment must be protected.
          missing_envs=""
          while IFS= read -r want_env; do
            [ -n "$want_env" ] || continue
            case ",${envs_with_reviewers}," in
              *",${want_env},"*) : ;;
              *) missing_envs="${missing_envs}${want_env} " ;;
            esac
          done <<<"$required_envs"
          [ -z "$missing_envs" ] \
            && pass "every required release environment has reviewers: ${envs_with_reviewers}" \
            || fail "release environment(s) without required reviewers: ${missing_envs}"
        fi
        ;;
      restrict_release_creation)
        # Not API-verifiable (a role/settings action with no ruleset equivalent),
        # so the only honest states are `pending` or a move to not_api_verifiable.
        if [ "$(pol pending.restrict_release_creation)" = "pending" ]; then
          pass "restrict_release_creation declared pending (not API-verifiable; needs a dated manual check)"
        else
          fail "restrict_release_creation is declared '$(pol pending.restrict_release_creation)' but cannot be verified from the API — move it to not_api_verifiable or return it to pending"
        fi
        ;;
      *)
        fail "policy declares pending.${key} but this verifier does not evaluate it — implement it, or move it to not_api_verifiable"
        ;;
    esac
  done <<<"$pending_keys"

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
  # --- comparators the review findings depend on ---------------------------
  # Two-way rule comparison: an UNDECLARED live rule must be caught, not just a
  # missing declared one.
  t "set_missing detects an extra live rule" \
    '[ "$(set_missing "$(printf "creation\ndeletion")" "$(printf "deletion")")" = "creation" ]'
  # Each direction answers a different question: what is DECLARED but absent
  # live (missing), and what is LIVE but undeclared (extra). Only checking the
  # first was the defect.
  t "declared-but-missing is detected" \
    '[ "$(set_missing "$(printf "a\nb")" "$(printf "a")")" = "b" ]'
  t "live-but-undeclared is detected" \
    '[ "$(set_missing "$(printf "a\nc")" "$(printf "a")")" = "c" ]'

  # Review-date arithmetic (the gate the policy claimed but never implemented).
  t "an overdue review date is detected" \
    '[ "$(python3 -c "
import datetime
print((datetime.date(2026,12,1) - datetime.date(2026,1,1)).days)")" -gt 92 ]'
  t "a future review date is not overdue" \
    '[ "$(python3 -c "
import datetime
print((datetime.date(2026,1,1) - datetime.date(2026,12,1)).days)")" -lt 0 ]'

  # Per-environment naming: "any environment" is not "the release environments".
  t "named-environment matching rejects a partial set" \
    '! case ",foundry-rc," in *",foundry-production,"*) true ;; *) false ;; esac'
  t "named-environment matching accepts the full set" \
    'case ",foundry-rc,foundry-production," in *",foundry-production,"*) true ;; *) false ;; esac'

  # An unhandled policy key must fail rather than be silently ignored.
  t "unknown pending keys are rejected by the case arm" \
    'grep -q "does not evaluate it" "$0"'
  t "undeclared active rulesets are checked" \
    'grep -q "undeclared ACTIVE ruleset" "$0"'

  # --- org runner group: the control that silently broke CI ------------------
  t "policy declares the org runner group" \
    '[ -n "$(pol org_runner_group.name)" ] && [ -n "$(pol org_runner_group.allows_public_repositories)" ]'
  t "policy ties the flag to the fork-PR boundary" \
    '[ "$(pol org_runner_group.requires_fork_pr_boundary)" = "scripts/assert-runner-trust.sh" ]'
  t "a false flag on a public repo is a divergence" \
    '[ "$(pol org_runner_group.allows_public_repositories)" = "true" ] && [ "$(pol repository.visibility)" = "public" ]'
  t "the boundary gate exists and is wired" \
    'test -f "${ROOT}/scripts/assert-runner-trust.sh" && grep -q assert-runner-trust.sh "${ROOT}/Makefile"'
  t "an unreadable runner-group endpoint is a FAILURE, not a skip" \
    'grep -q "cannot be read cannot be claimed" "$0"'
  # Precise: nothing may claim the FLAG itself is unverifiable now that it is
  # checked. Prose mentioning the runner group is fine — the first version of
  # this assertion matched its own policy comment.
  t "the public-repo flag is not claimed unverifiable" \
    '! POLICY="$POLICY" python3 -c "
import os, yaml
d = yaml.safe_load(open(os.environ[\"POLICY\"]))
raise SystemExit(0 if any(\"allows_public_repositories\" in x for x in d.get(\"not_api_verifiable\", [])) else 1)"'

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
