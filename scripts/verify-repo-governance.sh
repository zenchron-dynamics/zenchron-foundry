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
  # The BRANCH RULESET must require what a PULL REQUEST can actually produce.
  # Since #96 the pull-request path and the release path emit different checks:
  # build+smoke and the image scans now run on the restricted self-hosted pool,
  # which no pull request can reach. Requiring the release set on the ruleset
  # would block every merge for ever, so the ruleset is compared against
  # pr_required_checks; release_required_checks gates the seal instead.
  CHECKS_POLICY="$CHECKS_POLICY" python3 - <<'PY'
import os, sys, yaml
doc = yaml.safe_load(open(os.environ["CHECKS_POLICY"])) or {}
names = doc.get("pr_required_checks")
if not names:
    print("checks policy has no pr_required_checks list", file=sys.stderr)
    sys.exit(2)
print("\n".join(names))
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
    grace="$(( interval / 4 ))"; [ "$grace" -lt 7 ] && grace=7
    # COHERENCE first. Checking review_date against today alone let the policy
    # declare a 92-day review interval and a review_date years out: the gate
    # would report "current" forever while the stated cadence was fiction.
    # The three fields must agree with each other before the date is used.
    local coh
    coh="$(REV="$rev_date" RD="$review_date" IV="$interval" TD="$today" python3 - <<'PY'
import datetime, os, sys

def parse(name, raw):
    try:
        return datetime.date.fromisoformat(raw)
    except (ValueError, TypeError):
        sys.exit("%s is not a valid ISO date: %r" % (name, raw))

dec = parse("decision_date", os.environ["REV"])
rev = parse("review_date", os.environ["RD"])
today = parse("today", os.environ["TD"])
try:
    interval = int(os.environ["IV"])
except ValueError:
    sys.exit("review_interval_days is not an integer: %r" % os.environ["IV"])
if interval < 1:
    sys.exit("review_interval_days must be >= 1, got %d" % interval)
if dec > today:
    sys.exit("decision_date %s is in the FUTURE (today %s) — a decision cannot "
             "have been taken tomorrow" % (dec, today))
if rev < dec:
    sys.exit("review_date %s precedes decision_date %s" % (rev, dec))
span = (rev - dec).days
if span > interval:
    sys.exit("review_date is %d days after decision_date but the declared "
             "review_interval_days is %d — the policy states a cadence it does "
             "not keep" % (span, interval))
PY
)" || { fail "policy review block is incoherent: $coh"; coh=""; }

    local overdue_by
    overdue_by="$(python3 -c "
import datetime
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

  # --- organization runner group: THE fork-PR boundary ----------------------
  # Every field is verified, because each one is load-bearing. Checking only
  # allows_public_repositories left the questions that actually matter — WHICH
  # repositories and WHICH workflows may use these runners — unasked.
  local org grp_id grp_name org_json grp
  org="${REPO%%/*}"
  grp_id="$(pol org_runner_group.id)"
  grp_name="$(pol org_runner_group.name)"

  if ! org_json="$(gh api "orgs/${org}/actions/runner-groups" 2>/dev/null)"; then
    fail "cannot read orgs/${org}/actions/runner-groups — needs the admin:org scope (gh auth refresh -h github.com -s admin:org). A control that cannot be read cannot be claimed."
  else
    grp="$(jq -r --argjson id "$grp_id" '.runner_groups[]? | select(.id==$id)' <<<"$org_json")"
    if [ -z "$grp" ]; then
      fail "runner group id ${grp_id} does not exist — the boundary group was deleted or renumbered"
    else
      [ "$(jq -r '.name' <<<"$grp")" = "$grp_name" ] \
        && pass "runner group ${grp_id} is '${grp_name}'" \
        || fail "runner group ${grp_id} is named '$(jq -r '.name' <<<"$grp")', declared '${grp_name}'"

      local f
      for f in visibility allows_public_repositories restricted_to_workflows; do
        local live want
        live="$(jq -r --arg k "$f" '.[$k]' <<<"$grp")"
        want="$(pol "org_runner_group.${f}")"
        [ "$live" = "$want" ] \
          && pass "runner group ${f}=${live}" \
          || fail "runner group ${f}='${live}', declared '${want}'"
      done

      # Selected repositories, EXACTLY. A second repository here would let it
      # reach these runners without carrying this repository's controls.
      local live_repos want_repos
      if live_repos="$(gh api "orgs/${org}/actions/runner-groups/${grp_id}/repositories" \
                        --jq '[.repositories[].id] | sort | join(",")' 2>/dev/null)"; then
        want_repos="$(pol org_runner_group.selected_repository_ids | tr -d '[]' | tr -d ' ' )"
        [ "$live_repos" = "$want_repos" ] \
          && pass "runner group repositories match exactly (${live_repos})" \
          || fail "runner group repositories are [${live_repos}], declared [${want_repos}]"

        # Explicitly answer "can another PUBLIC repo use this pool?"
        local extra_public
        extra_public="$(gh api "orgs/${org}/actions/runner-groups/${grp_id}/repositories" \
                         --jq '[.repositories[] | select(.full_name != "'"$REPO"'") | select(.private==false) | .full_name] | join(", ")' 2>/dev/null)"
        [ -z "$extra_public" ] \
          && pass "no other public repository can use these runners" \
          || fail "other PUBLIC repositories can use these runners: ${extra_public}"
      else
        fail "cannot read the runner group's selected repositories"
      fi

      # Allowed workflows, EXACTLY — paths AND refs. An extra entry, or the same
      # path on a different ref, widens the boundary.
      local live_wf want_wf missing_wf extra_wf
      live_wf="$(jq -r '.selected_workflows[]?' <<<"$grp" | sort)"
      want_wf="$(pol org_runner_group.selected_workflows | sort)"
      missing_wf="$(set_missing "$want_wf" "$live_wf")"
      extra_wf="$(set_missing "$live_wf" "$want_wf")"
      if [ -z "$missing_wf" ] && [ -z "$extra_wf" ]; then
        pass "runner group allowed workflows match exactly ($(grep -c . <<<"$live_wf") entries, all @refs/heads/master)"
      else
        [ -n "$missing_wf" ] && fail "declared workflow(s) not allowed live: $(tr '\n' ' ' <<<"$missing_wf")"
        [ -n "$extra_wf" ] && fail "UNDECLARED workflow(s) allowed on the boundary group: $(tr '\n' ' ' <<<"$extra_wf")"
      fi
      # Every entry must be ref-pinned; an unpinned path would match any ref,
      # including a pull request's merge ref.
      if grep -qv '@refs/heads/master$' <<<"$live_wf"; then
        fail "runner group has workflow entries not pinned to @refs/heads/master: $(grep -v '@refs/heads/master$' <<<"$live_wf" | tr '\n' ' ')"
      else
        pass "every allowed workflow is pinned to refs/heads/master"
      fi
    fi

    # No runner may sit in an unrestricted org-wide group.
    local forbidden fid fname n
    forbidden="$(pol org_runner_group.forbid_runners_in_groups)"
    while IFS= read -r fname; do
      [ -n "$fname" ] || continue
      fid="$(jq -r --arg n "$fname" '.runner_groups[]? | select(.name==$n) | .id' <<<"$org_json")"
      [ -n "$fid" ] || continue
      n="$(gh api "orgs/${org}/actions/runner-groups/${fid}/runners" --jq '.total_count' 2>/dev/null || echo unknown)"
      [ "$n" = "0" ] \
        && pass "group '${fname}' holds no runners" \
        || fail "group '${fname}' holds ${n} runner(s) — it is not restricted to this repository"
    done <<<"$forbidden"
  fi

  # EXECUTE the repository-side drift check rather than grepping for its name.
  local boundary
  boundary="$(pol org_runner_group.requires_fork_pr_boundary)"
  if [ ! -f "${ROOT}/${boundary}" ]; then
    fail "drift check '${boundary}' is missing"
  elif ! bash "${ROOT}/${boundary}" >/dev/null 2>&1; then
    fail "drift check '${boundary}' FAILS when executed"
  # Capture first, then match. `make ... | grep -q` is a race: grep -q exits on
  # the first match and SIGPIPEs make, and under `set -o pipefail` that makes
  # the pipeline report make's death as a failure. It reported the boundary as
  # unwired at random.
  elif ! printf '%s' "$(make -C "$ROOT" -n validate 2>/dev/null)" | grep -q "$(basename "$boundary")"; then
    fail "drift check '${boundary}' is not part of the real 'make validate' target"
  else
    pass "pull-request drift check executes clean and is in the validate target"
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

# The org runner group is the actual fork-PR boundary (#96): repository code
# cannot govern runner assignment, so the evidence has to record the control
# plane's own view of it, not just the repository's rulesets.
runner_group_evidence() {
  local gid; gid="$(pol org_runner_group.id)"
  local org="${REPO%%/*}"
  local grp runners repos wfs
  grp="$(api "orgs/${org}/actions/runner-groups/${gid}" 2>/dev/null || echo '{}')"
  repos="$(api "orgs/${org}/actions/runner-groups/${gid}/repositories" 2>/dev/null \
            | jq '[.repositories[]? | {id, full_name, visibility}]' 2>/dev/null || echo '[]')"
  # The workflow list lives on the GROUP object, same as the verifier reads at
  # line ~367. The separate /selected-workflows endpoint returns nothing here,
  # and silently recording an empty list would make the evidence understate the
  # restriction rather than prove it.
  wfs="$(jq '.selected_workflows // []' <<<"$grp" 2>/dev/null || echo '[]')"
  runners="$(api "orgs/${org}/actions/runner-groups/${gid}/runners" 2>/dev/null \
              | jq '[.runners[]? | {id, name, status, busy, labels: [.labels[].name]}]' 2>/dev/null || echo '[]')"
  local default_runners
  default_runners="$(api "orgs/${org}/actions/runner-groups/1/runners" 2>/dev/null \
                      | jq '[.runners[]? | .name]' 2>/dev/null || echo '[]')"
  jq -n --argjson g "$grp" --argjson repos "$repos" --argjson wfs "$wfs" \
        --argjson runners "$runners" --argjson dflt "$default_runners" \
    '{id: $g.id, name: $g.name, visibility: $g.visibility,
      allows_public_repositories: $g.allows_public_repositories,
      restricted_to_workflows: $g.restricted_to_workflows,
      selected_repositories: $repos, selected_workflows: $wfs,
      runners: $runners, default_group_runners: $dflt}'
}

write_evidence() { # write_evidence <path> <verdict>
  local out="$1" verdict="$2"
  # The evidence must describe COMMITTED bytes: a snapshot generated from a
  # dirty tree binds content that exists nowhere in history.
  bash "$ROOT/scripts/governance-content-binding.sh" --assert-clean || return 1
  jq -n \
    --arg repo "$REPO" \
    --argjson content_binding "$(bash "$ROOT/scripts/governance-content-binding.sh" --json)" \
    --arg checked_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg verdict "$verdict" \
    --arg revision "$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)" \
    --argjson repo_json "$(api "repos/${REPO}" | jq '{visibility,private,default_branch,allow_forking,license:.license.spdx_id}')" \
    --argjson rulesets "$(api "repos/${REPO}/rulesets")" \
    --argjson applied_to_default "$(api "repos/${REPO}/rules/branches/$(pol repository.default_branch)")" \
    --argjson environments "$(api "repos/${REPO}/environments" | jq '[.environments[]? | {name, protection_rules: [.protection_rules[]?.type]}]')" \
    --argjson pr_required_checks "$(required_check_names | jq -R . | jq -s .)" \
    --argjson release_required_checks "$(yq -r '.release_required_checks[]' "$CHECKS_POLICY" | jq -R . | jq -s .)" \
    --argjson runner_group "$(runner_group_evidence)" \
    '{repository:$repo, checked_at:$checked_at,
      binding_note:"content_binding is the durable security binding; source_revision is PROVENANCE ONLY and is rewritten by squash/rebase merges",
      content_binding:$content_binding,
      source_revision:$revision, verdict:$verdict,
      settings:$repo_json, rulesets:$rulesets, rules_applied_to_default_branch:$applied_to_default,
      environments:$environments,
      pr_required_checks:$pr_required_checks,
      release_required_checks:$release_required_checks,
      org_runner_group:$runner_group}' > "$out"
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

  # --- the boundary group's full contract ------------------------------------
  t "policy pins the group by ID and name" \
    '[ -n "$(pol org_runner_group.id)" ] && [ -n "$(pol org_runner_group.name)" ]'
  t "policy declares visibility: selected" \
    '[ "$(pol org_runner_group.visibility)" = "selected" ]'
  t "policy declares restricted_to_workflows" \
    '[ "$(pol org_runner_group.restricted_to_workflows)" = "true" ]'
  t "policy pins exactly one repository" \
    '[ "$(pol org_runner_group.selected_repository_ids | tr -d "[] " )" = "1254295268" ]'
  t "every declared workflow is ref-pinned to master" \
    '! pol org_runner_group.selected_workflows | grep -qv "@refs/heads/master$"'
  t "no declared workflow is a bare path" \
    '! pol org_runner_group.selected_workflows | grep -qv "@"'
  t "Default is forbidden from holding runners" \
    'pol org_runner_group.forbid_runners_in_groups | grep -qx Default'
  t "the drift check is the renamed, honest one" \
    '[ "$(pol org_runner_group.requires_fork_pr_boundary)" = "scripts/assert-pr-workflows-github-hosted.sh" ]'
  t "an unreadable org API is a FAILURE, not a skip" \
    'grep -q "cannot be read cannot be claimed" "$0"'
  t "undeclared allowed workflows are rejected" \
    'grep -q "UNDECLARED workflow" "$0"'
  t "other public repositories are explicitly checked" \
    'grep -q "other PUBLIC repositories can use these runners" "$0"'

  # --- org runner group: the control that silently broke CI ------------------
  t "policy declares the org runner group" \
    '[ -n "$(pol org_runner_group.name)" ] && [ -n "$(pol org_runner_group.allows_public_repositories)" ]'

  t "a false flag on a public repo is a divergence" \
    '[ "$(pol org_runner_group.allows_public_repositories)" = "true" ] && [ "$(pol repository.visibility)" = "public" ]'
  t "the drift check exists and is in validate" \
    'test -f "${ROOT}/scripts/assert-pr-workflows-github-hosted.sh" && _mk="$(make -C "$ROOT" -n validate 2>/dev/null)" && printf "%s" "$_mk" | grep -q assert-pr-workflows-github-hosted.sh'
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
  t "the ruleset check set is the PR-producible one" \
    '[ "$(required_check_names | grep -c .)" = "5" ] && required_check_names | grep -qx "repo structure"'
  # --- review-block coherence -----------------------------------------------
  # A date compared only against today says nothing about the cadence claimed
  # beside it. These drive the same python the gate runs.
  _coh() { # _coh <decision> <review> <interval> <today>
    REV="$1" RD="$2" IV="$3" TD="$4" python3 - <<'PY'
import datetime, os, sys
def parse(name, raw):
    try: return datetime.date.fromisoformat(raw)
    except (ValueError, TypeError): sys.exit("%s invalid: %r" % (name, raw))
dec = parse("decision_date", os.environ["REV"])
rev = parse("review_date", os.environ["RD"])
today = parse("today", os.environ["TD"])
try: interval = int(os.environ["IV"])
except ValueError: sys.exit("interval not an integer")
if interval < 1: sys.exit("interval < 1")
if dec > today: sys.exit("decision_date in the future")
if rev < dec: sys.exit("review_date precedes decision_date")
if (rev - dec).days > interval: sys.exit("review_date beyond the declared interval")
PY
  }
  t "a coherent review block passes"          '_coh 2026-07-28 2026-10-28 92 2026-07-30'
  t "review_date beyond the interval FAILS"   '! _coh 2026-07-28 2099-01-01 92 2026-07-30 2>/dev/null'
  t "review_date before decision_date FAILS"  '! _coh 2026-07-28 2026-07-01 92 2026-07-30 2>/dev/null'
  t "a future decision_date FAILS"            '! _coh 2099-01-01 2099-02-01 92 2026-07-30 2>/dev/null'
  t "a non-ISO decision_date FAILS"           '! _coh 28-07-2026 2026-10-28 92 2026-07-30 2>/dev/null'
  t "a non-ISO review_date FAILS"             '! _coh 2026-07-28 not-a-date 92 2026-07-30 2>/dev/null'
  t "a non-integer interval FAILS"            '! _coh 2026-07-28 2026-10-28 ninety 2026-07-30 2>/dev/null'
  t "a zero interval FAILS"                   '! _coh 2026-07-28 2026-07-28 0 2026-07-30 2>/dev/null'
  t "exactly the interval is allowed"         '_coh 2026-07-28 2026-10-28 92 2026-07-30'
  t "the live policy review block is coherent" \
    '_coh "$(pol review.decision_date)" "$(pol review.review_date)" "$(pol review.review_interval_days)" "$(date -u +%F)"'

  t "the release set is larger than the PR set" \
    '[ "$(python3 -c "
import yaml
d = yaml.safe_load(open(\"$CHECKS_POLICY\"))
print(len(d[\"release_required_checks\"]) > len(d[\"pr_required_checks\"]))")" = "True" ]'
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
