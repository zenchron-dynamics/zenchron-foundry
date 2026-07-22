#!/usr/bin/env bash
# =============================================================================
# Zenchron Dynamics — release-environment preflight.
#
# Proves, via the live GitHub API, that the protected release environments exist
# and are configured before any RC publish / stable promotion / release seal is
# allowed to proceed. This is the runtime companion to the static guard
# scripts/assert-environment-names.sh (which only checks the workflow YAML).
#
# FAIL CLOSED. Every check that the API cannot positively prove is a FAILURE,
# never a warning. An auth error, a missing environment, an unreadable
# protection rule → non-zero exit → the release is blocked. We never downgrade
# an API error to "assume it's fine".
#
# Modes:
#   --structure      existence + non-human protections (branch/tag policy,
#                    self-review-where-exposed). Does NOT require reviewers.
#   --release-ready  everything in --structure AND at least one required
#                    reviewer on each environment, plus prevent_self_review on
#                    production. This is what the release workflows must run.
#
# Auth: uses `gh` (GITHUB_TOKEN in Actions, or your login locally). The token
# must be able to READ environment protection rules (repo admin / a fine-grained
# PAT with "Environments: read" + "Administration: read"). If it cannot, the
# reviewer/self-review checks cannot be proven and the script fails closed.
# =============================================================================
set -euo pipefail

EXPECTED_REPO="zenchron-dynamics/zenchron-foundry"
RC_ENV="foundry-rc"
PROD_ENV="foundry-production"

MODE="--structure"
if [ "$#" -gt 0 ]; then MODE="$1"; fi
case "$MODE" in
    --structure|--release-ready|--self-test) ;;
    -h|--help)
        echo "usage: $0 [--structure|--release-ready|--self-test]"; exit 0 ;;
    *)
        echo "FAIL: unknown mode '$MODE' (use --structure, --release-ready or --self-test)"; exit 2 ;;
esac

fail=0
waived=0
note() { printf '    %s\n' "$*"; }
pass() { printf 'PASS  %s\n' "$*"; }
bad()  { printf 'FAIL  %s\n' "$*"; fail=1; }
warn() { printf 'WAIVE %s\n' "$*"; waived=1; }

# Free-tier escape hatch. GitHub Free + PRIVATE repos CANNOT attach environment
# required reviewers (the PUT returns HTTP 422 "billing plan"). Setting
# ALLOW_FREE_TIER_NO_REVIEWERS=1 is an EXPLICIT, logged acceptance of that gap:
# --release-ready then treats the (impossible) reviewer + prevent_self_review
# checks as WAIVED and leans on the deployment branch/tag policies + workflow
# guards instead. Everything else still fails closed. Default (unset) = strict.
# See docs/audits/free-tier-governance-accepted-risk.md.
FREE_TIER=0
case "${ALLOW_FREE_TIER_NO_REVIEWERS:-}" in 1|true|yes|TRUE|YES) FREE_TIER=1 ;; esac

# --- self-test (stubbed gh; offline) ----------------------------------------
# Proves the fail-closed contract (SC-16): an UNREADABLE API response is a
# REFUSAL — never "zero reviewers" (which ALLOW_FREE_TIER_NO_REVIEWERS could
# then waive into a vacuous pass). Also proves the waiver semantics are
# preserved exactly for a READABLE zero-reviewer response.
_cre_self_test() {
    command -v jq >/dev/null 2>&1 || { echo "SKIP - jq absent"; return 0; }
    local fail=0 tmp; tmp="$(mktemp -d)"
    _t() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }
    mkdir -p "$tmp/bin"
    cat > "$tmp/bin/gh" <<'STUB'
#!/usr/bin/env bash
# gh stub for check-release-environments --self-test. STUB_MODE:
#   ok          everything readable + fully protected
#   envfail     environment endpoint unreadable (exit 1 + error body on stdout)
#   polfail     deployment-branch-policies endpoint unreadable
#   noreviewers environments readable, protection_rules present but EMPTY
args="$*"
case "$args" in
  "api user -q .login") echo stub-user; exit 0 ;;
esac
case "$args" in
  *deployment-branch-policies*)
    if [ "${STUB_MODE:?}" = polfail ]; then echo '{"message":"Resource not accessible"}'; exit 1; fi
    case "$args" in
      *foundry-production*) echo '{"total_count":1,"branch_policies":[{"type":"tag","name":"v*"}]}' ;;
      *)                    echo '{"total_count":1,"branch_policies":[{"type":"branch","name":"master"}]}' ;;
    esac ;;
  *environments/*)
    if [ "${STUB_MODE:?}" = envfail ]; then echo '{"message":"Resource not accessible"}'; exit 1; fi
    name="${args##*environments/}"
    rules='[{"type":"required_reviewers","prevent_self_review":true,"reviewers":[{"type":"User"}]}]'
    [ "$STUB_MODE" = noreviewers ] && rules='[]'
    printf '{"name":"%s","deployment_branch_policy":{"custom_branch_policies":true},"protection_rules":%s}\n' "$name" "$rules" ;;
  *) echo '{}' ;;
esac
STUB
    chmod +x "$tmp/bin/gh"
    _run() { # <stub-mode> <script-mode> [extra env...]
        local sm="$1" mode="$2"; shift 2
        ( env "$@" PATH="$tmp/bin:$PATH" STUB_MODE="$sm" \
            GITHUB_REPOSITORY=zenchron-dynamics/zenchron-foundry \
            bash "$0" "$mode" ) >/dev/null 2>&1
    }
    local rc
    _run ok --release-ready; rc=$?
    _t "fully protected passes --release-ready"            '[ "$rc" -eq 0 ]'
    _run envfail --release-ready ALLOW_FREE_TIER_NO_REVIEWERS=1; rc=$?
    _t "unreadable environment REFUSES (even with free-tier waiver)" '[ "$rc" -ne 0 ]'
    _run polfail --release-ready ALLOW_FREE_TIER_NO_REVIEWERS=1; rc=$?
    _t "unreadable branch policies REFUSES (even with waiver)"       '[ "$rc" -ne 0 ]'
    _run noreviewers --release-ready; rc=$?
    _t "readable zero reviewers fails strict --release-ready"        '[ "$rc" -ne 0 ]'
    _run noreviewers --release-ready ALLOW_FREE_TIER_NO_REVIEWERS=1; rc=$?
    _t "readable zero reviewers WAIVED under free-tier flag"         '[ "$rc" -eq 0 ]'
    _run noreviewers --structure; rc=$?
    _t "zero reviewers acceptable for --structure"                   "[ $rc -eq 0 ]"
    rm -rf "$tmp"; return $fail
}
if [ "$MODE" = "--self-test" ]; then
    _cre_self_test && echo "check-release-environments.sh: SELF-TEST OK"
    exit $?
fi

# --- Preconditions: tooling + auth + correct repo --------------------------
command -v gh >/dev/null 2>&1 || { echo "FAIL: gh CLI not found (cannot prove environment protection) — failing closed."; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "FAIL: jq not found (needed to parse protection rules) — failing closed."; exit 1; }

if ! gh api user -q .login >/dev/null 2>&1; then
    echo "FAIL: not authenticated to GitHub (gh api user failed) — failing closed."
    exit 1
fi
pass "authenticated to GitHub as $(gh api user -q .login 2>/dev/null || echo '?')"

REPO="${GITHUB_REPOSITORY:-}"
if [ -z "$REPO" ]; then
    REPO="$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null || true)"
fi
if [ "$REPO" != "$EXPECTED_REPO" ]; then
    bad "repository mismatch: got '${REPO:-<empty>}', expected '$EXPECTED_REPO'"
    echo; echo "==> check-release-environments ($MODE): FAILED (wrong repository)."; exit 1
fi
pass "repository is $REPO"

# --- Per-environment checks -------------------------------------------------
# Fetch the environment object. A non-2xx (missing env, no permission) => fail.
env_json() { gh api "repos/$REPO/environments/$1" 2>/dev/null; }
policies_json() { gh api "repos/$REPO/environments/$1/deployment-branch-policies" 2>/dev/null; }

# jq extraction that FAILS on unparseable input (SC-16). Assign-then-test at
# every call site (mirrors check-exact-commit-ci.sh's fetch pattern): a value
# the API/JSON cannot positively yield must become a REFUSAL, never a silent
# `|| echo 0` / `|| true` default that downstream logic could read as
# "zero reviewers" and (under the free-tier waiver) pass vacuously.
jqx() { # <json> <jq-filter>
    printf '%s' "$1" | jq -r "$2"
}

check_env() {
    local env="$1" kind="$2"   # kind = rc | production
    echo
    echo "[$env]"
    local json
    if ! json="$(env_json "$env")"; then
        bad "$env: does not exist or is unreadable (fail closed)"
        return
    fi

    # 1) exists + name matches
    local api_name
    if ! api_name="$(jqx "$json" '.name // empty')"; then
        bad "$env: unparseable environment response — fail closed"
        return
    fi
    if [ "$api_name" = "$env" ]; then
        pass "$env: exists (name matches)"
    else
        bad "$env: name mismatch (api reported '${api_name:-<none>}')"
    fi

    # 2) deployment branch/tag policy present (custom policies + at least one entry)
    local custom pjson pcount branch_count tag_count
    if ! custom="$(jqx "$json" '.deployment_branch_policy.custom_branch_policies // false')"; then
        bad "$env: unparseable deployment_branch_policy — fail closed"
        return
    fi
    if ! pjson="$(policies_json "$env")"; then
        bad "$env: cannot read deployment branch policies (API error) — fail closed"
        return
    fi
    if ! pcount="$(jqx "$pjson" '.total_count // 0')" \
    || ! branch_count="$(jqx "$pjson" '[.branch_policies[]? | select(.type=="branch")] | length')" \
    || ! tag_count="$(jqx "$pjson" '[.branch_policies[]? | select(.type=="tag")] | length')"; then
        bad "$env: unparseable deployment-branch-policies response — fail closed"
        return
    fi

    if [ "$custom" = "true" ] && [ "${pcount:-0}" -ge 1 ]; then
        pass "$env: deployment policy configured ($pcount custom pattern(s): ${branch_count} branch, ${tag_count} tag)"
    else
        bad "$env: no deployment branch/tag policy (arbitrary refs would be deployable)"
    fi

    # kind-specific ref restrictions
    if [ "$kind" = "production" ]; then
        if [ "${branch_count:-0}" -eq 0 ] && [ "${tag_count:-0}" -ge 1 ]; then
            pass "$env: restricted to tags only (no branch deployments)"
        else
            bad "$env: production must allow tags ONLY (found ${branch_count} branch policy/policies)"
        fi
    else
        if [ "${branch_count:-0}" -ge 1 ]; then
            pass "$env: restricted to an explicit branch policy (default branch)"
        else
            bad "$env: expected an explicit default-branch deployment policy"
        fi
    fi

    # 3) reviewers + self-review. An unreadable/unparseable rule set REFUSES —
    # it must never be misread as "zero reviewers", which the free-tier waiver
    # could then turn into a vacuous pass (SC-16).
    local rev_count self_review
    if ! rev_count="$(jqx "$json" '[.protection_rules[]? | select(.type=="required_reviewers") | .reviewers[]?] | length')" \
    || ! self_review="$(jqx "$json" '(.protection_rules[]? | select(.type=="required_reviewers") | .prevent_self_review) // empty' | head -n1)"; then
        bad "$env: unparseable protection rules — cannot prove reviewers/self-review, fail closed"
        return
    fi

    if [ "${rev_count:-0}" -ge 1 ]; then
        pass "$env: required reviewers CONFIGURED ($rev_count)"
    else
        if [ "$MODE" = "--release-ready" ]; then
            if [ "$FREE_TIER" -eq 1 ]; then
                warn "$env: required reviewers MISSING — WAIVED (ALLOW_FREE_TIER_NO_REVIEWERS): GitHub Free private repo cannot attach reviewers; relying on deployment policies + workflow guards"
            else
                bad "$env: required reviewers MISSING — human reviewers must be assigned before release (fail closed)"
            fi
        else
            note "$env: required reviewers MISSING (expected at this stage; assign before release)"
        fi
    fi

    # self-review prevention: enforce on production; "where exposed" for structure
    if [ "$kind" = "production" ]; then
        if [ "$self_review" = "true" ]; then
            pass "$env: prevent_self_review ENABLED"
        elif [ -z "$self_review" ]; then
            if [ "$MODE" = "--release-ready" ]; then
                if [ "$FREE_TIER" -eq 1 ]; then
                    warn "$env: prevent_self_review not exposed — WAIVED (reviewers unavailable on GitHub Free private repo)"
                else
                    bad "$env: prevent_self_review not provable (no required_reviewers rule yet) — fail closed"
                fi
            else
                note "$env: prevent_self_review not yet exposed (attaches once reviewers are assigned)"
            fi
        else
            if [ "$FREE_TIER" -eq 1 ]; then
                warn "$env: prevent_self_review DISABLED — WAIVED (free-tier self-review accepted)"
            else
                bad "$env: prevent_self_review is DISABLED — production self-approval must be blocked"
            fi
        fi
    fi
}

check_env "$RC_ENV" rc
check_env "$PROD_ENV" production

echo
if [ "$fail" -eq 0 ]; then
    if [ "$MODE" = "--release-ready" ]; then
        if [ "$waived" -eq 1 ]; then
            echo "==> check-release-environments (--release-ready): PASS (COMPENSATING-CONTROL MODE)."
            echo "    Reviewer/self-review protections WAIVED via ALLOW_FREE_TIER_NO_REVIEWERS."
            echo "    Enforcement rests on deployment branch/tag policies + workflow guards."
            echo "    Accepted risk: docs/audits/free-tier-governance-accepted-risk.md."
        else
            echo "==> check-release-environments (--release-ready): PASS (environments protected AND reviewers assigned)."
        fi
    else
        echo "==> check-release-environments (--structure): PASS (environments exist with non-human protections)."
    fi
    exit 0
else
    echo "==> check-release-environments ($MODE): FAILED — see FAIL lines above. Release is blocked."
    exit 1
fi
