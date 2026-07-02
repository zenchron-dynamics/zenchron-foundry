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
    --structure|--release-ready) ;;
    -h|--help)
        echo "usage: $0 [--structure|--release-ready]"; exit 0 ;;
    *)
        echo "FAIL: unknown mode '$MODE' (use --structure or --release-ready)"; exit 2 ;;
esac

fail=0
note() { printf '    %s\n' "$*"; }
pass() { printf 'PASS  %s\n' "$*"; }
bad()  { printf 'FAIL  %s\n' "$*"; fail=1; }

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
    api_name="$(printf '%s' "$json" | jq -r '.name // empty' 2>/dev/null || true)"
    if [ "$api_name" = "$env" ]; then
        pass "$env: exists (name matches)"
    else
        bad "$env: name mismatch (api reported '${api_name:-<none>}')"
    fi

    # 2) deployment branch/tag policy present (custom policies + at least one entry)
    local custom pjson pcount branch_count tag_count
    custom="$(printf '%s' "$json" | jq -r '.deployment_branch_policy.custom_branch_policies // false' 2>/dev/null || echo false)"
    pjson="$(policies_json "$env" || true)"
    pcount="$(printf '%s' "$pjson" | jq -r '.total_count // 0' 2>/dev/null || echo 0)"
    branch_count="$(printf '%s' "$pjson" | jq -r '[.branch_policies[]? | select(.type=="branch")] | length' 2>/dev/null || echo 0)"
    tag_count="$(printf '%s' "$pjson" | jq -r '[.branch_policies[]? | select(.type=="tag")] | length' 2>/dev/null || echo 0)"

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

    # 3) reviewers + self-review
    local rev_count self_review
    rev_count="$(printf '%s' "$json" | jq -r '[.protection_rules[]? | select(.type=="required_reviewers") | .reviewers[]?] | length' 2>/dev/null || echo 0)"
    self_review="$(printf '%s' "$json" | jq -r '(.protection_rules[]? | select(.type=="required_reviewers") | .prevent_self_review) // empty' 2>/dev/null | head -n1 || true)"

    if [ "${rev_count:-0}" -ge 1 ]; then
        pass "$env: required reviewers CONFIGURED ($rev_count)"
    else
        if [ "$MODE" = "--release-ready" ]; then
            bad "$env: required reviewers MISSING — human reviewers must be assigned before release (fail closed)"
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
                bad "$env: prevent_self_review not provable (no required_reviewers rule yet) — fail closed"
            else
                note "$env: prevent_self_review not yet exposed (attaches once reviewers are assigned)"
            fi
        else
            bad "$env: prevent_self_review is DISABLED — production self-approval must be blocked"
        fi
    fi
}

check_env "$RC_ENV" rc
check_env "$PROD_ENV" production

echo
if [ "$fail" -eq 0 ]; then
    if [ "$MODE" = "--release-ready" ]; then
        echo "==> check-release-environments (--release-ready): PASS (environments protected AND reviewers assigned)."
    else
        echo "==> check-release-environments (--structure): PASS (environments exist with non-human protections)."
    fi
    exit 0
else
    echo "==> check-release-environments ($MODE): FAILED — see FAIL lines above. Release is blocked."
    exit 1
fi
