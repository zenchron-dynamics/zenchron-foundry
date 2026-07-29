#!/usr/bin/env bash
# =============================================================================
# tests/runner/test_pr_workflow_runners.sh — the pull-request path must be
# statically GitHub-hosted (#96).
#
# The security boundary is NOT here. It is GitHub's runner-group configuration
# (org group `zenchron-foundry-trusted`: visibility=selected, one repository,
# restricted_to_workflows, every entry pinned to refs/heads/master). Evidence:
# docs/security/fork-boundary-test-2026-07-29.md.
#
# What these tests lock is the repository-side shape that must accompany it:
# no pull_request job may name a privileged label or compute its runner from an
# expression, and heavy validation must live in the trusted workflow.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

GATE=scripts/assert-pr-workflows-github-hosted.sh

ck "gate self-test passes"                 "bash $GATE --self-test >/dev/null"
ck "gate passes on this repository"        "bash $GATE >/dev/null"
ck "gate is wired into make validate"      "grep -q 'assert-pr-workflows-github-hosted.sh' Makefile"
ck "gate is wired into ci.yml"             "grep -q 'assert-pr-workflows-github-hosted.sh' .github/workflows/ci.yml"
ck "gate is a YAML parser, not a matcher"  "test -f scripts/lib/pr_workflow_runners.py"

# --- the pull-request path is statically GitHub-hosted -----------------------
ck "no ci.yml job names a privileged label" \
   "! grep -vE '^[[:space:]]*#' .github/workflows/ci.yml | grep -qE '^\s+runs-on:.*self-hosted'"
ck "no ci.yml runs-on is an expression" \
   "! grep -qE '^\s+runs-on:.*\\$\{\{' .github/workflows/ci.yml"
ck "every ci.yml runs-on is ubuntu-latest" \
   "[ \"\$(grep -cE '^\s+runs-on: ubuntu-latest\$' .github/workflows/ci.yml)\" = \"\$(grep -cE '^\s+runs-on:' .github/workflows/ci.yml)\" ]"
ck "scan-images has no pull_request trigger" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('.github/workflows/scan-images.yml'))
t=d.get('on') or d.get(True)
assert 'pull_request' not in (t if isinstance(t,(list,dict)) else [t]), t\""
ck "no workflow uses pull_request_target" \
   "! grep -rlE '^[[:space:]]+pull_request_target:' .github/workflows/ | grep -q ."

# --- heavy validation lives in the trusted workflow --------------------------
TV=.github/workflows/trusted-validation.yml
ck "trusted workflow exists"               "test -f $TV"
ck "trusted workflow is dispatch-only" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$TV'))
t=d.get('on') or d.get(True)
assert list(t)==['workflow_dispatch'], list(t)\""
ck "trusted workflow takes an explicit SHA"      "grep -q 'sha:' $TV"
ck "trusted workflow requires a typed confirmation" "grep -q 'VALIDATE-' $TV"
ck "trusted workflow proves the SHA belongs to the PR" \
   "grep -q 'is not a commit of PR' $TV"
ck "authorization runs on a GitHub-hosted runner (before any self-hosted job)" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$TV'))
assert d['jobs']['authorize']['runs-on']=='ubuntu-latest'
assert 'authorize' in d['jobs']['validate']['needs']\""
ck "checkout pins the authorized SHA, not a ref" \
   "grep -q 'ref: \${{ needs.authorize.outputs.sha }}' $TV"
ck "checkout is re-verified after the fact"      "grep -q 'checked out' $TV"
ck "evidence is bound to the validated commit"   "grep -q 'validated_sha' $TV"
ck "the seal refuses a partially green matrix"   "grep -q 'not success' $TV"

# --- the boundary itself is documented as control-plane ----------------------
ck "fork-boundary evidence is recorded" \
   "test -f docs/security/fork-boundary-test-2026-07-29.md"
ck "the gate does not claim to be the boundary" \
   "grep -q 'NOT A SECURITY BOUNDARY' $GATE"

echo "----"; [ "$fail" -eq 0 ] && echo "test_pr_workflow_runners: PASS" || echo "test_pr_workflow_runners: FAIL"
exit $fail
