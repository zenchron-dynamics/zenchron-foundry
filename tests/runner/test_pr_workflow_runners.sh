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
   "grep -q 'is not the CURRENT head of PR' $TV"

# --- two modes, because a check run attaches to the DISPATCHED ref -----------
# `trusted validation result` is release-required, and a release commit belongs
# to a MERGED (closed) PR. A single PR-only mode could never produce it.
ck "the workflow declares pr and release modes" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$TV'))
o=d[True]['workflow_dispatch']['inputs']['mode']
assert o['type']=='choice' and o['options']==['pr','release'], o\""
ck "release mode requires sha == the dispatched commit" \
   "grep -q 'release mode requires sha == the dispatched' $TV"
ck "release mode does NOT require an open PR" \
   "grep -q 'closed — pull request, so open-ness must not be required' $TV"
ck "pr mode requires the EXACT current head" \
   "grep -q 'head_sha=\"\$(gh api .repos/\${REPO}/pulls/\${PR}. --jq ..head.sha.)\"' $TV"
ck "pr mode no longer accepts any historical commit of the PR" \
   "! grep -q 'pulls/\${PR}/commits' $TV"
ck "the pr head is re-checked AFTER the matrix, in the seal" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$TV'))
seal=d['jobs']['seal']['steps']
recheck=[s for s in seal if 'Re-confirm' in s.get('name','')]
assert recheck, [s.get('name') for s in seal]
cond=recheck[0]['if']
assert 'outputs.mode' in cond and 'pr' in cond, cond
assert 'advanced to' in recheck[0]['run']\""
ck "release_required_checks holds the trusted check, pr_required_checks does not" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('policies/required-release-checks.yaml'))
assert 'trusted validation result' in d['release_required_checks']
assert 'trusted validation result' not in d['pr_required_checks']\""

# --- the trusted matrix must actually do what the docs claim ----------------
# #96 removed the pull_request trigger from scan-images.yml, so if trusted
# validation only builds and smoke-tests, nothing scans a reviewed commit.
ck "the trusted matrix runs a Trivy scan" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$TV'))
ids=[s.get('id') for s in d['jobs']['validate']['steps']]
for need in ('build','smoke','trivy_full','trivy_gate'):
    assert need in ids, (need, ids)\""
ck "the scan suppresses nothing and fails closed on missing JSON" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$TV'))
s=[x for x in d['jobs']['validate']['steps'] if x.get('id')=='trivy_full'][0]['run']
assert '--severity CRITICAL,HIGH' in s and '--exit-code 0' in s
assert 'test -s' in s
assert '--ignore-unfixed' not in s and 'ignorefile' not in s\""
ck "reconciliation is bound to an explicit architecture" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$TV'))
s=[x for x in d['jobs']['validate']['steps'] if x.get('id')=='trivy_gate'][0]['run']
assert '--arch' in s and 'reconcile-vulnerabilities.sh' in s\""
ck "reconciliation evidence is uploaded under the aggregate's pattern" \
   "grep -q 'name: vuln-reconciliation-' $TV"
ck "the matrix-wide stale-exception aggregate runs" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$TV'))
j=d['jobs']['stale-exceptions']
assert 'assert-no-stale-exceptions.sh' in str(j['steps'])
# It fails closed on a short matrix, so it must not run on a broken matrix and
# report a vacuous pass.
assert 'validate.result' in j['if'] and 'success' in j['if'], j['if']\""
ck "the seal refuses a SKIPPED aggregate as well as a failed one" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$TV'))
r=str(d['jobs']['seal']['steps'][0]['run'])
assert 'AGG' in r and 'not success' in r\""
ck "the trusted matrix labels images exactly like scan-images.yml" \
   "python3 -c \"
import yaml
a=yaml.safe_load(open('$TV'))['jobs']['validate']['strategy']['matrix']['target']
b=yaml.safe_load(open('.github/workflows/scan-images.yml'))['jobs']['scan']['strategy']['matrix']['include']
ka=sorted((t['fam'],str(t['ver'])) for t in a)
kb=sorted((t['fam'],str(t['ver'])) for t in b)
assert ka==kb, (ka,kb)\""
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
