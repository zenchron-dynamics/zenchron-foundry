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
# The runner group allows this workflow ONLY as
# trusted-validation.yml@refs/heads/master, so a tag dispatch has a different
# workflow identity and the self-hosted matrix can never be scheduled.
ck "release mode refuses a dispatch from anything but master" \
   "[ \"\$(grep -c 'refs/heads/master) : ;;' $TV)\" = 1 ] && \
    ! grep -qE 'refs/(heads|tags)/[*]\)' $TV && \
    grep -q 'dispatch this workflow from master' $TV"
ck "release mode no longer demands sha == github.sha" \
   "! grep -q 'sha == the dispatched' $TV"
ck "the runner-group pin that forces this is documented" \
   "grep -q 'trusted-validation.yml@refs/heads/master' $TV"
# The runner-group contract itself is declared in #97's policy file; assert it
# only where that file exists, so this branch does not depend on that one.
ck "where declared, the runner group pins only master refs" \
   "python3 -c \"
import os, yaml
p='policies/repository-governance.yaml'
if os.path.exists(p):
    g=yaml.safe_load(open(p)).get('org_runner_group')
    if g:
        wfs=list(g.get('selected_workflows') or [])+list(g.get('pending_workflows') or [])
        assert wfs and all(w.endswith('@refs/heads/master') for w in wfs), wfs\""
ck "release mode proves the SHA is a real commit" \
   "grep -q 'is not a commit of' $TV"

# A check run attaches to the DISPATCHED ref, never to inputs.sha. So no job in
# this workflow may be named after a release-required check: a pr-mode run
# dispatched on master would paint it green on a master commit.
ck "no job is named after a release-required check" \
   "python3 -c \"
import yaml
req=set(yaml.safe_load(open('policies/required-release-checks.yaml'))['release_required_checks'])
d=yaml.safe_load(open('$TV'))
names={j.get('name','') for j in d['jobs'].values()}
clash=names & req
assert not clash, clash\""
ck "the release-required results are published as commit statuses" \
   "python3 -c \"
import yaml
d=yaml.safe_load(open('$TV'))
j=d['jobs']['publish-status']
run=str(j['steps'][0]['run'])
assert '/statuses/' in run, run[:200]
assert 'trusted validation result' in run
assert 'no stale vulnerability exceptions' in run
assert j['permissions']['statuses']=='write'\""
ck "statuses are published ONLY in release mode" \
   "python3 -c \"
import yaml
d=yaml.safe_load(open('$TV'))
cond=d['jobs']['publish-status']['if']
assert 'outputs.mode' in cond and 'release' in cond, cond\""
ck "a skipped or cancelled job publishes FAILURE, not success" \
   "python3 -c \"
import yaml
d=yaml.safe_load(open('$TV'))
run=str(d['jobs']['publish-status']['steps'][0]['run'])
assert 'state=failure' in run and 'state=success' in run, run[:300]\""
ck "the exact-commit consumer reads commit statuses too" \
   "grep -q 'commits/\$sha/status' scripts/check-exact-commit-ci.sh"
ck "the required-checks gate knows these are statuses, not jobs" \
   "grep -q 'published_statuses' scripts/assert-required-checks.sh && \
    bash scripts/assert-required-checks.sh >/dev/null"

# Release-mode provenance must be PROVEN, not quoted.
ck "release mode requires the PR to be merged" \
   "grep -q 'is not merged; it cannot be the provenance' $TV"
ck "release mode ties the SHA to that PR" \
   "grep -q 'is not the merge commit of PR' $TV"
ck "release mode does NOT require an open PR" \
   "grep -q 'A merged (closed)' $TV && grep -q 'is not merged; it cannot be the provenance' $TV"
ck "pr mode requires the EXACT current head" \
   "grep -q 'head_sha=\"\$(gh api .repos/\${REPO}/pulls/\${PR}. --jq ..head.sha.)\"' $TV"
# PR mode must bind to .head.sha. Release mode legitimately consults the commit
# list to recognise a squash/rebase merge, so the assertion is scoped to the
# pr-mode branch rather than the whole file.
ck "pr mode no longer accepts any historical commit of the PR" \
   "python3 -c \"
import yaml
d=yaml.safe_load(open('$TV'))
run=[s for s in d['jobs']['authorize']['steps'] if s.get('id')=='check'][0]['run']
pr_branch=run.split('else',1)[1]
# Strip comments: the branch EXPLAINS why the commit list is not used, so a
# bare substring match would fail on the explanation itself.
code='\\n'.join(l for l in pr_branch.split('\\n') if not l.strip().startswith('#'))
assert 'head.sha' in code, code[:200]
assert '/commits' not in code, 'pr mode still consults the commit list'\""
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
