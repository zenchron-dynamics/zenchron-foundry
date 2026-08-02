#!/usr/bin/env bash
# =============================================================================
# tests/governance/test_repo_governance.sh — repository governance (issue #97).
#
# Offline only: the live half of the verification needs `gh` + network and runs
# via `make verify-governance`. What is testable offline is the part that
# actually rotted — the coupling between the declared policy, the single source
# of required-check names, and the documents that make governance claims.
#
# The regression this locks: a document asserting a control that no file
# declares and no check verifies (repository-security.md claimed protections
# were impossible while the repo ran with zero protections).
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

POLICY=policies/repository-governance.yaml
EVIDENCE=docs/audits/governance-verification-2026-08-02.json

ck "governance policy exists"          "test -f $POLICY"
ck "verifier comparators self-test"    "bash scripts/verify-repo-governance.sh --self-test >/dev/null"
ck "verifier is wired into the Makefile" \
   "grep -q 'scripts/verify-repo-governance.sh' Makefile"

# The policy must declare the enforced state, not an aspiration.
ck "policy declares visibility public (verified 2026-07-28)" \
   "python3 -c \"import yaml;assert yaml.safe_load(open('$POLICY'))['repository']['visibility']=='public'\""
ck "branch ruleset declares active enforcement" \
   "python3 -c \"import yaml;assert yaml.safe_load(open('$POLICY'))['branch_ruleset']['enforcement']=='active'\""
ck "tag ruleset declares active enforcement" \
   "python3 -c \"import yaml;assert yaml.safe_load(open('$POLICY'))['tag_ruleset']['enforcement']=='active'\""

# No bypass actors anywhere: an escapable ruleset is not a control. The verifier
# refuses a non-empty declaration, so this keeps the policy inside what it models.
ck "no bypass actors declared for either ruleset" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$POLICY'))
assert d['branch_ruleset']['bypass_actors']==[] and d['tag_ruleset']['bypass_actors']==[]\""

# Release tags must be immutable, and tag CREATION must stay unrestricted or
# scripts/prepare-release.sh can no longer cut a release.
ck "tag ruleset makes v* immutable (deletion+non_fast_forward+update)" \
   "python3 -c \"
import yaml;r=set(yaml.safe_load(open('$POLICY'))['tag_ruleset']['required_rules'])
assert {'deletion','non_fast_forward','update'} <= r, r\""
ck "tag ruleset does NOT restrict tag creation (release path stays open)" \
   "python3 -c \"
import yaml;r=set(yaml.safe_load(open('$POLICY'))['tag_ruleset']['required_rules'])
assert 'creation' not in r\""

# Required checks have exactly ONE source of truth, shared with the release gate.
ck "policy points required checks at required-release-checks.yaml" \
   "python3 -c \"
import yaml;s=yaml.safe_load(open('$POLICY'))['branch_ruleset']['required_status_checks']['source']
assert s=='policies/required-release-checks.yaml', s\""
ck "policy does not duplicate the check-name list" \
   "! grep -q 'build+smoke' $POLICY"

# Dated evidence must exist and must match the policy it evidences.
ck "dated evidence snapshot is committed"  "test -f $EVIDENCE"
ck "evidence records a PASS verdict"       "python3 -c \"import json;assert json.load(open('$EVIDENCE'))['verdict']=='PASS'\""
ck "evidence shows both rulesets active"   "python3 -c \"
import json;rs=json.load(open('$EVIDENCE'))['rulesets']
names={r['name'] for r in rs}
assert names=={'master-protection','release-tags-immutable'}, names
assert all(r['enforcement']=='active' for r in rs)\""
ck "evidence shows the rules LIVE on master" "python3 -c \"
import json;t={r['type'] for r in json.load(open('$EVIDENCE'))['rules_applied_to_default_branch']}
assert {'deletion','non_fast_forward','required_linear_history','pull_request','required_status_checks'} <= t, t\""
ck "evidence records visibility public"    "python3 -c \"import json;assert json.load(open('$EVIDENCE'))['settings']['visibility']=='public'\""

# --- truth-sync -------------------------------------------------------------
# Scoped deliberately: a bare repo-wide grep cannot tell a live claim from
# narrative that quotes the retired one ("previously asserted ... must remain
# private"), and loosening the pattern until it passes would make the check
# meaningless. So assert on the documents a reader treats as current, and on the
# status line of each governance document.

ck "README carries no private-repo claim" \
   "! grep -qiE 'must remain private|stays \*\*private\*\*|private repo' README.md"
ck "SECURITY.md carries no private-repo claim" \
   "! grep -qiE 'must remain private|GitHub Free, private repo' SECURITY.md"
ck "README states governance is enforced" \
   "grep -qiE 'Governance \(enforced' README.md"
ck "repository-security.md status banner says ENFORCED" \
   "head -8 docs/repository-security.md | grep -q 'ENFORCED AND MACHINE-VERIFIED'"
ck "the expired accepted-risk record is superseded in its title and banner" \
   "head -3 docs/audits/free-tier-governance-accepted-risk.md | grep -qi 'SUPERSEDED'"
ck "repository-security.md points at the machine-checked policy" \
   "grep -q 'repository-governance.yaml' docs/repository-security.md"

# The stale apply-payload is the specific thing that would wedge merges if a
# maintainer followed it: dead check names, and an approval count no single
# maintainer can satisfy. What matters is what someone would COPY — so these
# assert on fenced code blocks, not on prose that explains why not to use them.
codeblocks() { awk '/^```/{f=!f;next} f' "$1"; }

ck "no runnable snippet prescribes the rotted check names" \
   "! codeblocks docs/repository-security.md | grep -q 'build representative images'"
ck "no runnable snippet prescribes an unsatisfiable approval count" \
   "! codeblocks docs/repository-security.md | grep -q '\"required_approving_review_count\": 1'"
ck "apply snippets use rulesets, not the classic branch-protection API" \
   "! codeblocks docs/repository-security.md | grep -q 'branches/master/protection'"
ck "apply snippets rebuild the payload from the policy files" \
   "codeblocks docs/repository-security.md | grep -q 'repository-governance.yaml'"
ck "policies/ carries no rotted check names" \
   "! grep -rq 'build representative images' policies/"

# --- review findings: the verifier must enforce what the policy claims ------
ck "rule types are compared BOTH ways" \
   "grep -q 'UNDECLARED live rule' scripts/verify-repo-governance.sh"
ck "undeclared active rulesets are rejected" \
   "grep -q 'undeclared ACTIVE ruleset' scripts/verify-repo-governance.sh"
ck "the review-date gate is implemented" \
   "grep -q 'governance review is' scripts/verify-repo-governance.sh"
ck "every pending key is evaluated (unknown ones fail)" \
   "grep -q 'does not evaluate it' scripts/verify-repo-governance.sh"
ck "restrict_release_creation is evaluated" \
   "grep -q 'restrict_release_creation' scripts/verify-repo-governance.sh"
ck "release environments are checked by NAME" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$POLICY'))
assert d['release_environments']==['foundry-rc','foundry-production'], d.get('release_environments')\""
ck "verifier self-test covers the review findings" \
   "bash scripts/verify-repo-governance.sh --self-test >/dev/null"

# --- org runner group: the control that silently broke CI for two days ------
ck "policy declares the org runner group flag" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$POLICY'))
g=d['org_runner_group']
assert g['allows_public_repositories'] is True, g
assert g['requires_fork_pr_boundary']=='scripts/assert-pr-workflows-github-hosted.sh'\""
ck "verifier checks allows_public_repositories" \
   "grep -q 'allows_public_repositories' scripts/verify-repo-governance.sh"
ck "an unreadable runner-group endpoint FAILS (not skipped)" \
   "grep -q 'cannot be read cannot be claimed' scripts/verify-repo-governance.sh"
ck "the drift check is executed by the verifier" \
   "grep -q 'FAILS when executed' scripts/verify-repo-governance.sh"
ck "the flag is no longer claimed unverifiable" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$POLICY'))
assert not any('allows_public_repositories' in x for x in d.get('not_api_verifiable',[]))\""

# --- review findings ---------------------------------------------------------
ck "policy has no duplicate top-level keys" \
   "python3 -c \"
import yaml, collections
class L(yaml.SafeLoader): pass
def nodup(loader, node, deep=False):
    seen = collections.Counter(loader.construct_object(k, deep=deep) for k, _ in node.value)
    dups = [k for k, n in seen.items() if n > 1]
    assert not dups, dups
    return {loader.construct_object(k, deep=deep): loader.construct_object(v, deep=deep) for k, v in node.value}
L.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, nodup)
yaml.load(open('$POLICY'), Loader=L)\""
ck "verifier rejects duplicate policy keys" \
   "grep -q 'duplicate key' scripts/verify-repo-governance.sh"
ck "boundary gate is EXECUTED, not grepped" \
   "grep -q 'FAILS when executed' scripts/verify-repo-governance.sh"
ck "boundary membership proven via make -n validate" \
   "grep -q 'make -C .* -n validate' scripts/verify-repo-governance.sh"
ck "the drift check is really in the validate target" \
   "mk=\"\$(make -C . -n validate 2>/dev/null)\"; printf '%s' \"\$mk\" | grep -q assert-pr-workflows-github-hosted.sh"

# --- the runner group IS the fork-PR boundary -------------------------------
ck "policy declares the full group contract" \
   "python3 -c \"
import yaml;g=yaml.safe_load(open('$POLICY'))['org_runner_group']
assert g['visibility']=='selected', g['visibility']
assert g['restricted_to_workflows'] is True
assert g['selected_repository_ids']==[1254295268], g['selected_repository_ids']
assert g['allows_public_repositories'] is True
assert all(w.endswith('@refs/heads/master') for w in g['selected_workflows'])
assert g['forbid_runners_in_groups']==['Default']\""
ck "verifier checks selected repositories exactly" \
   "grep -q 'runner group repositories are' scripts/verify-repo-governance.sh"
ck "verifier checks allowed workflows exactly" \
   "grep -q 'UNDECLARED workflow' scripts/verify-repo-governance.sh"
ck "verifier requires every workflow ref-pinned" \
   "grep -q 'not pinned to @refs/heads/master' scripts/verify-repo-governance.sh"
ck "verifier proves no other public repo has access" \
   "grep -q 'other PUBLIC repositories' scripts/verify-repo-governance.sh"
ck "verifier proves Default holds no runners" \
   "grep -q 'holds no runners' scripts/verify-repo-governance.sh"
# Was: "tracked as pending until it reaches master". It reached master with #131
# (01a1181) and went live on 2026-08-02, so the pending list must now be EMPTY —
# a workflow left in `pending` while it is live is undeclared drift.
ck "trusted-validation is live, no longer pending" \
   "python3 -c \"
import yaml;g=yaml.safe_load(open('$POLICY'))['org_runner_group']
assert g['pending_workflows']==[], g['pending_workflows']
assert any('trusted-validation.yml@refs/heads/master' in w for w in g['selected_workflows'])\""
ck "ruleset is compared against PR-producible checks" \
   "grep -q 'pr_required_checks' scripts/verify-repo-governance.sh"
ck "fork-boundary evidence is committed" \
   "test -f docs/security/fork-boundary-test-2026-07-29.md"

# --- the evidence must cover the control that IS the boundary ---------------
# The 2026-07-28 snapshot predated the org runner group, recorded a stale source
# revision, and described a 26-check ruleset that never existed. Evidence that
# omits the fork boundary cannot be used to argue the fork boundary holds.
ck "evidence records the org runner group" \
   "python3 -c \"
import json;g=json.load(open('$EVIDENCE'))['org_runner_group']
for k in ('id','name','visibility','allows_public_repositories',
          'restricted_to_workflows','selected_repositories','selected_workflows',
          'runners','default_group_runners'):
    assert k in g, k\""
ck "evidence shows the group restricted to this repository only" \
   "python3 -c \"
import json;g=json.load(open('$EVIDENCE'))['org_runner_group']
assert g['visibility']=='selected', g['visibility']
assert g['restricted_to_workflows'] is True
names=[r['full_name'] for r in g['selected_repositories']]
assert names==['zenchron-dynamics/zenchron-foundry'], names\""
ck "evidence shows every allowed workflow ref-pinned to master" \
   "python3 -c \"
import json;g=json.load(open('$EVIDENCE'))['org_runner_group']
wfs=g['selected_workflows']
assert len(wfs)==10, len(wfs)
assert all(w.endswith('@refs/heads/master') for w in wfs), wfs\""
ck "evidence shows the Default group holds no runners" \
   "python3 -c \"
import json;g=json.load(open('$EVIDENCE'))['org_runner_group']
assert g['default_group_runners']==[], g['default_group_runners']
assert len(g['runners'])>=1\""
ck "evidence records BOTH check sets, distinctly" \
   "python3 -c \"
import json;d=json.load(open('$EVIDENCE'))
assert len(d['pr_required_checks'])==5, d['pr_required_checks']
assert len(d['release_required_checks'])>len(d['pr_required_checks'])
assert 'trusted validation result' in d['release_required_checks']
assert 'trusted validation result' not in d['pr_required_checks']\""
# Evidence must describe a COMMITTED state. The 2026-08-02 snapshot was first
# generated from a modified working tree: source_revision named e7c4e80, which
# did not yet contain the policy sync, the incident bundle, the admin helper or
# these tests. Evidence naming a revision that does not hold the configuration it
# verified is worse than no evidence — it looks authoritative and is wrong.
#
# The check asserts a SEMANTIC property, not a structural one. The first version
# required source_revision == HEAD^, which held only on the evidence commit
# itself: squash-merging the pull request collapses that parent relationship and
# the assertion then failed on master and on every branch built from it.
#
# What actually matters is that the revision the evidence names carries the SAME
# governed policy as the tree the evidence is committed in. That survives a
# squash merge and still catches the original defect, because evidence generated
# from a dirty tree names a revision whose policy differs from the one on disk.
ck "evidence is bound to a committed revision, not a dirty tree" \
   "python3 -c \"
import json,subprocess,sys
POLICY='policies/repository-governance.yaml'
rev=json.load(open('$EVIDENCE'))['source_revision']

def git(*a):
    r=subprocess.run(['git',*a],capture_output=True,text=True)
    return r.returncode, r.stdout

rc,_=git('cat-file','-e',rev+'^{commit}')
if rc!=0:
    # Unreachable after history rewriting or garbage collection. The guard did
    # its work before the merge; it cannot re-prove it from an absent object.
    print('SKIP: %s is no longer reachable' % rev[:8]); raise SystemExit(0)

rc,named=git('show','%s:%s' % (rev,POLICY))
if rc!=0:
    sys.exit('%s does not contain %s — the evidence names a revision without the '
             'policy it claims to verify' % (rev[:8],POLICY))
current=open(POLICY).read()
if named!=current:
    sys.exit('the policy at source_revision %s differs from the committed policy; '
             'the evidence was generated from a tree that is not %s'
             % (rev[:8],rev[:8]))\""

# Syntax only, deliberately. Requiring the object to EXIST contradicted the
# skip in the check above: once the merged branch is deleted or the intermediate
# commit is no longer fetched, `git cat-file -e` fails and master goes red again
# — the exact durability problem this pair is meant to remove. Reachability is
# the semantic check's business, and it skips when the object is gone.
ck "evidence source_revision has full SHA syntax" \
   "python3 -c \"
import json,re,sys
rev=json.load(open('$EVIDENCE'))['source_revision']
sys.exit(0 if isinstance(rev,str) and re.fullmatch(r'[0-9a-f]{40}',rev) else 1)\""
# THE DURABILITY REGRESSION. A valid 40-hex SHA that does not exist locally is
# what every one of these files looks like after the branch is deleted and the
# object is pruned. The WHOLE suite must still pass, emitting the documented
# skip — not just the semantic fragment in isolation, since it was the
# neighbouring reachability assertion that broke this before.
#
# GOV_SUITE_NESTED guards the recursion: without it this case re-invokes the
# suite, which re-runs this case, forever.
if [ -z "${GOV_SUITE_NESTED:-}" ]; then
  ck "an unreachable source_revision skips, and the whole suite still passes" \
     "_bak=\"\$(mktemp)\"; cp '$EVIDENCE' \"\$_bak\";
      python3 -c \"
import json
p='$EVIDENCE'; d=json.load(open(p))
d['source_revision']='deadbeef'*5
json.dump(d,open(p,'w'),indent=2)\";
      out=\"\$(GOV_SUITE_NESTED=1 bash '$0' 2>&1)\"; rc=\$?;
      cp \"\$_bak\" '$EVIDENCE'; rm -f \"\$_bak\";
      printf '%s' \"\$out\" | grep -q 'SKIP: deadbeef' && [ \"\$rc\" -eq 0 ]"
fi

ck "no document still claims 26 required checks" \
   "! grep -rn '26 required\|26 status\|all 26 check' --include='*.md' --include='*.yaml' . | grep -v originally"

# --- the 2026-08-02 allowlist swap, and the incident it exposed -------------
ck "the policy declares trusted-validation, not ci.yml" \
   "python3 -c \"
import yaml
g=yaml.safe_load(open('$POLICY'))['org_runner_group']
w=g['selected_workflows']
assert not any('/ci.yml@' in x for x in w), 'ci.yml still declared'
assert sum('trusted-validation.yml@refs/heads/master' in x for x in w)==1, w
assert g['pending_workflows']==[], g['pending_workflows']\""
ck "the policy pins exactly one repository by ID" \
   "python3 -c \"
import yaml
g=yaml.safe_load(open('$POLICY'))['org_runner_group']
assert g['selected_repository_ids']==[1254295268], g['selected_repository_ids']\""
ck "the PATCH hazard is documented beside the field it destroys" \
   "grep -q 'MUTATION HAZARD' $POLICY && grep -q 'selected_repository_ids CLEARS it' $POLICY"

# A declarative policy cannot stop a hand-written curl; the helper is the guard.
ck "the admin mutation helper exists and self-tests" \
   "test -x scripts/admin/runner-group-patch.sh && \
    bash scripts/admin/runner-group-patch.sh --self-test >/dev/null"
ck "the helper REFUSES the exact payload that caused the incident" \
   "! bash -c '
      . scripts/admin/runner-group-patch.sh --self-test >/dev/null 2>&1
      eval \"\$(sed -n \"/^assert_patch_payload_safe()/,/^}/p\" scripts/admin/runner-group-patch.sh)\"
      die() { return 1; }
      printf %s \"{\\\"selected_workflows\\\":[\\\"a@refs/heads/master\\\"]}\" > /tmp/_incident.json
      assert_patch_payload_safe /tmp/_incident.json' >/dev/null 2>&1"
ck "the helper verifies AFTER the mutation, not just the HTTP status" \
   "grep -q 'a 200 is not evidence' scripts/admin/runner-group-patch.sh && \
    grep -q 'compare_snapshots' scripts/admin/runner-group-patch.sh"

# --- incident evidence is committed and intact -----------------------------
# NOTE: read inside the strings ck() evals, which the linter cannot follow.
# shellcheck disable=SC2034
EVDIR=docs/audits/runner-group-swap-2026-08-02
ck "the incident evidence bundle is committed" \
   "test -f \$EVDIR/README.md && test -f \$EVDIR/SHA256SUMS"
ck "every evidence file matches its checksum" \
   "( cd \$EVDIR && shasum -a 256 -c SHA256SUMS >/dev/null 2>&1 )"
ck "the evidence records the fail-closed classification" \
   "grep -q 'Fail-closed runner-group availability incident' \$EVDIR/README.md && \
    grep -q 'not.*a privilege exposure' \$EVDIR/README.md"
ck "the evidence shows the repository selection going 1 -> 0 -> 1" \
   "python3 -c \"
import json
b=json.load(open('\$EVDIR/selected-repositories-before.json'))
a=json.load(open('\$EVDIR/selected-repositories-after-patch.json'))
r=json.load(open('\$EVDIR/selected-repositories-restored.json'))
assert (b['total_count'],a['total_count'],r['total_count'])==(1,0,1), (b,a,r)\""
ck "the evidence proves the trusted matrix reached self-hosted runners" \
   "python3 -c \"
import json
j=json.load(open('\$EVDIR/trusted-validation-jobs.json'))
legs=[x for x in j['jobs'] if x['name'].startswith('trusted dispatch build')]
assert len(legs)==10, len(legs)
runners={x.get('runner_name') for x in legs}
assert all(r and r.startswith('runner-prod-') for r in runners), runners\""
ck "the evidence contains no credentials or host paths" \
   "! grep -rqiE 'ghp_|ghs_|github_pat_|authorization:|bearer |X-Amz-Signature' \$EVDIR && \
    ! grep -rq '/Users/' \$EVDIR"

echo "----"; [ "$fail" -eq 0 ] && echo "test_repo_governance: PASS" || echo "test_repo_governance: FAIL"
exit $fail
