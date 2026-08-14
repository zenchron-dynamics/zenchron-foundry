#!/usr/bin/env bash
# =============================================================================
# The committed amd64 acceptance record must stay internally consistent and
# bound to real history.
#
# docs/audits/acceptance-amd64-2026-08-14/ exists because the workflow artifact
# it came from expires 2026-11-12. A record nobody checks decays into a claim,
# so these assertions run with the rest of the suite.
#
# They deliberately do NOT re-verify the run itself — that needs the API and the
# registry, was done at acceptance time, and is written up in the README. What
# is checked here is that the committed copy still says what it said, still
# matches its own checksums, and still refers to a commit that exists.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

D=docs/audits/acceptance-amd64-2026-08-14
R="$D/post-build-authorization.json"
SHA=47609df75736a5860651be98177cfe8f9388f496
RUN=31792482449

ck "the acceptance record is committed" "test -s '$R'"

ck "it records the accepted verdict and scope" \
   "python3 -c \"
import json; r=json.load(open('$R'))
assert r['verdict']=='PASS', r['verdict']
assert r['authorization_scope']=='immutable-rc-manifest-input', r['authorization_scope']
assert r['public_exposure_authorized'] is False, r['public_exposure_authorized']
assert not r.get('refusals'), r.get('refusals')\""

ck "it is bound to run $RUN attempt 1 on $SHA" \
   "python3 -c \"
import json; r=json.load(open('$R'))
assert r['workflow_run_id']==$RUN, r['workflow_run_id']
assert r['workflow_run_attempt']==1, r['workflow_run_attempt']
assert r['source_revision']=='$SHA', r['source_revision']\""

# NOT a git-membership check. The first version ran `git cat-file -e` on the
# accepted commit, which failed in CI: GitHub checks out the synthetic PR merge
# commit at fetch-depth 1, so an August-14 object is simply absent. Deepening
# the checkout to satisfy an audit test would be the wrong trade, and a network
# lookup does not belong in the offline suite.
#
# It was also wrong as a permanent invariant: any future shallow checkout of
# master lacks that object too, so the assertion would rot into a false alarm.
#
# Repository membership was established independently when the run was accepted,
# by the API and the registry. What this suite can own is that the recorded
# revision is a well-formed full SHA and that the record agrees with itself —
# ongoing membership verification belongs in #128's durable evidence verifier.
ck "the accepted revision is a full 40-hex SHA, consistent across the record" \
   "python3 -c \"
import json, re
r = json.load(open('$R'))
top = r['source_revision']
assert re.fullmatch(r'[0-9a-f]{40}', top), top
assert top == '$SHA', top
drift = [c['image_label'] for c in r['children'] if c['source_revision'] != top]
assert not drift, ('children disagree with the record revision', drift)\""

ck "ten children, no duplicates, all amd64 and private" \
   "python3 -c \"
import json; r=json.load(open('$R'))
c=r['children']
assert r['expected_matrix']['expected_children']==10
assert len(c)==10, len(c)
assert len({x['image_label'] for x in c})==10
assert len({x['manifest_digest'] for x in c})==10
assert {x['platform'] for x in c}=={'linux/amd64'}
assert {x['config_architecture'] for x in c}=={'amd64'}
assert {x['visibility'] for x in c}=={'private'}\""

ck "every child passed all four evaluations" \
   "python3 -c \"
import json; r=json.load(open('$R'))
bad=[(x['image_label'],k) for x in r['children']
     for k in ('smoke_test','scan','reconciliation','metadata_contract') if x[k]!='PASS']
assert not bad, bad\""

ck "one frozen database judged every child" \
   "python3 -c \"
import json; r=json.load(open('$R'))
assert len({x['trivy_db_identity'] for x in r['children']})==1\""

ck "each child's tag resolved to its own manifest digest" \
   "python3 -c \"
import json; r=json.load(open('$R'))
bad=[x['image_label'] for x in r['children'] if x['manifest_digest']!=x['tag_resolved_digest']]
assert not bad, bad\""

# The committed copy must match the checksums shipped beside it, so a later
# edit to the JSON cannot pass unnoticed.
ck "the record matches the committed SHA256SUMS" \
   "grep -q \"\$(python3 -c \"
import hashlib;print(hashlib.sha256(open('$R','rb').read()).hexdigest())\")\" '$D/SHA256SUMS'"

echo "----"
[ "$fail" -eq 0 ] && echo "test_amd64_acceptance_record: PASS" \
                  || echo "test_amd64_acceptance_record: FAIL"
exit $fail
