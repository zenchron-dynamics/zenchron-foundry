#!/usr/bin/env bash
# shellcheck disable=SC2034  # assertion locals are consumed inside ck() eval strings
# =============================================================================
# tests/release/test_staged_storage_path.sh — #241 phase D, ACTIVE STAGED PATH.
# -----------------------------------------------------------------------------
# The staged evidence path is the one that RUNS TODAY. stage-and-authorize.yml
# uploads per-child evidence and the sealed authorization record as GitHub
# Actions artifacts, and until now nothing checked what became of them.
#
# This file does not grep the workflow. It PARSES it, takes the exact `run:`
# body of the receipt step and EXECUTES that body against fixtures, because a
# script name appearing in YAML proves nothing about whether the gate runs, what
# it is handed, or whether anybody reads the answer.
#
# WHAT IS IN SCOPE. A GitHub Actions artifact and nothing else. No bucket, no
# object lock, no WORM, no external provider, no release asset, no publication.
# The mechanism has no lock and no versioning, the receipt says so in those
# words, and this file asserts that it says so — a receipt that flattered the
# mechanism would be worse than no receipt.
#
# WHAT IS DELIBERATELY NOT HERE. Expiry alerting is not required for a class
# whose policy says `may_expire: true`; a staged candidate reaching day 91 is an
# accepted outcome, not an incident. Published-artifact upload, readback and
# monitoring are specified and fixture-tested in test_storage_receipt.sh and
# remain deferred until publication is authorized. Their absence is not a defect
# in this path.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1

fail=0 nck=0
ck() { nck=$((nck+1)); if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

WF=.github/workflows/stage-and-authorize.yml
STEP=tests/lib/workflow_step.py
EMIT=scripts/release/emit-storage-receipt.sh
VERIFY=scripts/release/verify-storage-receipt.sh
POLICY=policies/retention.yaml
MKAUTH=tests/lib/make_authorization_fixture.py
ACCEPTED=docs/audits/acceptance-multiarch-2026-08-20/acceptance-evidence.json

TMP="$(mktemp -d)"
# shellcheck disable=SC2064
trap "rm -rf '$TMP'" EXIT

python3 "$MKAUTH" "$ACCEPTED" "$TMP/record.json" >/dev/null 2>&1
python3 "$MKAUTH" "$ACCEPTED" "$TMP/other.json" --extra-child >/dev/null 2>&1

# A read-back copy shaped exactly like the artifact the workflow uploads: the
# contents of authorization/, manifest included.
mkdir -p "$TMP/readback/licence"
cp "$TMP/record.json" "$TMP/readback/post-build-authorization.json"
printf 'notice\n' > "$TMP/readback/licence/NOTICE"
( cd "$TMP/readback" \
  && find . -type f ! -name SHA256SUMS -print0 | sort -z \
     | xargs -0 shasum -a 256 > SHA256SUMS )

# The artifact authority's own report. Built here, never invented by the
# producer: the fields below are the ones GitHub assigns.
obs() { # obs <out> <days> [mutation]
  python3 - "$1" "$2" "${3:-ok}" <<'PY'
import datetime, json, sys
out, days, mode = sys.argv[1], int(sys.argv[2]), sys.argv[3]
up = datetime.datetime(2026, 8, 20, 17, 10, tzinfo=datetime.timezone.utc)
o = {"id": 4237781234, "node_id": "MDg6QXJ0aWZhY3Q0MjM3NzgxMjM0",
     "name": "post-build-authorization-32395890071-1",
     "size_in_bytes": 448122, "expired": False,
     "created_at": up.isoformat().replace("+00:00", "Z"),
     "expires_at": (up + datetime.timedelta(days=days))
                   .isoformat().replace("+00:00", "Z")}
if mode == "no-identity":
    o.pop("node_id")
elif mode == "no-expiry":
    o.pop("expires_at")
elif mode == "already-expired":
    o["expired"] = True
if mode == "not-json":
    open(out, "w").write("<html>rate limited</html>")
else:
    json.dump(o, open(out, "w"), indent=1)
PY
}

# Execute the workflow step's OWN body. Nothing is retyped: if somebody drops the
# verify call, weakens a flag or stops consuming the result, this changes.
BODY="$TMP/step.sh"
python3 "$STEP" "$WF" authorize evidence-storage-receipt --run > "$BODY"
step() { # step <observation> <readback-dir> <record> -> exit status of the body
  RECEIPT_RECORD="$3" RECEIPT_OBSERVATION="$1" RECEIPT_READBACK="$2" \
  RECEIPT_OUT="$TMP/receipt.json" RECEIPT_REPOSITORY="zenchron-dynamics/zenchron-foundry" \
  bash "$BODY" > "$TMP/out" 2>&1
}
says() { grep -q -- "$1" "$TMP/out"; }

echo "== the workflow REALLY uploads staged evidence, and names its period ====="

ck "the authorize job uploads the sealed authorization record" \
   "python3 -c \"
import yaml
w = yaml.safe_load(open('$WF'))
ups = [s for s in w['jobs']['authorize']['steps']
       if 'upload-artifact' in str(s.get('uses', ''))]
assert any(s['with']['path'] == 'authorization/' for s in ups), ups\""
ck "the stage job uploads per-child evidence" \
   "python3 -c \"
import yaml
w = yaml.safe_load(open('$WF'))
ups = [s for s in w['jobs']['stage']['steps']
       if 'upload-artifact' in str(s.get('uses', ''))]
assert any(s['with']['path'] == 'evidence/out/' for s in ups), ups\""
ck "both evidence uploads declare the period the POLICY defines, not a guess" \
   "python3 -c \"
import yaml
w = yaml.safe_load(open('$WF'))
pol = yaml.safe_load(open('$POLICY'))
want = {c['evidence_class']: c['retention_days'] for c in pol['classes']}
assert want['staged-candidate'] == want['foundry-child'] == 90, want
paths = {'authorization/': 'authorize', 'evidence/out/': 'stage'}
seen = {}
for p, job in paths.items():
    for s in w['jobs'][job]['steps']:
        if 'upload-artifact' in str(s.get('uses', '')) and s['with'].get('path') == p:
            seen[p] = s['with'].get('retention-days')
assert seen == {'authorization/': want['staged-candidate'],
                'evidence/out/': want['foundry-child']}, seen\""
ck "...and the class it names is allowed to expire, so no alerting is owed" \
   "python3 -c \"
import yaml
pol = yaml.safe_load(open('$POLICY'))
for k in ('staged-candidate', 'foundry-child'):
    c = [x for x in pol['classes'] if x['evidence_class'] == k][0]
    assert c['may_expire'] is True and c['lifecycle'] == 'unpublished', c\""

echo
echo "== the receipt is CONSUMED in the job that makes it ======================"

ck "the receipt step exists and its body is not empty" \
   "[ -s '$BODY' ]"
ck "its body emits AND verifies — production scripts, not a test harness" \
   "grep -q 'emit-storage-receipt.sh' '$BODY' && grep -q 'verify-storage-receipt.sh' '$BODY'"
ck "the step is not allowed to fail quietly" \
   "python3 -c \"
import yaml
w = yaml.safe_load(open('$WF'))
st = [s for s in w['jobs']['authorize']['steps']
      if s.get('id') == 'evidence-storage-receipt'][0]
assert not st.get('continue-on-error'), st
assert st.get('if') == 'always()', st.get('if')\""
ck "the observe step asks the AUTHORITY, rather than restating the request" \
   "python3 '$STEP' '$WF' authorize evidence-storage-observe --run \
      > '$TMP/observe.sh' && grep -q 'actions/runs' '$TMP/observe.sh' \
    && grep -q 'artifacts' '$TMP/observe.sh'"
ck "the evidence is read BACK before anything is claimed about it" \
   "python3 -c \"
import yaml
w = yaml.safe_load(open('$WF'))
ids = [s.get('id') for s in w['jobs']['authorize']['steps']]
assert ids.index('evidence-storage-readback') < ids.index('evidence-storage-receipt')
st = [s for s in w['jobs']['authorize']['steps']
      if s.get('id') == 'evidence-storage-readback'][0]
assert 'download-artifact' in st['uses'], st\""

echo
echo "== NON-VACUITY: the body PASSES on a truthful 90-day observation =========="

ck "a 90-day artifact, read back intact, VERIFIES" \
   "obs '$TMP/obs90.json' 90
    step '$TMP/obs90.json' '$TMP/readback' '$TMP/record.json' \
    && says 'storage receipt VERIFIED' && says 'class staged-candidate'"
ck "...and the receipt binds checksum, revision, candidate, class and expiry" \
   "python3 -c \"
import hashlib, json
r = json.load(open('$TMP/receipt.json'))
a = json.load(open('$TMP/record.json'))
b, st = r['bundle'], r['storage']
assert b['authorization_record_sha256'] == hashlib.sha256(
    open('$TMP/record.json','rb').read()).hexdigest()
assert b['source_revision'] == a['source_revision']
assert b['candidate']['children_expected'] == a['expected_matrix']['expected_children']
assert {c['child_key'] for c in b['candidate']['children']} \
    == {c['child_key'] for c in a['children']}
assert b['retention_class'] == b['evidence_class'] == 'staged-candidate'
assert b['manifest_sha256'] == r['readback']['manifest_sha256']
assert st['retain_until'] == '2026-11-18T17:10:00Z'
assert r['readback']['files_verified'] == r['readback']['files_expected'] == len(b['files'])\""

echo
echo "== SABOTAGE: every way this can be wrong is REFUSED ======================"

ck "S1 89 days is REFUSED — the floor is the policy's, not the workflow's" \
   "obs '$TMP/obs89.json' 89
    ! step '$TMP/obs89.json' '$TMP/readback' '$TMP/record.json' \
    && says 'SR-RETENTION-SHORT' && says '89 day'"
ck "S2 exactly 90 is accepted (the floor is inclusive, and S1 is not vacuous)" \
   "step '$TMP/obs90.json' '$TMP/readback' '$TMP/record.json'"
ck "S3 a MISSING observation is REFUSED, not treated as an empty success" \
   "! step '$TMP/nothing-here.json' '$TMP/readback' '$TMP/record.json' \
    && says 'SE-OBSERVATION-ABSENT'"
ck "S4 a MALFORMED observation is REFUSED" \
   "obs '$TMP/obsbad.json' 90 not-json
    ! step '$TMP/obsbad.json' '$TMP/readback' '$TMP/record.json' \
    && says 'SE-OBSERVATION-ABSENT'"
ck "S5 an observation with no authority-assigned identity is REFUSED" \
   "obs '$TMP/obsni.json' 90 no-identity
    ! step '$TMP/obsni.json' '$TMP/readback' '$TMP/record.json' \
    && says 'SE-OBSERVATION-ABSENT' && says 'node_id'"
ck "S6 an observation with no expiry at all is REFUSED" \
   "obs '$TMP/obsne.json' 90 no-expiry
    ! step '$TMP/obsne.json' '$TMP/readback' '$TMP/record.json' \
    && says 'SE-OBSERVATION-ABSENT' && says 'expires_at'"
ck "S7 an artifact the authority reports as already gone is REFUSED" \
   "obs '$TMP/obsae.json' 90 already-expired
    ! step '$TMP/obsae.json' '$TMP/readback' '$TMP/record.json' \
    && says 'SE-OBSERVATION-ABSENT' && says 'ALREADY EXPIRED'"
ck "S8 evidence that came back CHANGED is REFUSED" \
   "cp -r '$TMP/readback' '$TMP/rb-tampered' \
    && printf 'edited\\n' > '$TMP/rb-tampered/licence/NOTICE'
    ! step '$TMP/obs90.json' '$TMP/rb-tampered' '$TMP/record.json' \
    && says 'SE-READBACK-FAILED'"
ck "S9 evidence that came back INCOMPLETE is REFUSED" \
   "cp -r '$TMP/readback' '$TMP/rb-short' && rm '$TMP/rb-short/licence/NOTICE'
    ! step '$TMP/obs90.json' '$TMP/rb-short' '$TMP/record.json' \
    && says 'SE-READBACK-FAILED' && says 'is NOT in the read-back copy'"
ck "S10 no readback at all is REFUSED — an upload is not a measurement" \
   "cp -r '$TMP/readback' '$TMP/rb-none' && rm '$TMP/rb-none/SHA256SUMS'
    ! step '$TMP/obs90.json' '$TMP/rb-none' '$TMP/record.json' \
    && says 'SE-READBACK-ABSENT'"
ck "S11 a receipt for a DIFFERENT candidate is REFUSED by the consumer" \
   "step '$TMP/obs90.json' '$TMP/readback' '$TMP/record.json'
    ! bash '$VERIFY' '$TMP/receipt.json' --authorization '$TMP/other.json' \
        > '$TMP/out' 2>&1 && says 'SR-UNBOUND'"
ck "S12 a MALFORMED receipt is REFUSED by the consumer" \
   "printf '{\\\"schema\\\":\\\"nope\\\"}\\n' > '$TMP/junk.json'
    ! bash '$VERIFY' '$TMP/junk.json' --authorization '$TMP/record.json' \
        > '$TMP/out' 2>&1 && says 'SR-RECEIPT-MALFORMED'"
ck "S13 an UNCONSUMED receipt cannot pass: dropping the verify call changes the outcome" \
   "sed '/verify-storage-receipt/,+1d' '$BODY' > '$TMP/unconsumed.sh'
    RECEIPT_RECORD='$TMP/record.json' RECEIPT_OBSERVATION='$TMP/obs89.json' \
    RECEIPT_READBACK='$TMP/readback' RECEIPT_OUT='$TMP/r2.json' \
    RECEIPT_REPOSITORY='r/r' bash '$TMP/unconsumed.sh' >/dev/null 2>&1
    # emitting alone SUCCEEDS on the same 89-day input the real body REFUSES,
    # which is exactly what makes the verify call load-bearing.
    [ \$? -eq 0 ] && ! step '$TMP/obs89.json' '$TMP/readback' '$TMP/record.json'"

echo
echo "== the workflow claims NOTHING it cannot show ============================"

ck "the receipt records the mechanism honestly: no lock, no versioning" \
   "step '$TMP/obs90.json' '$TMP/readback' '$TMP/record.json'
    python3 -c \"
import json
st = json.load(open('$TMP/receipt.json'))['storage']
assert st['provider'] == 'github-actions-artifact', st['provider']
assert st['lock_mode'] == 'none' and st['versioning'] == 'not-applicable', st
assert st['region'] == 'not-applicable'\""
ck "...and requests neither, because this class's model requires neither" \
   "python3 -c \"
import json
q = json.load(open('$TMP/receipt.json'))['request']
assert q['required_lock_mode'] == 'none', q
assert q['required_versioning'] is False, q
assert q['required_min_retention_days'] == 90, q\""
ck "the readback is NOT described as offline — it came back over the network" \
   "python3 -c \"
import json
assert json.load(open('$TMP/receipt.json'))['readback']['network_isolated'] is False\""
ck "no added step claims durable, immutable or write-once storage" \
   "! grep -niE 'immutab|write-once|\\bWORM\\b|durable storage' '$BODY' '$TMP/observe.sh'"
ck "the producer says in writing what version_id and audit_event_id are NOT" \
   "grep -q 'tamper-evident audit-log entry' '$EMIT'"

echo
echo "== staged expiry is ALLOWED, and nothing here publishes =================="

ck "the same receipt, read after its period, does NOT become a violation" \
   "bash '$VERIFY' '$TMP/receipt.json' --authorization '$TMP/record.json' \
      --today 2027-06-01 > '$TMP/out' 2>&1 \
    && says 'may_expire: true' && says 'no release retention is violated' \
    && ! says 'SR-EVIDENCE-EXPIRED'"
ck "the receipt carries NO release identity and NO published evidence" \
   "python3 -c \"
import json
b = json.load(open('$TMP/receipt.json'))['bundle']
assert 'release' not in b and 'published_evidence' not in b, sorted(b)\""
ck "the workflow creates no release and no tag" \
   "! grep -qE 'gh release create|action-gh-release|actions/create-release|git tag' '$WF'"
ck "the workflow names no published-artifact class anywhere" \
   "! grep -q 'published-artifact' '$WF'"
ck "the authorize job still holds read-only permissions" \
   "python3 -c \"
import yaml
p = yaml.safe_load(open('$WF'))['jobs']['authorize']['permissions']
assert p == {'contents': 'read', 'packages': 'read', 'actions': 'read'}, p\""

echo
echo "== the gate is REQUIRED, not optional ===================================="

ck "the REQUIRED CI path executes this file" \
   "grep -q 'tests/release/test_staged_storage_path.sh' .github/workflows/ci.yml"
ck "the subsystem-coverage list names the producer" \
   "grep -q 'scripts/release/emit-storage-receipt.sh' tests/governance/test_subsystem_ci_coverage.sh"
ck "the test mutated no tracked file" \
   "test -z \"\$(git -C '$ROOT' status --porcelain -- policies scripts schemas .github 2>/dev/null | grep -v '^??' || true)\""

echo "----"
printf 'assertions: %d proven\n' "$nck"
[ "$fail" -eq 0 ] && echo "test_staged_storage_path: PASS" || echo "test_staged_storage_path: FAIL"
exit "$fail"
