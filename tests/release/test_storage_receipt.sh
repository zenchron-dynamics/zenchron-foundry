#!/usr/bin/env bash
# shellcheck disable=SC2034  # assertion locals are consumed inside ck() eval strings
# =============================================================================
# tests/release/test_storage_receipt.sh — #241 Phase A.
# -----------------------------------------------------------------------------
# The storage-receipt contract, exercised fail-closed BEFORE any provider is
# chosen and before anything is provisioned.
#
# WHAT THIS IS AND IS NOT. Nothing here contacts a provider, creates a bucket,
# changes an IAM policy, uploads an object or enables object lock. Every receipt
# is built by tests/lib/make_storage_receipt.py, whose header says in as many
# words that its `version_id` and `audit_event_id` came from nowhere. The point
# is to prove the CONSUMER refuses correctly, which is the half that has to
# exist before the storage does — otherwise the first real receipt is verified by
# code nobody ever watched fail.
#
# WHAT THIS FILE ENFORCES, after the 2026-08-30 correction. Retention follows
# LIFECYCLE, and the verifier reads the model from policy rather than a constant:
#
#   repository-artifact         unpublished. 90 days, the repository's own
#                               period. NO lock, NO versioning, NO encryption
#                               claim required — a GitHub artifact offers none of
#                               them, and demanding them would refuse the only
#                               mechanism in use.
#   supported-release-lifetime  published. The floor is the RELEASE's support end
#                               plus the notice buffers, so it differs per
#                               release rather than being a constant.
#   regulated-worm              compliance lock, versioning, encryption — and
#                               ONLY where the class records a named external
#                               obligation with duration, jurisdiction/contract,
#                               approver and date. A WORM class with no authority
#                               REFUSES, because the seven-year rule this
#                               repository carried for a week was assigned
#                               silently and nothing checked.
#
# Both halves are asserted. Requiring compliance mode everywhere was the old
# defect; letting a WORM class be claimed without an authority would be a new one.
#
# PHASE D IS DELIBERATELY NOT DONE. The workflow does not yet pass
# --require-storage-receipt, and this file PINS that as a gap rather than
# pretending the control is wired. When somebody wires it, the gap assertion
# fails and says to promote the line.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1

fail=0 nck=0 ngap=0
ck()  { nck=$((nck+1));  if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }
gap() { ngap=$((ngap+1)); if eval "$2"; then echo "GAP  - $1"; else
          echo "FAIL - GAP ASSERTION NO LONGER HOLDS (promote to ck): $1"; fail=1; fi; }

VERIFY=scripts/release/verify-storage-receipt.sh
SCHEMA=schemas/storage-receipt-v1.schema.json
MKR=tests/lib/make_storage_receipt.py
MKAUTH=tests/lib/make_authorization_fixture.py
ACCEPTED=docs/audits/acceptance-multiarch-2026-08-20/acceptance-evidence.json
POLICY=policies/retention.yaml

TMP="$(mktemp -d)"
# shellcheck disable=SC2064
trap "rm -rf '$TMP'" EXIT

python3 "$MKAUTH" "$ACCEPTED" "$TMP/auth.json" >/dev/null 2>&1
python3 "$MKAUTH" "$ACCEPTED" "$TMP/auth-other.json" --extra-child >/dev/null 2>&1

mk() { python3 "$MKR" --authorization "$TMP/auth.json" --out "$TMP/$1.json" "${@:2}" >/dev/null 2>&1; }
run() { bash "$VERIFY" "$1" --authorization "${2:-$TMP/auth.json}" "${@:3}" >"$TMP/out" 2>&1; }
says() { grep -q -- "$1" "$TMP/out"; }

echo "== the contract exists and is provider-NEUTRAL ==========================="

ck "the schema exists and is a valid JSON Schema" \
   "python3 -c \"
import json, jsonschema
jsonschema.Draft202012Validator.check_schema(json.load(open('$SCHEMA')))\""
ck "the verifier exists and is executable" "[ -x '$VERIFY' ]"
ck "the schema NAMES a provider field and CONSTRAINS no provider" \
   "python3 -c \"
import json
s=json.load(open('$SCHEMA'))
st=s['properties']['storage']['properties']
assert 'provider' in st and 'region' in st
for k in ('provider','region'):
    assert 'enum' not in st[k] and 'const' not in st[k], (k, st[k])
    assert 'pattern' not in st[k], k\""
ck "...and the verifier hardcodes no provider name either" \
   "! grep -qiE '\\b(aws|s3|gcs|azure|backblaze|wasabi|minio)\\b' '$VERIFY'"
ck "the retention floor comes from the POLICY, not from a number in the verifier" \
   "grep -q 'policies/retention.yaml' '$VERIFY' \\
    && ! grep -qE '\\b2555\\b' '$VERIFY'"

echo
echo "== NON-VACUITY: a conforming receipt VERIFIES ============================="

ck "a conforming receipt is accepted, and says what it observed" \
   "mk ok; run '$TMP/ok.json' '$TMP/auth.json' --today 2026-09-01 \
    && says 'storage receipt VERIFIED' && says 'class staged-candidate' \
    && says 'retained 90 day'"

echo
echo "== the policy no longer carries the unapproved seven-year rule ==========="

ck "the 2555-day requirement is GONE from every class" \
   "python3 -c \"
import yaml
d=yaml.safe_load(open('$POLICY'))
for c in d['classes']:
    assert c['retention_days'] != 2555, c
    assert c['immutable_storage_required'] is False, c\""
ck "compliance-mode / WORM is NOT the default for any shipped class" \
   "python3 -c \"
import yaml
d=yaml.safe_load(open('$POLICY'))
m=d['retention_models']
for c in d['classes']:
    assert m[c['retention_model']]['worm_required'] is False, c['evidence_class']
assert d['regulated_retention']['default'] is False
assert d['regulated_retention']['applies_to_classes'] == []\""
ck "unpublished evidence is allowed to EXPIRE, and the policy says so" \
   "python3 -c \"
import yaml
d=yaml.safe_load(open('$POLICY'))
for c in d['classes']:
    if c['lifecycle'] == 'unpublished':
        assert c['may_expire'] is True, c['evidence_class']
        assert c['retention_days'] == 90, c\""
ck "release assets are NOT described as permanent or immutable" \
   "python3 -c \"
import yaml
d=yaml.safe_load(open('$POLICY'))
c=[x for x in d['classes'] if x['evidence_class']=='published-artifact'][0]
claim=c['storage']['durability_claim'].lower()
assert 'not permanence' in claim and 'not immutability' in claim, claim
assert 'deletable' in claim\""
ck "reproducible SBOM bytes are NOT retained; identities are" \
   "python3 -c \"
import yaml
d=yaml.safe_load(open('$POLICY'))
r=d['reproducible_evidence']
assert 'sbom_documents' in r['not_retained']
assert 'immutable_image_digest' in r['retain_instead']
assert 'pinned_producer_identity' in r['retain_instead']
assert 'per_document_sha256' in r['retain_instead']
assert 'byte-identical' in r['honest_limit']\""
ck "the vulnerability database separates VERDICT from RERUN capability" \
   "python3 -c \"
import yaml
d=yaml.safe_load(open('$POLICY'))
v=d['vulnerability_database']
assert v['preserve_verdict']['required'] is True
assert v['preserve_rerun_capability']['required'] is False
assert 'DOES NOT MAKE A DELETED SNAPSHOT RETRIEVABLE' in v['identity_is_not_retrievability']\""
ck "detection of missing or prematurely deleted evidence is required" \
   "python3 -c \"
import yaml
d=yaml.safe_load(open('$POLICY'))
m=d['monitoring']
assert 'published-artifact' in m['required_for']
for k in ('missing_required_evidence','prematurely_deleted_evidence','retention_shorter_than_policy'):
    assert k in m['detect'], k\""

echo
echo "== STAGED: 90-day transport is ACCEPTED, with no lock and no versioning ==="

ck "a staged receipt with lock=none and versioning=not-applicable VERIFIES" \
   "mk staged --retention-days 90; run '$TMP/staged.json' '$TMP/auth.json' --today 2026-09-01 \
    && says 'model repository-artifact' && says 'lock=none'"
ck "...so the mechanism actually in use is not refused by its own policy" \
   "says 'retained 90 day'"
ck "S1 SABOTAGE: under the repository period is still REFUSED" \
   "mk s89 --retention-days 89; ! run '$TMP/s89.json' '$TMP/auth.json' --today 2026-09-01 \
    && says 'SR-RETENTION-SHORT' && says '89 day'"
ck "S2 SABOTAGE: exactly 90 days is accepted (the floor is inclusive)" \
   "mk s90 --retention-days 90; run '$TMP/s90.json' '$TMP/auth.json' --today 2026-09-01"

echo
echo "== PUBLISHED: retention binds to the release lifecycle plus its buffers ==="

# Every published fixture composes its evidence in, because a published receipt
# that does not is refused — see L1. The flag is part of what "published" means
# here, not an option.
PUB="--retention-class published-artifact --supported-until 2028-12-31T00:00:00Z --published-evidence"
ck "a published receipt retained past support end + 270 days VERIFIES" \
   "mk pub $PUB --retention-days 1200
    run '$TMP/pub.json' '$TMP/auth.json' --today 2026-09-01 \
    && says 'model supported-release-lifetime'"
ck "S3 SABOTAGE: retention short of support end + buffer is REFUSED" \
   "mk pubshort $PUB --mutate release-short
    ! run '$TMP/pubshort.json' '$TMP/auth.json' --today 2026-09-01 \
    && says 'SR-RETENTION-SHORT' && says 'notice buffer'"
ck "...and the diagnostic names the release, its support end and the floor" \
   "says 'v2026.07.24' && says '2028-12-31' && says '2029-09-27'"
ck "S4 SABOTAGE: a published receipt with NO release identity is REFUSED" \
   "mk pubnorel --retention-class published-artifact --retention-days 1200
    ! run '$TMP/pubnorel.json' '$TMP/auth.json' --today 2026-09-01 \
    && says 'SR-RELEASE-BINDING-ABSENT' && says 'lifecycle it does not identify'"
# The class matters. Lapse is a REFUSAL for a distributed release and an
# ACCEPTED OUTCOME for an undistributed staged candidate — see L5 below. The
# fixture puts the support end far in the past so the floor is already met and
# the lapse, not the floor, is what the verifier is reacting to.
ck "S5 DETECTION: a PUBLISHED receipt whose retention has already lapsed is REFUSED" \
   "mk gone --retention-class published-artifact --published-evidence \
       --supported-until 2020-01-01T00:00:00Z --retention-days 5
    ! run '$TMP/gone.json' '$TMP/auth.json' --today 2026-09-01 \
    && says 'SR-EVIDENCE-EXPIRED' && says 'may no longer exist'"

echo
echo "== LIFECYCLE BOUNDARY: proven with fixtures, not assumed ================="
# The 90-day classes and the published class meet at exactly one place: the
# moment evidence stops being a private staging artifact and starts being the
# reason a distributed release was accepted. Six proofs, because "the boundary
# holds" is otherwise a sentence in a policy file that nothing executes.

ck "L1 a published bundle must CARRY its evidence, and carrying is CHECKED" \
   "mk L1 $PUB --retention-days 1200 --published-evidence
    run '$TMP/L1.json' '$TMP/auth.json' --today 2026-09-01 \
    && python3 -c \"
import json
b = json.load(open('$TMP/L1.json'))['bundle']
pe = b['published_evidence']
have = {f['sha256'] for f in b['files']}
assert pe['authorization_record_sha256'] in have
assert have.issuperset(v['sha256'] for v in pe['scan_verdicts'])
for k in ('image_digests','scanner','vulnerability_database','source_revision',
          'policy_identity','ledger_identity'):
    assert pe.get(k), k\""
ck "L1 SABOTAGE: a published bundle with NO composed evidence is REFUSED" \
   "mk L1a $PUB --retention-days 1200 --published-evidence \
       --mutate published-no-evidence
    ! run '$TMP/L1a.json' '$TMP/auth.json' --today 2026-09-01 \
    && says 'SR-PUBLISHED-INCOMPLETE'"
ck "L1 SABOTAGE: NAMING a scan verdict it does not carry is REFUSED" \
   "mk L1b $PUB --retention-days 1200 --published-evidence \
       --mutate published-verdict-not-carried
    ! run '$TMP/L1b.json' '$TMP/auth.json' --today 2026-09-01 \
    && says 'SR-PUBLISHED-INCOMPLETE' && says 'Naming evidence is not carrying it'"
ck "L1 SABOTAGE: naming an authorization record it does not carry is REFUSED" \
   "mk L1c $PUB --retention-days 1200 --published-evidence \
       --mutate published-auth-not-carried
    ! run '$TMP/L1c.json' '$TMP/auth.json' --today 2026-09-01 \
    && says 'SR-PUBLISHED-INCOMPLETE'"

# support end + deprecation notice + withdrawal notice, from the POLICY's own
# numbers rather than a constant retyped here.
FLOORD="$(python3 -c "
import datetime, yaml
d = yaml.safe_load(open('$POLICY'))
c = [x for x in d['classes'] if x['evidence_class'] == 'published-artifact'][0]
end = datetime.date(2028, 12, 31)
floor = end + datetime.timedelta(days=c['buffer_deprecation_days']
                                 + c['buffer_withdrawal_days'])
print((floor - datetime.date(2026, 8, 20)).days)")"
ck "L2 the floor is support end + 180 + 90, and the policy's buffers say so" \
   "python3 -c \"
import yaml
d = yaml.safe_load(open('$POLICY'))
c = [x for x in d['classes'] if x['evidence_class'] == 'published-artifact'][0]
assert c['buffer_deprecation_days'] == 180 and c['buffer_withdrawal_days'] == 90
assert c['retention_days'] == 270 == 180 + 90\" \
    && [ '$FLOORD' = 1134 ]"
ck "L2 retention that reaches exactly that day is ACCEPTED" \
   "mk L2 $PUB --retention-days '$FLOORD' --published-evidence
    run '$TMP/L2.json' '$TMP/auth.json' --today 2026-09-01 && says '2029-09-27'"
ck "L2 SABOTAGE: one day short of it is REFUSED" \
   "mk L2a $PUB --retention-days \$(( FLOORD - 1 )) --published-evidence
    ! run '$TMP/L2a.json' '$TMP/auth.json' --today 2026-09-01 \
    && says 'SR-RETENTION-SHORT' && says 'notice buffer'"

ck "L3 the published bundle still VERIFIES long after the 90-day copies lapse" \
   "run '$TMP/L1.json' '$TMP/auth.json' --today 2027-06-01 \
    && says 'storage receipt VERIFIED' && says 'class published-artifact'"
ck "L3 ...on the same day a 90-day staged copy of the same run has lapsed" \
   "mk L3 --retention-days 90
    run '$TMP/L3.json' '$TMP/auth.json' --today 2027-06-01 && says 'lapsed on'"
ck "L3 ...and the published bundle's completeness never depended on that copy" \
   "python3 -c \"
import json
b = json.load(open('$TMP/L1.json'))['bundle']
r = json.load(open('$TMP/L1.json'))['readback']
assert not b['published_evidence'].get('transient_references')
assert r['files_expected'] == r['files_verified'] == len(b['files'])\""

ck "L4 SABOTAGE: a published bundle POINTING at an expiring artifact is REFUSED" \
   "mk L4 $PUB --retention-days 1200 --published-evidence \
       --mutate published-references-transient
    ! run '$TMP/L4.json' '$TMP/auth.json' --today 2026-09-01 \
    && says 'SR-PUBLISHED-REFERENCES-TRANSIENT' \
    && says 'shortest-lived thing it depends on'"

ck "L5 an unpublished staged candidate MAY lapse, and that is not a violation" \
   "run '$TMP/L3.json' '$TMP/auth.json' --today 2027-06-01 \
    && says 'may_expire: true' && says 'no release retention is violated' \
    && ! says 'SR-EVIDENCE-EXPIRED'"
ck "L5 ...and the policy grants that only to the unpublished classes" \
   "python3 -c \"
import yaml
d = yaml.safe_load(open('$POLICY'))
for c in d['classes']:
    assert bool(c.get('may_expire')) == (c['lifecycle'] == 'unpublished'), c\""

# L6. Every proof above ran against a FIXTURE. This repository publishes nothing
# today and this PR does not change that — the boundary is being built before the
# thing it bounds, on purpose, so the first real published bundle is verified by
# code somebody already watched refuse.
ck "L6 publication authority is still undetermined — nothing is published" \
   "python3 -c \"
import yaml
assert yaml.safe_load(open('policies/license-policy.yaml'))['publication']['decision'] \
    == 'undetermined'\""
ck "L6 no workflow creates a release or a tag" \
   "! grep -rqE 'gh release create|action-gh-release|actions/create-release' .github/workflows/"
ck "L6 no workflow names the published-artifact class at all" \
   "! grep -rq 'published-artifact' .github/workflows/"
ck "L6 the published path is exercised ONLY by fixtures built in this test" \
   "grep -q 'FIXTURE-provider-not-selected' '$TMP/L1.json'"

echo
echo "== THE SCAN VERDICT IS RETAINED; THE SCAN IS NOT REPRODUCIBLE ============="
# The database bytes (~110 MB per run) are NOT required. What is required is the
# small set of things that make the recorded verdict checkable — and a written
# statement of exactly what that does and does not prove, so nobody upgrades
# "we know which database it was" into "we can run it again".

ck "V1 the database BYTES are not required, and the policy says why not" \
   "python3 -c \"
import yaml
v = yaml.safe_load(open('$POLICY'))['vulnerability_database']
assert v['preserve_verdict']['required'] is True
assert v['preserve_rerun_capability']['required'] is False
assert 'NOT REQUIRED' in v['preserve_rerun_capability']['decision_status']\""
ck "V2 the limitation is recorded VERBATIM, not paraphrased" \
   "python3 -c \"
import yaml
v = yaml.safe_load(open('$POLICY'))['vulnerability_database']
assert ' '.join(v['limitation_statement'].split()) == (
    'The retained evidence proves the verdict recorded at decision time. '
    'Database identity alone does not preserve the deleted database snapshot '
    'and therefore does not support an exact historical rerun.'), \
    v['limitation_statement']\""
ck "V3 the policy forbids calling the scan reproducible once the bytes expire" \
   "python3 -c \"
import yaml
v = yaml.safe_load(open('$POLICY'))['vulnerability_database']
assert 'Do not describe the scan as reproducible' in v['prohibited_claim']\""
ck "V4 ...and no policy section claims it anyway: the scan is IRREPRODUCIBLE" \
   "python3 -c \"
import yaml
d = yaml.safe_load(open('$POLICY'))
req = d['irreproducible_evidence']['required']
assert 'scan_verdicts' in req and 'vulnerability_database_identity' in req
assert 'scan_verdicts' not in d['reproducible_evidence']['not_retained']\""
ck "V5 seven items are bound in place of the bytes" \
   "python3 -c \"
import yaml
v = yaml.safe_load(open('$POLICY'))['vulnerability_database']
assert len(v['bind_instead_of_bytes']) == 7, v['bind_instead_of_bytes']\""
ck "V6 ...and the SCHEMA requires every one of them of a published bundle" \
   "python3 -c \"
import json
s = json.load(open('$SCHEMA'))
def find(o):
    if isinstance(o, dict):
        if 'published_evidence' in o.get('properties', {}):
            return o['properties']['published_evidence']
        for v in o.values():
            r = find(v)
            if r:
                return r
    return None
pe = find(s)
need = {'image_digests','scan_verdicts','authorization_record_sha256','scanner',
        'vulnerability_database','source_revision','policy_identity',
        'ledger_identity'}
assert need.issubset(set(pe['required'])), sorted(need - set(pe['required']))
vd = pe['properties']['vulnerability_database']
assert set(vd['required']) == {'identity','observed_at'}, vd['required']\""
ck "V7 the not-yet-authorized shape is written down: dedup by database digest" \
   "python3 -c \"
import yaml
v = yaml.safe_load(open('$POLICY'))['vulnerability_database']
t = v['if_bytes_are_later_authorized']
assert 'Deduplicate snapshots by database digest' in t
assert 'per child' in t and 'per run' in t\""

echo
echo "== REGULATED WORM: opt-in, and never assignable in silence ================"

# The class is built in a COPY of the policy. The shipped policy has no
# regulated class and this test does not add one to it.
regpol() { # regpol <out> <with-authority: yes|no>
  python3 - "$POLICY" "$1" "$2" <<'PYR'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
c = [x for x in d['classes'] if x['evidence_class'] == 'published-artifact'][0]
c['retention_model'] = 'regulated-worm'
if sys.argv[3] == 'yes':
    c['external_obligation'] = {
        'name': 'FIXTURE-obligation-not-real',
        'duration': 'P7Y',
        'jurisdiction_or_contract': 'FIXTURE-jurisdiction',
        'approved_by': 'FIXTURE-approver',
        'approved_on': '2026-08-30',
    }
yaml.safe_dump(d, open(sys.argv[2], 'w'))
PYR
}
ck "S6 SABOTAGE: a WORM class with NO named external obligation is REFUSED" \
   "regpol '$TMP/pol-reg-noauth.yaml' no
    mk regna $PUB --retention-days 1200 --lock-mode compliance --versioning enabled
    ! run '$TMP/regna.json' '$TMP/auth.json' --retention-policy '$TMP/pol-reg-noauth.yaml' --today 2026-09-01 \
    && says 'SR-REGULATED-UNAUTHORIZED' && says 'NAMED obligation'"
ck "...naming every field the authority record is missing" \
   "says 'name' && says 'duration' && says 'approved_by'"
ck "S7 NON-VACUOUS: WITH a complete authority record the same receipt verifies" \
   "regpol '$TMP/pol-reg-auth.yaml' yes
    run '$TMP/regna.json' '$TMP/auth.json' --retention-policy '$TMP/pol-reg-auth.yaml' --today 2026-09-01 \
    && says 'model regulated-worm'"
ck "S8 SABOTAGE: an authorised WORM class still REFUSES a governance-mode lock" \
   "mk reggov $PUB --retention-days 1200 --lock-mode governance --versioning enabled
    ! run '$TMP/reggov.json' '$TMP/auth.json' --retention-policy '$TMP/pol-reg-auth.yaml' --today 2026-09-01 \
    && says 'SR-LOCK-MODE-WEAK' && says 'privileged principal' && says 'is not immutability'"
ck "S9 SABOTAGE: an authorised WORM class REFUSES versioning that is off" \
   "mk regnv $PUB --retention-days 1200 --lock-mode compliance --versioning suspended
    ! run '$TMP/regnv.json' '$TMP/auth.json' --retention-policy '$TMP/pol-reg-auth.yaml' --today 2026-09-01 \
    && says 'SR-VERSIONING-ABSENT'"
ck "S10 SABOTAGE: an authorised WORM class REFUSES an unencrypted object" \
   "mk regne $PUB --retention-days 1200 --lock-mode compliance --versioning enabled --mutate encryption-off
    ! run '$TMP/regne.json' '$TMP/auth.json' --retention-policy '$TMP/pol-reg-auth.yaml' --today 2026-09-01 \
    && says 'SR-ENCRYPTION-ABSENT'"
ck "S11 NON-VACUOUS: none of those WORM properties is demanded of ORDINARY evidence" \
   "run '$TMP/staged.json' '$TMP/auth.json' --today 2026-09-01"
ck "S12 SABOTAGE: a class naming a model the policy does not declare is REFUSED" \
   "python3 - '$POLICY' '$TMP/pol-badmodel.yaml' <<'PYM'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
c = [x for x in d['classes'] if x['evidence_class'] == 'staged-candidate'][0]
c['retention_model'] = 'not-a-declared-model'
yaml.safe_dump(d, open(sys.argv[2], 'w'))
PYM
    ! run '$TMP/staged.json' '$TMP/auth.json' --retention-policy '$TMP/pol-badmodel.yaml' --today 2026-09-01 \
    && says 'SR-RETENTION-MODEL' && says 'nothing enforces'"

echo
echo "== A CLAIMED UPLOAD IS NOT A RECEIPT ====================================="

ck "S13 SABOTAGE: an ABSENT receipt is REFUSED, never skipped" \
   "! run '$TMP/no-such-receipt.json' && says 'SR-RECEIPT-ABSENT' && says 'never a skip'"
ck "S14 SABOTAGE: an EMPTY path is not 'not asked for' — it also REFUSES" \
   "! run '' && says 'SR-RECEIPT-ABSENT'"
ck "S15 SABOTAGE: a receipt with no audit event or version REFUSES as unobserved" \
   "mk noauth --mutate authority-unavailable; ! run '$TMP/noauth.json' \\
    && says 'SR-AUTHORITY-UNAVAILABLE' && says 'could have written for itself'"
ck "S16 SABOTAGE: no readback at all is REFUSED" \
   "mk norb --mutate readback-absent; ! run '$TMP/norb.json' \\
    && says 'SR-READBACK-ABSENT' && says 'claim about durability'"
ck "S17 SABOTAGE: a readback that did not match is REFUSED" \
   "mk rbfail --mutate readback-failed; ! run '$TMP/rbfail.json' \\
    && says 'SR-READBACK-FAILED'"
ck "S18 SABOTAGE: one file short on readback is REFUSED" \
   "mk fmiss --mutate file-missing; ! run '$TMP/fmiss.json' \\
    && says 'SR-FILE-MISSING'"
ck "S19 SABOTAGE: a stored object that is not the bundle is REFUSED" \
   "mk cksum --mutate checksum-mismatch; ! run '$TMP/cksum.json' \\
    && says 'SR-CHECKSUM-MISMATCH'"

echo
echo "== THE RECEIPT MUST BE FOR THIS CANDIDATE ================================"

ck "S20 SABOTAGE: a receipt bound to ANOTHER authorization record is REFUSED" \
   "mk ok2; ! run '$TMP/ok2.json' '$TMP/auth-other.json' && says 'SR-UNBOUND'"
ck "S21 SABOTAGE: an explicitly unbound receipt is REFUSED" \
   "mk unb --mutate unbound; ! run '$TMP/unb.json' && says 'SR-UNBOUND'"
ck "S22 SABOTAGE: another source revision is REFUSED" \
   "mk rev --mutate wrong-revision; ! run '$TMP/rev.json' \\
    && says 'SR-REVISION-MISMATCH'"
ck "S23 SABOTAGE: a PARTIAL child set is REFUSED" \
   "mk part --mutate wrong-candidate; ! run '$TMP/part.json' \\
    && says 'SR-CANDIDATE-MISMATCH' && says 'no evidence in this receipt'"
ck "S24 SABOTAGE: a wrong image digest is REFUSED" \
   "mk dig --mutate wrong-digest; ! run '$TMP/dig.json' \\
    && says 'SR-CANDIDATE-MISMATCH' && says 'digest'"
ck "S25 SABOTAGE: a wrong platform is REFUSED" \
   "mk plat --mutate wrong-platform; ! run '$TMP/plat.json' \\
    && says 'SR-CANDIDATE-MISMATCH' && says 'platform'"
ck "S26 SABOTAGE: a receipt that is not a storage-receipt/v1 record is REFUSED" \
   "printf '{\"schema\":\"nope\"}\n' > '$TMP/bad.json'
    ! run '$TMP/bad.json' && says 'SR-RECEIPT-MALFORMED'"
# TWO controls, and each is asserted where it actually fires. The schema's enum
# rejects a class that is not one of the four the repository declares at all; the
# verifier's policy lookup rejects a schema-valid class that policies/retention.yaml
# has stopped declaring. The second is not hypothetical — a class can be removed
# from the policy while the schema still lists it, and that is exactly when a
# retention rule quietly becomes a rule about nothing.
ck "S27 SABOTAGE: a class outside the declared four fails the SCHEMA" \
   "mk unk
    python3 - '$TMP/unk.json' <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d['bundle']['retention_class'] = 'not-a-declared-class'
json.dump(d, open(sys.argv[1], 'w'))
PY
    ! run '$TMP/unk.json' && says 'SR-RECEIPT-MALFORMED' \
    && says 'does not satisfy storage-receipt-v1'"
ck "S28 SABOTAGE: a schema-valid class the POLICY no longer declares is REFUSED" \
   "python3 - '$POLICY' '$TMP/policy-stripped.yaml' <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
d['classes'] = [c for c in d['classes']
                if c['evidence_class'] != 'staged-candidate']
yaml.safe_dump(d, open(sys.argv[2], 'w'))
PY
    mk ok3
    ! run '$TMP/ok3.json' '$TMP/auth.json' --retention-policy '$TMP/policy-stripped.yaml' \
    && says 'SR-RECEIPT-MALFORMED' && says 'a rule about nothing'"
ck "S23 NON-VACUOUS: the same receipt passes against the SHIPPED policy" \
   "run '$TMP/ok3.json'"

echo
echo "== the missing validator must NOT pass ==================================="

ck "jsonschema and PyYAML are present here, so the checks above were not skipped" \
   "python3 -c 'import jsonschema, yaml'"
ck "the verifier REFUSES rather than passing when they are absent" \
   "grep -q 'PyYAML and jsonschema are required' '$VERIFY'"

echo
echo "== PHASE D IS NOT DONE, and is pinned rather than implied ================="

gap "the acceptance workflow does NOT yet require a storage receipt (#241 phase D)" \
   "! grep -q -- '--require-storage-receipt' .github/workflows/stage-and-authorize.yml"
gap "...so authorization can still complete with no durable evidence at all" \
   "! grep -q 'verify-storage-receipt' .github/workflows/stage-and-authorize.yml"
echo "       WHAT WOULD CLOSE THEM: phases B-D of #241 — provisioning, a canary"
echo "       upload with a real lock and readback, then workflow integration."
echo "       Each is separately authorized; none is done here."

ck "the REQUIRED CI path executes this file" \
   "grep -q 'tests/release/test_storage_receipt.sh' .github/workflows/ci.yml"
ck "the subsystem-coverage list names the verifier" \
   "grep -q 'scripts/release/verify-storage-receipt.sh' tests/governance/test_subsystem_ci_coverage.sh"

echo
echo "== nothing here provisioned, uploaded or configured anything ============="

ck "no fixture claims a real provider" \
   "grep -q 'FIXTURE-provider-not-selected' '$MKR'"
ck "the fixture builder says in writing that its values came from nowhere" \
   "grep -qi 'came from nowhere' '$MKR' || grep -qi 'never be presented as evidence' '$MKR'"
ck "the test mutated no tracked file" \
   "test -z \"\$(git -C '$ROOT' status --porcelain -- policies scripts schemas docs 2>/dev/null | grep -v '^??' || true)\""

echo "----"
printf 'assertions: %d proven, %d pinned gaps\n' "$nck" "$ngap"
[ "$fail" -eq 0 ] && echo "test_storage_receipt: PASS" || echo "test_storage_receipt: FAIL"
exit "$fail"
