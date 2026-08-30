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
# THE DISTINCTION THIS FILE EXISTS TO ENFORCE. `governance` mode and `compliance`
# mode are both "object lock" and only one of them is immutability: under
# governance a privileged principal can shorten the retention or delete the
# object early. A class that requires immutable storage must refuse a
# governance-mode receipt, and the refusal must SAY that, because "object lock is
# enabled" is exactly the sentence that hides the difference.
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
ck "the policy really does declare 2555 days and immutability for the class" \
   "python3 -c \"
import yaml
d=yaml.safe_load(open('$POLICY'))
c=[x for x in d['classes'] if x['evidence_class']=='staged-candidate'][0]
assert c['retention_days']==2555, c['retention_days']
assert c['immutable_storage_required'] is True\""

echo
echo "== NON-VACUITY: a conforming receipt VERIFIES ============================="

ck "a conforming receipt is accepted, and says what it observed" \
   "mk ok; run '$TMP/ok.json' && says 'storage receipt VERIFIED' \\
    && says 'compliance mode' && says '2555 day'"

echo
echo "== RETENTION BOUNDARY ===================================================="

ck "exactly 2555 days is ACCEPTED (the floor is inclusive)" \
   "mk b2555 --retention-days 2555; run '$TMP/b2555.json'"
ck "2554 days is REFUSED (one day under the floor)" \
   "mk b2554 --retention-days 2554; ! run '$TMP/b2554.json' \\
    && says 'SR-RETENTION-SHORT' && says '2554 day'"
ck "...and the diagnostic names the class and the number the policy requires" \
   "says 'staged-candidate' && says '2555'"
ck "90 days — the GitHub artifact baseline — is REFUSED outright" \
   "mk b90 --retention-days 90; ! run '$TMP/b90.json' && says 'SR-RETENTION-SHORT'"
ck "S1 SABOTAGE: retention shorter than the authority was ASKED for is REFUSED" \
   "mk short --mutate retention-short; ! run '$TMP/short.json' \\
    && says 'SR-RETENTION-SHORT'"
ck "S2 SABOTAGE: meeting the class floor but NOT what Foundry required is REFUSED" \
   "mk reqnot --mutate required-not-met; ! run '$TMP/reqnot.json' \\
    && says 'SR-RETENTION-SHORT' && says 'What'"
ck "S3 SABOTAGE: expiry inside the supported period is REFUSED" \
   "mk sup; ! run '$TMP/sup.json' '$TMP/auth.json' --support-until 2035-01-01 \\
    && says 'SR-EXPIRY-BEFORE-SUPPORT' && says 'inside the support window'"

echo
echo "== COMPLIANCE MODE IS NOT GOVERNANCE MODE ================================"

ck "S4 SABOTAGE: a GOVERNANCE-mode lock is REFUSED where immutability is required" \
   "mk gov --mutate governance-mode; ! run '$TMP/gov.json' && says 'SR-LOCK-MODE-WEAK'"
ck "...and the diagnostic says a privileged principal can still delete it" \
   "says 'privileged principal' && says 'is not immutability'"
ck "S5 SABOTAGE: no lock at all is REFUSED, and called a label" \
   "mk nolock --mutate no-lock; ! run '$TMP/nolock.json' \\
    && says 'SR-LOCK-MODE-WEAK' && says 'is a label'"
ck "S6 SABOTAGE: versioning off is REFUSED — lock has nothing to pin" \
   "mk nover --mutate versioning-off; ! run '$TMP/nover.json' \\
    && says 'SR-VERSIONING-ABSENT' && says 'indistinguishable from the original'"
ck "S7 SABOTAGE: an unencrypted object is REFUSED" \
   "mk noenc --mutate encryption-off; ! run '$TMP/noenc.json' \\
    && says 'SR-ENCRYPTION-ABSENT'"

echo
echo "== A CLAIMED UPLOAD IS NOT A RECEIPT ====================================="

ck "S8 SABOTAGE: an ABSENT receipt is REFUSED, never skipped" \
   "! run '$TMP/no-such-receipt.json' && says 'SR-RECEIPT-ABSENT' && says 'never a skip'"
ck "S9 SABOTAGE: an EMPTY path is not 'not asked for' — it also REFUSES" \
   "! run '' && says 'SR-RECEIPT-ABSENT'"
ck "S10 SABOTAGE: a receipt with no audit event or version REFUSES as unobserved" \
   "mk noauth --mutate authority-unavailable; ! run '$TMP/noauth.json' \\
    && says 'SR-AUTHORITY-UNAVAILABLE' && says 'could have written for itself'"
ck "S11 SABOTAGE: no readback at all is REFUSED" \
   "mk norb --mutate readback-absent; ! run '$TMP/norb.json' \\
    && says 'SR-READBACK-ABSENT' && says 'claim about durability'"
ck "S12 SABOTAGE: a readback that did not match is REFUSED" \
   "mk rbfail --mutate readback-failed; ! run '$TMP/rbfail.json' \\
    && says 'SR-READBACK-FAILED'"
ck "S13 SABOTAGE: one file short on readback is REFUSED" \
   "mk fmiss --mutate file-missing; ! run '$TMP/fmiss.json' \\
    && says 'SR-FILE-MISSING'"
ck "S14 SABOTAGE: a stored object that is not the bundle is REFUSED" \
   "mk cksum --mutate checksum-mismatch; ! run '$TMP/cksum.json' \\
    && says 'SR-CHECKSUM-MISMATCH'"

echo
echo "== THE RECEIPT MUST BE FOR THIS CANDIDATE ================================"

ck "S15 SABOTAGE: a receipt bound to ANOTHER authorization record is REFUSED" \
   "mk ok2; ! run '$TMP/ok2.json' '$TMP/auth-other.json' && says 'SR-UNBOUND'"
ck "S16 SABOTAGE: an explicitly unbound receipt is REFUSED" \
   "mk unb --mutate unbound; ! run '$TMP/unb.json' && says 'SR-UNBOUND'"
ck "S17 SABOTAGE: another source revision is REFUSED" \
   "mk rev --mutate wrong-revision; ! run '$TMP/rev.json' \\
    && says 'SR-REVISION-MISMATCH'"
ck "S18 SABOTAGE: a PARTIAL child set is REFUSED" \
   "mk part --mutate wrong-candidate; ! run '$TMP/part.json' \\
    && says 'SR-CANDIDATE-MISMATCH' && says 'no evidence in this receipt'"
ck "S19 SABOTAGE: a wrong image digest is REFUSED" \
   "mk dig --mutate wrong-digest; ! run '$TMP/dig.json' \\
    && says 'SR-CANDIDATE-MISMATCH' && says 'digest'"
ck "S20 SABOTAGE: a wrong platform is REFUSED" \
   "mk plat --mutate wrong-platform; ! run '$TMP/plat.json' \\
    && says 'SR-CANDIDATE-MISMATCH' && says 'platform'"
ck "S21 SABOTAGE: a receipt that is not a storage-receipt/v1 record is REFUSED" \
   "printf '{\"schema\":\"nope\"}\n' > '$TMP/bad.json'
    ! run '$TMP/bad.json' && says 'SR-RECEIPT-MALFORMED'"
# TWO controls, and each is asserted where it actually fires. The schema's enum
# rejects a class that is not one of the four the repository declares at all; the
# verifier's policy lookup rejects a schema-valid class that policies/retention.yaml
# has stopped declaring. The second is not hypothetical — a class can be removed
# from the policy while the schema still lists it, and that is exactly when a
# retention rule quietly becomes a rule about nothing.
ck "S22 SABOTAGE: a class outside the declared four fails the SCHEMA" \
   "mk unk
    python3 - '$TMP/unk.json' <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d['bundle']['retention_class'] = 'not-a-declared-class'
json.dump(d, open(sys.argv[1], 'w'))
PY
    ! run '$TMP/unk.json' && says 'SR-RECEIPT-MALFORMED' \
    && says 'does not satisfy storage-receipt-v1'"
ck "S23 SABOTAGE: a schema-valid class the POLICY no longer declares is REFUSED" \
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
