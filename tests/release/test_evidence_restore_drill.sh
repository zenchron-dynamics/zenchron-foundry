#!/usr/bin/env bash
# shellcheck disable=SC2034  # assertion locals are consumed inside ck() eval strings
# =============================================================================
# tests/release/test_evidence_restore_drill.sh — #241, the restore drill.
# -----------------------------------------------------------------------------
# The receipt proved that uploaded evidence comes BACK. This proves it can be
# USED: archived, restored by bundle id onto a filesystem that holds nothing
# else, re-verified offline, and compared byte for byte with what was handed
# over.
#
# WHAT THE DRILL IS. Two jobs on two runners. `evidence-drill-produce` builds a
# bundle and uploads it; `evidence-drill-restore` starts empty, downloads it,
# DELETES the downloaded working copy, restores from the archive alone and
# compares every byte. A producer and a consumer sharing a directory would prove
# nothing, which is why the boundary is a real artifact and a real second runner.
#
# WHAT IT IS NOT. It is not production evidence and its bundle is not an
# accepted candidate: the authorization record is a fixture from
# tests/lib/make_authorization_fixture.py, every artifact is named
# `evidence-drill-*`, and the verdict carries that sentence in a field this file
# asserts. Nothing builds an image, pulls one, scans anything, dispatches
# acceptance, publishes, tags or releases.
#
# HOW THIS FILE TESTS IT. It does not grep the workflow. It parses ci.yml, takes
# the exact `run:` bodies of the drill steps and EXECUTES them, with the artifact
# hop stood in for by copies between distinct directories — the REAL hop is
# exercised by the workflow itself on every pull request, and `repo structure`,
# a required check, consumes the verdict.
#
# THE POSITIVE ROUND TRIP RUNS FIRST. Every refusal below is measured against a
# drill that has already been shown to pass.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1

fail=0 nck=0
ck() { nck=$((nck+1)); if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

WF=.github/workflows/ci.yml
STEP=tests/lib/workflow_step.py
DRILL=scripts/ci/evidence-restore-drill.sh
GEN=scripts/release/generate-evidence-bundle.sh
ACCEPTED=docs/audits/acceptance-multiarch-2026-08-20/acceptance-evidence.json
POLICY=policies/retention.yaml

TMP="$(mktemp -d)"
# shellcheck disable=SC2064
trap "chmod -R u+w '$TMP' 2>/dev/null; rm -rf '$TMP'" EXIT

# The four step bodies, taken from the workflow rather than retyped here.
for spec in "evidence-drill-produce:drill-produce:produce" \
            "evidence-drill-produce:drill-receipt:receipt" \
            "evidence-drill-restore:drill-restore:restore" \
            "structure:drill-consume:consume"; do
  job="${spec%%:*}"; rest="${spec#*:}"; sid="${rest%%:*}"; nm="${rest##*:}"
  python3 "$STEP" "$WF" "$job" "$sid" --run > "$TMP/body-$nm.sh" 2>/dev/null
done

obs() { # obs <out> <days>
  python3 - "$1" "$2" <<'PY'
import datetime, json, sys
up = datetime.datetime(2026, 8, 20, 17, 10, tzinfo=datetime.timezone.utc)
json.dump({"id": 991122, "node_id": "MDg6QXJ0aWZhY3Q5OTExMjI",
           "name": "evidence-drill-bundle-1-1", "size_in_bytes": 20480,
           "expired": False,
           "created_at": up.isoformat().replace("+00:00", "Z"),
           "expires_at": (up + datetime.timedelta(days=int(sys.argv[2])))
                         .isoformat().replace("+00:00", "Z")},
          open(sys.argv[1], "w"), indent=1)
PY
}

# One produced bundle, reused by every case below. The artifact hop is a copy
# into a DIFFERENT directory each time, so no case can see another's state.
BUILD="$TMP/build"
DRILL_EVIDENCE="$ACCEPTED" DRILL_OUT="$BUILD/upload" bash "$TMP/body-produce.sh" \
  > "$TMP/produce.log" 2>&1
cp -r "$BUILD/upload" "$BUILD/readback"
obs "$BUILD/observation.json" 90
DRILL_RECORD="$BUILD/upload/record.json" DRILL_READBACK="$BUILD/readback/bundle" \
DRILL_OBSERVATION="$BUILD/observation.json" \
DRILL_RECEIPT="$BUILD/receipt/storage-receipt.json" DRILL_REPOSITORY="z/z" \
  bash "$TMP/body-receipt.sh" > "$TMP/receipt.log" 2>&1

# hop <case> -> $TMP/<case>/{dl,rcpt}: a fresh pair of downloaded directories.
hop() {
  local c="$TMP/$1"; rm -rf "$c"; mkdir -p "$c"
  cp -r "$BUILD/upload" "$c/dl"; cp -r "$BUILD/receipt" "$c/rcpt"; echo "$c"
}
# run_restore <case-dir> -> executes the workflow's own restore body
run_restore() {
  DRILL_BUNDLE_ARTIFACT="$1/dl" DRILL_RECEIPT_ARTIFACT="$1/rcpt" \
  DRILL_WORK="$1/work" DRILL_VERDICT="$1/verdict/verdict.json" \
  DRILL_RUN_ID=1 DRILL_COMMIT=abc123 \
    bash "$TMP/body-restore.sh" > "$TMP/out" 2>&1
}
run_consume() { # run_consume <verdict> [run] [commit]
  DRILL_VERDICT="$1" DRILL_RUN_ID="${2-1}" DRILL_COMMIT="${3-abc123}" \
    bash "$TMP/body-consume.sh" > "$TMP/out" 2>&1
}
says() { grep -q -- "$1" "$TMP/out"; }

echo "== the drill exists in the workflow, on TWO runners ======================"

ck "both drill jobs exist and the restore job needs the produce job" \
   "python3 -c \"
import yaml
j = yaml.safe_load(open('$WF'))['jobs']
assert 'evidence-drill-produce' in j and 'evidence-drill-restore' in j
assert j['evidence-drill-restore']['needs'] == ['evidence-drill-produce']
assert j['evidence-drill-produce']['runs-on'] == 'ubuntu-latest'
assert j['evidence-drill-restore']['runs-on'] == 'ubuntu-latest'\""
ck "the restore job downloads the bundle rather than inheriting a directory" \
   "python3 -c \"
import yaml
st = yaml.safe_load(open('$WF'))['jobs']['evidence-drill-restore']['steps']
dl = [s for s in st if 'download-artifact' in str(s.get('uses',''))]
assert len(dl) == 2, dl
assert not any('upload-artifact' in str(s.get('uses','')) for s in st[:st.index(dl[-1])])\""
ck "every drill artifact uses the policy's staged period, and says so" \
   "python3 -c \"
import yaml
w = yaml.safe_load(open('$WF'))['jobs']
pol = {c['evidence_class']: c for c in yaml.safe_load(open('$POLICY'))['classes']}
want = pol['staged-candidate']['retention_days']
assert want == 90
n = 0
for jid in ('evidence-drill-produce', 'evidence-drill-restore'):
    for s in w[jid]['steps']:
        if 'upload-artifact' in str(s.get('uses','')):
            assert s['with']['retention-days'] == want, s['with']
            assert s['with']['name'].startswith('evidence-drill-'), s['with']['name']
            n += 1
assert n == 3, n\""
ck "the REQUIRED check needs the drill and cannot be skipped past it" \
   "python3 -c \"
import yaml
j = yaml.safe_load(open('$WF'))['jobs']['structure']
assert j['name'] == 'repo structure'
assert j['needs'] == ['evidence-drill-restore'], j['needs']
assert j['if'] == 'always()', j.get('if')
ids = [s.get('id') for s in j['steps']]
assert 'drill-consume' in ids, ids\""
ck "...and 'repo structure' really is a required PR check" \
   "python3 -c \"
import yaml
assert 'repo structure' in yaml.safe_load(
    open('policies/required-release-checks.yaml'))['pr_required_checks']\""

echo
echo "== NON-VACUITY: the positive round trip PASSES first ====================="

ck "the produce body built a bundle and indexed every uploaded byte" \
   "[ -s '$BUILD/upload/UPLOADED.sha256' ] && [ -f '$BUILD/upload/bundle/manifest.json' ] \
    && [ \"\$(wc -l < '$BUILD/upload/UPLOADED.sha256' | tr -d ' ')\" -ge 20 ]"
ck "the receipt body emitted AND verified a receipt before any upload" \
   "[ -s '$BUILD/receipt/storage-receipt.json' ] \
    && grep -q 'storage receipt VERIFIED' '$TMP/receipt.log'"
ck "a clean round trip RESTORES and re-verifies from the archive alone" \
   "c=\$(hop ok) && run_restore \"\$c\" && says 'restore drill PASSED'"
ck "...the downloaded working copy was DELETED before the restore" \
   "[ ! -e '$TMP/ok/dl/bundle' ]"
ck "...every restored byte equals the byte that was uploaded" \
   "python3 -c \"
import hashlib, os, sys
idx = dict((l.split('  ')[1].strip(), l.split('  ')[0])
           for l in open('$TMP/ok/dl/UPLOADED.sha256') if l.strip())
root = '$TMP/ok/work/restored'
seen = set()
for r, _, fs in os.walk(root):
    for f in fs:
        p = os.path.join(r, f); rel = os.path.relpath(p, root); seen.add(rel)
        assert rel in idx, ('extra', rel)
        assert hashlib.sha256(open(p,'rb').read()).hexdigest() == idx[rel], rel
assert seen == set(idx), set(idx) ^ seen\""
ck "...and the verdict is consumed by the required check's own body" \
   "run_consume '$TMP/ok/verdict/verdict.json' && says 'verdict CONSUMED'"
ck "the verdict names the restore consumer it ran, by content hash" \
   "python3 -c \"
import hashlib, json
v = json.load(open('$TMP/ok/verdict/verdict.json'))
rc = v['restore_consumer']
assert rc['name'] == 'scripts/release/restore-evidence.sh' and rc['exit'] == 0
assert rc['sha256'] == hashlib.sha256(
    open('scripts/release/restore-evidence.sh','rb').read()).hexdigest()\""
ck "the verdict states IN WRITING that it is not production evidence" \
   "python3 -c \"
import json
v = json.load(open('$TMP/ok/verdict/verdict.json'))
t = v['not_production_evidence']
assert 'NOT production evidence' in t and 'NOT an accepted candidate' in t, t
assert v['evidence_class'] == 'staged-candidate'\""

echo
echo "== SABOTAGE: twelve ways this can be wrong, twelve named refusals ========"

ck "S1 the bundle artifact ABSENT is REFUSED, not read as nothing to check" \
   "c=\$(hop s1) && rm -rf \"\$c/dl/bundle\"
    ! run_restore \"\$c\" && says 'DR-ARTIFACT-ABSENT' && says 'never a skip'"
ck "S2 the receipt artifact ABSENT is REFUSED" \
   "c=\$(hop s2) && rm -f \"\$c/rcpt/storage-receipt.json\"
    ! run_restore \"\$c\" && says 'DR-RECEIPT-ABSENT'"
ck "S3 a bundle file MISSING after transport is REFUSED, and named" \
   "c=\$(hop s3) && rm -f \"\$c/dl/bundle/content/retention/retention.json\"
    ! run_restore \"\$c\" && says 'DR-FILE-MISSING' && says 'retention.json'"
ck "S4 ONE modified byte is REFUSED, with both hashes" \
   "c=\$(hop s4) && printf 'x' >> \"\$c/dl/bundle/content/vex/openvex.json\"
    ! run_restore \"\$c\" && says 'DR-BYTES-DIFFER' && says 'not the evidence anybody decided on'"
ck "S5 a modified RECEIPT is REFUSED" \
   "c=\$(hop s5) && python3 -c \"
import json
p = '\$c/rcpt/storage-receipt.json'
d = json.load(open(p)); d['schema'] = 'not-a-receipt'
json.dump(d, open(p,'w'))\"
    ! run_restore \"\$c\" && says 'SR-RECEIPT-MALFORMED'"
ck "S6 a receipt for the WRONG SOURCE REVISION is REFUSED" \
   "c=\$(hop s6) && python3 -c \"
import json
p = '\$c/rcpt/storage-receipt.json'
d = json.load(open(p)); d['bundle']['source_revision'] = 'de' * 20
json.dump(d, open(p,'w'))\"
    ! run_restore \"\$c\" && says 'SR-REVISION-MISMATCH'"
ck "S7 a bundle of the WRONG EVIDENCE CLASS is REFUSED" \
   "c=\$(hop s7) && rm -rf \"\$c/dl/bundle\" \
    && bash '$GEN' generate --evidence '$ACCEPTED' \
         --authorization \"\$c/dl/record.json\" --out \"\$c/dl/bundle\" \
         --evidence-class published-artifact --release v2026.07.24 \
         --candidate rc1 --today 2026-08-25 >/dev/null 2>&1 \
    && ( cd \"\$c/dl/bundle\" && find . -type f | sed 's|^\\./||' | LC_ALL=C sort \
         | while IFS= read -r f; do printf '%s  %s\\n' \
             \"\$(shasum -a 256 \"\$f\" | cut -d' ' -f1)\" \"\$f\"; done ) \
       > \"\$c/dl/UPLOADED.sha256\"
    ! run_restore \"\$c\" && says 'DR-CLASS-MISMATCH' && says 'not a release'"
ck "S8 an INTERNALLY inconsistent bundle is REFUSED by the production verifier" \
   "c=\$(hop s8) && python3 - \"\$c\" <<'PY'
import hashlib, os, sys
c = sys.argv[1]
p = os.path.join(c, 'dl', 'bundle', 'SHA256SUMS')
lines = open(p).read().splitlines()
lines[0] = '0' * 64 + lines[0][64:]
open(p, 'w').write('\n'.join(lines) + '\n')
root = os.path.join(c, 'dl', 'bundle')
out = []
for r, _, fs in os.walk(root):
    for f in fs:
        fp = os.path.join(r, f)
        out.append('%s  %s' % (hashlib.sha256(open(fp,'rb').read()).hexdigest(),
                               os.path.relpath(fp, root)))
open(os.path.join(c, 'dl', 'UPLOADED.sha256'), 'w').write(
    '\n'.join(sorted(out, key=lambda l: l.split('  ')[1])) + '\n')
PY
    ! run_restore \"\$c\" && says 'DR-BUNDLE-REFUSED'"
ck "S9 an UNEXPECTED EXTRA file is REFUSED — the manifest is closed-world" \
   "c=\$(hop s9) && printf 'surprise\\n' > \"\$c/dl/bundle/content/EXTRA.txt\"
    ! run_restore \"\$c\" && says 'DR-EXTRA-FILE' && says 'EXTRA.txt'"
ck "S10 a verdict recording NO run of the restore consumer is REFUSED" \
   "c=\$(hop s10) && run_restore \"\$c\" && python3 -c \"
import json
p = '\$c/verdict/verdict.json'
d = json.load(open(p)); d['restore_consumer'] = {}
json.dump(d, open(p,'w'))\"
    ! run_consume \"\$c/verdict/verdict.json\" \
    && says 'DR-RESTORE-NOT-EXECUTED' && says 'not restoring anything'"
ck "S11 a verdict that exists but is NOT CONSUMED cannot pass the required check" \
   "! run_consume '$TMP/nonexistent/verdict.json' && says 'DR-VERDICT-ABSENT'"
ck "S11 ...and dropping the consume call is what would make that silent" \
   "grep -q 'evidence-restore-drill.sh consume' '$TMP/body-consume.sh' \
    && sed '/evidence-restore-drill.sh consume/,+2d' '$TMP/body-consume.sh' \
       > '$TMP/unconsumed.sh'
    DRILL_VERDICT='$TMP/nonexistent/verdict.json' DRILL_RUN_ID=1 DRILL_COMMIT=abc123 \
      bash '$TMP/unconsumed.sh' >/dev/null 2>&1"
ck "S12 retention of 89 days is REFUSED at the receipt, before any upload" \
   "obs '$TMP/obs89.json' 89
    DRILL_RECORD='$BUILD/upload/record.json' DRILL_READBACK='$BUILD/readback/bundle' \
    DRILL_OBSERVATION='$TMP/obs89.json' DRILL_RECEIPT='$TMP/r89/storage-receipt.json' \
    DRILL_REPOSITORY='z/z' bash '$TMP/body-receipt.sh' > '$TMP/out' 2>&1
    [ \$? -ne 0 ] && says 'SR-RETENTION-SHORT' && says '89 day'"
ck "BONUS a verdict from ANOTHER run is REFUSED by the required check" \
   "! run_consume '$TMP/ok/verdict/verdict.json' 999 abc123 && says 'DR-VERDICT-UNBOUND'"
ck "BONUS a verdict for ANOTHER commit is REFUSED" \
   "! run_consume '$TMP/ok/verdict/verdict.json' 1 feedface && says 'DR-VERDICT-UNBOUND'"

echo
echo "== R3 IS NOT RELAXED, and the drill is cheap ============================="

ck "R3 the archived tree is still write-once, and the drill CHECKS it" \
   "grep -q 'DR-ARCHIVE-WRITABLE' '$DRILL' \
    && am=\"\$(find '$TMP/ok/work/archive' -name manifest.json | head -1)\" \
    && [ -n \"\$am\" ] && ! ( printf x >> \"\$am\" ) 2>/dev/null"
ck "no drill step builds, pulls or scans an image" \
   "! grep -nEi 'docker (build|pull)|buildx|trivy|syft|cosign' \
        '$TMP/body-produce.sh' '$TMP/body-receipt.sh' '$TMP/body-restore.sh' '$TMP/body-consume.sh'"
ck "no drill job dispatches acceptance, releases, tags or publishes" \
   "python3 -c \"
import yaml
w = yaml.safe_load(open('$WF'))['jobs']
bad = ('workflow_dispatch', 'gh release', 'git tag', 'action-gh-release',
       'stage-and-authorize')
for jid in ('evidence-drill-produce', 'evidence-drill-restore'):
    blob = yaml.safe_dump(w[jid])
    for b in bad:
        assert b not in blob, (jid, b)\""
ck "the drill jobs hold read-only permissions and no secret" \
   "python3 -c \"
import yaml
w = yaml.safe_load(open('$WF'))
for jid in ('evidence-drill-produce', 'evidence-drill-restore'):
    p = w['jobs'][jid]['permissions']
    assert p == {'contents': 'read', 'actions': 'read'}, (jid, p)
assert 'secrets.' not in yaml.safe_dump(w['jobs'][jid])\""
ck "the workflow adds no scheduled run" \
   "! python3 -c \"
import yaml, sys
on = yaml.safe_load(open('$WF'))[True]
sys.exit(0 if 'schedule' in on else 1)\""
ck "the drill uses no external storage and names no provider" \
   "! grep -qiE '\\b(aws|s3|gcs|azure|bucket|backblaze|wasabi|minio)\\b' '$DRILL'"

echo
echo "== the gate is REQUIRED, not optional ===================================="

ck "the subsystem-coverage list names the drill" \
   "grep -q 'scripts/ci/evidence-restore-drill.sh' tests/governance/test_subsystem_ci_coverage.sh"
ck "the test mutated no tracked file" \
   "test -z \"\$(git -C '$ROOT' status --porcelain -- policies scripts schemas .github docs 2>/dev/null | grep -v '^??' || true)\""

echo "----"
printf 'assertions: %d proven\n' "$nck"
[ "$fail" -eq 0 ] && echo "test_evidence_restore_drill: PASS" || echo "test_evidence_restore_drill: FAIL"
exit "$fail"
