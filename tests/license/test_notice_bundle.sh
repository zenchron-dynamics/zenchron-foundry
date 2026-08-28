#!/usr/bin/env bash
# shellcheck disable=SC2034  # assertion locals are consumed inside ck() eval strings
# =============================================================================
# tests/license/test_notice_bundle.sh
# -----------------------------------------------------------------------------
# THE GAP THIS CLOSES, in #120's own words.
#
#   "Produce third-party notices and preserve corresponding license
#    texts/source-offer obligations."
#
# Before this change the repository produced an attribution LIST
# (scripts/license/generate-notice.sh) that was bound to no candidate, carried
# no licence text, knew nothing about a source obligation, and whose output
# nothing read. A release could be authorized with no notice material at all and
# no check would move.
#
# NOTHING HERE IS PROVED BY GREPPING YAML. The precedent this repository already
# paid for is `grep -rq 'scripts/license/'` matching one `--self-test` line and
# reporting a gate as wired. So the workflow assertions below PARSE
# .github/workflows/stage-and-authorize.yml with a real YAML parser
# (tests/lib/workflow_step.py), take the exact `run:` body of the named steps,
# and EXECUTE them. Delete the step, weaken a flag or stop consuming the result
# and the executed body changes and these assertions stop refusing.
#
# WHAT COUNTS AS REAL INPUT HERE. Nothing builds, pulls, publishes, promotes,
# signs or tags anything, and no image is rebuilt. Two input sets are used and
# they are labelled everywhere they appear:
#
#   REAL EVIDENCE REPLAY — the accepted 20-child production run, rebuilt from
#     committed records by tests/lib/make_replay_inventory.py: the image_binding
#     the binding gate itself stamped (20 immutable digests, both platforms,
#     both execution modes, source revision 7061caaf) and the 8,507 findings the
#     policy gate itself printed. Nothing is regenerated; the 40 SBOM documents
#     are 86 MB and are not committed.
#   SATISFIABLE FIXTURE — tests/lib/make_notice_inputs.py, whose header states
#     exactly which fields are real and which are fixture. It exists because a
#     suite that only ever saw a refusal would prove the producer can say no and
#     nothing about whether it can ever say yes.
#
# TWENTY-ONE SABOTAGES, each asserting its INTENDED diagnostic rather than a
# non-zero exit. They are numbered S1..S21 below.
#
# AMBIENT SAFETY. Every byte written lands under one mktemp -d.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1

fail=0 nck=0
ck() { nck=$((nck+1)); if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

PROD=scripts/license/generate-notice-bundle.py
VALID=scripts/release/validate-authorization-record.sh
STEP=tests/lib/workflow_step.py
WF=.github/workflows/stage-and-authorize.yml
CI=.github/workflows/ci.yml
JOB=authorize
MKAUTH=tests/lib/make_authorization_fixture.py
MKINV=tests/lib/make_replay_inventory.py
MKIN=tests/lib/make_notice_inputs.py
ACCEPTED=docs/audits/acceptance-multiarch-2026-08-20/acceptance-evidence.json
AUDIT=docs/audits/real-image-inventories-2026-08-28
BINDING="$AUDIT/licence/rerun-image-binding.json"
DIAG="$AUDIT/licence/image-licence-policy-diagnostic.log"
REV=7061caafb3ea09bd5b2342a1daf022151b33f822

TMP="$(mktemp -d)"
# shellcheck disable=SC2064
trap "rm -rf '$TMP'" EXIT

# The disposable repository the extracted workflow step bodies execute against.
# The step bodies write under authorization/ relative to the working directory,
# and the producer resolves the tree it reads licence texts from relative to its
# OWN location — so both need a real checkout, and it must not be this one.
WORK="$TMP/repo"
mkdir -p "$WORK"
cp -R "$ROOT/." "$WORK/"

echo "== the producer and its inputs exist and are what they claim =============="

ck "the producer exists and is executable" "[ -x '$PROD' ]"
ck "its schema exists and is a valid JSON Schema" \
   "python3 -c \"
import json, jsonschema
s=json.load(open('schemas/notice-bundle-v1.schema.json'))
jsonschema.Draft202012Validator.check_schema(s)\""
ck "the carried licence-text store is declared, non-empty and provenance-bound" \
   "python3 -c \"
import yaml
d=yaml.safe_load(open('third-party/licence-texts/PROVENANCE.yaml'))
assert d['record_type']=='carried-licence-texts'
assert len(d['files'])>=50, len(d['files'])
u=d['upstream']
assert u['revision_tag'] and u['revision_commit'] and u['retrieved_at']
for f in d['files']:
    assert f['sha256'] and f['upstream_path'] and f['source_url'] and f['verbatim']\""
ck "the upstream attestations declare exact components, never a wildcard" \
   "python3 -c \"
import yaml
d=yaml.safe_load(open('policies/upstream-licence-attestations.yaml'))
assert d['schema']=='foundry.upstream-licence-attestation/v1'
n=0
for a in d['attestations']:
    assert a['upstream']['revision_commit'] and a['upstream']['content_sha256']
    assert a['applies_to']['image_families'] and a['applies_to']['image_versions']
    for c in a['components']:
        assert c['name'] and c['version'] and '*' not in str(c['version'])
        n+=1
assert n==46, n\""
ck "the source-obligation facts resolve every component to an immutable source" \
   "python3 -c \"
import yaml
d=yaml.safe_load(open('policies/source-obligations.yaml'))
assert d['schema']=='foundry.source-obligations/v1'
cs=d['components']
assert len(cs)==162, len(cs)
for c in cs:
    assert c['source'] and c['source_version'], c
    assert c['source_obligation']=='unresolved', c\""
ck "...and NOT ONE of them is recorded satisfied, because none has been approved" \
   "python3 -c \"
import yaml
d=yaml.safe_load(open('policies/source-obligations.yaml'))
assert not [c for c in d['components'] if c['source_obligation']!='unresolved']\""
ck "...and it records the legal questions rather than answering them" \
   "python3 -c \"
import yaml
d=yaml.safe_load(open('policies/source-obligations.yaml'))
q=d['unresolved_legal_questions']
assert len(q)>=5, len(q)
assert all(str(x['owner']).startswith('#98') for x in q), q
for m in d['delivery_mechanisms_considered']:
    assert m['foundry_can_execute_today'] is False, m\""

echo
echo "== the REAL-EVIDENCE REPLAY: the accepted 20 children, nothing regenerated"

python3 "$MKAUTH" "$ACCEPTED" "$TMP/auth.json" >/dev/null 2>&1
python3 "$MKINV" --binding "$BINDING" --diagnostic "$DIAG" \
        --out "$TMP/replay-inventory.json" 2>/dev/null

REAL="$TMP/real"
ck "the replay carries the binding gate's OWN stamped image_binding, 20/20" \
   "python3 -c \"
import json
d=json.load(open('$TMP/replay-inventory.json'))
b=d['image_binding']
assert b['children_bound']==b['children_expected']==20, b
assert b['source_revision']=='$REV', b['source_revision']
assert sorted(b['platforms'])==['linux/amd64','linux/arm64'], b['platforms']
assert sorted(b['execution_modes'])==['native','qemu'], b['execution_modes']\""
ck "the replay carries the 8,507 findings the gate itself printed" \
   "python3 -c \"
import json
d=json.load(open('$TMP/replay-inventory.json'))
assert d['component_count']==8507, d['component_count']
assert d['package_component_count']==535, d['package_component_count']
assert d['file_component_count']==7972, d['file_component_count']
assert d['conflict_count']==196, d['conflict_count']\""

produce() { # produce <out-dir> [ARG ...]
  local out="$1"; shift
  python3 "$PROD" --inventory "${INV:-$TMP/replay-inventory.json}" \
    --authorization "${AUTH:-$TMP/auth.json}" \
    --material "${MAT:-policies/repository-material.yaml}" \
    --policy "${POL:-policies/license-policy.yaml}" \
    --licence-texts "${LTX:-third-party/licence-texts/PROVENANCE.yaml}" \
    --attestations "${ATT:-policies/upstream-licence-attestations.yaml}" \
    --source-obligations "${SO:-policies/source-obligations.yaml}" \
    --out-dir "$out" "$@" >"$TMP/out" 2>&1
}
says() { grep -q -- "$1" "$TMP/out"; }
code() { python3 -c "
import json,sys
m=json.load(open(sys.argv[1]))
sys.exit(0 if sys.argv[2] in (m.get('finding_codes') or []) else 1)" "$1" "$2"; }
# The producer prints at most 40 findings to stderr on purpose — 699 lines is
# not a diagnostic. So a sabotage asserts on the BUNDLE, which carries them all.
detail() { # detail <out-dir> <code> <substring>
  python3 -c "
import json,sys
u=json.load(open(sys.argv[1]+'/unresolved-obligations.json'))
hit=[f for f in u['findings'] if f['code']==sys.argv[2] and sys.argv[3] in f['detail']]
sys.exit(0 if hit else 1)" "$1" "$2" "$3"; }

ck "the producer REFUSES over the real evidence, and writes its draft anyway" \
   "! produce '$REAL'; [ -s '$REAL/notice-manifest.json' ]"
ck "...as REFUSE / incomplete, marked draft, satisfying no authorization" \
   "python3 -c \"
import json
m=json.load(open('$REAL/notice-manifest.json'))
assert m['verdict']=='REFUSE' and m['status']=='incomplete', m['status']
assert m['draft'] is True and m['satisfies_authorization'] is False\""
ck "...bound to the 20 real children by their IMMUTABLE digests and platforms" \
   "python3 -c \"
import json
m=json.load(open('$REAL/notice-manifest.json'))
a=json.load(open('$TMP/auth.json'))
c={x['child_key']:x for x in m['candidate']['children']}
assert len(c)==20, len(c)
for ch in a['children']:
    g=c[ch['child_key']]
    assert g['manifest_digest']==ch['manifest_digest'], ch['child_key']
    assert g['platform']==ch['platform'], ch['child_key']
assert m['source_revision']=='$REV'\""
ck "...and the emulation disclosure survives into the notice path" \
   "python3 -c \"
import json
m=json.load(open('$REAL/notice-manifest.json'))
assert sorted(m['candidate']['execution_modes'])==['native','qemu']\""
ck "...refusing on SIX distinct causes, each with its own code" \
   "python3 -c \"
import json
m=json.load(open('$REAL/notice-manifest.json'))
want={'NB-CONFLICT-UNRESOLVED','NB-DISPOSITION-MISSING','NB-FILE-UNRESOLVED',
      'NB-LEGAL-REVIEW-REQUIRED','NB-PUBLICATION-AUTHORITY-MISSING',
      'NB-SOURCE-OBLIGATION-UNRESOLVED'}
assert set(m['finding_codes'])==want, sorted(m['finding_codes'])\""
ck "...and the refusal is SUBSTANTIVE, not caused by missing evidence" \
   "python3 -c \"
import json
m=json.load(open('$REAL/notice-manifest.json'))
for bad in ('NB-INPUT-ABSENT','NB-INPUT-MALFORMED','NB-BINDING-ABSENT',
            'NB-BINDING-INCOMPLETE','NB-REVISION-MISMATCH','NB-DIGEST-MISMATCH',
            'NB-PLATFORM-MISMATCH','NB-MATRIX-MISMATCH','NB-LICENCE-TEXT-MISSING',
            'NB-LICENCE-TEXT-HASH','NB-NOTICE-MISSING','NB-NOTICE-HASH'):
    assert bad not in m['finding_codes'], bad\""

echo
echo "== the UPSTREAM ATTESTATION: what the scanner cannot see =================="

ck "PHP-3.01 is measured ABSENT from the cohort, so the policy row never fires" \
   "python3 -c \"
import json
d=json.load(open('$AUDIT/licence/identifier-reconciliation.json'))
assert 'PHP-3.01' in d['classification']['policy_listed_but_absent']['identifiers']\""
ck "the attestation fills exactly the 46 components the scanner left silent" \
   "python3 -c \"
import json
m=json.load(open('$REAL/notice-manifest.json'))
assert m['components_by_source']['upstream-attested']==46, m['components_by_source']\""
ck "...each recording upstream revision, commit, content hash and its TEXT" \
   "python3 -c \"
import json
m=json.load(open('$REAL/notice-manifest.json'))
a=[d for d in m['dispositions'] if d.get('source')=='upstream-attested']
assert len(a)==46, len(a)
for d in a:
    e=d['attestation']
    assert e['spdx_id']=='PHP-3.01'
    assert e['upstream_revision'].startswith('php-8.')
    assert len(e['upstream_commit'])==40
    assert e['upstream_content_sha256']=='b42e4df5e50e6ecda1047d503d6d91d71032d09ed1027ba1ef29eed26f890c5a'
    assert e['licence_text']=='third-party/licence-texts/PHP-3.01.txt'\""
ck "...and the SOURCE is recorded, so an attestation cannot pass as an observation" \
   "python3 -c \"
import json
m=json.load(open('$REAL/notice-manifest.json'))
s=m['components_by_source']
assert set(s)=={'scanner-observed','upstream-attested','policy-asserted','legally-approved'}
assert s['legally-approved']==0 and s['policy-asserted']==0, s\""
ck "an attested identifier still reaches the POLICY, and PHP-3.01 needs counsel" \
   "python3 -c \"
import json
u=json.load(open('$REAL/unresolved-obligations.json'))
php=[f for f in u['findings']
     if f['code']=='NB-LEGAL-REVIEW-REQUIRED' and 'PHP-3.01' in f['detail']]
assert len(php)==46, len(php)\""

echo
echo "== DETERMINISM: the same ordered inputs, byte for byte ===================="

ck "two runs into different directories produce byte-identical output" \
   "produce '$TMP/d1'; produce '$TMP/d2'; diff -r '$TMP/d1' '$TMP/d2' >/dev/null"
ck "...including the manifest's own bundle_sha256" \
   "[ \"\$(python3 -c \"import json;print(json.load(open('$TMP/d1/notice-manifest.json'))['bundle_sha256'])\")\" \
    = \"\$(python3 -c \"import json;print(json.load(open('$TMP/d2/notice-manifest.json'))['bundle_sha256'])\")\" ]"
ck "NON-VACUOUS: no manifest FIELD is a timestamp, hostname or run id" \
   "python3 -c \"
import json
def walk(o, path=''):
    if isinstance(o, dict):
        for k, v in o.items():
            assert k.lower() not in {'generated_at','created_at','timestamp',
                                     'hostname','run_id','workflow_run_id','date',
                                     'decision_date','retrieved_at','evidence_generated_at'}, path+k
            walk(v, path+k+'.')
    elif isinstance(o, list):
        for x in o:
            walk(x, path)
walk(json.load(open('$TMP/d1/notice-manifest.json')))\""
ck "every emitted artifact is checksummed, and SHA256SUMS covers all of them" \
   "python3 -c \"
import hashlib, json, os
d='$TMP/d1'
m=json.load(open(os.path.join(d,'notice-manifest.json')))
sums={l.split('  ',1)[1].strip(): l.split('  ',1)[0]
      for l in open(os.path.join(d,'SHA256SUMS'))}
assert set(sums)=={f for f in os.listdir(d) if f!='SHA256SUMS'}, sorted(sums)
for name,h in m['artifacts'].items():
    got=hashlib.sha256(open(os.path.join(d,name),'rb').read()).hexdigest()
    assert got==h==sums[name], name\""

echo
echo "== the FILE-COMPONENT accounting is carried through, not re-derived ======="

ck "the four-way accounting reaches the bundle and closes" \
   "python3 -c \"
import json
m=json.load(open('$REAL/notice-manifest.json'))
f=m['image_files']
assert sum(f['by_class'].values())==f['input_file_components']==7972, f
assert set(f['by_class'])=={'scanner-observation','package-attributed',
                            'independently-licensed','unresolved'}\""
ck "an unresolved image file REFUSES rather than being counted as harmless" \
   "code '$REAL/notice-manifest.json' NB-FILE-UNRESOLVED"
ck "...and the 7,972 are deferred to that accounting, never double-counted" \
   "python3 -c \"
import json
m=json.load(open('$REAL/notice-manifest.json'))
assert m['image_file_components_deferred_to_file_accounting']==7972
u=json.load(open('$REAL/unresolved-obligations.json'))
n=sum(1 for x in u['findings'] if x['code']=='NB-FILE-UNRESOLVED')
assert n==1, n\""
ck "S1 SABOTAGE: an inventory with NO file accounting at all is REFUSED" \
   "python3 - '$TMP/replay-inventory.json' '$TMP/nofiles.json' <<'PY'
import json, sys
d=json.load(open(sys.argv[1])); d.pop('image_files', None)
json.dump(d, open(sys.argv[2],'w'))
PY
    INV='$TMP/nofiles.json' produce '$TMP/s1'
    detail '$TMP/s1' NB-INPUT-MALFORMED 'four-way'"
ck "S2 SABOTAGE: an accounting that does not sum to its input is REFUSED" \
   "python3 - '$TMP/replay-inventory.json' '$TMP/badsum.json' <<'PY'
import json, sys
d=json.load(open(sys.argv[1]))
d['image_files']['by_class_observations']['unresolved']=1
json.dump(d, open(sys.argv[2],'w'))
PY
    INV='$TMP/badsum.json' produce '$TMP/s2'
    detail '$TMP/s2' NB-INPUT-MALFORMED 'does not close'"
ck "S3 SABOTAGE: a package-attributed file with no relationship is REFUSED" \
   "python3 - '$TMP/replay-inventory.json' '$TMP/noedge.json' <<'PY'
import json, sys
d=json.load(open(sys.argv[1]))
d['image_files']['package_attributed_sample']=[
    {'path':'/opt/orphan.so','class':'package-attributed','reason':'x','licenses':[]}]
json.dump(d, open(sys.argv[2],'w'))
PY
    INV='$TMP/noedge.json' produce '$TMP/s3'
    detail '$TMP/s3' NB-ATTRIBUTION-UNSUPPORTED 'never sufficient'"
ck "S4 SABOTAGE: an independently licensed image file is REFUSED, not absorbed" \
   "python3 - '$TMP/replay-inventory.json' '$TMP/indep.json' <<'PY'
import json, sys
d=json.load(open(sys.argv[1]))
d['image_files']['independently_licensed']=[
    {'path':'/usr/share/vendor/libevil.so','class':'independently-licensed',
     'reason':'the document gives this file a licence of its own',
     'licenses':['AGPL-3.0-only']}]
json.dump(d, open(sys.argv[2],'w'))
PY
    INV='$TMP/indep.json' produce '$TMP/s4'
    detail '$TMP/s4' NB-FILE-INDEPENDENT-UNTREATED 'libevil.so' \
    && detail '$TMP/s4' NB-FILE-INDEPENDENT-UNTREATED 'NO repository control'"

echo
echo "== BINDING sabotages: evidence for another candidate is not evidence ======"

ck "S5 SABOTAGE: an inventory with NO image binding is REFUSED" \
   "python3 - '$TMP/replay-inventory.json' '$TMP/nobind.json' <<'PY'
import json, sys
d=json.load(open(sys.argv[1])); d.pop('image_binding', None)
json.dump(d, open(sys.argv[2],'w'))
PY
    INV='$TMP/nobind.json' produce '$TMP/s5'
    says 'NB-BINDING-ABSENT' && says 'assert-image-sbom-licences.sh'"
ck "S6 SABOTAGE: a PARTIAL matrix is REFUSED, never reported clean" \
   "python3 - '$TMP/replay-inventory.json' '$TMP/short.json' <<'PY'
import json, sys
d=json.load(open(sys.argv[1]))
b=d['image_binding']; b['children']=b['children'][:-1]; b['children_bound']=19
json.dump(d, open(sys.argv[2],'w'))
PY
    INV='$TMP/short.json' produce '$TMP/s6'
    says 'NB-BINDING-INCOMPLETE' && says 'happened to see'"
ck "S7 SABOTAGE: a WRONG candidate digest is REFUSED" \
   "python3 - '$TMP/replay-inventory.json' '$TMP/dig.json' <<'PY'
import json, sys
d=json.load(open(sys.argv[1]))
d['image_binding']['children'][0]['manifest_digest']='sha256:'+'0'*64
json.dump(d, open(sys.argv[2],'w'))
PY
    INV='$TMP/dig.json' produce '$TMP/s7'
    detail '$TMP/s7' NB-DIGEST-MISMATCH 'another image is not notice material'"
ck "S8 SABOTAGE: a WRONG platform is REFUSED" \
   "python3 - '$TMP/replay-inventory.json' '$TMP/plat.json' <<'PY'
import json, sys
d=json.load(open(sys.argv[1]))
d['image_binding']['children'][0]['platform']='linux/s390x'
json.dump(d, open(sys.argv[2],'w'))
PY
    INV='$TMP/plat.json' produce '$TMP/s8'
    detail '$TMP/s8' NB-PLATFORM-MISMATCH 'amd64 bill of materials'"
ck "S9 SABOTAGE: notice evidence from ANOTHER SOURCE REVISION is REFUSED" \
   "python3 - '$TMP/replay-inventory.json' '$TMP/rev.json' <<'PY'
import json, sys
d=json.load(open(sys.argv[1]))
d['image_binding']['source_revision']='0'*40
json.dump(d, open(sys.argv[2],'w'))
PY
    INV='$TMP/rev.json' produce '$TMP/s9'
    detail '$TMP/s9' NB-REVISION-MISMATCH 'another tree'"
ck "S10 SABOTAGE: a MISSING CHILD is named, not silently dropped" \
   "python3 '$MKAUTH' '$ACCEPTED' '$TMP/auth-short.json' --drop-child 0 >/dev/null 2>&1
    AUTH='$TMP/auth-short.json' produce '$TMP/s10'
    code '$TMP/s10/notice-manifest.json' NB-MATRIX-MISMATCH"

echo
echo "== ARTIFACT sabotages: a carried text that is not its bytes ==============="

# S11..S14 sabotage the DISPOSABLE CHECKOUT, because the producer resolves the
# tree it reads carried texts and upstream NOTICE files from relative to its own
# location — which is exactly the property that makes a substituted text
# detectable at all.
wproduce() { # wproduce <out-dir>
  python3 "$WORK/$PROD" --inventory "$TMP/replay-inventory.json" \
    --authorization "$TMP/auth.json" \
    --material "$WORK/policies/repository-material.yaml" \
    --policy "$WORK/policies/license-policy.yaml" \
    --licence-texts "$WORK/third-party/licence-texts/PROVENANCE.yaml" \
    --attestations "$WORK/policies/upstream-licence-attestations.yaml" \
    --source-obligations "$WORK/policies/source-obligations.yaml" \
    --out-dir "$1" >"$TMP/out" 2>&1
}
ck "S11 SABOTAGE: a DELETED licence text is REFUSED, naming the identifier" \
   "cp '$WORK/third-party/licence-texts/Zlib.txt' '$TMP/zlib.orig'
    rm -f '$WORK/third-party/licence-texts/Zlib.txt'
    ! wproduce '$TMP/s11'
    r=\$?
    cp '$TMP/zlib.orig' '$WORK/third-party/licence-texts/Zlib.txt'
    detail '$TMP/s11' NB-LICENCE-TEXT-MISSING 'Zlib'"
ck "S12 SABOTAGE: a licence text whose HASH is wrong is REFUSED" \
   "python3 - '$ROOT/third-party/licence-texts/PROVENANCE.yaml' '$TMP/prov-hash.yaml' <<'PY'
import sys, yaml
d=yaml.safe_load(open(sys.argv[1]))
for f in d['files']:
    if f['spdx_id']=='MIT':
        f['sha256']='0'*64
yaml.safe_dump(d, open(sys.argv[2],'w'))
PY
    LTX='$TMP/prov-hash.yaml' produce '$TMP/s12'
    detail '$TMP/s12' NB-LICENCE-TEXT-HASH 'first to find out'"
ck "S13 SABOTAGE: an upstream NOTICE that is not its recorded bytes is REFUSED" \
   "cp '$WORK/third-party/moby-v27.3.1/NOTICE' '$TMP/notice.orig'
    printf 'tampered\n' >> '$WORK/third-party/moby-v27.3.1/NOTICE'
    ! wproduce '$TMP/s13'
    cp '$TMP/notice.orig' '$WORK/third-party/moby-v27.3.1/NOTICE'
    detail '$TMP/s13' NB-NOTICE-HASH 'is not the bytes it claims'"
ck "S14 SABOTAGE: a DELETED upstream NOTICE is REFUSED, not skipped" \
   "mv '$WORK/third-party/moby-v27.3.1/NOTICE' '$TMP/notice.moved'
    ! wproduce '$TMP/s14'
    mv '$TMP/notice.moved' '$WORK/third-party/moby-v27.3.1/NOTICE'
    detail '$TMP/s14' NB-NOTICE-MISSING 'absent or empty'"

echo
echo "== ATTESTATION sabotages: scope, conflict and text ========================"

ck "S15 SABOTAGE: an attestation cannot WIDEN to another component version" \
   "python3 - '$ROOT/policies/upstream-licence-attestations.yaml' '$TMP/att-widen.yaml' <<'PY'
import sys, yaml
d=yaml.safe_load(open(sys.argv[1]))
for a in d['attestations']:
    for c in a['components']:
        c['version']='9.9.9'          # a version no component in the cohort has
yaml.safe_dump(d, open(sys.argv[2],'w'))
PY
    ATT='$TMP/att-widen.yaml' produce '$TMP/s15'
    python3 -c \"
import json
m=json.load(open('$TMP/s15/notice-manifest.json'))
assert m['components_by_source']['upstream-attested']==0, m['components_by_source']\""
ck "S16 SABOTAGE: an attestation cannot widen to another PLATFORM" \
   "python3 - '$ROOT/policies/upstream-licence-attestations.yaml' '$TMP/att-plat.yaml' <<'PY'
import sys, yaml
d=yaml.safe_load(open(sys.argv[1]))
for a in d['attestations']:
    a['applies_to']['platforms']=['linux/amd64']   # the cohort also ships arm64
yaml.safe_dump(d, open(sys.argv[2],'w'))
PY
    ATT='$TMP/att-plat.yaml' produce '$TMP/s16'
    detail '$TMP/s16' NB-ATTESTATION-SCOPE 'linux/arm64'"
ck "S16b SABOTAGE: an attestation cannot widen to another IMAGE FAMILY" \
   "python3 - '$ROOT/policies/upstream-licence-attestations.yaml' '$TMP/att-fam.yaml' <<'PYFAM'
import sys, yaml
d=yaml.safe_load(open(sys.argv[1]))
for a in d['attestations']:
    a['applies_to']['image_families']=['php-8-5-experimental']
yaml.safe_dump(d, open(sys.argv[2],'w'))
PYFAM
    ATT='$TMP/att-fam.yaml' produce '$TMP/s16b'
    detail '$TMP/s16b' NB-ATTESTATION-SCOPE 'must not reach a family it does not cover'"
ck "S16c SABOTAGE: an attestation cannot widen to another IMAGE VERSION" \
   "python3 - '$ROOT/policies/upstream-licence-attestations.yaml' '$TMP/att-ver.yaml' <<'PYVER'
import sys, yaml
d=yaml.safe_load(open(sys.argv[1]))
for a in d['attestations']:
    a['applies_to']['image_versions']=['8.5']
yaml.safe_dump(d, open(sys.argv[2],'w'))
PYVER
    ATT='$TMP/att-ver.yaml' produce '$TMP/s16c'
    detail '$TMP/s16c' NB-ATTESTATION-SCOPE 'must not widen to another'"
ck "S17 SABOTAGE: an attestation with NO scope at all is REFUSED" \
   "python3 - '$ROOT/policies/upstream-licence-attestations.yaml' '$TMP/att-noscope.yaml' <<'PY'
import sys, yaml
d=yaml.safe_load(open(sys.argv[1]))
for a in d['attestations']:
    a['applies_to']={}
yaml.safe_dump(d, open(sys.argv[2],'w'))
PY
    ATT='$TMP/att-noscope.yaml' produce '$TMP/s17'
    detail '$TMP/s17' NB-ATTESTATION-SCOPE 'would reach anything'"
ck "S18 SABOTAGE: an attestation that CONTRADICTS the scanner refuses for review" \
   "python3 - '$ROOT/policies/upstream-licence-attestations.yaml' '$TMP/att-conflict.yaml' <<'PY'
import sys, yaml
d=yaml.safe_load(open(sys.argv[1]))
# busybox IS observed by the scanner as GPL-2.0-only; asserting MIT for it is
# the case where an attestation would otherwise silently override an observation
a=d['attestations'][0]
a['asserts']['spdx_id']='MIT'
a['asserts']['licence_text']='third-party/licence-texts/MIT.txt'
a['components']=[{'name':'busybox','version':'1.37.0-r30'}]
d['attestations']=[a]
yaml.safe_dump(d, open(sys.argv[2],'w'))
PY
    ATT='$TMP/att-conflict.yaml' produce '$TMP/s18'
    detail '$TMP/s18' NB-ATTESTATION-CONFLICT 'never OVERRIDE an observation'"
ck "S19 SABOTAGE: an attestation whose asserted TEXT is not carried is REFUSED" \
   "python3 - '$ROOT/policies/upstream-licence-attestations.yaml' '$TMP/att-notext.yaml' <<'PY'
import sys, yaml
d=yaml.safe_load(open(sys.argv[1]))
for a in d['attestations']:
    a['asserts']['spdx_id']='LicenseRef-Nonexistent'
    a['asserts']['licence_text']='third-party/licence-texts/Nonexistent.txt'
yaml.safe_dump(d, open(sys.argv[2],'w'))
PY
    ATT='$TMP/att-notext.yaml' produce '$TMP/s19'
    detail '$TMP/s19' NB-ATTESTATION-TEXT-MISSING 'discharges nothing'"

echo
echo "== SOURCE OBLIGATIONS: unresolved refuses, and nothing here resolves them =="

ck "S20 an unresolved source obligation REFUSES" \
   "code '$REAL/notice-manifest.json' NB-SOURCE-OBLIGATION-UNRESOLVED"
ck "...naming the exact binary, its source package and version, 162 times" \
   "python3 -c \"
import json
u=json.load(open('$REAL/unresolved-obligations.json'))
n=[f for f in u['findings'] if f['code']=='NB-SOURCE-OBLIGATION-UNRESOLVED']
assert len(n)==162, len(n)
assert any('liblzma5' in f['detail'] and 'xz-utils' in f['detail'] for f in n)\""
ck "...and the manifest says no engineering act can mark one satisfied" \
   "python3 -c \"
import json
m=json.load(open('$REAL/source-obligation-manifest.json'))
assert m['unresolved_count']==162 and m['satisfied_count']==0, m
assert 'No engineering act' in m['note']\""
ck "the 28 LGPL-2.0 components are all resolved to an immutable Debian source" \
   "python3 -c \"
import json
m=json.load(open('$REAL/source-obligation-manifest.json'))
l=[c for c in m['components']
   if any(i.startswith('LGPL-2.0') for i in c['reciprocal_identifiers'])]
assert len(l)==28, len(l)
for c in l:
    assert c['source_package'] and c['source_version'] and c['licence_texts_carried']\""

echo
echo "== the COMPOSITION TRUTH TABLE, through the REAL consumer ================="

# The satisfiable set. Its builder's header states exactly which fields are real
# (the 20 candidate identities, the shipped texts, attestations and material) and
# which are fixture (two components, the publication block, the obligation
# states). Without it the table would have four REFUSE rows and no PASS row,
# which proves the producer can say no and nothing about whether it can say yes.
mkin() { python3 "$MKIN" --authorization "$TMP/auth.json" --root "$ROOT" \
           --out "$1" --publication "$2" --source-obligations "$3" >/dev/null 2>&1; }
sat() { # sat <name> <publication> <source-obligations>
  mkin "$TMP/in-$1" "$2" "$3"
  INV="$TMP/in-$1/inventory.json" MAT="$TMP/in-$1/repository-material.yaml" \
  POL="$TMP/in-$1/license-policy.yaml" LTX="$TMP/in-$1/licence-texts.yaml" \
  ATT="$TMP/in-$1/attestations.yaml" SO="$TMP/in-$1/source-obligations.yaml" \
  produce "$TMP/tt-$1"
}
consume() { bash "$VALID" "$TMP/auth.json" --require-notice-bundle "$1" \
              >"$TMP/out" 2>&1; }

ck "TT notice PASS + publication PRESENT -> eligible for the next control" \
   "sat pass present satisfied && consume '$TMP/tt-pass/notice-manifest.json'
    says 'notice bundle CONSUMED' && says 'PASS' && says '20/20'"
ck "TT ...and 'eligible' is NOT publication: the bundle authorizes no exposure" \
   "python3 -c \"
import json
m=json.load(open('$TMP/tt-pass/notice-manifest.json'))
assert 'authorize publication' in m['note'] and 'eligible' in m['note']\""
ck "TT notice PASS + publication MISSING -> REFUSE, independently" \
   "sat nopub missing satisfied
    ! consume '$TMP/tt-nopub/notice-manifest.json'
    says 'AR-PUBLICATION-AUTHORITY-MISSING' && says 'INDEPENDENT'"
ck "TT ...and the bundle itself still says PASS, so the axes did not collapse" \
   "python3 -c \"
import json
m=json.load(open('$TMP/tt-nopub/notice-manifest.json'))
assert m['verdict']=='PASS' and m['status']=='publication-authority-missing'
assert m['engineering_complete'] is True and m['legal_review_outstanding'] is False
assert m['satisfies_authorization'] is False and m['draft'] is True\""
ck "TT notice REFUSE (source obligation) + publication PRESENT -> REFUSE" \
   "sat sorc present unresolved
    ! consume '$TMP/tt-sorc/notice-manifest.json'
    says 'AR-NOTICE-REFUSED' && says 'NB-SOURCE-OBLIGATION-UNRESOLVED'"
ck "TT notice REFUSE + publication MISSING -> REFUSE" \
   "sat both missing unresolved
    ! consume '$TMP/tt-both/notice-manifest.json'
    says 'AR-NOTICE-REFUSED'"
ck "TT notice MISSING entirely -> REFUSE, never a skip" \
   "! consume '$TMP/no-such-bundle.json'
    says 'AR-NOTICE-EVIDENCE-ABSENT' && says 'never a skip'"
ck "TT an EMPTY path is not 'not asked for' — it also REFUSES" \
   "! consume ''
    says 'AR-NOTICE-EVIDENCE-ABSENT'"
ck "TT the REAL cohort's bundle -> REFUSE" \
   "! consume '$REAL/notice-manifest.json'
    says 'AR-NOTICE-REFUSED'"

echo
echo "== CONSUMER sabotages: a bundle for another record decides nothing ========"

ck "S21 SABOTAGE: a bundle bound to ANOTHER authorization record is REFUSED" \
   "python3 '$MKAUTH' '$ACCEPTED' '$TMP/auth-extra.json' --extra-child >/dev/null 2>&1
    ! bash '$VALID' '$TMP/auth-extra.json' \
        --require-notice-bundle '$TMP/tt-pass/notice-manifest.json' >'$TMP/out' 2>&1
    says 'AR-NOTICE-UNBOUND'"
ck "S22 SABOTAGE: a SUBSTITUTED notice artifact is REFUSED by its own checksum" \
   "cp -R '$TMP/tt-pass' '$TMP/tt-sub'
    printf 'substituted\n' >> '$TMP/tt-sub/THIRD-PARTY-NOTICES.txt'
    ! bash '$VALID' '$TMP/auth.json' \
        --require-notice-bundle '$TMP/tt-sub/notice-manifest.json' >'$TMP/out' 2>&1
    says 'AR-NOTICE-ARTIFACT-DRIFT' && says 'THIRD-PARTY-NOTICES.txt'"
ck "S23 SABOTAGE: a MISSING notice artifact is REFUSED the same way" \
   "cp -R '$TMP/tt-pass' '$TMP/tt-gone'
    rm -f '$TMP/tt-gone/source-obligation-manifest.json'
    ! bash '$VALID' '$TMP/auth.json' \
        --require-notice-bundle '$TMP/tt-gone/notice-manifest.json' >'$TMP/out' 2>&1
    says 'AR-NOTICE-ARTIFACT-DRIFT'"
ck "S24 SABOTAGE: a DRAFT that claims to be complete fails the schema" \
   "python3 - '$TMP/tt-pass/notice-manifest.json' '$TMP/tt-lie.json' <<'PY'
import json, sys
d=json.load(open(sys.argv[1])); d['draft']=True
json.dump(d, open(sys.argv[2],'w'))
PY
    cp -R '$TMP/tt-pass' '$TMP/tt-liedir'
    cp '$TMP/tt-lie.json' '$TMP/tt-liedir/notice-manifest.json'
    ! bash '$VALID' '$TMP/auth.json' \
        --require-notice-bundle '$TMP/tt-liedir/notice-manifest.json' >'$TMP/out' 2>&1
    says 'AR-NOTICE-MALFORMED'"
ck "S25 SABOTAGE: a notice bundle that is not a notice bundle is REFUSED" \
   "printf '{\"schema\":\"nope\"}\n' > '$TMP/notbundle.json'
    ! bash '$VALID' '$TMP/auth.json' --require-notice-bundle '$TMP/notbundle.json' \
        >'$TMP/out' 2>&1
    says 'AR-NOTICE-MALFORMED'"

echo
echo "== the workflow INVOKES it, with these inputs, and CONSUMES the result ===="

# NOT a grep. The step bodies are extracted by a real YAML parser and EXECUTED.
wf_run() { python3 "$STEP" "$WF" "$JOB" "$1" --run; }
wf_env() { python3 "$STEP" "$WF" "$JOB" "$1" --env; }

ck "the authorize job has a notice step, and it RUNS the producer" \
   "wf_run notice | grep -q 'scripts/license/generate-notice-bundle.py'"
ck "...handed the run's OWN inventory and authorization record, not fixtures" \
   "wf_env notice | grep -qx 'IMAGE_INVENTORY=authorization/licence/image-inventory.json' \
    && wf_env notice | grep -qx 'AUTH_RECORD=authorization/post-build-authorization.json'"
ck "...and every one of the seven required inputs is supplied by the step" \
   "for k in IMAGE_INVENTORY AUTH_RECORD MATERIAL_INVENTORY LICENCE_POLICY \
             LICENCE_TEXTS ATTESTATIONS SOURCE_OBLIGATIONS NOTICE_DIR; do
      wf_env notice | grep -q \"^\$k=\" || exit 1
    done"
ck "...writing under a release-evidence path, NEVER a root NOTICE file" \
   "wf_env notice | grep -qx 'NOTICE_DIR=authorization/notice' \
    && [ ! -e '$ROOT/NOTICE' ]"
ck "the validator step CONSUMES the bundle with --require-notice-bundle" \
   "wf_run schema | grep -q -- '--require-notice-bundle' \
    && wf_run schema | grep -q -- '--require-licence-authorization'"
ck "...and the SEALING step turns the validator's result into the job verdict" \
   "wf_run seal | grep -q 'schema.rc' && wf_run seal | grep -q 'schema_rc'"

# EXECUTED, not read. The step body runs in the disposable checkout against the
# real replay inventory and the real authorization record.
gate() { # gate <step-id> [VAR=VALUE ...]
  local id="$1"; shift
  local body; body="$(wf_run "$id")" || return 2
  local -a envs=(); local line
  while IFS= read -r line; do [ -n "$line" ] && envs+=("$line"); done < <(wf_env "$id")
  ( cd "$WORK" && mkdir -p authorization/licence authorization/notice \
      && env ${envs[@]+"${envs[@]}"} GITHUB_OUTPUT="$TMP/gh-out" \
             GITHUB_STEP_SUMMARY="$TMP/gh-sum" "$@" \
             bash --noprofile --norc -c "$body" ) >"$TMP/out" 2>&1
}
cp "$TMP/replay-inventory.json" "$WORK/authorization/licence/image-inventory.json" 2>/dev/null \
  || { mkdir -p "$WORK/authorization/licence"; cp "$TMP/replay-inventory.json" "$WORK/authorization/licence/image-inventory.json"; }
cp "$TMP/auth.json" "$WORK/authorization/post-build-authorization.json"

ck "EXECUTED: the workflow's own notice step REFUSES over the real evidence" \
   "! gate notice; says 'notice bundle: REFUSE'"
ck "...and it WROTE its draft, so the refusal can be read afterwards" \
   "[ -s '$WORK/authorization/notice/notice-manifest.json' ] \
    && [ -s '$WORK/authorization/notice/unresolved-obligations.json' ] \
    && [ -s '$WORK/authorization/notice/THIRD-PARTY-NOTICES.txt' ]"
ck "...whose first line says DRAFT, INCOMPLETE, NOT APPROVED FOR DISTRIBUTION" \
   "head -1 '$WORK/authorization/notice/THIRD-PARTY-NOTICES.txt' \
      | grep -q 'DRAFT, INCOMPLETE, NOT APPROVED FOR DISTRIBUTION'"
# The licence half is composed by the workflow's OWN decide body, at PASS, so
# the refusal below is provably the NOTICE half and not the licence half
# leaking through. A licence PASS beside a notice REFUSE is the row that matters.
ck "EXECUTED: the workflow's own decide body composes a PASSING licence verdict" \
   "gate lic_decide BIND=success IMAGE_POLICY=success COMPOSED=success \
      AUTH_RECORD=authorization/post-build-authorization.json \
      IMAGE_INVENTORY=authorization/licence/image-inventory.json \
      LICENCE_RECORD=authorization/licence/licence-authorization.json \
      MATERIAL_INVENTORY='$WORK/policies/repository-material.yaml'
    python3 -c \"
import json
d=json.load(open('$WORK/authorization/licence/licence-authorization.json'))
assert d['verdict']=='PASS', d['verdict']\""
ck "EXECUTED: licence PASS + notice REFUSE -> the validator still REFUSES" \
   "! gate schema; says 'AR-NOTICE-REFUSED'"
ck "...and records its refusal for the sealing step, never silently" \
   "[ \"\$(cat '$WORK/authorization/schema.rc' 2>/dev/null)\" != 0 ]"
ck "SABOTAGE: with the bundle DELETED the same step body still REFUSES" \
   "rm -f '$WORK/authorization/notice/notice-manifest.json'
    ! gate schema; says 'AR-NOTICE-EVIDENCE-ABSENT'"
# THE GAP, RECREATED AND MEASURED. Not "the flag is present in the YAML" — the
# step body is taken, the flag is stripped out of it, and the stripped body is
# EXECUTED against the same tree with the bundle deleted. It passes. That is the
# exact shape this change exists to remove, and it is what makes the assertion
# above non-vacuous.
# Delete the flag line and un-continue the line above it, so the stripped body
# is a body that actually runs — a dangling `\` would fail for the wrong reason.
wf_run schema \
  | sed -e 's/\(--require-licence-authorization "\$LICENCE_RECORD"\) \\$/\1/' \
        -e '/--require-notice-bundle "\$NOTICE_BUNDLE"/d' > "$TMP/schema-stripped.sh"
# Comments mention the flag by name; only an executable line counts.
_exec_lines() { grep -vE '^[[:space:]]*#' "$1"; }
gate_body() { # gate_body <file-with-step-body> [VAR=VALUE ...]
  local bodyf="$1"; shift
  local -a envs=(); local line
  while IFS= read -r line; do [ -n "$line" ] && envs+=("$line"); done < <(wf_env schema)
  ( cd "$WORK" && env ${envs[@]+"${envs[@]}"} GITHUB_OUTPUT="$TMP/gh-out" \
        GITHUB_STEP_SUMMARY="$TMP/gh-sum" "$@" \
        bash --noprofile --norc "$bodyf" ) >"$TMP/out" 2>&1
}
ck "SABOTAGE: the stripped body no longer RUNS the flag" \
   "! _exec_lines '$TMP/schema-stripped.sh' | grep -q -- '--require-notice-bundle' \
    && _exec_lines '$TMP/schema-stripped.sh' | grep -q -- '--require-licence-authorization'"
ck "SABOTAGE: and EXECUTED, it passes with no bundle at all — the gap, recreated" \
   "[ ! -e '$WORK/authorization/notice/notice-manifest.json' ]
    gate_body '$TMP/schema-stripped.sh'
    [ \"\$(cat '$WORK/authorization/schema.rc' 2>/dev/null)\" = 0 ]"
ck "NON-VACUOUS: the SHIPPED body, same tree, same absence, REFUSES" \
   "! gate schema; says 'AR-NOTICE-EVIDENCE-ABSENT'"

echo
echo "== the REQUIRED CI path executes this file ================================"

CI_CMD="$(python3 "$STEP" "$CI" --job-named 'repo structure' \
            --run-containing 'test_notice_bundle.sh' 2>/dev/null)"
ck "ci.yml's REQUIRED 'repo structure' job runs this exact file" \
   "printf '%s' \"\$CI_CMD\" | grep -q 'tests/license/test_notice_bundle.sh'"
ck "the subsystem-coverage list names the producer, so losing its test goes red" \
   "grep -q 'scripts/license/generate-notice-bundle.py' tests/governance/test_subsystem_ci_coverage.sh"
ck "run-all's discovery finds this file" \
   "find tests -name 'test_*.sh' | grep -qx 'tests/license/test_notice_bundle.sh'"

echo
echo "== NOTHING here selected a licence, published, or resolved an obligation ==="

ck "the shipped licence policy is UNCHANGED: publication is still undetermined" \
   "python3 -c \"
import yaml
p=yaml.safe_load(open('policies/license-policy.yaml'))['publication']
assert p['decision']=='undetermined' and p['decided_by'] is None
assert p['notices_approved_for_distribution'] is False
assert p['tracked_issue']==98\""
ck "the shipped policy's denied list and exceptions are still EMPTY" \
   "python3 -c \"
import yaml
d=yaml.safe_load(open('policies/license-policy.yaml'))
assert d['denied']==[] and d['exceptions']==[]
assert d['default_state']=='legal-review-required'\""
ck "the root LICENSE still declares itself provisional, in its own words" \
   "grep -qi 'replace this file' LICENSE"
ck "there is no root NOTICE that could read as Foundry's outbound terms" \
   "[ ! -e NOTICE ]"
ck "the test mutated no tracked file" \
   "test -z \"\$(git -C '$ROOT' status --porcelain -- policies scripts third-party docs 2>/dev/null | grep -v '^??' || true)\""

echo "----"
printf 'assertions: %d proven\n' "$nck"
[ "$fail" -eq 0 ] && echo "test_notice_bundle: PASS" || echo "test_notice_bundle: FAIL"
exit "$fail"
