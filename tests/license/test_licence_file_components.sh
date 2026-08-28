#!/usr/bin/env bash
# =============================================================================
# tests/license/test_licence_file_components.sh — the file-component evidence
# model (#120).
# -----------------------------------------------------------------------------
# scripts/license/license-inventory.sh used to fold CycloneDX `type: "file"`
# components into the package licence inventory as though a file path were a
# software component, and to ignore SPDX `files[]` entirely. Measured over the
# 20 accepted production children that produced 7,972 of 8,507 findings, every
# one of them a path with no licence.
#
# The obvious "fix" — drop file components — is the reason this file exists. It
# creates a FILE-LEVEL BLIND SPOT: an independently licensed file inside an image
# vanishes from every control, and anybody can hide a component by writing
# `"type": "file"` next to it.
#
# What is proved here:
#
#   1. EVERY file component gets ONE of four classifications with a recorded
#      reason — scanner-observation, package-attributed, independently-licensed,
#      unresolved — and the ACCOUNTING INVARIANT is asserted by the parser, not
#      merely printed: input == the four classes summed, or it refuses.
#   2. OWNERSHIP IS PROVEN, never inferred. Only a stable SBOM relationship
#      (SPDX CONTAINS, syft evident-by, a CycloneDX dependencies edge) attributes
#      a file. Filename, path and version prove nothing, and a digest that
#      disagrees between the two documents REVOKES the attribution.
#   3. DE-DUPLICATION IS NOT EXEMPTION. A package-attributed file records its
#      owning package, that package's version, the relationship that proves it
#      and the licence expression it INHERITS. The obligation still exists; it is
#      counted once on the package instead of once per path.
#   4. FOUR SABOTAGES:
#        a. an independently-licensed component cannot be hidden by relabelling
#           its CycloneDX type to "file";
#        b. an unresolved file cannot become a scanner-observation by DELETING
#           its licence metadata — absence of metadata is not evidence of absence
#           of licence;
#        c. breaking the owning-package relationship must stop the file being
#           package-attributed, not leave it silently de-duplicated;
#        d. a file whose licence declaration CONFLICTS with its owning package's
#           stays visible.
#   5. NON-VACUITY AGAINST THE REAL PRODUCER. One assertion runs over a REAL,
#      COMMITTED syft document (docs/audits/caddy-openssl-2026-08-27/), not a
#      hand-written fixture. A fixture that only carries the shape the consumer
#      already reads cannot discover that the producer disagrees — which is how
#      a 113-assertion suite once missed a gate that bound nothing.
#
# Everything else runs in a scratch directory. Nothing writes to the checkout.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

TMP="$(mktemp -d)"
# shellcheck disable=SC2064
trap "rm -rf '$TMP'" EXIT

INV=scripts/license/license-inventory.sh
GATE=scripts/license/assert-license-policy.sh
REAL=docs/audits/caddy-openssl-2026-08-27/evidence/sbom-candidate-linux-amd64.spdx.json

# `cmd | grep -q X` under `set -o pipefail` returns 1 (or 141 on SIGPIPE) even
# when the grep MATCHES, because the pipeline inherits the producer's status.
# Every assertion below therefore captures first and asserts second.
run_inv() { bash "$INV" --sbom-dir "$1" --out "$2" >"$TMP/inv.out" 2>&1; }

# ---------------------------------------------------------------------------
# 1. REAL PRODUCER OUTPUT — a committed syft SPDX document, unmodified.
# ---------------------------------------------------------------------------
mkdir -p "$TMP/real"
cp "$REAL" "$TMP/real/"
ck "a real committed syft document is parsed" \
   "run_inv '$TMP/real' '$TMP/real.json'"
ck "REAL PRODUCER: every SPDX files[] entry is classified, none ignored" \
   "python3 -c \"
import json
d=json.load(open('$TMP/real.json'))
src=json.load(open('$REAL'))
f=d['image_files']
assert f['input_file_components']==len(src['files']), (f['input_file_components'],len(src['files']))
assert sum(f['by_class_observations'].values())==f['input_file_components'], f
print(f['by_class_observations'])\""
ck "REAL PRODUCER: every excluded file records owner, version, relationship and inherited licence" \
   "python3 -c \"
import json
f=json.load(open('$TMP/real.json'))['image_files']
assert f['by_class_observations']['package-attributed']>200, f['by_class_observations']
assert f['by_class_observations']['unresolved']==0, f['unresolved']
for s in f['package_attributed_sample']:
    assert s['owning_package'] and all(p.startswith('pkg:') for p in s['owning_package']), s
    assert s['relationship_evidence'], s
    assert 'inherited_licence_expression' in s, s
    assert s['reason'], s\""
ck "REAL PRODUCER: no file path leaked into the package component list" \
   "python3 -c \"
import json
d=json.load(open('$TMP/real.json'))
bad=[c['name'] for c in d['components'] if c.get('component_type')=='file']
assert bad==[], bad
assert d['file_component_count']==0, d['file_component_count']\""
ck "REAL PRODUCER: de-duplication is stated as de-duplication, not as exemption" \
   "python3 -c \"
import json
f=json.load(open('$TMP/real.json'))['image_files']
n=f['deduplication_note']
assert 'not exempted' in n and 'counted once' in n and 'removes an obligation' in n, n
assert f['raw_file_components']==224, f['raw_file_components']
assert f['normalised_policy_findings_from_files']==0, f\""

# ---------------------------------------------------------------------------
# 2. OWNERSHIP IS PROVEN. The SPDX companion of the SAME image subject is where
#    a CycloneDX file's ownership fact lives; without it nothing is proven.
# ---------------------------------------------------------------------------
mk_cdx() { # mk_cdx <dir>
  mkdir -p "$1"
  cat >"$1/img.cdx.json" <<'JSON'
{"bomFormat":"CycloneDX","specVersion":"1.5",
 "metadata":{"component":{"type":"container","name":"img",
   "bom-ref":"pkg:oci/img@sha256%3Aaaaa","purl":"pkg:oci/img@sha256%3Aaaaa"}},
 "components":[
  {"type":"library","name":"zlib1g","version":"1.3","bom-ref":"ref-zlib",
   "purl":"pkg:deb/debian/zlib1g@1.3","licenses":[{"license":{"id":"Zlib"}}]},
  {"type":"file","name":"/usr/lib/libz.so.1","bom-ref":"ref-libz-file",
   "hashes":[{"alg":"SHA-256","content":"aa11"}]},
  {"type":"file","name":"/opt/vendor/thirdparty.bin","bom-ref":"ref-orphan"}
 ]}
JSON
}
mk_spdx() { # mk_spdx <dir> <relationship-type-for-libz|none> <libz-digest>
  local rel="$2" dig="$3"
  local relline=""
  if [ "$rel" != "none" ]; then
    relline=',
  {"spdxElementId":"SPDXRef-Package-zlib","relatedSpdxElement":"SPDXRef-File-libz",
   "relationshipType":"'"$rel"'"}'
  fi
  cat >"$1/img.spdx.json" <<JSON
{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"img",
 "packages":[
  {"name":"img","SPDXID":"SPDXRef-Root","versionInfo":"sha256:aaaa",
   "licenseConcluded":"NOASSERTION","licenseDeclared":"NOASSERTION"},
  {"name":"zlib1g","SPDXID":"SPDXRef-Package-zlib","versionInfo":"1.3",
   "licenseConcluded":"Zlib","licenseDeclared":"Zlib",
   "externalRefs":[{"referenceType":"purl",
     "referenceLocator":"pkg:deb/debian/zlib1g@1.3"}]}],
 "files":[
  {"fileName":"usr/lib/libz.so.1","SPDXID":"SPDXRef-File-libz",
   "checksums":[{"algorithm":"SHA256","checksumValue":"$dig"}],
   "licenseConcluded":"NOASSERTION","licenseInfoInFiles":["NOASSERTION"]}],
 "relationships":[
  {"spdxElementId":"SPDXRef-DOCUMENT","relatedSpdxElement":"SPDXRef-Root",
   "relationshipType":"DESCRIBES"}$relline]}
JSON
}

mk_cdx "$TMP/pair"; mk_spdx "$TMP/pair" CONTAINS aa11
ck "a CycloneDX file with an SPDX CONTAINS owner is PACKAGE-ATTRIBUTED" \
   "run_inv '$TMP/pair' '$TMP/pair.json' && python3 -c \"
import json
f=json.load(open('$TMP/pair.json'))['image_files']
s=[x for x in f['package_attributed_sample'] if x['path']=='usr/lib/libz.so.1']
assert len(s)==1, s
assert f['by_class_observations']['package-attributed']==2, f['by_class_observations']
for x in s:
    assert x['owning_package']==['pkg:deb/debian/zlib1g@1.3'], x
    assert x['owning_package_version']==['1.3'], x
    assert x['inherited_licence_expression']==['Zlib'], x
    assert 'SPDX:CONTAINS' in x['relationship_evidence'], x\""
ck "...and it is withheld from package policy" \
   "python3 -c \"
import json
names=[c['name'] for c in json.load(open('$TMP/pair.json'))['components']]
assert '/usr/lib/libz.so.1' not in names and 'usr/lib/libz.so.1' not in names, names\""

# SABOTAGE (c): break the relationship. The file must STOP being attributed.
mk_cdx "$TMP/norel"; mk_spdx "$TMP/norel" none aa11
ck "SABOTAGE c: breaking the owning-package relationship UN-attributes the file" \
   "run_inv '$TMP/norel' '$TMP/norel.json' && python3 -c \"
import json
f=json.load(open('$TMP/norel.json'))['image_files']
u={x['path'] for x in f['unresolved']}
assert 'usr/lib/libz.so.1' in u, sorted(u)
assert not [x for x in f['package_attributed_sample'] if 'libz' in x['path']], f['package_attributed_sample']\""
ck "...and the un-attributed file REACHES the policy gate" \
   "! bash $GATE --inventory '$TMP/norel.json' --policy policies/license-policy.yaml >'$TMP/g0' 2>&1 && grep -q 'libz.so.1' '$TMP/g0'"

# A DIFFERENT DIGEST is a different file. Attribution must be revoked, not reused.
mk_cdx "$TMP/digest"; mk_spdx "$TMP/digest" CONTAINS bb22
ck "SABOTAGE c2: a digest that disagrees between the two documents REVOKES attribution" \
   "run_inv '$TMP/digest' '$TMP/digest.json' && python3 -c \"
import json
d=json.load(open('$TMP/digest.json')); f=d['image_files']
vis={x['path']:x for x in f['unresolved']+f['independently_licensed']}
assert 'usr/lib/libz.so.1' in vis, sorted(vis)
assert 'records' in vis['usr/lib/libz.so.1']['reason'], vis['usr/lib/libz.so.1']['reason']
# the SPDX document's OWN CONTAINS still attributes its own file entry; what is
# revoked is the CROSS-DOCUMENT transfer to the CycloneDX component, which is
# the only place a filename join could have substituted for evidence.
att=[x for x in f['package_attributed_sample'] if x['path']=='usr/lib/libz.so.1']
assert all(x['document'].endswith('.spdx.json') for x in att), att
assert '/usr/lib/libz.so.1' in {c['name'] for c in d['components']}, d['components']\""

# THE ORPHAN. No edge anywhere -> unresolved -> still a finding.
ck "a file with NO owner edge anywhere is UNRESOLVED, not silently dropped" \
   "python3 -c \"
import json
d=json.load(open('$TMP/pair.json'))
u=[x['path'] for x in d['image_files']['unresolved']]
assert 'opt/vendor/thirdparty.bin' in u, u
names=[c['name'] for c in d['components']]
assert '/opt/vendor/thirdparty.bin' in names, names\""
ck "...and the UNRESOLVED file still REFUSES at the licence policy gate" \
   "! bash $GATE --inventory '$TMP/pair.json' --policy policies/license-policy.yaml >'$TMP/g1' 2>&1"
ck "...naming the file path in the refusal" \
   "grep -q '/opt/vendor/thirdparty.bin' '$TMP/g1'"

# ---------------------------------------------------------------------------
# 3. SABOTAGE (a) — an independently licensed image file must not be hideable by
#    changing its CycloneDX type to "file".
# ---------------------------------------------------------------------------
mkdir -p "$TMP/evade"
cat >"$TMP/evade/img.cdx.json" <<'JSON'
{"bomFormat":"CycloneDX","specVersion":"1.5",
 "metadata":{"component":{"type":"container","name":"img","bom-ref":"root"}},
 "components":[
  {"type":"file","name":"/usr/share/vendor/libevil.so","bom-ref":"ref-evil",
   "licenses":[{"license":{"id":"EVIL-1.0"}}]},
  {"type":"file","name":"/usr/bin/caddy","bom-ref":"ref-caddy",
   "purl":"pkg:golang/github.com/caddyserver/caddy@2.10.2"},
  {"type":"file","name":"/opt/agpl-thing","bom-ref":"ref-agpl",
   "licenses":[{"expression":"AGPL-3.0-only"}]},
  {"type":"file","name":"/opt/conflicted","bom-ref":"ref-conf",
   "licenses":[{"license":{"id":"GPL-3.0-only"}}]},
  {"type":"file","name":"/opt/two-minds","bom-ref":"ref-two",
   "licenses":[{"license":{"id":"MIT"}},{"license":{"id":"GPL-2.0-only"}}]},
  {"type":"file","name":"/opt/patched.so","bom-ref":"ref-patched",
   "pedigree":{"patches":[{"type":"unofficial"}]}},
  {"type":"file","name":"/etc/owned.conf","bom-ref":"ref-owned"},
  {"type":"library","name":"base","version":"1","bom-ref":"ref-base",
   "purl":"pkg:deb/debian/base@1","licenses":[{"license":{"id":"MIT"}}]}],
 "dependencies":[
  {"ref":"ref-base","dependsOn":["ref-owned","ref-evil","ref-caddy","ref-agpl",
                                 "ref-conf","ref-two","ref-patched"]}]}
JSON
ck "the evasion fixture parses" "run_inv '$TMP/evade' '$TMP/evade.json'"
ck "SABOTAGE a: a licence-asserting component relabelled type=file is NOT hidden" \
   "python3 -c \"
import json
d=json.load(open('$TMP/evade.json'))
names={c['name'] for c in d['components']}
for p in ('/usr/share/vendor/libevil.so','/opt/agpl-thing','/usr/bin/caddy'):
    assert p in names, (p, sorted(names))
cls={x['path'] for x in d['image_files']['independently_licensed']}
assert {'usr/share/vendor/libevil.so','opt/agpl-thing','usr/bin/caddy'} <= cls, cls\""
ck "SABOTAGE a: the licence identity WINS over an owner edge — it is tested first" \
   "python3 -c \"
import json
b=json.load(open('$TMP/evade.json'))['image_files']['by_class_observations']
assert b['independently-licensed']==6, b
assert b['package-attributed']==1, b
assert b['scanner-observation']==0 and b['unresolved']==0, b\""
ck "SABOTAGE a: the DENIED/unreviewed licence on the relabelled file REFUSES at the gate" \
   "! bash $GATE --inventory '$TMP/evade.json' --policy policies/license-policy.yaml >'$TMP/g2' 2>&1"
ck "...and the refusal names the file and its identifier" \
   "grep -q 'libevil.so' '$TMP/g2' && grep -q 'AGPL-3.0-only' '$TMP/g2'"

# SABOTAGE (d): a file whose declaration conflicts with its owner's stays visible.
ck "SABOTAGE d: a file/package licence CONFLICT stays visible and says so" \
   "python3 -c \"
import json
f=json.load(open('$TMP/evade.json'))['image_files']
by={x['path']:x for x in f['independently_licensed']}
c=by['opt/conflicted']
assert c['licenses']==['GPL-3.0-only'], c
assert c['conflicting_or_exceptional_licence_metadata'] is True, c
assert 'MIT' in c['reason'], c['reason']
t=by['opt/two-minds']
assert t['conflicting_or_exceptional_licence_metadata'] is True, t
assert set(t['licenses'])=={'MIT','GPL-2.0-only'}, t\""
ck "SABOTAGE d: a file recording LOCAL MODIFICATION is never a scanner observation" \
   "python3 -c \"
import json
f=json.load(open('$TMP/evade.json'))['image_files']
by={x['path']:x for x in f['independently_licensed']}
p=by['opt/patched.so']
assert 'pedigree' in p['reason'], p['reason']\""
ck "the genuinely owned config file IS de-duplicated — the fix is not vacuous either" \
   "python3 -c \"
import json
d=json.load(open('$TMP/evade.json'))
names={c['name'] for c in d['components']}
assert '/etc/owned.conf' not in names, sorted(names)
s=[x for x in d['image_files']['package_attributed_sample'] if x['path']=='etc/owned.conf'][0]
assert s['owning_package']==['pkg:deb/debian/base@1'], s
assert s['inherited_licence_expression']==['MIT'], s
assert 'CycloneDX:dependencies' in s['relationship_evidence'], s\""

# ---------------------------------------------------------------------------
# 4. SABOTAGE (b) — deleting licence metadata must not promote a file into the
#    excludable class. Absence of metadata is not evidence of absence of licence.
# ---------------------------------------------------------------------------
mkdir -p "$TMP/strip"
python3 - "$TMP/evade/img.cdx.json" "$TMP/strip/img.cdx.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
keep = []
for c in d["components"]:
    if c.get("name") in ("/usr/share/vendor/libevil.so", "/opt/agpl-thing"):
        c.pop("licenses", None)          # the sabotage: delete the metadata
        c.pop("purl", None)
    keep.append(c)
d["components"] = keep
d["dependencies"] = []                   # and remove every edge as well
json.dump(d, open(sys.argv[2], "w"), indent=1)
PY
ck "SABOTAGE b: stripping licence metadata does NOT make a file excludable" \
   "run_inv '$TMP/strip' '$TMP/strip.json' && python3 -c \"
import json
d=json.load(open('$TMP/strip.json'))
f=d['image_files']
u={x['path'] for x in f['unresolved']}
assert {'usr/share/vendor/libevil.so','opt/agpl-thing'} <= u, sorted(u)
assert f['by_class_observations']['scanner-observation']==0, f['by_class_observations']
names={c['name'] for c in d['components']}
assert '/usr/share/vendor/libevil.so' in names and '/opt/agpl-thing' in names, sorted(names)\""
ck "...and the stripped inventory still REFUSES, so the evasion buys nothing" \
   "! bash $GATE --inventory '$TMP/strip.json' --policy policies/license-policy.yaml >'$TMP/g3' 2>&1 && grep -q 'libevil.so' '$TMP/g3'"
ck "...the reason recorded says absence of metadata is not absence of licence" \
   "python3 -c \"
import json
f=json.load(open('$TMP/strip.json'))['image_files']
r=[x for x in f['unresolved'] if x['path']=='opt/agpl-thing'][0]['reason']
assert 'absence of licence metadata is not evidence' in r, r\""

# ---------------------------------------------------------------------------
# 5. THE ACCOUNTING INVARIANT is asserted by the parser, not just reported.
# ---------------------------------------------------------------------------
ck "every file component lands in exactly one of the four classes, and they total" \
   "python3 -c \"
import json
for p in ('$TMP/real.json','$TMP/pair.json','$TMP/evade.json','$TMP/strip.json'):
    f=json.load(open(p))['image_files']
    assert set(f['by_class_observations'])=={'scanner-observation','package-attributed',
        'independently-licensed','unresolved'}, f['by_class_observations']
    assert sum(f['by_class_observations'].values())==f['input_file_components'], (p,f)
    assert f['accounting_invariant_holds'] is True, f
    assert str(f['input_file_components']) in f['accounting_invariant'], f\""
ck "the raw count and the normalised policy-finding count are BOTH reported" \
   "python3 -c \"
import json
f=json.load(open('$TMP/evade.json'))['image_files']
assert f['raw_file_components']==7, f['raw_file_components']
assert f['normalised_policy_findings_from_files']==6, f['normalised_policy_findings_from_files']\""
ck "an unaccounted or reasonless component is REFUSED by the parser itself" \
   "grep -q 'An unaccounted component is a component nobody decided anything' $INV \
    && grep -q 'was classified %r with no' $INV \
    && grep -q 'not one of the four declared dispositions' $INV"
ck "the inventory states in writing that repository-material does NOT cover these" \
   "python3 -c \"
import json
n=json.load(open('$TMP/real.json'))['image_files']['note']
assert 'does NOT cover' in n and 'never in the tree' in n, n\""

ck "the GATE reports findings split by component type, not as one number" \
   "! bash $GATE --inventory '$TMP/pair.json' --policy policies/license-policy.yaml >'$TMP/g4' 2>&1
    grep -q 'by component type' '$TMP/g4' \
    && grep -q 'image FILE components' '$TMP/g4' \
    && grep -q 'gated exactly like a package' '$TMP/g4'"

# ---------------------------------------------------------------------------
# 5b. The BACKLOG GROUPER loses nothing. A grouping that drops a finding is a
#     suppression with a nicer name, so the tool reconciles or refuses.
# ---------------------------------------------------------------------------
GROUP=scripts/license/group-licence-backlog.py
DIAG=docs/audits/real-image-inventories-2026-08-28/licence/image-licence-policy-diagnostic.log
BACKLOG=docs/licensing/image-licence-backlog-2026-08-28.json
ck "the committed backlog is exactly what the grouper produces from the committed log" \
   "python3 '$GROUP' --diagnostic '$DIAG' --out '$TMP/regen.json' 2>/dev/null
    cmp -s '$TMP/regen.json' '$BACKLOG'"
ck "every finding in the diagnostic lands in exactly one group" \
   "python3 -c \"
import json
d=json.load(open('$BACKLOG'))
assert sum(g['count'] for g in d['groups'])==d['total_findings']==8507, d['total_findings']
assert d['image_file_findings']==7972 and d['substantive_findings']==535, d
assert sum(d['totals'].values())==8507, d['totals']\""
ck "SABOTAGE: a truncated diagnostic is REFUSED, not silently under-reported" \
   "head -200 '$DIAG' > '$TMP/trunc.log'
    ! python3 '$GROUP' --diagnostic '$TMP/trunc.log' --out - >'$TMP/tg' 2>'$TMP/tge'
    grep -q 'under-reports the thing it exists to report' '$TMP/tge'"
# ---------------------------------------------------------------------------
# 5c. The OWNER PARTITION. "Assign the backlog to #98" buries the four questions
#     only a rights holder can answer under 516 that engineering owns, so every
#     substantive finding gets exactly ONE primary owner and the classes
#     reconcile to the substantive total or the tool refuses.
# ---------------------------------------------------------------------------
ck "every substantive finding has exactly one primary owner, and they reconcile" \
   "python3 -c \"
import json
p=json.load(open('$BACKLOG'))['owner_partition']
assert p['assigned']==p['substantive_findings']==535, p
assert sum(p['by_class'].values())==535, p['by_class']
assert set(p['by_class'])==set(p['classes']), p
assert p['unowned']==0 and p['double_counted']==0, p\""
ck "the partition does NOT dump the backlog on #98" \
   "python3 -c \"
import json
p=json.load(open('$BACKLOG'))['owner_partition']['by_class']
assert p['project-rights-98']==0, p
assert p['legal-interpretation']==19, p
assert p['evidence-producer-defect']==298, p
assert p['normalization-or-mapping-gap']==218, p\""
ck "the PHP binary/extension gap is owned as EVIDENCE COMPLETENESS, not as a legal call" \
   "python3 -c \"
import json
g={x['group_id']:x for x in json.load(open('$BACKLOG'))['groups']}
x=g['G-NOASSERT-PKG-GENERIC-PHP-BINARY-EXTENSION']
assert x['owner_class']=='evidence-producer-defect', x['owner_class']
assert x['owner_class_residual_after_primary_fix']=='legal-interpretation', x\""
ck "SABOTAGE: a group with no owner rule REFUSES rather than defaulting to #98" \
   "python3 -c \"
import importlib.util, sys
spec=importlib.util.spec_from_file_location('g','$GROUP')
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
try:
    m.owner_of('G-SOMETHING-NOBODY-CLASSIFIED')
except SystemExit as e:
    sys.exit(0 if e.code==1 else 1)
sys.exit(1)\""
ck "SABOTAGE: a partition that does not reconcile REFUSES" \
   "python3 -c \"
import importlib.util, sys
spec=importlib.util.spec_from_file_location('g','$GROUP')
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
try:
    m.partition([{'group_id':'G-REVIEW-X','count':3}], 99)
except SystemExit as e:
    sys.exit(0 if e.code==1 else 1)
sys.exit(1)\""

ck "SABOTAGE: a Go module path is NOT mistaken for an image file path" \
   "python3 -c \"
import json
d=json.load(open('$BACKLOG'))
g={x['group_id']:x for x in d['groups']}
assert g['G-NOASSERT-PKG-GOLANG-GO-MODULE']['count']==248, g['G-NOASSERT-PKG-GOLANG-GO-MODULE']['count']
assert g['G-FILE-NOASSERTION']['count']==7972, g['G-FILE-NOASSERTION']['count']\""

# ---------------------------------------------------------------------------
# 6. The checkout is untouched.
# ---------------------------------------------------------------------------
ck "the test mutated no tracked file" \
   "test -z \"\$(git -C '$ROOT' status --porcelain -- policies scripts docs 2>/dev/null | grep -v '^??' || true)\""

echo "----"
[ "$fail" -eq 0 ] && echo "test_licence_file_components: PASS" || echo "test_licence_file_components: FAIL"
exit "$fail"
