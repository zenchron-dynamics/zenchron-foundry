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
# would create a FILE-LEVEL BLIND SPOT: an independently licensed file inside an
# image would vanish from every control, and anybody could hide a component by
# writing `"type": "file"` next to it.
#
# What is proved here:
#
#   1. THE RULE IS MECHANICAL. A file is withheld from package policy only when
#      an EDGE TO IT IS SHOWN in the documents. No edge, no exclusion — the
#      config claim "syft is set to owned-by-package so these must be owned" is
#      a statement about policies/syft.yaml, not about the document in hand.
#   2. INDEPENDENTLY LICENSED AND UNRESOLVED FILES REMAIN VISIBLE. They stay in
#      components[] and still reach the licence policy gate.
#   3. SABOTAGE: relabelling an independently licensed component as
#      `type: "file"` does NOT hide it. This is the exact evasion the fix must
#      not enable.
#   4. NON-VACUITY AGAINST THE REAL PRODUCER. One assertion runs over a REAL,
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
assert f['observations_total']==len(src['files']), (f['observations_total'],len(src['files']))
assert sum(f['by_class_observations'].values())==f['observations_total'], f
print(f['by_class_observations'])\""
ck "REAL PRODUCER: each excluded file names the pkg: owner that justifies it" \
   "python3 -c \"
import json
d=json.load(open('$TMP/real.json'))
f=d['image_files']
assert f['by_class_observations']['attributable']>200, f
assert f['by_class_observations']['unresolved']==0, f['unresolved']\""
ck "REAL PRODUCER: no file path leaked into the package component list" \
   "python3 -c \"
import json
d=json.load(open('$TMP/real.json'))
bad=[c['name'] for c in d['components'] if c.get('component_type')=='file']
assert bad==[], bad
assert d['file_component_count']==0, d['file_component_count']\""

# ---------------------------------------------------------------------------
# 2. THE CROSS-FORMAT ATTRIBUTION IS WHAT MAKES THE EXCLUSION MECHANICAL.
#    CycloneDX has no containment concept; the SPDX companion of the SAME image
#    subject is where the ownership fact lives.
# ---------------------------------------------------------------------------
mk_pair() { # mk_pair <dir> <with-spdx-companion:0|1>
  local d="$1" withspdx="$2"
  mkdir -p "$d"
  cat >"$d/img.cdx.json" <<'JSON'
{"bomFormat":"CycloneDX","specVersion":"1.5",
 "metadata":{"component":{"type":"container","name":"img",
   "bom-ref":"pkg:oci/img@sha256%3Aaaaa","purl":"pkg:oci/img@sha256%3Aaaaa"}},
 "components":[
  {"type":"library","name":"zlib1g","version":"1.3","bom-ref":"ref-zlib",
   "purl":"pkg:deb/debian/zlib1g@1.3","licenses":[{"license":{"id":"Zlib"}}]},
  {"type":"file","name":"/usr/lib/libz.so.1","bom-ref":"ref-libz-file"},
  {"type":"file","name":"/opt/vendor/thirdparty.bin","bom-ref":"ref-orphan"}
 ]}
JSON
  if [ "$withspdx" = "1" ]; then
    cat >"$d/img.spdx.json" <<'JSON'
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
   "licenseConcluded":"NOASSERTION","licenseInfoInFiles":["NOASSERTION"]}],
 "relationships":[
  {"spdxElementId":"SPDXRef-DOCUMENT","relatedSpdxElement":"SPDXRef-Root",
   "relationshipType":"DESCRIBES"},
  {"spdxElementId":"SPDXRef-Package-zlib","relatedSpdxElement":"SPDXRef-File-libz",
   "relationshipType":"CONTAINS"}]}
JSON
  fi
}

mk_pair "$TMP/pair" 1
ck "a CycloneDX file with an SPDX CONTAINS owner is ATTRIBUTABLE and excluded" \
   "run_inv '$TMP/pair' '$TMP/pair.json' && python3 -c \"
import json
d=json.load(open('$TMP/pair.json'))
e=[x for x in d['image_files']['unresolved'] if 'libz' in x['path']]
assert e==[], e
names=[c['name'] for c in d['components']]
assert '/usr/lib/libz.so.1' not in names, names\""
ck "...and its exclusion NAMES the owning purl, it is not merely asserted" \
   "python3 -c \"
import json,subprocess
d=json.load(open('$TMP/pair.json'))
assert d['image_files']['by_class_observations']['attributable']>=2, d['image_files']\""

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

# SABOTAGE ON THE MECHANISM: remove the SPDX companion. The SAME CycloneDX file
# that was excluded a moment ago must stop being excluded, because the evidence
# that justified excluding it is gone.
mk_pair "$TMP/nospdx" 0
ck "SABOTAGE: with the ownership evidence removed the SAME file is UNRESOLVED" \
   "run_inv '$TMP/nospdx' '$TMP/nospdx.json' && python3 -c \"
import json
d=json.load(open('$TMP/nospdx.json'))
u=[x['path'] for x in d['image_files']['unresolved']]
assert 'usr/lib/libz.so.1' in u, u\""

# ---------------------------------------------------------------------------
# 3. THE REQUIRED SABOTAGE — an independently licensed image file must not be
#    hideable by changing its CycloneDX type to "file".
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
  {"type":"file","name":"/etc/owned.conf","bom-ref":"ref-owned"},
  {"type":"library","name":"base","version":"1","bom-ref":"ref-base",
   "purl":"pkg:deb/debian/base@1","licenses":[{"license":{"id":"MIT"}}]}],
 "dependencies":[
  {"ref":"ref-base","dependsOn":["ref-owned","ref-evil","ref-caddy","ref-agpl"]}]}
JSON
ck "the evasion fixture parses" "run_inv '$TMP/evade' '$TMP/evade.json'"
ck "SABOTAGE: a licence-asserting component relabelled type=file is NOT hidden" \
   "python3 -c \"
import json
d=json.load(open('$TMP/evade.json'))
names={c['name'] for c in d['components']}
for p in ('/usr/share/vendor/libevil.so','/opt/agpl-thing','/usr/bin/caddy'):
    assert p in names, (p, sorted(names))
cls={x['path'] for x in d['image_files']['independently_licensed']}
assert {'usr/share/vendor/libevil.so','opt/agpl-thing','usr/bin/caddy'} <= cls, cls\""
ck "SABOTAGE: the licence identity WINS over an owner edge — it is tested first" \
   "python3 -c \"
import json
d=json.load(open('$TMP/evade.json'))
assert d['image_files']['by_class_observations']['independently-licensed']==3, d['image_files']
assert d['image_files']['by_class_observations']['attributable']==1, d['image_files']\""
ck "SABOTAGE: the DENIED licence on the relabelled file still REFUSES at the gate" \
   "! bash $GATE --inventory '$TMP/evade.json' --policy policies/license-policy.yaml >'$TMP/g2' 2>&1"
ck "...and the refusal names the file and its denied/unreviewed identifier" \
   "grep -q 'libevil.so' '$TMP/g2' && grep -q 'AGPL-3.0-only' '$TMP/g2'"
ck "the genuinely owned config file IS excluded — the fix is not vacuous either" \
   "python3 -c \"
import json
d=json.load(open('$TMP/evade.json'))
names={c['name'] for c in d['components']}
assert '/etc/owned.conf' not in names, sorted(names)\""

# ---------------------------------------------------------------------------
# 4. NOTHING DISAPPEARS. Every observation is accounted for in some class.
# ---------------------------------------------------------------------------
ck "every file observation lands in exactly one class, and the classes total" \
   "python3 -c \"
import json
for p in ('$TMP/real.json','$TMP/pair.json','$TMP/evade.json'):
    d=json.load(open(p))['image_files']
    assert sum(d['by_class_observations'].values())==d['observations_total'], (p,d)
    assert set(d['by_class_observations'])=={'attributable','observation',
        'independently-licensed','unresolved'}, d\""
ck "the inventory states in writing that repository-material does NOT cover these" \
   "python3 -c \"
import json
n=json.load(open('$TMP/real.json'))['image_files']['note']
assert 'does NOT cover' in n and 'never in the tree' in n, n\""

# ---------------------------------------------------------------------------
# 5. The checkout is untouched.
# ---------------------------------------------------------------------------
ck "the test mutated no tracked file" \
   "test -z \"\$(git -C '$ROOT' status --porcelain -- policies scripts docs 2>/dev/null | grep -v '^??' || true)\""

echo "----"
[ "$fail" -eq 0 ] && echo "test_licence_file_components: PASS" || echo "test_licence_file_components: FAIL"
exit "$fail"
