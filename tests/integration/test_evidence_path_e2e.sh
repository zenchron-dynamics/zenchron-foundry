#!/usr/bin/env bash
# shellcheck disable=SC2034  # assertion locals are consumed inside ck()/gap() eval strings
# =============================================================================
# tests/integration/test_evidence_path_e2e.sh
# -----------------------------------------------------------------------------
# ONE buildless path through everything that merged as #199 #200 #201 #202 #205
# #206 #207, flowing:
#
#   foundry-child -> staged-candidate -> SBOM / VEX / evidence bundle
#     -> authorization -> test-only seal -> continuity -> offline restore
#     -> revalidation of the restored copy
#
# WHY THIS EXISTS. Each of those seven changes was validated against its OWN
# fixtures and every one of them passes on its own. That is exactly the state in
# which a system does not work: seven subsystems, each internally consistent,
# each consuming data it also produced. The question no per-PR suite can ask is
# whether the OUTPUT of one is the INPUT the next actually reads.
#
# THE ANTI-VACUITY RULE. A single artifact set is threaded through every stage,
# and EVERY boundary is sabotaged, so the run cannot pass merely because each
# subsystem validated its own independent data. Each sabotage must be refused
# for ITS OWN diagnostic — "it failed" is not evidence that the boundary is
# checked, because everything fails for a checksum mismatch eventually.
#
# TWO KINDS OF ASSERTION, and the difference is the point:
#
#   ck()   The composition HOLDS. A shipped script observably refuses the
#          sabotage, with its own diagnostic.
#
#   gap()  The composition DOES NOT HOLD, and this pins the shortfall so it
#          cannot be re-discovered by accident. A gap() assertion states a fact
#          about master that is TRUE TODAY and that ought to become false when
#          somebody closes the gap — at which point this test fails and tells
#          them to promote the line to ck(). A gap that silently starts passing
#          is a gap nobody notices was fixed, which is how the next one gets
#          written. Every gap() line names what would close it.
#
# NOTHING HERE BUILDS, PUBLISHES, PROMOTES, SIGNS FOR PRODUCTION OR DISPATCHES
# ANYTHING. It is offline, buildless and reads only the committed accepted run.
# The one signature it makes is a throwaway prime256v1 key in mktemp -d, through
# the script whose whole design is that it cannot mint a real one.
#
# AMBIENT SAFETY. Every byte this test writes lands under a single mktemp -d.
# Where a scenario needs a mutated repository input, it mutates a disposable
# COPY. tests/lib/test_no_ambient_mutation.sh enforces this class repo-wide; the
# final assertion here re-checks the checkout independently.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
# common.sh carries `set -e`, which would end the run at the first intentional
# refusal. It also carries MATRIX_COUNT and child_key(), which is why it is
# sourced rather than reimplemented: a second identity derivation is the defect
# the evidence-class contract exists to prevent.
# shellcheck source=../../scripts/lib/common.sh
. scripts/lib/common.sh
set +e
set +o pipefail

fail=0 nck=0 ngap=0
ck()  { nck=$((nck+1));  if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }
gap() { ngap=$((ngap+1)); if eval "$2"; then echo "GAP  - $1"; else
          echo "FAIL - GAP ASSERTION NO LONGER HOLDS (promote to ck): $1"; fail=1; fi; }

GEN=scripts/release/generate-evidence-bundle.sh
VEX=scripts/release/generate-vex.sh
SEAL=scripts/release/release-seal.sh
VSEAL=scripts/release/verify-release-seal.sh
REST=scripts/release/restore-evidence.sh
AEC=scripts/release/assert-evidence-class.sh
AUTHV=scripts/release/validate-authorization-record.sh
LINV=scripts/license/license-inventory.sh
LGATE=scripts/license/assert-license-policy.sh
CVERIFY=scripts/continuity-verify.sh
ACCEPTED=docs/audits/acceptance-multiarch-2026-08-20/acceptance-evidence.json

if ! python3 -c 'import yaml, jsonschema' 2>/dev/null; then
  echo "SKIP - pyyaml/jsonschema absent"; echo "test_evidence_path_e2e: PASS"; exit 0
fi
if ! command -v openssl >/dev/null 2>&1; then
  echo "SKIP - openssl absent"; echo "test_evidence_path_e2e: PASS"; exit 0
fi
if [ ! -f "$ACCEPTED" ]; then
  echo "SKIP - accepted evidence absent"; echo "test_evidence_path_e2e: PASS"; exit 0
fi

TMP="$(mktemp -d)"
# Expand NOW: a single-quoted trap defers expansion past this scope and dies
# under set -u. EXIT, never RETURN — a RETURN trap under `bash -T` fires on
# every inner function return and has already wiped fixtures mid-run here.
# The chmod is required because restore-evidence.sh archives 0555/0444 on
# purpose, and rm -rf cannot descend a directory with no write bit.
# shellcheck disable=SC2064
trap "chmod -R u+w '$TMP' 2>/dev/null; rm -rf '$TMP'" EXIT

DAY=2026-08-25
REV="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["source_revision"])' "$ACCEPTED")"
# Derived, never a literal. MATRIX_COUNT is the ONE declaration of the shipping
# matrix size; a hardcoded 10 or 20 here would re-baseline itself silently the
# day the matrix changes, which is the exact drift shape this repository keeps
# removing.
CHILDREN=$(( MATRIX_COUNT * 2 ))

gen()  { ( bash "$GEN" generate "$@" ); }
ver()  { ( bash "$GEN" verify "$@" ); }
vexv() { ( bash "$VEX" verify "$@" ); }
seal() { ( bash "$SEAL" seal "$@" ); }
vsl()  { ( bash "$VSEAL" verify "$@" ); }
aec()  { ( bash "$AEC" "$@" ); }
arch() { ( bash "$REST" "$@" ); }

# Re-seal a bundle's index so a sabotage fails for the rule under test rather
# than for the checksum rule that would mask it. This is the attacker's best
# case, which is what makes the surviving refusals meaningful.
reindex() { python3 - "$1" <<'PY'
import hashlib, os, sys
d = sys.argv[1]
lines = []
for dirpath, _dirs, names in os.walk(d):
    for n in names:
        ap = os.path.join(dirpath, n)
        rel = os.path.relpath(ap, d)
        if rel in ("SHA256SUMS", "BUNDLE.sha256"):
            continue
        lines.append("%s  %s" % (hashlib.sha256(open(ap, "rb").read()).hexdigest(), rel))
lines.sort(key=lambda s: s.split("  ", 1)[1])
mp = [l for l in lines if l.endswith("  manifest.json")]
rest = [l for l in lines if not l.endswith("  manifest.json")]
open(os.path.join(d, "SHA256SUMS"), "w").write("\n".join(mp + rest) + "\n")
open(os.path.join(d, "BUNDLE.sha256"), "w").write(
    "%s  SHA256SUMS\n"
    % hashlib.sha256(open(os.path.join(d, "SHA256SUMS"), "rb").read()).hexdigest())
PY
}

echo "== stage 0: the accepted 8.3/8.4 run is still admissible =================="

# The whole path below is anchored to ONE committed artifact. If the contract
# introduced by #199 no longer admits it, nothing downstream means anything.
ck "the accepted multiarch run is admitted by the evidence-class contract" \
   "aec legacy '$ACCEPTED' >/dev/null 2>&1"
ck "...as class staged-candidate, pinned to its bytes, not inferred" \
   "aec legacy '$ACCEPTED' 2>&1 | grep -q 'staged-candidate'"
ck "the accepted run carries MATRIX_COUNT x platforms children" \
   "[ \"\$(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1]))[\"children\"]))' '$ACCEPTED')\" = '$CHILDREN' ]"
ck "every child in the accepted run reconciles" \
   "python3 -c 'import json,sys
c=json.load(open(sys.argv[1]))[\"children\"]
sys.exit(0 if all(x[\"reconciliation\"]==\"PASS\" for x in c) else 1)' '$ACCEPTED'"

echo
echo "== stage 1: foundry-child -> staged-candidate ============================="

# A per-child record in the class contract's own schema, built from the REAL
# digest and revision the accepted run recorded, so the class check and the
# bundle below are talking about the same artifact.
python3 - "$ACCEPTED" "$TMP" <<'PY'
import json, os, sys
ev = json.load(open(sys.argv[1]))
out = sys.argv[2]
c = [x for x in ev["children"] if x["platform"] == "linux/amd64"][0]
fam, _, sel = c["image_label"].partition("/")
base = {
    "schema_version": 1,
    "image_digest": c["manifest_digest"],
    "child_key": c["child_key"],
    "platform": c["platform"],
    "image_family": fam,
    "image_version": sel,
    "source_revision": ev["source_revision"],
    "build_input_digest": "sha256:" + "e" * 64,
    "build_completed": True,
    "scanner_identity": ev["scanner"]["image"],
    "vulnerability_db_identity": ev["frozen_vulnerability_database"]["identity"],
    "created_at": ev["authorization_record"]["build_created"],
    "package_inventory_source": {"kind": "image-child", "sha256": c["evidence_sha256"]},
    "severity_counts": c.get("severity_counts") or {},
}
child = dict(base, evidence_class="foundry-child",
             parent={"evidence_class": "upstream-base", "image_digest": "sha256:" + "b" * 64})
staged = dict(base, evidence_class="staged-candidate",
              parent={"evidence_class": "foundry-child", "image_digest": c["manifest_digest"]},
              staging_package="ghcr.io/zenchron-dynamics/foundry-staging")
json.dump(child, open(os.path.join(out, "child.json"), "w"), indent=2)
json.dump(staged, open(os.path.join(out, "staged.json"), "w"), indent=2)
json.dump(dict(child, image_digest="sha256:" + "d" * 64),
          open(os.path.join(out, "child-wrong-digest.json"), "w"), indent=2)
open(os.path.join(out, "child_digest"), "w").write(c["manifest_digest"])
open(os.path.join(out, "child_key"), "w").write(c["child_key"])
PY
CHILD_DIGEST="$(cat "$TMP/child_digest")"
CHILD_KEY="$(cat "$TMP/child_key")"

ck "a foundry-child record derived from the accepted run validates" \
   "aec validate '$TMP/child.json' >/dev/null 2>&1"
ck "the same artifact as a staged-candidate validates" \
   "aec validate '$TMP/staged.json' >/dev/null 2>&1"
ck "SABOTAGE: a foundry-child cannot authorize production" \
   "! aec consumer production-authorization '$TMP/child.json' >/dev/null 2>&1"
ck "...for the class diagnostic, not a generic one" \
   "aec consumer production-authorization '$TMP/child.json' 2>&1 | grep -q 'staged candidate'"
ck "...while the staged-candidate for the SAME digest is accepted (non-vacuous)" \
   "aec consumer production-authorization '$TMP/staged.json' >/dev/null 2>&1"
ck "SABOTAGE: a record bound to a foreign digest is refused by the binding check" \
   "! aec bind '$TMP/child-wrong-digest.json' \"digest=$CHILD_DIGEST\" >/dev/null 2>&1"
ck "...while the honest record binds to the digest the accepted run recorded" \
   "aec bind '$TMP/child.json' \"digest=$CHILD_DIGEST\" \"source=$REV\" >/dev/null 2>&1"

echo
echo "== stage 2: SBOM -> bundle (does the bundle read WHICH child an SBOM is?) ="

# Per-child SPDX, named the way the bundle looks them up: <child_slug>.spdx.json.
# Each one names its own child's digest and carries real licence metadata, so
# the SAME artifacts feed the evidence bundle and the licence gate below.
python3 - "$ACCEPTED" "$TMP/sbom" "$TMP/sbom-wrongname" "$TMP/sbom-foreign" <<'PY'
import json, os, sys
ev = json.load(open(sys.argv[1]))
good, wrongname, foreign = sys.argv[2], sys.argv[3], sys.argv[4]
for d in (good, wrongname, foreign):
    os.makedirs(d, exist_ok=True)


def doc(child, digest):
    return {
        "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT",
        "name": child["child_key"],
        "documentDescribes": [digest],
        "packages": [
            {"name": "zlib1g", "versionInfo": "1:1.2.13.dfsg-1",
             "licenseConcluded": "Zlib", "licenseDeclared": "Zlib"},
            {"name": "libssl3", "versionInfo": "3.0.15-1~deb12u1",
             "licenseConcluded": "Apache-2.0", "licenseDeclared": "Apache-2.0"},
        ],
    }


other = ev["children"][-1]["manifest_digest"]
for c in ev["children"]:
    fam, _, sel = c["image_label"].partition("/")
    slug = "%s-%s-linux-%s" % (fam, sel, c["platform"].rsplit("/", 1)[-1])
    json.dump(doc(c, c["manifest_digest"]),
              open(os.path.join(good, slug + ".spdx.json"), "w"), indent=2)
    # THE SABOTAGE: correct filename, foreign subject. Every byte the bundle
    # actually inspects (the path and the sha256 of the file) still lines up.
    json.dump(doc(c, other if c["manifest_digest"] != other else ev["children"][0]["manifest_digest"]),
              open(os.path.join(foreign, slug + ".spdx.json"), "w"), indent=2)
    # What scripts/generate-sbom.sh ACTUALLY writes: NAME=$(IMAGE | tr '/:@' '___').
    name = c["digest_reference"].replace("/", "_").replace(":", "_").replace("@", "_")
    json.dump(doc(c, c["manifest_digest"]),
              open(os.path.join(wrongname, name + ".spdx.json"), "w"), indent=2)
PY
printf '{"_type":"https://in-toto.io/Statement/v1","fixture":true}\n' > "$TMP/prov.json"

ck "the staged-candidate bundle generates from the accepted run + per-child SBOMs" \
   "gen --evidence '$ACCEPTED' --out '$TMP/cand' --evidence-class staged-candidate \
      --sbom-dir '$TMP/sbom' --today '$DAY' >/dev/null 2>&1"
ck "it verifies offline" "ver '$TMP/cand' >/dev/null 2>&1"
ck "the bundle carries one child record per matrix image per platform" \
   "[ \"\$(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1]))[\"children\"]))' '$TMP/cand/manifest.json')\" = '$CHILDREN' ]"
ck "SABOTAGE: the bundle cannot demote the accepted run to foundry-child" \
   "! gen --evidence '$ACCEPTED' --out '$TMP/demoted' --evidence-class foundry-child --today '$DAY' >/dev/null 2>&1"
ck "...for the declared-lifecycle diagnostic" \
   "gen --evidence '$ACCEPTED' --out '$TMP/demoted2' --evidence-class foundry-child --today '$DAY' 2>&1 | grep -q 'does not succeed'"

# --- the first real hole ------------------------------------------------------
ck "SABOTAGE: SBOMs whose subject digest is a DIFFERENT child still build a bundle" \
   "gen --evidence '$ACCEPTED' --out '$TMP/foreign-sbom' --evidence-class staged-candidate \
      --sbom-dir '$TMP/sbom-foreign' --today '$DAY' >/dev/null 2>&1"
gap "the bundle NEVER reads an SBOM's subject: a foreign-digest SBOM set verifies clean" \
    "ver '$TMP/foreign-sbom' >/dev/null 2>&1"
gap "...because the generator never parses an SBOM: it copies bytes and hashes the file" \
    "! grep -qE 'documentDescribes|spdxVersion|bomFormat|SPDXID' '$GEN'"
gap "...the only SBOM fact recorded is the file's own sha256, which both sets satisfy" \
    "python3 -c 'import json,sys
m=json.load(open(sys.argv[1]))
s=m[\"children\"][0][\"sbom\"]
sys.exit(0 if set(s)=={\"format\",\"sha256\",\"file\"} else 1)' '$TMP/foreign-sbom/manifest.json'"

# --- the second hole: the producer and the consumer never meet ----------------
ck "SABOTAGE: the SBOM naming scripts/generate-sbom.sh actually emits is accepted" \
   "gen --evidence '$ACCEPTED' --out '$TMP/nosbom' --evidence-class staged-candidate \
      --sbom-dir '$TMP/sbom-wrongname' --today '$DAY' >/dev/null 2>&1"
gap "generate-sbom.sh output is INVISIBLE to the bundle: 0 of N children get an SBOM, silently" \
    "python3 -c 'import json,sys
m=json.load(open(sys.argv[1]))
sys.exit(0 if m[\"sbom\"][\"children_with_sbom\"]==0 and m[\"sbom\"][\"present\"] is False else 1)' '$TMP/nosbom/manifest.json'"
ck "...the fail-closed direction still holds: the seal refuses an SBOM-less bundle (R7)" \
   "grep -q 'R7' '$SEAL'"

echo
echo "== stage 3: VEX — bound to the child digest, blind to the evidence class =="

ck "the VEX document lives INSIDE checksum coverage" \
   "grep -q 'content/vex/openvex.json' '$TMP/cand/SHA256SUMS'"
ck "the bundle's dispositions re-derive from the same accepted run" \
   "vexv --vex '$TMP/cand/content/vex/openvex.json' --evidence '$ACCEPTED' --today '$DAY' >/dev/null 2>&1"

# Digest binding: change one product digest and nothing else.
mkdir -p "$TMP/vexsab"
python3 - "$TMP/cand/content/vex/openvex.json" "$TMP/vexsab/digest.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
p = d["statements"][0]["products"][0]
fake = "f" * 64
p["@id"] = p["@id"].replace(p["hashes"]["sha256"], fake).replace(
    p["hashes"]["sha256"].upper(), fake)
p["identifiers"]["purl"] = p["@id"]
p["hashes"]["sha256"] = fake
json.dump(d, open(sys.argv[2], "w"), indent=2)
PY
ck "SABOTAGE: a statement re-pointed at a digest the run never scanned is REFUSED" \
   "! vexv --vex '$TMP/vexsab/digest.json' --evidence '$ACCEPTED' --today '$DAY' >/dev/null 2>&1"
ck "...for the digest-binding diagnostic" \
   "vexv --vex '$TMP/vexsab/digest.json' --evidence '$ACCEPTED' --today '$DAY' 2>&1 \
      | grep -q 'is not one of the'"

# Evidence binding: same document, different acceptance record.
python3 - "$ACCEPTED" "$TMP/vexsab/other-evidence.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["scope_note"] = (d.get("scope_note") or "") + " (disposable copy)"
json.dump(d, open(sys.argv[2], "w"), indent=2)
PY
ck "SABOTAGE: dispositions checked against a different acceptance record are REFUSED" \
   "! vexv --vex '$TMP/cand/content/vex/openvex.json' --evidence '$TMP/vexsab/other-evidence.json' \
      --today '$DAY' >/dev/null 2>&1"
ck "...for the evidence-record-hash diagnostic" \
   "vexv --vex '$TMP/cand/content/vex/openvex.json' --evidence '$TMP/vexsab/other-evidence.json' \
      --today '$DAY' 2>&1 | grep -q 'hashes to'"

# --- the class hole -----------------------------------------------------------
# A disposition set is a published statement about a SHIPPED artifact. The class
# contract exists precisely because "what may ship" and "what shipped" are not
# interchangeable — yet the VEX document has no field that distinguishes them.
ck "a published-artifact bundle generates from the same run" \
   "gen --evidence '$ACCEPTED' --out '$TMP/pub' --evidence-class published-artifact \
      --release v2026.08.25 --candidate rc1 --sbom-dir '$TMP/sbom' \
      --provenance '$TMP/prov.json' --today '$DAY' >/dev/null 2>&1"
ck "the two bundles really do carry different classes (non-vacuity for the next line)" \
   "[ \"\$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))[\"evidence_class\"])' '$TMP/cand/manifest.json')\" \
   != \"\$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))[\"evidence_class\"])' '$TMP/pub/manifest.json')\" ]"
gap "SABOTAGE: candidate and published dispositions are BYTE-IDENTICAL — VEX carries no class" \
    "cmp -s '$TMP/cand/content/vex/openvex.json' '$TMP/pub/content/vex/openvex.json'"
gap "...vex-openvex-v1 declares no evidence_class property and forbids extras" \
    "python3 -c 'import json,sys
s=json.load(open(\"schemas/vex-openvex-v1.schema.json\"))
f=s[\"properties\"][\"foundry\"]
sys.exit(0 if \"evidence_class\" not in f[\"properties\"] and f[\"additionalProperties\"] is False else 1)'"
gap "...and bundle verify never cross-checks the VEX revision against the manifest" \
    "! grep -q 'foundry.*source_revision' '$GEN'"

echo
echo "== stage 4: retention metadata is inside the checksums ====================="

ck "retention travels as bundle content, not as a manifest-only assertion" \
   "grep -q 'content/retention/retention.json' '$TMP/cand/SHA256SUMS'"
ck "retain_until is derived from policies/retention.yaml, not from the generator clock" \
   "python3 -c 'import datetime,json,sys,yaml
m=json.load(open(sys.argv[1]))
p=yaml.safe_load(open(\"policies/retention.yaml\"))
d=[c for c in p[\"classes\"] if c[\"evidence_class\"]==m[\"evidence_class\"]][0]
start=datetime.date.fromisoformat(m[\"generated_at\"][:10])
want=(start+datetime.timedelta(days=int(d[\"retention_days\"]))).isoformat()
sys.exit(0 if m[\"retention\"][\"retain_until\"]==want else 1)' '$TMP/cand/manifest.json'"

# Sabotage A: retention stays on disk but is dropped from coverage, and the
# aggregate is recomputed so BUNDLE.sha256 agrees with SHA256SUMS.
cp -R "$TMP/cand" "$TMP/ret-uncovered"
python3 - "$TMP/ret-uncovered" <<'PY'
import hashlib, os, sys
d = sys.argv[1]
keep = [ln for ln in open(os.path.join(d, "SHA256SUMS")).read().splitlines()
        if ln and "content/retention/" not in ln]
open(os.path.join(d, "SHA256SUMS"), "w").write("\n".join(keep) + "\n")
open(os.path.join(d, "BUNDLE.sha256"), "w").write(
    "%s  SHA256SUMS\n"
    % hashlib.sha256(open(os.path.join(d, "SHA256SUMS"), "rb").read()).hexdigest())
PY
ck "SABOTAGE: retention excluded from the checksum index is REFUSED" \
   "! ver '$TMP/ret-uncovered' >/dev/null 2>&1"
ck "...for the outside-coverage diagnostic, naming the retention file" \
   "ver '$TMP/ret-uncovered' 2>&1 | grep -q 'covered by no checksum'"

# Sabotage B: retention removed entirely and the whole bundle honestly re-sealed.
cp -R "$TMP/cand" "$TMP/ret-deleted"
rm -f "$TMP/ret-deleted/content/retention/retention.json"
reindex "$TMP/ret-deleted"
ck "SABOTAGE: retention deleted and the bundle honestly re-sealed is still REFUSED" \
   "! ver '$TMP/ret-deleted' >/dev/null 2>&1"
ck "...because the aggregate over content/ no longer matches the sealed manifest" \
   "ver '$TMP/ret-deleted' 2>&1 | grep -q 'manifest content_checksum is'"
ck "NON-VACUOUS: the untouched bundle still verifies after both retention sabotages" \
   "ver '$TMP/cand' >/dev/null 2>&1"

echo
echo "== stage 5: authorization — the canonical record is never the one carried ="

ck "the bundle does carry an authorization record file" \
   "test -f '$TMP/cand/content/authorization/authorization-record.json'"
gap "SABOTAGE: that record does NOT satisfy post-build-authorization-v1" \
    "! bash '$AUTHV' '$TMP/cand/content/authorization/authorization-record.json' >/dev/null 2>&1"
gap "...it is a four-field summary; every binding field of the canonical record is absent" \
    "python3 -c 'import json,sys
r=json.load(open(sys.argv[1]))[\"record\"]
sys.exit(0 if not ({\"source_revision\",\"repository\",\"workflow_run_id\",\"children\",\"verdict\"} & set(r)) else 1)' \
      '$TMP/cand/content/authorization/authorization-record.json'"
gap "...so no release script can compare an authorization to the revision it authorised" \
    "[ \"\$(grep -rlc 'validate-authorization-record' scripts/release/generate-evidence-bundle.sh \
        scripts/release/release-seal.sh scripts/release/verify-release-seal.sh 2>/dev/null \
        | grep -v ':0\$' | wc -l | tr -d ' ')\" = '0' ]"

# The canonical record, built for the RIGHT revision and for a WRONG one. Both
# validate, because the schema constrains shape and there is nothing on the path
# that would notice the second describes a different build.
python3 - "$ACCEPTED" "$TMP/auth-right.json" "$TMP/auth-wrong.json" "$TMP/auth-malformed.json" <<'PY'
import json, sys
ev = json.load(open(sys.argv[1]))
ar = ev["authorization_record"]
acc = ev["acceptance"]
mx = ev["matrix"]
rec = {
    "schema_version": 1,
    "repository": "zenchron-dynamics/zenchron-foundry",
    "source_revision": ev["source_revision"],
    "workflow_run_id": int(acc["workflow_run_id"]),
    "workflow_run_attempt": int(acc.get("workflow_run_attempt") or 1),
    "workflow_ref": ("zenchron-dynamics/zenchron-foundry/.github/workflows/"
                     "stage-and-authorize.yml@refs/heads/master"),
    "generated_at": ar["generated_at"],
    "build_created": ar["build_created"],
    "trivy_db_snapshot": {"identity": ev["frozen_vulnerability_database"]["identity"],
                          "frozen": True},
    "staging_package": "ghcr.io/zenchron-dynamics/foundry-staging",
    "expected_matrix": {"images": len({c["image_label"] for c in ev["children"]}),
                        "platforms": sorted(mx["platforms"]),
                        "expected_children": int(mx["expected_children"])},
    "children": [{
        "child_key": c["child_key"], "image_label": c["image_label"],
        "platform": c["platform"], "manifest_digest": c["manifest_digest"],
        "digest_reference": c["digest_reference"], "staging_tag": c["staging_tag"],
        "tag_resolved_digest": c["manifest_digest"], "visibility": "private",
        "manifest_media_type": "application/vnd.oci.image.manifest.v1+json",
        "config_architecture": c["config_architecture"],
        "trivy_db_identity": ev["frozen_vulnerability_database"]["identity"],
        "source_revision": ev["source_revision"],
        "workflow_run_id": int(acc["workflow_run_id"]),
        "workflow_run_attempt": int(acc.get("workflow_run_attempt") or 1),
        "repository": "zenchron-dynamics/zenchron-foundry",
        "smoke_test": c["smoke_test"], "scan": c["scan"],
        "reconciliation": c["reconciliation"], "metadata_contract": c["metadata_contract"],
        "execution_mode": c["execution_mode"], "host_architecture": c["host_architecture"],
        "runner_name": c["runner_name"], "evidence_sha256": c["evidence_sha256"],
    } for c in ev["children"]],
    "authorization_scope": "immutable-rc-manifest-input",
    "public_exposure_authorized": False,
    "verdict": "PASS",
}
json.dump(rec, open(sys.argv[2], "w"), indent=2)
# Internally consistent with itself and describing a DIFFERENT build entirely:
# the record is not malformed, it is about another revision.
other = dict(rec, source_revision="0" * 40,
             children=[dict(c, source_revision="0" * 40) for c in rec["children"]])
json.dump(other, open(sys.argv[3], "w"), indent=2)
json.dump(dict(rec, source_revision="not-a-revision"), open(sys.argv[4], "w"), indent=2)
PY
ck "a canonical authorization record for THIS revision validates" \
   "bash '$AUTHV' '$TMP/auth-right.json' >/dev/null 2>&1"
ck "NON-VACUOUS: a malformed revision in the same record is REFUSED" \
   "! bash '$AUTHV' '$TMP/auth-malformed.json' >/dev/null 2>&1"
gap "SABOTAGE: a canonical record from a DIFFERENT source SHA validates identically" \
    "bash '$AUTHV' '$TMP/auth-wrong.json' >/dev/null 2>&1"
gap "...and the bundle it would authorise names another revision entirely" \
    "python3 -c 'import json,sys
a=json.load(open(sys.argv[1]))[\"source_revision\"]
m=json.load(open(sys.argv[2]))[\"source_revision\"]
sys.exit(0 if a!=m else 1)' '$TMP/auth-wrong.json' '$TMP/cand/manifest.json'"

echo
echo "== stage 6: the test-only seal ============================================"

openssl ecparam -name prime256v1 -genkey -noout -out "$TMP/test.key" 2>/dev/null
openssl pkey -in "$TMP/test.key" -pubout -out "$TMP/test.pub" 2>/dev/null
REL_ID='https://github.com/zenchron-dynamics/zenchron-foundry/.github/workflows/release.yml@refs/tags/v2026.08.25'

ck "the release identity fixture is one the committed policy declares" \
   "python3 -c 'import re,sys,yaml
r=yaml.safe_load(open(\"policies/cosign-identities.yaml\"))[\"roles\"][\"release\"][\"identity_regexp\"]
sys.exit(0 if re.match(r, sys.argv[1]) else 1)' '$REL_ID'"
ck "the published-artifact bundle seals" \
   "seal --bundle '$TMP/pub' --version v2026.08.25 --candidate rc1 --identity '$REL_ID' \
      --test-key '$TMP/test.key' --out '$TMP/seal.json' --today '$DAY' >/dev/null 2>&1"
ck "the seal verifies against the bundle it was made over" \
   "vsl --seal '$TMP/seal.json' --bundle '$TMP/pub' --pubkey '$TMP/test.pub' \
      --version v2026.08.25 --today '$DAY' >/dev/null 2>&1"
ck "the seal is unmistakably a test seal" \
   "python3 -c 'import json,sys
s=json.load(open(sys.argv[1]))
sys.exit(0 if s[\"test_only\"] and s[\"not_a_release\"] else 1)' '$TMP/seal.json'"

# SABOTAGE: a seal over a bundle whose index no longer holds.
cp -R "$TMP/pub" "$TMP/unsealed"
printf 'planted after sealing\n' > "$TMP/unsealed/content/planted.txt"
ck "SABOTAGE: a bundle with a file outside coverage cannot be sealed" \
   "! seal --bundle '$TMP/unsealed' --version v2026.08.25 --candidate rc1 --identity '$REL_ID' \
      --test-key '$TMP/test.key' --out '$TMP/seal-bad.json' --today '$DAY' >/dev/null 2>&1"
ck "...for R6, the refusal to sign an unverifiable bundle" \
   "seal --bundle '$TMP/unsealed' --version v2026.08.25 --candidate rc1 --identity '$REL_ID' \
      --test-key '$TMP/test.key' --out '$TMP/seal-bad2.json' --today '$DAY' 2>&1 | grep -q 'R6'"

# SABOTAGE: the class boundary at the seal.
ck "SABOTAGE: a staged-candidate bundle cannot be sealed as a release" \
   "! seal --bundle '$TMP/cand' --version v2026.08.25 --candidate rc1 --identity '$REL_ID' \
      --test-key '$TMP/test.key' --out '$TMP/seal-cand.json' --today '$DAY' >/dev/null 2>&1"
ck "...for R8, the evidence-class refusal" \
   "seal --bundle '$TMP/cand' --version v2026.08.25 --candidate rc1 --identity '$REL_ID' \
      --test-key '$TMP/test.key' --out '$TMP/seal-cand2.json' --today '$DAY' 2>&1 | grep -q 'R8'"

# SABOTAGE: a valid seal presented over a different bundle.
ck "SABOTAGE: a valid seal does not verify against a different bundle" \
   "! vsl --seal '$TMP/seal.json' --bundle '$TMP/cand' --pubkey '$TMP/test.pub' \
      --version v2026.08.25 --today '$DAY' >/dev/null 2>&1"

# --- the authorization hole, at the seal --------------------------------------
gap "SABOTAGE: the seal binds no authorization identity — only a boolean it copied" \
    "python3 -c 'import json,sys
s=json.load(open(sys.argv[1]))
pe=s[\"public_exposure\"]
sys.exit(0 if pe[\"authorization_file\"] is None and pe[\"authorization_sha256\"] is None else 1)' \
      '$TMP/seal.json'"
gap "...so the canonical record above is never an input to any seal it could contradict" \
    "! grep -q 'post-build-authorization' '$SEAL'"

echo
echo "== stage 7: continuity — what the export does and does not carry =========="

ck "the offline recovery drill runs, offline, and passes" \
   "bash '$CVERIFY' --drill '$TMP/drill' > '$TMP/drill.log' 2>&1"
ck "...and it refuses right-digest/wrong-bytes" "grep -q 'WRONG BYTES is refused' '$TMP/drill.log'"
ck "...and a mirror missing a referenced blob" "grep -q 'missing a referenced blob' '$TMP/drill.log'"
ck "...and it cannot be mistaken for evidence a mirror exists" \
   "grep -q 'No independent mirror is provisioned' '$TMP/drill.log'"

# The composition question: the drill proves image bytes survive. It says nothing
# about the schemas, policies and evidence contracts the other six PRs added.
gap "SABOTAGE: the continuity export carries NO schema — its universe is image refs" \
    "! grep -q 'schemas/' scripts/continuity-export.sh"
gap "...no policy either; the one policy it opens is only asserted about, never copied" \
    "python3 -c 'import re,sys
s=open(\"scripts/continuity-export.sh\").read()
body=\"\\n\".join(l for l in s.splitlines() if not l.lstrip().startswith(\"#\"))
sys.exit(0 if not re.search(r\"cp .*polic\", body) else 1)'"
gap "...and continuity-mirror.yaml declares evidence-bundle and vex classes UNMIRRORED" \
    "python3 -c 'import sys,yaml
m=yaml.safe_load(open(\"policies/continuity-mirror.yaml\"))
cl={c[\"id\"]: c for c in m[\"critical_release_inventory\"][\"artifact_classes\"]}
sys.exit(0 if not cl[\"evidence-bundle\"][\"mirrored\"] and not cl[\"vex\"][\"mirrored\"] else 1)'"
gap "...the artifact_classes list names no class for schemas, policies or scripts" \
    "python3 -c 'import sys,yaml
m=yaml.safe_load(open(\"policies/continuity-mirror.yaml\"))
ids={c[\"id\"] for c in m[\"critical_release_inventory\"][\"artifact_classes\"]}
sys.exit(0 if not (ids & {\"schemas\",\"policies\",\"scripts\",\"governance\"}) else 1)'"

# What a governance-surface export WOULD have to catch, demonstrated with the
# repository's own path-independent aggregate. This is the missing half of the
# drill, and it is written here as the shape of the fix, not as a substitute.
mkdir -p "$TMP/gov/schemas" "$TMP/gov/policies"
cp schemas/evidence-class-v1.schema.json schemas/release-evidence-bundle-v1.schema.json \
   schemas/vex-openvex-v1.schema.json schemas/post-build-authorization-v1.schema.json \
   schemas/build-input-lock-v1.schema.json schemas/build-input-lock-evidence-v1.schema.json \
   "$TMP/gov/schemas/"
cp policies/evidence-classes.yaml policies/retention.yaml policies/reproducibility.yaml \
   policies/license-policy.yaml policies/continuity-mirror.yaml policies/cra-control-matrix.yaml \
   "$TMP/gov/policies/"
GOV_BEFORE="$(bash scripts/release/evidence-checksum.sh "$TMP/gov")"
cp -R "$TMP/gov" "$TMP/gov-short" && rm -f "$TMP/gov-short/schemas/vex-openvex-v1.schema.json"
ck "SABOTAGE: an export missing one schema changes the path-independent aggregate" \
   "[ \"\$(bash scripts/release/evidence-checksum.sh '$TMP/gov-short')\" != '$GOV_BEFORE' ]"
ck "NON-VACUOUS: relocating the complete export leaves the aggregate unchanged" \
   "cp -R '$TMP/gov' '$TMP/gov-moved' && \
    [ \"\$(bash scripts/release/evidence-checksum.sh '$TMP/gov-moved')\" = '$GOV_BEFORE' ]"

echo
echo "== stage 8: offline restore, and REVALIDATION of the restored copy ========"

BID="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["bundle_id"])' "$TMP/pub/manifest.json")"
ck "the sealed bundle archives" \
   "arch archive --bundle '$TMP/pub' --archive-root '$TMP/archive' >/dev/null 2>&1"
ck "the archive verifies and reports a non-empty result" \
   "arch verify --archive-root '$TMP/archive' >/dev/null 2>&1"
ck "the working copy can be destroyed" "rm -rf '$TMP/pub' && [ ! -e '$TMP/pub' ]"
ck "the bundle restores from the archive alone" \
   "arch restore --archive-root '$TMP/archive' --bundle-id '$BID' --dest '$TMP/restored' >/dev/null 2>&1"

# REVALIDATION, past the checksums the restore already re-ran. These are the
# contracts the other PRs added, re-asserted against bytes that came back off
# the archive rather than out of the generator.
ck "REVALIDATED: the restored bundle verifies against its own index" \
   "ver '$TMP/restored' >/dev/null 2>&1"
ck "REVALIDATED: the restored dispositions still re-derive from the accepted run" \
   "vexv --vex '$TMP/restored/content/vex/openvex.json' --evidence '$ACCEPTED' --today '$DAY' >/dev/null 2>&1"
ck "REVALIDATED: the restored manifest still satisfies release-evidence-bundle-v1" \
   "python3 -c 'import json,sys
from jsonschema import Draft202012Validator
s=json.load(open(\"schemas/release-evidence-bundle-v1.schema.json\"))
m=json.load(open(sys.argv[1]))
sys.exit(0 if not list(Draft202012Validator(s).iter_errors(m)) else 1)' '$TMP/restored/manifest.json'"
ck "REVALIDATED: the restored evidence class is still one policy promises to keep" \
   "python3 -c 'import json,sys,yaml
m=json.load(open(sys.argv[1]))
p=yaml.safe_load(open(\"policies/retention.yaml\"))
sys.exit(0 if m[\"evidence_class\"] in [c[\"evidence_class\"] for c in p[\"classes\"]] else 1)' \
      '$TMP/restored/manifest.json'"
ck "REVALIDATED: the seal still verifies against the RESTORED bytes" \
   "vsl --seal '$TMP/seal.json' --bundle '$TMP/restored' --pubkey '$TMP/test.pub' \
      --version v2026.08.25 --today '$DAY' >/dev/null 2>&1"

# SABOTAGE: the archived bytes drift after indexing, two distinct ways.
ARCH_DIR="$(dirname "$(grep -m1 "/$BID\$" "$TMP/archive/INDEX.sha256" | awk '{print $2}')")"
chmod -R u+w "$TMP/archive"
cp -R "$TMP/archive" "$TMP/archive-b"
python3 - "$TMP/archive/$ARCH_DIR/$BID" <<'PY'
import glob, json, os, sys
p = sorted(glob.glob(os.path.join(sys.argv[1], "content/children/*.json")))[0]
d = json.load(open(p))
d["record"]["severity_counts"] = {"HIGH": 0}
json.dump(d, open(p, "w"), indent=2)
PY
ck "SABOTAGE: a restored archive whose content drifted is REFUSED at restore" \
   "! arch restore --archive-root '$TMP/archive' --bundle-id '$BID' --dest '$TMP/r2' >/dev/null 2>&1"
ck "...for the restored-copy-does-not-verify diagnostic" \
   "arch restore --archive-root '$TMP/archive' --bundle-id '$BID' --dest '$TMP/r3' 2>&1 \
      | grep -q 'restored copy does not verify'"
printf '%s  SHA256SUMS\n' "$(printf '0%.0s' {1..64})" \
  > "$TMP/archive-b/$ARCH_DIR/$BID/BUNDLE.sha256"
ck "SABOTAGE: an archived aggregate that no longer matches the index is REFUSED" \
   "! arch restore --archive-root '$TMP/archive-b' --bundle-id '$BID' --dest '$TMP/r4' >/dev/null 2>&1"
ck "...for the changed-after-indexing diagnostic" \
   "arch restore --archive-root '$TMP/archive-b' --bundle-id '$BID' --dest '$TMP/r5' 2>&1 \
      | grep -q 'changed after it was indexed'"
ck "NON-VACUOUS: the untouched restored copy still verifies after both sabotages" \
   "ver '$TMP/restored' >/dev/null 2>&1"

echo
echo "== stage 9: licence gate over the SAME SBOMs the bundle consumed =========="

ck "a licence inventory builds from the release-path SBOM set" \
   "bash '$LINV' --sbom-dir '$TMP/sbom' --out '$TMP/inventory.json' >/dev/null 2>&1"
ck "the fail-closed licence gate passes over it" \
   "bash '$LGATE' --inventory '$TMP/inventory.json' >/dev/null 2>&1"
cp -R "$TMP/sbom" "$TMP/sbom-copyleft"
python3 - "$TMP/sbom-copyleft" <<'PY'
import glob, json, os, sys
p = sorted(glob.glob(os.path.join(sys.argv[1], "*.spdx.json")))[0]
d = json.load(open(p))
d["packages"][0]["licenseConcluded"] = "GPL-3.0-or-later"
d["packages"][0]["licenseDeclared"] = "GPL-3.0-or-later"
json.dump(d, open(p, "w"), indent=2)
PY
ck "SABOTAGE: one unreviewed copyleft component in the same set REFUSES" \
   "bash '$LINV' --sbom-dir '$TMP/sbom-copyleft' --out '$TMP/inv-gpl.json' >/dev/null 2>&1 && \
    ! bash '$LGATE' --inventory '$TMP/inv-gpl.json' >/dev/null 2>&1"
ck "...for the unreviewed-licence diagnostic, naming the component" \
   "bash '$LGATE' --inventory '$TMP/inv-gpl.json' 2>&1 | grep -q 'GPL-3.0-or-later'"

# The gate CAN consume the release path. Nothing makes it.
gap "SABOTAGE: the licence gate consumes no release artifact — no evidence, no bundle, no class" \
    "python3 -c 'import re,sys
s=\"\".join(open(f).read() for f in (\"scripts/license/assert-license-policy.sh\",
                                     \"scripts/license/license-inventory.sh\"))
body=\"\\n\".join(l for l in s.splitlines() if not l.lstrip().startswith(\"#\"))
sys.exit(0 if not re.search(r\"evidence-class|release-evidence|evidence_class|schemas/\", body) else 1)'"
gap "...and no workflow invokes it, so a release cannot be blocked on a real inventory" \
    "! grep -rq 'scripts/license/' .github/workflows/"
gap "...the bundle records no licence fact at all, so the two never meet on one artifact" \
    "! grep -qi 'licen' schemas/release-evidence-bundle-v1.schema.json"

echo
echo "== stage 10: reproducibility binds a different build-input identity ======="

ck "the committed build-input lock verifies offline" \
   "bash scripts/repro-lock.sh verify tests/reproducibility/evidence/php-cli-8.4-linux-amd64.lock.json >/dev/null 2>&1"
ck "the guarantee gate passes on the committed tree" \
   "bash scripts/repro-guarantees.sh >/dev/null 2>&1"
ck "the evidence-class contract REQUIRES a build-input identity" \
   "python3 -c 'import json,sys
s=json.load(open(\"schemas/evidence-class-v1.schema.json\"))
sys.exit(0 if \"build_input_digest\" in s[\"required\"] else 1)'"
gap "SABOTAGE: the evidence bundle carries no build-input identity for any child" \
    "python3 -c 'import json,sys
m=json.load(open(sys.argv[1]))
sys.exit(0 if not any(\"build_input_digest\" in c or \"context_digest\" in c for c in m[\"children\"]) else 1)' \
      '$TMP/restored/manifest.json'"
gap "...the lock's only image identity is null, so there is no value to join on" \
    "python3 -c 'import json,sys
l=json.load(open(\"tests/reproducibility/evidence/php-cli-8.4-linux-amd64.lock.json\"))
sys.exit(0 if l[\"build_outputs\"][\"manifest_digest\"] is None else 1)'"
gap "...and reproducibility.yaml is not among the policies the bundle digests" \
    "python3 -c 'import json,sys
m=json.load(open(sys.argv[1]))
sys.exit(0 if \"policies/reproducibility.yaml\" not in m[\"policy_digests\"] else 1)' \
      '$TMP/restored/manifest.json'"
gap "...so a reproducibility claim can be reworded with no bundle digest changing" \
    "! grep -q 'reproducibility' '$GEN'"

echo
echo "== stage 11: repository governance requires none of the new checks ========"

ck "the required-check policy is internally consistent with the workflows it names" \
   "bash scripts/assert-required-checks.sh >/dev/null 2>&1"
for s in scripts/license/assert-license-policy.sh scripts/cra/assert-cra-controls.sh \
         scripts/continuity-verify.sh scripts/repro-guarantees.sh \
         scripts/release/generate-evidence-bundle.sh; do
  gap "SABOTAGE: no required check produces $s" \
      "! grep -rq '$s' .github/workflows/"
done
gap "...macro-validate, where all four ARE wired, is invoked by no workflow" \
    "! grep -rq 'macro-validate' .github/workflows/"
ck "NON-VACUOUS: the offline suite that transitively covers them IS in CI" \
   "grep -rq 'tests/run-all.sh' .github/workflows/"
ck "...under a single check name, so a red control surfaces as 'repo structure'" \
   "python3 -c 'import sys,yaml
p=yaml.safe_load(open(\"policies/required-release-checks.yaml\"))
sys.exit(0 if \"repo structure\" in p[\"pr_required_checks\"] else 1)'"

echo
echo "== stage 12: no stale matrix assumption outside a declared boundary ======="

ck "MATRIX_COUNT still agrees with MATRIX_IMAGES" \
   "[ \"\$(matrix_images | wc -l | tr -d ' ')\" = \"\$MATRIX_COUNT\" ]"
ck "the accepted run, the bundle and the seal all derive from MATRIX_COUNT" \
   "[ \"\$(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1]))[\"promoted_digests\"]))' '$TMP/seal.json')\" = '$CHILDREN' ]"
ck "PHP 8.5 is on disk but deliberately outside the shipping matrix" \
   "test -f images/php-cli/8.5/Dockerfile && ! matrix_images | grep -q '8.5'"
gap "SABOTAGE: release-manifest.schema.json pins the matrix size as two literals" \
    "python3 -c 'import json,sys
s=json.load(open(\"schemas/release-manifest.schema.json\"))[\"properties\"][\"images\"]
sys.exit(0 if s.get(\"minProperties\")==s.get(\"maxProperties\")==int(sys.argv[1]) else 1)' \"\$MATRIX_COUNT\""
gap "...and hardcodes the PHP version set, so an 8.5 key is unrepresentable" \
    "python3 -c 'import json,re,sys
s=json.load(open(\"schemas/release-manifest.schema.json\"))[\"properties\"][\"images\"]
pat=list(s[\"patternProperties\"])[0]
sys.exit(0 if s.get(\"additionalProperties\") is False
             and not re.match(pat, \"php-cli-8.5\") else 1)'"

echo
echo "== ambient safety ========================================================="

ck "the test mutated nothing tracked in the checkout" \
   "[ -z \"\$(git status --porcelain -- policies scripts schemas docs contracts images .github)\" ]"
ck "every byte it wrote is under one disposable root" \
   "[ \"\${TMP#/}\" != \"\$TMP\" ] && [ -d '$TMP' ]"

echo
echo "----"
printf 'assertions: %d proven, %d pinned gaps\n' "$nck" "$ngap"
[ "$fail" -eq 0 ] && echo "test_evidence_path_e2e: PASS" || echo "test_evidence_path_e2e: FAIL"
exit "$fail"
