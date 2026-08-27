#!/usr/bin/env bash
# shellcheck disable=SC2034  # assertion locals are consumed inside ck()/gap() eval strings
# =============================================================================
# tests/integration/test_evidence_path_e2e.sh
# -----------------------------------------------------------------------------
# ONE buildless path through everything that merged as #199 #200 #201 #202 #205
# #206 #207, flowing:
#
#   foundry-child evidence -> staged candidate -> canonical authorization
#     -> SBOM -> VEX -> evidence bundle -> test-only seal -> continuity export
#     -> offline restoration -> checksum/schema revalidation
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
# checked, because everything fails for a checksum mismatch eventually. And
# every sabotage is paired with a NON-VACUOUS line proving the identical path
# succeeds once the sabotage is removed.
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
# THIS FILE ONCE REPORTED 81 PROVEN ASSERTIONS AND 33 PINNED GAPS. Every one of
# those 33 has been dispositioned and none remains pinned. Where the behaviour
# was INTENTIONALLY UNSUPPORTED — no independent mirror exists, so no artifact
# class may claim to be mirrored; PHP 8.5 does not build, so it must stay
# unrepresentable in a release manifest; a reproducibility lock emitted from a
# locally built image names no shipped digest — the shortfall is now an EXPLICIT
# REFUSAL with documentation rather than a silent absence, and this file asserts
# the refusal fires.
#
# THE TWELVE REQUIRED SABOTAGES and where each is exercised:
#
#   missing source revision ................. stage 2  (A-S1)
#   schema-invalid authorization ............ stage 2  (A-S2)
#   missing SBOM ............................ stage 3  (B-S3)
#   incorrect SBOM filename ................. stage 3  (B-S1)
#   SBOM from another digest ................ stage 3  (B-S2, B-S5)
#   missing VEX disposition ................. stage 4  (V-S3)
#   expired governance ...................... stage 6  (S-S4)
#   changed bundle content after checksum ... stage 5  (R-S1, R-S2) + stage 6 (S-S2)
#   incomplete retention metadata ........... stage 5  (R-S1, R-S3)
#   experimental PHP 8.5 in a production bundle  stage 12 (M-S1..M-S3)
#   QEMU evidence presented as native arm64 . stage 6  (S-S5)
#   continuity restoration missing an artifact  stage 7  (C-S1) + stage 8 (X-S1)
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
# refusal. It also carries MATRIX_COUNT, child_key() and sbom_filename(), which
# is why it is sourced rather than reimplemented: a second identity derivation is
# the defect the evidence-class contract exists to prevent, and the defect that
# made a complete SBOM directory read as sbom.present=false.
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
CEXPORT=scripts/continuity-export.sh
MKAUTH=tests/lib/make_authorization_fixture.py
MKNATIVE=tests/lib/make_native_arm64_fixture.py
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
if [ ! -f "$MKAUTH" ]; then
  echo "SKIP - authorization fixture builder absent"; echo "test_evidence_path_e2e: PASS"; exit 0
fi
if [ ! -f "$MKNATIVE" ]; then
  echo "SKIP - native fixture builder absent"; echo "test_evidence_path_e2e: PASS"; exit 0
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
cexp() { ( bash "$CEXPORT" "$@" ); }

# Capture a refusal's combined output for a diagnostic assertion. A here-string,
# NOT a pipe: `cmd | grep -q X` makes grep exit on the first match, the producer
# take SIGPIPE, and pipefail report 141 — intermittently, which is a green run
# that proves nothing.
says() { # says <fragment> <command...>
  local want="$1"; shift
  grep -q -- "$want" <<<"$( "$@" 2>&1 )"
}

# Re-seal a bundle's index so a sabotage fails for the rule under test rather
# than for the checksum rule that would mask it. The path-independent aggregate
# is recomputed too, so manifest.checksums.content_checksum agrees. This is the
# attacker's best case, which is what makes the surviving refusals meaningful.
reindex() {
  local cs; cs="$(bash scripts/release/evidence-checksum.sh "$1/content")" || return 1
  python3 - "$1" "$cs" <<'PY'
import hashlib, json, os, sys
d, cs = sys.argv[1], sys.argv[2]
mp = os.path.join(d, "manifest.json")
if os.path.exists(mp):
    m = json.load(open(mp))
    files = []
    for dirpath, _dirs, names in os.walk(os.path.join(d, "content")):
        for n in names:
            ap = os.path.join(dirpath, n)
            files.append({"path": os.path.relpath(ap, d),
                          "sha256": hashlib.sha256(open(ap, "rb").read()).hexdigest()})
    files.sort(key=lambda f: f["path"])
    m["files"] = files
    m["checksums"]["content_checksum"] = cs
    json.dump(m, open(mp, "w"), indent=2)
lines = []
for dirpath, _dirs, names in os.walk(d):
    for n in names:
        ap = os.path.join(dirpath, n)
        rel = os.path.relpath(ap, d)
        if rel in ("SHA256SUMS", "BUNDLE.sha256"):
            continue
        lines.append("%s  %s" % (hashlib.sha256(open(ap, "rb").read()).hexdigest(), rel))
lines.sort(key=lambda s: s.split("  ", 1)[1])
mn = [l for l in lines if l.endswith("  manifest.json")]
rest = [l for l in lines if not l.endswith("  manifest.json")]
open(os.path.join(d, "SHA256SUMS"), "w").write("\n".join(mn + rest) + "\n")
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
   "says 'staged-candidate' aec legacy '$ACCEPTED'"
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
   "says 'staged candidate' aec consumer production-authorization '$TMP/child.json'"
ck "...while the staged-candidate for the SAME digest is accepted (non-vacuous)" \
   "aec consumer production-authorization '$TMP/staged.json' >/dev/null 2>&1"
ck "SABOTAGE: a record bound to a foreign digest is refused by the binding check" \
   "! aec bind '$TMP/child-wrong-digest.json' \"digest=$CHILD_DIGEST\" >/dev/null 2>&1"
ck "...while the honest record binds to the digest the accepted run recorded" \
   "aec bind '$TMP/child.json' \"digest=$CHILD_DIGEST\" \"source=$REV\" >/dev/null 2>&1"

echo
echo "== stage 2: the CANONICAL authorization record ============================"

# WHAT THIS STAGE USED TO PIN. The bundle wrote
# content/authorization/authorization-record.json — a name that reads as the
# canonical post-build authorization — holding a four-field summary that failed
# post-build-authorization-v1 on all FIFTEEN of its required properties and
# carried no source_revision at all. A wrong-SHA authorization was therefore
# undetectable by construction, and no release script ever called the shipped
# validator.
#
# THE DECISION, made from the code: the bundle IS meant to consume the canonical
# record. The generator's own header names "which authorization" among the facts
# that must survive artifact expiry; it wrote the file under the canonical name;
# validate-authorization-record.sh ships as a RUNTIME validator that nothing
# consumed; and release-seal.sh already declared authorization_file /
# authorization_sha256 slots that were permanently null. So the canonical record
# is now an INPUT, not a lookalike rebuilt from parts.
#
# The fixture is reconstructed offline from the accepted evidence because the
# run's own record was a 30-day workflow artifact and has expired — which is the
# exact retention failure the evidence bundle exists for. The builder lives under
# tests/ deliberately: a tool in scripts/ that derived a canonical-looking
# authorization from any acceptance record would be a bypass of the gate rather
# than a fixture generator.
python3 "$MKAUTH" "$ACCEPTED" "$TMP/auth-right.json"
python3 "$MKAUTH" "$ACCEPTED" "$TMP/auth-wrong.json" --revision "$(printf '0%.0s' {1..40})"
python3 "$MKAUTH" "$ACCEPTED" "$TMP/auth-malformed.json" --malformed-revision
python3 "$MKAUTH" "$ACCEPTED" "$TMP/auth-norev.json" --drop-source-revision
python3 "$MKAUTH" "$ACCEPTED" "$TMP/auth-badschema.json" --schema-invalid
python3 "$MKAUTH" "$ACCEPTED" "$TMP/auth-short.json" --drop-child 0
python3 "$MKAUTH" "$ACCEPTED" "$TMP/auth-extra.json" --extra-child
python3 "$MKAUTH" "$ACCEPTED" "$TMP/auth-fail.json" --verdict FAIL
python3 "$MKAUTH" "$ACCEPTED" "$TMP/auth-otherdb.json" --db-identity 'v2+updated:1999-01-01T00:00:00Z'
python3 "$MKAUTH" "$ACCEPTED" "$TMP/auth-badsha.json" --evidence-sha "$(printf 'a%.0s' {1..64})"
# THE #111 BOUNDARY, THREADED THROUGH THE WHOLE PATH.
# policies/native-arch-requirements.yaml now sets require_native_arm64: true and
# the seal enforces it, so the REAL accepted record — whose ten linux/arm64
# children ran under QEMU — can no longer be sealed as a release. That is
# asserted directly at S-S5. Everything else in stage 6 needs a bundle that
# WOULD otherwise seal, or R5/R6/R7/R8/R13 quietly start passing for the
# native-architecture reason instead of their own.
python3 "$MKNATIVE" "$ACCEPTED" "$TMP/ev-native.json" >/dev/null
ACCEPTED_NATIVE="$TMP/ev-native.json"
python3 "$MKAUTH" "$ACCEPTED_NATIVE" "$TMP/auth-native.json"

ck "a canonical authorization record for THIS revision validates against v1" \
   "bash '$AUTHV' '$TMP/auth-right.json' >/dev/null 2>&1"
ck "...and it really does carry every required property of the canonical schema" \
   "python3 -c 'import json,sys
req=json.load(open(\"schemas/post-build-authorization-v1.schema.json\"))[\"required\"]
r=json.load(open(sys.argv[1]))
missing=[k for k in req if k not in r]
sys.exit(0 if not missing and len(req)==15 else 1)' '$TMP/auth-right.json'"
ck "NON-VACUOUS: a malformed revision in the same record is REFUSED by the schema" \
   "! bash '$AUTHV' '$TMP/auth-malformed.json' >/dev/null 2>&1"

# --- the bundle CONSUMES it -----------------------------------------------
ck "the bundle refuses to generate with no authorization DECISION at all" \
   "! gen --evidence '$ACCEPTED' --out '$TMP/noauth' --evidence-class staged-candidate \
       --today '$DAY' >/dev/null 2>&1"
ck "...saying an unauthorised bundle records a build, not a decision" \
   "says 'records a build, not a decision' \
      gen --evidence '$ACCEPTED' --out '$TMP/noauth2' --evidence-class staged-candidate --today '$DAY'"
ck "a bundle generated WITH the canonical record carries it verbatim" \
   "gen --evidence '$ACCEPTED' --out '$TMP/auth-bundle' --evidence-class staged-candidate \
       --authorization '$TMP/auth-right.json' --today '$DAY' >/dev/null 2>&1 \
    && cmp -s '$TMP/auth-right.json' '$TMP/auth-bundle/content/authorization/post-build-authorization.json'"
ck "...it satisfies post-build-authorization-v1 INSIDE the bundle" \
   "bash '$AUTHV' '$TMP/auth-bundle/content/authorization/post-build-authorization.json' >/dev/null 2>&1"
ck "...and it is covered by the bundle's own checksum index" \
   "grep -q 'content/authorization/post-build-authorization.json' '$TMP/auth-bundle/SHA256SUMS'"
ck "the manifest binds the revision, run, children, platforms, database and verdict" \
   "python3 -c 'import json,sys
m=json.load(open(sys.argv[1]))
a=m[\"authorization\"]
b=a[\"record_binding\"]
sys.exit(0 if a[\"record_present\"] and b[\"source_revision\"]==m[\"source_revision\"]
             and b[\"authorized_children\"]==len(m[\"children\"])
             and b[\"platforms\"]==m[\"matrix\"][\"platforms\"]
             and b[\"trivy_db_identity\"]==m[\"vulnerability_database\"][\"identity\"]
             and b[\"workflow_run_id\"]==m[\"acceptance\"][\"workflow_run_id\"]
             and b[\"verdict\"]==\"PASS\" else 1)' '$TMP/auth-bundle/manifest.json'"
ck "the four-field summary is no longer NAMED as a post-build authorization" \
   "[ ! -e '$TMP/auth-bundle/content/authorization/authorization-record.json' ] \
    && python3 -c 'import json,sys
d=json.load(open(sys.argv[1]))
sys.exit(0 if d[\"record_type\"]==\"evidence-bundle-authorization-summary\"
             and d[\"canonical_record_file\"].endswith(\"post-build-authorization.json\") else 1)' \
       '$TMP/auth-bundle/content/authorization/authorization-summary.json'"
ck "a release script now DOES compare an authorization to what it authorised" \
   "[ \"\$(grep -rlc 'validate-authorization-record' '$GEN' 2>/dev/null | grep -vc ':0\$')\" != '0' ] \
    && grep -q 'post-build-authorization' '$SEAL'"

# --- A-S1  REQUIRED SABOTAGE: missing source revision ----------------------
ck "A-S1 SABOTAGE: an authorization with NO source_revision is REFUSED" \
   "! gen --evidence '$ACCEPTED' --out '$TMP/a-s1' --evidence-class staged-candidate \
       --authorization '$TMP/auth-norev.json' --today '$DAY' >/dev/null 2>&1"
ck "A-S1 ...by the shipped schema validator, naming the absent property" \
   "says \"'source_revision' is a required property\" bash '$AUTHV' '$TMP/auth-norev.json'"
ck "A-S1 SABOTAGE: an authorization for a DIFFERENT source SHA is REFUSED" \
   "! gen --evidence '$ACCEPTED' --out '$TMP/a-s1b' --evidence-class staged-candidate \
       --authorization '$TMP/auth-wrong.json' --today '$DAY' >/dev/null 2>&1"
ck "A-S1 ...for the revision-binding diagnostic, not a generic schema one" \
   "says 'is not this build' \
      gen --evidence '$ACCEPTED' --out '$TMP/a-s1c' --evidence-class staged-candidate \
        --authorization '$TMP/auth-wrong.json' --today '$DAY'"
ck "A-S1 ...and the wrong-SHA record is still SCHEMA-valid, which is the point" \
   "bash '$AUTHV' '$TMP/auth-wrong.json' >/dev/null 2>&1"
ck "A-S1 NON-VACUOUS: the honest record generates the same bundle cleanly" \
   "gen --evidence '$ACCEPTED' --out '$TMP/a-s1-ok' --evidence-class staged-candidate \
       --authorization '$TMP/auth-right.json' --today '$DAY' >/dev/null 2>&1"

# --- A-S2  REQUIRED SABOTAGE: schema-invalid authorization -----------------
ck "A-S2 SABOTAGE: a schema-invalid authorization is REFUSED before anything is written" \
   "! gen --evidence '$ACCEPTED' --out '$TMP/a-s2' --evidence-class staged-candidate \
       --authorization '$TMP/auth-badschema.json' --today '$DAY' >/dev/null 2>&1"
ck "A-S2 ...naming the field the aggregator never inspects" \
   "says 'is not of type' \
      gen --evidence '$ACCEPTED' --out '$TMP/a-s2b' --evidence-class staged-candidate \
        --authorization '$TMP/auth-badschema.json' --today '$DAY'"
ck "A-S2 NON-VACUOUS: the same path succeeds once the type violation is removed" \
   "gen --evidence '$ACCEPTED' --out '$TMP/a-s2-ok' --evidence-class staged-candidate \
       --authorization '$TMP/auth-right.json' --today '$DAY' >/dev/null 2>&1"

# --- the child set, the database, the verdict ------------------------------
ck "SABOTAGE: an authorization that omits a child the run produced is REFUSED" \
   "! gen --evidence '$ACCEPTED' --out '$TMP/a-short' --evidence-class staged-candidate \
       --authorization '$TMP/auth-short.json' --today '$DAY' >/dev/null 2>&1"
ck "SABOTAGE: an authorization for a child the run NEVER produced is REFUSED" \
   "! gen --evidence '$ACCEPTED' --out '$TMP/a-extra' --evidence-class staged-candidate \
       --authorization '$TMP/auth-extra.json' --today '$DAY' >/dev/null 2>&1"
ck "...which is how an experimental 8.5 line cannot enter through an authorization" \
   "says 'never produced' \
      gen --evidence '$ACCEPTED' --out '$TMP/a-extra2' --evidence-class staged-candidate \
        --authorization '$TMP/auth-extra.json' --today '$DAY'"
ck "SABOTAGE: an authorization judged against another frozen database is REFUSED" \
   "! gen --evidence '$ACCEPTED' --out '$TMP/a-db' --evidence-class staged-candidate \
       --authorization '$TMP/auth-otherdb.json' --today '$DAY' >/dev/null 2>&1"
ck "SABOTAGE: an authorization naming a different per-child evidence checksum is REFUSED" \
   "! gen --evidence '$ACCEPTED' --out '$TMP/a-esha' --evidence-class staged-candidate \
       --authorization '$TMP/auth-badsha.json' --today '$DAY' >/dev/null 2>&1"
ck "SABOTAGE: a REFUSED authorization (verdict FAIL) cannot become a bundle" \
   "! gen --evidence '$ACCEPTED' --out '$TMP/a-fail' --evidence-class staged-candidate \
       --authorization '$TMP/auth-fail.json' --today '$DAY' >/dev/null 2>&1"

# --- the explicit, argued absence ------------------------------------------
# INTENTIONALLY UNSUPPORTED, WITH A REFUSAL RATHER THAN SILENCE. A run whose
# authorization artifact has expired can still produce a bundle, but it must SAY
# SO in prose that travels with the bundle, and such a bundle can never be
# sealed as a release.
ck "an argued absence is accepted and recorded as an absence" \
   "gen --evidence '$ACCEPTED' --out '$TMP/absent' --evidence-class staged-candidate \
       --authorization-absent 'the 30-day workflow artifact holding this run authorization expired before the bundle was built' \
       --today '$DAY' >/dev/null 2>&1 \
    && test -f '$TMP/absent/content/authorization/AUTHORIZATION-ABSENT.json'"
ck "...and it states the CONSEQUENCE, not just the fact" \
   "python3 -c 'import json,sys
d=json.load(open(sys.argv[1]))
sys.exit(0 if d[\"authorization_record_present\"] is False and \"R13\" in d[\"consequence\"] else 1)' \
      '$TMP/absent/content/authorization/AUTHORIZATION-ABSENT.json'"
ck "SABOTAGE: a token excuse is REFUSED — 'n/a' is not a reason" \
   "! gen --evidence '$ACCEPTED' --out '$TMP/absent-bad' --evidence-class staged-candidate \
       --authorization-absent 'n/a' --today '$DAY' >/dev/null 2>&1"
ck "SABOTAGE: a published-artifact bundle cannot declare its authorization absent" \
   "! gen --evidence '$ACCEPTED' --out '$TMP/absent-pub' --evidence-class published-artifact \
       --release v2026.08.25 --candidate rc1 \
       --authorization-absent 'the workflow artifact for this run expired before the bundle was built' \
       --today '$DAY' >/dev/null 2>&1"

echo
echo "== stage 3: SBOM — ONE identity, producer and consumer ===================="

# WHAT THIS STAGE USED TO PIN. scripts/generate-sbom.sh named its output by
# blind substitution on the image reference (NAME=$(IMAGE | tr '/:@' '___'))
# while the bundle looked up <child_slug>.spdx.json. The producer's output set
# and the consumer's lookup set NEVER intersected, so handing the bundle a
# complete, correct SBOM directory produced sbom.present=false with exit 0 — a
# release whose bill of materials was silently absent, reported as clean. And
# the bundle recorded only format, path and the file's own sha256, so an SPDX
# document describing a DIFFERENT child, filed under the correct name, verified
# clean: every byte the bundle inspected lined up and the SUBJECT was never read.
#
# Both halves are fixed by sbom_filename() in scripts/lib/common.sh, built from
# the same validated components as child_slug(). The fixtures below are named by
# that function — never by a literal — so this test cannot pass by re-deriving
# the identity a third way.
mkdir -p "$TMP/sbom" "$TMP/sbom-foreign" "$TMP/sbom-trname" "$TMP/sbom-extra"
python3 - "$ACCEPTED" "$TMP/ident.tsv" <<'PY'
import json, sys
ev = json.load(open(sys.argv[1]))
other = ev["children"][-1]["manifest_digest"]
first = ev["children"][0]["manifest_digest"]
with open(sys.argv[2], "w") as fh:
    for c in ev["children"]:
        fam, _, ver = c["image_label"].partition("/")
        foreign = other if c["manifest_digest"] != other else first
        tr = c["digest_reference"].replace("/", "_").replace(":", "_").replace("@", "_")
        fh.write("\t".join([fam, ver, c["platform"], c["child_key"],
                            c["manifest_digest"], foreign, tr]) + "\n")
PY
mk_spdx() { # mk_spdx <path> <child_key> <subject-digest>
  python3 - "$1" "$2" "$3" <<'PY'
import json, sys
json.dump({"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT",
           "name": sys.argv[2], "documentDescribes": [sys.argv[3]],
           "packages": [
               {"name": "zlib1g", "versionInfo": "1:1.2.13.dfsg-1",
                "licenseConcluded": "Zlib", "licenseDeclared": "Zlib"},
               {"name": "libssl3", "versionInfo": "3.0.15-1~deb12u1",
                "licenseConcluded": "Apache-2.0", "licenseDeclared": "Apache-2.0"}]},
          open(sys.argv[1], "w"), indent=2)
PY
}
while IFS="$(printf '\t')" read -r fam ver plat key dig foreign tr; do
  [ -n "$fam" ] || continue
  # THE CANONICAL NAME, from the ONE function the producer also calls.
  name="$(sbom_filename "$fam" "$ver" "$plat" spdx-json)"
  mk_spdx "$TMP/sbom/$name"          "$key" "$dig"
  # Correct filename, FOREIGN subject. Every byte the bundle used to inspect
  # still lines up.
  mk_spdx "$TMP/sbom-foreign/$name"  "$key" "$foreign"
  # What scripts/generate-sbom.sh USED to write.
  mk_spdx "$TMP/sbom-trname/$tr.spdx.json" "$key" "$dig"
done < "$TMP/ident.tsv"
cp -R "$TMP/sbom/." "$TMP/sbom-extra/"
mk_spdx "$TMP/sbom-extra/$(sbom_filename php-cli 8.5 linux/amd64 spdx-json)" \
        "php-cli/8.5/linux/amd64" "sha256:$(printf '5%.0s' {1..64})"
rm -rf "$TMP/sbom-short"; cp -R "$TMP/sbom" "$TMP/sbom-short"
rm -f "$TMP/sbom-short/$(sbom_filename nginx prod linux/arm64 spdx-json)"
printf '{"_type":"https://in-toto.io/Statement/v1","fixture":true}\n' > "$TMP/prov.json"

ck "producer and consumer derive the SAME SBOM identity function" \
   "[ \"\$(bash scripts/generate-sbom.sh --print-names php-fpm 8.3 linux/amd64 \
        | awk -F'\\t' '\$1==\"spdx-json\"{print \$2}')\" \
    = \"\$(sbom_filename php-fpm 8.3 linux/amd64 spdx-json)\" ]"
ck "...and it is child_slug(), not a second derivation" \
   "[ \"\$(sbom_filename php-fpm 8.3 linux/amd64 spdx-json)\" \
    = \"\$(child_slug php-fpm 8.3 linux/amd64).spdx.json\" ]"
ck "the PLATFORM stays part of the identity" \
   "[ \"\$(sbom_filename php-fpm 8.3 linux/amd64 spdx-json)\" \
   != \"\$(sbom_filename php-fpm 8.3 linux/arm64 spdx-json)\" ]"
ck "NO TWO CHILDREN COLLIDE across the whole matrix and both platforms" \
   "n=0; out=''
    for t in \$MATRIX_IMAGES; do for p in linux/amd64 linux/arm64; do
      out=\"\$out\$(sbom_filename \"\${t%:*}\" \"\${t##*:}\" \"\$p\" spdx-json)
\"; n=\$((n+1)); done; done
    [ \"\$(printf %s \"\$out\" | sort -u | wc -l | tr -d ' ')\" = \"\$n\" ]"
ck "EVERY expected child maps to exactly one SBOM in the fixture set" \
   "[ \"\$(find '$TMP/sbom' -name '*.spdx.json' | wc -l | tr -d ' ')\" = '$CHILDREN' ]"

# --- the happy path -------------------------------------------------------
ck "the staged-candidate bundle generates from the accepted run + per-child SBOMs" \
   "gen --evidence '$ACCEPTED' --out '$TMP/cand' --evidence-class staged-candidate \
      --sbom-dir '$TMP/sbom' --authorization '$TMP/auth-right.json' --today '$DAY' >/dev/null 2>&1"
ck "it verifies offline" "ver '$TMP/cand' >/dev/null 2>&1"
ck "the bundle carries one child record per matrix image per platform" \
   "[ \"\$(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1]))[\"children\"]))' '$TMP/cand/manifest.json')\" = '$CHILDREN' ]"
ck "sbom.present is TRUE and sbom.complete is TRUE — never a silent false" \
   "python3 -c 'import json,sys
m=json.load(open(sys.argv[1])); s=m[\"sbom\"]
sys.exit(0 if s[\"present\"] and s[\"complete\"]
             and s[\"children_with_sbom\"]==s[\"children_total\"]==len(m[\"children\"]) else 1)' \
      '$TMP/cand/manifest.json'"
ck "every child's SBOM records the SUBJECT it describes, not only the file hash" \
   "python3 -c 'import json,sys
m=json.load(open(sys.argv[1]))
sys.exit(0 if all(c[\"sbom\"] and c[\"sbom\"][\"subject_digest\"]==c[\"manifest_digest\"]
                  for c in m[\"children\"]) else 1)' '$TMP/cand/manifest.json'"
ck "the generator DOES parse an SBOM now — it no longer only copies bytes" \
   "grep -qE 'documentDescribes' '$GEN'"
ck "every SBOM digest is covered by the evidence-bundle checksum index" \
   "[ \"\$(grep -c 'content/sbom/.*\\.spdx\\.json' '$TMP/cand/SHA256SUMS')\" = '$CHILDREN' ] \
    && python3 -c 'import json,sys
m=json.load(open(sys.argv[1]))
idx={f[\"path\"]:f[\"sha256\"] for f in m[\"files\"]}
sys.exit(0 if all(c[\"sbom\"][\"file\"] in idx and idx[c[\"sbom\"][\"file\"]]==c[\"sbom\"][\"sha256\"]
                  for c in m[\"children\"]) else 1)' '$TMP/cand/manifest.json'"
ck "SABOTAGE: the bundle cannot demote the accepted run to foundry-child" \
   "! gen --evidence '$ACCEPTED' --out '$TMP/demoted' --evidence-class foundry-child \
       --authorization '$TMP/auth-right.json' --today '$DAY' >/dev/null 2>&1"
ck "...for the declared-lifecycle diagnostic" \
   "says 'does not succeed' \
      gen --evidence '$ACCEPTED' --out '$TMP/demoted2' --evidence-class foundry-child \
        --authorization '$TMP/auth-right.json' --today '$DAY'"

# --- B-S1  REQUIRED SABOTAGE: incorrect SBOM filename ----------------------
ck "B-S1 SABOTAGE: the filename generate-sbom.sh USED to emit is a MISSING SBOM" \
   "! gen --evidence '$ACCEPTED' --out '$TMP/b-s1' --evidence-class staged-candidate \
       --sbom-dir '$TMP/sbom-trname' --authorization '$TMP/auth-right.json' \
       --today '$DAY' >/dev/null 2>&1"
ck "B-S1 ...fatally, naming the ONE identity function both sides derive from" \
   "says 'sbom_filename()' \
      gen --evidence '$ACCEPTED' --out '$TMP/b-s1b' --evidence-class staged-candidate \
        --sbom-dir '$TMP/sbom-trname' --authorization '$TMP/auth-right.json' --today '$DAY'"
ck "B-S1 NON-VACUOUS: the correctly named set builds the same bundle cleanly" \
   "gen --evidence '$ACCEPTED' --out '$TMP/b-s1-ok' --evidence-class staged-candidate \
       --sbom-dir '$TMP/sbom' --authorization '$TMP/auth-right.json' --today '$DAY' >/dev/null 2>&1"

# --- B-S2  REQUIRED SABOTAGE: SBOM from another digest ---------------------
ck "B-S2 SABOTAGE: an SBOM whose SUBJECT is a different child is REFUSED" \
   "! gen --evidence '$ACCEPTED' --out '$TMP/b-s2' --evidence-class staged-candidate \
       --sbom-dir '$TMP/sbom-foreign' --authorization '$TMP/auth-right.json' \
       --today '$DAY' >/dev/null 2>&1"
ck "B-S2 ...for the SUBJECT diagnostic, though the filename and file hash both matched" \
   "says 'not this child' \
      gen --evidence '$ACCEPTED' --out '$TMP/b-s2b' --evidence-class staged-candidate \
        --sbom-dir '$TMP/sbom-foreign' --authorization '$TMP/auth-right.json' --today '$DAY'"

# --- B-S3  REQUIRED SABOTAGE: missing SBOM ---------------------------------
ck "B-S3 SABOTAGE: ONE missing SBOM is FATAL, never sbom.present=false with exit 0" \
   "! gen --evidence '$ACCEPTED' --out '$TMP/b-s3' --evidence-class staged-candidate \
       --sbom-dir '$TMP/sbom-short' --authorization '$TMP/auth-right.json' \
       --today '$DAY' >/dev/null 2>&1"
ck "B-S3 ...naming the child whose bill of materials is absent" \
   "says 'nginx/prod/linux/arm64' \
      gen --evidence '$ACCEPTED' --out '$TMP/b-s3b' --evidence-class staged-candidate \
        --sbom-dir '$TMP/sbom-short' --authorization '$TMP/auth-right.json' --today '$DAY'"

# --- B-S4  an extra / unbound SBOM -----------------------------------------
ck "B-S4 SABOTAGE: an SBOM bound to no child in the bundle is REFUSED" \
   "! gen --evidence '$ACCEPTED' --out '$TMP/b-s4' --evidence-class staged-candidate \
       --sbom-dir '$TMP/sbom-extra' --authorization '$TMP/auth-right.json' \
       --today '$DAY' >/dev/null 2>&1"
ck "B-S4 ...which is also how an experimental 8.5 document is kept out" \
   "says 'php-cli-8.5-linux-amd64.spdx.json' \
      gen --evidence '$ACCEPTED' --out '$TMP/b-s4b' --evidence-class staged-candidate \
        --sbom-dir '$TMP/sbom-extra' --authorization '$TMP/auth-right.json' --today '$DAY'"

# --- B-S5  a foreign SBOM swapped into a SEALED bundle and honestly re-sealed
# Every checksum, the file index and the path-independent aggregate all agree
# afterwards. This is the attacker's best case: only re-reading the SUBJECT can
# refuse it.
cp -R "$TMP/cand" "$TMP/b-s5"
SWAPPED="$(python3 - "$TMP/b-s5" "$TMP/sbom-foreign" <<'PY'
import glob, os, shutil, sys
tgt = sorted(glob.glob(os.path.join(sys.argv[1], "content/sbom/*.spdx.json")))[0]
shutil.copyfile(os.path.join(sys.argv[2], os.path.basename(tgt)), tgt)
print(os.path.relpath(tgt, sys.argv[1]))
PY
)"
python3 - "$TMP/b-s5" "$SWAPPED" <<'PY'
import hashlib, json, os, sys
b, rel = sys.argv[1], sys.argv[2]
h = hashlib.sha256(open(os.path.join(b, rel), "rb").read()).hexdigest()
mp = os.path.join(b, "manifest.json"); m = json.load(open(mp))
for c in m["children"]:
    if c["sbom"] and c["sbom"]["file"] == rel:
        c["sbom"]["sha256"] = h
json.dump(m, open(mp, "w"), indent=2)
PY
reindex "$TMP/b-s5"
ck "B-S5 SABOTAGE: a foreign SBOM swapped in and HONESTLY re-sealed is REFUSED" \
   "! ver '$TMP/b-s5' >/dev/null 2>&1"
ck "B-S5 ...because verify re-reads the SUBJECT, not just the file's own digest" \
   "says 'not this child' ver '$TMP/b-s5'"
ck "B-S5 NON-VACUOUS: the untouched bundle still verifies after every SBOM sabotage" \
   "ver '$TMP/cand' >/dev/null 2>&1"

echo
echo "== stage 4: VEX — bound to the digest AND to the evidence class =========="

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
   "says 'is not one of the' vexv --vex '$TMP/vexsab/digest.json' --evidence '$ACCEPTED' --today '$DAY'"

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
   "says 'hashes to' vexv --vex '$TMP/cand/content/vex/openvex.json' \
      --evidence '$TMP/vexsab/other-evidence.json' --today '$DAY'"

# --- the class boundary -----------------------------------------------------
# WHAT THIS USED TO PIN. A disposition set is a published statement about a
# SHIPPED artifact. The class contract exists precisely because "what may ship"
# and "what shipped" are not interchangeable — yet the VEX document had no field
# that distinguished them, vex-openvex-v1 declared none and forbade extras, and
# the two documents were BYTE-IDENTICAL. Either could be presented as the other.
ck "a published-artifact bundle generates from the same run" \
   "gen --evidence '$ACCEPTED_NATIVE' --out '$TMP/pub' --evidence-class published-artifact \
      --release v2026.08.25 --candidate rc1 --sbom-dir '$TMP/sbom' \
      --provenance '$TMP/prov.json' --authorization '$TMP/auth-native.json' \
      --today '$DAY' >/dev/null 2>&1"
ck "the two bundles really do carry different classes (non-vacuity for the next line)" \
   "[ \"\$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))[\"evidence_class\"])' '$TMP/cand/manifest.json')\" \
   != \"\$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))[\"evidence_class\"])' '$TMP/pub/manifest.json')\" ]"
ck "candidate and published dispositions are NO LONGER byte-identical" \
   "! cmp -s '$TMP/cand/content/vex/openvex.json' '$TMP/pub/content/vex/openvex.json'"
ck "...because each document NAMES the evidence class it was published for" \
   "[ \"\$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))[\"foundry\"][\"evidence_class\"])' '$TMP/cand/content/vex/openvex.json')\" = 'staged-candidate' ] \
    && [ \"\$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))[\"foundry\"][\"evidence_class\"])' '$TMP/pub/content/vex/openvex.json')\" = 'published-artifact' ]"
ck "vex-openvex-v1 now DECLARES evidence_class and REQUIRES it" \
   "python3 -c 'import json,sys
f=json.load(open(\"schemas/vex-openvex-v1.schema.json\"))[\"properties\"][\"foundry\"]
sys.exit(0 if \"evidence_class\" in f[\"properties\"] and \"evidence_class\" in f[\"required\"]
             and f[\"additionalProperties\"] is False else 1)'"
ck "SABOTAGE: candidate dispositions presented as a published release are REFUSED" \
   "! vexv --vex '$TMP/cand/content/vex/openvex.json' --evidence '$ACCEPTED' \
      --evidence-class published-artifact --today '$DAY' >/dev/null 2>&1"
ck "...for the class diagnostic, not a checksum one" \
   "says 'does not stand in for' vexv --vex '$TMP/cand/content/vex/openvex.json' \
      --evidence '$ACCEPTED' --evidence-class published-artifact --today '$DAY'"
ck "NON-VACUOUS: each verifies against the class it WAS published for" \
   "vexv --vex '$TMP/cand/content/vex/openvex.json' --evidence '$ACCEPTED' \
      --evidence-class staged-candidate --today '$DAY' >/dev/null 2>&1 \
    && vexv --vex '$TMP/pub/content/vex/openvex.json' --evidence '$ACCEPTED_NATIVE' \
      --evidence-class published-artifact --today '$DAY' >/dev/null 2>&1"

# --- bundle verify cross-checks the VEX against the manifest ----------------
# The digest check alone proved only that the file had not changed since
# sealing; it said nothing about whether the document was about this bundle.
# A disposition document re-pointed at another revision, then HONESTLY
# re-sealed: the manifest's recorded digest, the file index and the
# path-independent aggregate all agree afterwards, so only a cross-check
# against the manifest can refuse it.
cp -R "$TMP/cand" "$TMP/vex-rev"
python3 - "$TMP/vex-rev" <<'PY'
import hashlib, json, os, sys
b = sys.argv[1]
vp = os.path.join(b, "content/vex/openvex.json")
d = json.load(open(vp))
d["foundry"]["source_revision"] = "0" * 40
json.dump(d, open(vp, "w"), indent=2)
mp = os.path.join(b, "manifest.json")
m = json.load(open(mp))
m["dispositions"]["sha256"] = hashlib.sha256(open(vp, "rb").read()).hexdigest()
json.dump(m, open(mp, "w"), indent=2)
PY
reindex "$TMP/vex-rev"
ck "SABOTAGE: dispositions re-pointed at another revision and honestly re-sealed are REFUSED" \
   "! ver '$TMP/vex-rev' >/dev/null 2>&1"
ck "...by a cross-check against the manifest, which the digest check alone could not make" \
   "says 'binds source_revision' ver '$TMP/vex-rev'"

# The same for the class: a published set dropped into a candidate bundle.
cp -R "$TMP/cand" "$TMP/vex-cls"
cp "$TMP/pub/content/vex/openvex.json" "$TMP/vex-cls/content/vex/openvex.json"
python3 - "$TMP/vex-cls" <<'PY'
import hashlib, json, os, sys
b = sys.argv[1]
vp = os.path.join(b, "content/vex/openvex.json")
mp = os.path.join(b, "manifest.json")
m = json.load(open(mp))
m["dispositions"]["sha256"] = hashlib.sha256(open(vp, "rb").read()).hexdigest()
json.dump(m, open(mp, "w"), indent=2)
PY
reindex "$TMP/vex-cls"
ck "SABOTAGE: a PUBLISHED disposition set inside a candidate bundle is REFUSED" \
   "! ver '$TMP/vex-cls' >/dev/null 2>&1"
ck "...for the class diagnostic — 'what shipped' does not stand in for 'what may ship'" \
   "says 'does not stand in for' ver '$TMP/vex-cls'"

# --- V-S3  REQUIRED SABOTAGE: missing VEX disposition -----------------------
cp -R "$TMP/cand" "$TMP/v-s3"
rm -f "$TMP/v-s3/content/vex/openvex.json"
ck "V-S3 SABOTAGE: a bundle whose disposition document is DELETED is REFUSED" \
   "! ver '$TMP/v-s3' >/dev/null 2>&1"
cp -R "$TMP/cand" "$TMP/v-s3b"
rm -f "$TMP/v-s3b/content/vex/openvex.json"
reindex "$TMP/v-s3b"
ck "V-S3 SABOTAGE: ...and still REFUSED after an honest re-seal over the gap" \
   "! ver '$TMP/v-s3b' >/dev/null 2>&1"
# A disposition REMOVED from an otherwise intact document: an observed finding
# with no published statement about it.
cp -R "$TMP/cand" "$TMP/v-s3c"
python3 - "$TMP/v-s3c/content/vex/openvex.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["statements"] = d["statements"][1:]
json.dump(d, open(sys.argv[1], "w"), indent=2)
PY
ck "V-S3 SABOTAGE: an observed finding with NO disposition is REFUSED by the VEX verifier" \
   "! vexv --vex '$TMP/v-s3c/content/vex/openvex.json' --evidence '$ACCEPTED' \
      --evidence-class staged-candidate --today '$DAY' >/dev/null 2>&1"
ck "V-S3 ...for the no-disposition diagnostic" \
   "says 'no disposition' vexv --vex '$TMP/v-s3c/content/vex/openvex.json' \
      --evidence '$ACCEPTED' --evidence-class staged-candidate --today '$DAY'"
ck "V-S3 NON-VACUOUS: the complete document still verifies after all three" \
   "vexv --vex '$TMP/cand/content/vex/openvex.json' --evidence '$ACCEPTED' \
      --evidence-class staged-candidate --today '$DAY' >/dev/null 2>&1"

echo
echo "== stage 5: retention + content-after-checksum ============================"

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

# --- R-S1  REQUIRED SABOTAGE: incomplete retention metadata ----------------
# Retention stays on disk but is dropped from coverage, and the aggregate is
# recomputed so BUNDLE.sha256 agrees with SHA256SUMS.
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
ck "R-S1 SABOTAGE: retention excluded from the checksum index is REFUSED" \
   "! ver '$TMP/ret-uncovered' >/dev/null 2>&1"
ck "R-S1 ...for the outside-coverage diagnostic, naming the retention file" \
   "says 'covered by no checksum' ver '$TMP/ret-uncovered'"

# --- R-S2  REQUIRED SABOTAGE: changed bundle content after checksum --------
cp -R "$TMP/cand" "$TMP/ret-deleted"
rm -f "$TMP/ret-deleted/content/retention/retention.json"
python3 - "$TMP/ret-deleted" <<'PY'
import hashlib, os, sys
d = sys.argv[1]
lines = []
for dp, _dirs, ns in os.walk(d):
    for n in ns:
        ap = os.path.join(dp, n)
        rel = os.path.relpath(ap, d)
        if rel in ("SHA256SUMS", "BUNDLE.sha256"):
            continue
        lines.append("%s  %s" % (hashlib.sha256(open(ap, "rb").read()).hexdigest(), rel))
lines.sort(key=lambda s: s.split("  ", 1)[1])
mn = [l for l in lines if l.endswith("  manifest.json")]
open(os.path.join(d, "SHA256SUMS"), "w").write(
    "\n".join(mn + [l for l in lines if l not in mn]) + "\n")
open(os.path.join(d, "BUNDLE.sha256"), "w").write(
    "%s  SHA256SUMS\n"
    % hashlib.sha256(open(os.path.join(d, "SHA256SUMS"), "rb").read()).hexdigest())
PY
ck "R-S2 SABOTAGE: retention deleted and the index honestly rewritten is still REFUSED" \
   "! ver '$TMP/ret-deleted' >/dev/null 2>&1"
ck "R-S2 ...because the aggregate over content/ no longer matches the sealed manifest" \
   "says 'manifest content_checksum is' ver '$TMP/ret-deleted'"
cp -R "$TMP/cand" "$TMP/content-planted"
printf 'planted after sealing\n' > "$TMP/content-planted/content/planted.txt"
ck "R-S2 SABOTAGE: a file added after sealing is outside coverage and REFUSED" \
   "! ver '$TMP/content-planted' >/dev/null 2>&1"

# --- R-S3  retention metadata that is present but INCOMPLETE ---------------
cp -R "$TMP/cand" "$TMP/ret-partial"
python3 - "$TMP/ret-partial" <<'PY'
import json, os, sys
p = os.path.join(sys.argv[1], "manifest.json")
m = json.load(open(p))
m["retention"].pop("retain_until", None)
json.dump(m, open(p, "w"), indent=2)
PY
reindex "$TMP/ret-partial"
ck "R-S3 SABOTAGE: a manifest whose retention block is incomplete is REFUSED by the schema" \
   "! ver '$TMP/ret-partial' >/dev/null 2>&1"
ck "R-S3 ...naming release-evidence-bundle-v1 rather than a checksum" \
   "says 'release-evidence-bundle-v1' ver '$TMP/ret-partial'"
ck "R-S1/2/3 NON-VACUOUS: the untouched bundle still verifies after all four" \
   "ver '$TMP/cand' >/dev/null 2>&1"

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

# --- the authorization is now BOUND INTO the seal --------------------------
# WHAT THIS USED TO PIN. The seal bound no authorization identity at all — only
# a boolean it had copied out of a four-field summary — so the canonical record
# was never an input to any seal it could contradict.
ck "the seal BINDS the authorization record's file, digest, revision and scope" \
   "python3 -c 'import json,sys
s=json.load(open(sys.argv[1]))
a=s[\"authorization\"]
sys.exit(0 if a[\"record_sha256\"] and a[\"source_revision\"]==s[\"source_revision\"]
             and a[\"record_file\"].endswith(\"post-build-authorization.json\")
             and a[\"authorization_scope\"] and a[\"verdict\"]==\"PASS\"
             and a[\"authorized_children\"]==len(s[\"promoted_digests\"]) else 1)' '$TMP/seal.json'"
ck "...and release-seal.sh names the canonical record it can now contradict" \
   "grep -q 'post-build-authorization' '$SEAL' && grep -q 'R13' '$SEAL'"

# --- S-S1  a bundle whose index no longer holds ----------------------------
cp -R "$TMP/pub" "$TMP/unsealed"
printf 'planted after sealing\n' > "$TMP/unsealed/content/planted.txt"
ck "S-S1 SABOTAGE: a bundle with a file outside coverage cannot be sealed" \
   "! seal --bundle '$TMP/unsealed' --version v2026.08.25 --candidate rc1 --identity '$REL_ID' \
      --test-key '$TMP/test.key' --out '$TMP/seal-bad.json' --today '$DAY' >/dev/null 2>&1"
ck "S-S1 ...for R6, the refusal to sign an unverifiable bundle" \
   "says 'R6' seal --bundle '$TMP/unsealed' --version v2026.08.25 --candidate rc1 \
      --identity '$REL_ID' --test-key '$TMP/test.key' --out '$TMP/seal-bad2.json' --today '$DAY'"

# --- S-S2  REQUIRED SABOTAGE: changed bundle content after checksum --------
cp -R "$TMP/pub" "$TMP/seal-drift"
python3 - "$TMP/seal-drift" <<'PY'
import glob, json, os, sys
p = sorted(glob.glob(os.path.join(sys.argv[1], "content/children/*.json")))[0]
d = json.load(open(p))
d["record"]["severity_counts"] = {"HIGH": 0}
json.dump(d, open(p, "w"), indent=2)
PY
ck "S-S2 SABOTAGE: a valid seal does NOT verify once the bundle's bytes change" \
   "! vsl --seal '$TMP/seal.json' --bundle '$TMP/seal-drift' --pubkey '$TMP/test.pub' \
      --version v2026.08.25 --today '$DAY' >/dev/null 2>&1"
ck "S-S2 SABOTAGE: nor does it verify against a DIFFERENT bundle" \
   "! vsl --seal '$TMP/seal.json' --bundle '$TMP/cand' --pubkey '$TMP/test.pub' \
      --version v2026.08.25 --today '$DAY' >/dev/null 2>&1"

# --- S-S3  the class boundary at the seal ----------------------------------
ck "S-S3 SABOTAGE: a staged-candidate bundle cannot be sealed as a release" \
   "! seal --bundle '$TMP/cand' --version v2026.08.25 --candidate rc1 --identity '$REL_ID' \
      --test-key '$TMP/test.key' --out '$TMP/seal-cand.json' --today '$DAY' >/dev/null 2>&1"
ck "S-S3 ...for R8, the evidence-class refusal" \
   "says 'R8' seal --bundle '$TMP/cand' --version v2026.08.25 --candidate rc1 \
      --identity '$REL_ID' --test-key '$TMP/test.key' --out '$TMP/seal-cand2.json' --today '$DAY'"

# --- S-S4  REQUIRED SABOTAGE: expired governance ---------------------------
# The bundle is unchanged; only the date the seal is evaluated on moves past the
# retention window the class policy promises.
RETAIN="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["retention"]["retain_until"])' "$TMP/pub/manifest.json")"
LAPSED="$(python3 -c 'import datetime,sys;print((datetime.date.fromisoformat(sys.argv[1])+datetime.timedelta(days=1)).isoformat())' "$RETAIN")"
ck "S-S4 SABOTAGE: sealing after the governance window closed is REFUSED" \
   "! seal --bundle '$TMP/pub' --version v2026.08.25 --candidate rc1 --identity '$REL_ID' \
      --test-key '$TMP/test.key' --out '$TMP/seal-lapsed.json' --today '$LAPSED' >/dev/null 2>&1"
ck "S-S4 ...for R5, the expired-governance refusal" \
   "says 'R5' seal --bundle '$TMP/pub' --version v2026.08.25 --candidate rc1 \
      --identity '$REL_ID' --test-key '$TMP/test.key' --out '$TMP/seal-lapsed2.json' --today '$LAPSED'"
ck "S-S4 NON-VACUOUS: the same bundle seals inside the window" \
   "seal --bundle '$TMP/pub' --version v2026.08.25 --candidate rc1 --identity '$REL_ID' \
      --test-key '$TMP/test.key' --out '$TMP/seal-inwindow.json' --today '$DAY' >/dev/null 2>&1"

# --- S-S5  REQUIRED SABOTAGE: QEMU evidence presented as native arm64 ------
# WHAT THIS USED TO PIN. R9 fired only when the caller passed
# --claim-native-arm64, so a release that simply never made the claim sealed
# straight over emulated arm64 children and the #111 boundary was never
# consulted. policies/native-arch-requirements.yaml recorded that as
# `release_gate.known_gap` with `blocks_closure_of: 111`. The gap is closed: the
# POLICY arms the refusal now, and these cases run against the REAL accepted
# record, whose ten linux/arm64 children genuinely ran under QEMU on x86 hosts.
gen --evidence "$ACCEPTED" --out "$TMP/pub-emul" --evidence-class published-artifact \
    --release v2026.08.25 --candidate rc1 --sbom-dir "$TMP/sbom" \
    --provenance "$TMP/prov.json" --authorization "$TMP/auth-right.json" \
    --today "$DAY" >/dev/null 2>&1
ck "S-S5 the accepted run really did run arm64 under emulation (non-vacuity)" \
   "python3 -c 'import json,sys
m=json.load(open(sys.argv[1]))
q=[c for c in m[\"children\"] if c[\"platform\"]==\"linux/arm64\" and c[\"execution_mode\"]==\"qemu\"]
sys.exit(0 if len(q)==int(sys.argv[2]) else 1)' '$TMP/pub-emul/manifest.json' '$MATRIX_COUNT'"
ck "S-S5 the policy really does require native arm64 (non-vacuity)" \
   "python3 -c 'import sys,yaml
d=yaml.safe_load(open(\"policies/native-arch-requirements.yaml\"))
sys.exit(0 if d[\"release_gate\"][\"require_native_arm64\"] is True else 1)'"
ck "S-S5 SABOTAGE: the emulated bundle CANNOT be sealed, with no claim flag at all" \
   "! seal --bundle '$TMP/pub-emul' --version v2026.08.25 --candidate rc1 --identity '$REL_ID' \
      --test-key '$TMP/test.key' --out '$TMP/seal-emul.json' --today '$DAY' >/dev/null 2>&1"
ck "S-S5 ...for R9, and because the requirement belongs to the policy, not the caller" \
   "says 'does NOT depend on --claim-native-arm64' seal --bundle '$TMP/pub-emul' \
      --version v2026.08.25 --candidate rc1 --identity '$REL_ID' \
      --test-key '$TMP/test.key' --out '$TMP/seal-emul2.json' --today '$DAY'"
ck "S-S5 SABOTAGE: claiming native arm64 over QEMU evidence is REFUSED" \
   "! seal --bundle '$TMP/pub-emul' --version v2026.08.25 --candidate rc1 --identity '$REL_ID' \
      --claim-native-arm64 --test-key '$TMP/test.key' --out '$TMP/seal-native.json' \
      --today '$DAY' >/dev/null 2>&1"
ck "S-S5 ...for R9 specifically" \
   "says 'R9' seal --bundle '$TMP/pub-emul' --version v2026.08.25 --candidate rc1 \
      --identity '$REL_ID' --claim-native-arm64 --test-key '$TMP/test.key' \
      --out '$TMP/seal-native2.json' --today '$DAY'"
# The seal will not take the bundle's own word for its architecture: the
# CANONICAL post-build authorizer's recorded gate verdict has to say PASS.
python3 "$MKAUTH" "$ACCEPTED_NATIVE" "$TMP/auth-gatefail.json" --native-gate FAIL
gen --evidence "$ACCEPTED_NATIVE" --out "$TMP/pub-gatefail" \
    --evidence-class published-artifact --release v2026.08.25 --candidate rc1 \
    --sbom-dir "$TMP/sbom" --provenance "$TMP/prov.json" \
    --authorization "$TMP/auth-gatefail.json" --today "$DAY" >/dev/null 2>&1
ck "S-S5 SABOTAGE: native children whose AUTHORIZATION never passed the gate are REFUSED" \
   "! seal --bundle '$TMP/pub-gatefail' --version v2026.08.25 --candidate rc1 \
      --identity '$REL_ID' --test-key '$TMP/test.key' --out '$TMP/seal-gatefail.json' \
      --today '$DAY' >/dev/null 2>&1"
ck "S-S5 ...saying a bundle cannot vouch for its own architecture" \
   "says 'cannot vouch for its own architecture' seal --bundle '$TMP/pub-gatefail' \
      --version v2026.08.25 --candidate rc1 --identity '$REL_ID' \
      --test-key '$TMP/test.key' --out '$TMP/seal-gatefail2.json' --today '$DAY'"
ck "S-S5 ...and the seal that DOES succeed records the POLICY requirement, not a claim" \
   "python3 -c 'import json,sys
s=json.load(open(sys.argv[1]))
sys.exit(0 if s[\"native_arm64_claimed\"] is False
             and s[\"native_arm64_required_by_policy\"] is True
             and s[\"arm64_execution\"]==\"native\"
             and all(p[\"execution_mode\"]==\"native\"
                     for p in s[\"promoted_digests\"] if p[\"platform\"]==\"linux/arm64\") else 1)' \
      '$TMP/seal.json'"
ck "S-S5 ...and the authorization it was sealed over records the gate that ran" \
   "python3 -c 'import json,sys
a=json.load(open(sys.argv[1]))
g=a[\"native_arch_gate\"]
sys.exit(0 if g[\"verdict\"]==\"PASS\" and g[\"platform\"]==\"linux/arm64\"
             and g[\"covered_images\"]==g[\"expected_images\"]==int(sys.argv[2]) else 1)' \
      '$TMP/auth-native.json' '$MATRIX_COUNT'"

# --- S-S6  R13: an unauthorised bundle cannot be sealed --------------------
# The bundle is COMPLETE in every other respect — full SBOM set, provenance
# attestation, intact checksums, the right class and release — so the seal's
# earlier refusals (R6 an unverifiable bundle, R7 a missing bill of materials,
# R8 the wrong class) all pass and R13 is the reason it is refused. A sabotage
# that trips an earlier rule proves nothing about the rule under test.
ck "S-S6 the argued-absence bundle really exists and verifies (non-vacuity)" \
   "ver '$TMP/absent' >/dev/null 2>&1"
# From the NATIVE fixture on purpose: built from the emulated accepted record it
# would refuse at R9 before ever reaching R13, and the assertion below would then
# pass for a reason that has nothing to do with authorization.
gen --evidence "$ACCEPTED_NATIVE" --out "$TMP/noauth-pub" --evidence-class staged-candidate \
    --sbom-dir "$TMP/sbom" --provenance "$TMP/prov.json" \
    --authorization-absent 'the 30-day workflow artifact holding this run authorization expired before the bundle was built' \
    --today "$DAY" >/dev/null 2>&1
python3 - "$TMP/noauth-pub/manifest.json" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
m["evidence_class"] = "published-artifact"
m["release"] = {"version": "v2026.08.25", "candidate": "rc1"}
json.dump(m, open(sys.argv[1], "w"), indent=2)
PY
reindex "$TMP/noauth-pub"
ck "S-S6 the unauthorised bundle is otherwise complete: SBOMs, provenance, class" \
   "python3 -c 'import json,sys
m=json.load(open(sys.argv[1]))
sys.exit(0 if m[\"sbom\"][\"complete\"] and m[\"provenance\"][\"attestation_file\"]
             and m[\"evidence_class\"]==\"published-artifact\"
             and m[\"authorization\"][\"record_present\"] is False else 1)' \
      '$TMP/noauth-pub/manifest.json'"
ck "S-S6 SABOTAGE: a bundle naming NO authorization cannot be sealed as a release" \
   "! seal --bundle '$TMP/noauth-pub' --version v2026.08.25 --candidate rc1 --identity '$REL_ID' \
      --test-key '$TMP/test.key' --out '$TMP/seal-noauth.json' --today '$DAY' >/dev/null 2>&1"
ck "S-S6 ...for R13 specifically, not for R6, R7 or R8" \
   "says 'R13' seal --bundle '$TMP/noauth-pub' --version v2026.08.25 --candidate rc1 \
      --identity '$REL_ID' --test-key '$TMP/test.key' --out '$TMP/seal-noauth2.json' --today '$DAY'"
ck "S-S6 ...quoting the argued absence back, so the reader knows what is missing" \
   "says 'workflow artifact' seal --bundle '$TMP/noauth-pub' --version v2026.08.25 \
      --candidate rc1 --identity '$REL_ID' --test-key '$TMP/test.key' \
      --out '$TMP/seal-noauth3.json' --today '$DAY'"
ck "S-S6 NON-VACUOUS: the SAME bundle content WITH an authorization seals cleanly" \
   "seal --bundle '$TMP/pub' --version v2026.08.25 --candidate rc1 --identity '$REL_ID' \
      --test-key '$TMP/test.key' --out '$TMP/seal-ok.json' --today '$DAY' >/dev/null 2>&1"

echo
echo "== stage 7: continuity — the governance surface travels ==================="

ck "the offline recovery drill runs, offline, and passes" \
   "bash '$CVERIFY' --drill '$TMP/drill' > '$TMP/drill.log' 2>&1"
ck "...and it refuses right-digest/wrong-bytes" "grep -q 'WRONG BYTES is refused' '$TMP/drill.log'"
ck "...and a mirror missing a referenced blob" "grep -q 'missing a referenced blob' '$TMP/drill.log'"
ck "...and it cannot be mistaken for evidence a mirror exists" \
   "grep -q 'No independent mirror is provisioned' '$TMP/drill.log'"

# WHAT THIS STAGE USED TO PIN. The drill proves image BYTES survive. It said
# nothing about whether they could still be JUDGED: the export's universe was
# image references, so it carried no schema, no policy, and no verifier —
# everything that makes a restored digest interpretable lived only in the git
# repository the continuity plan exists to survive the loss of.
ck "the continuity export DOES carry the governance surface now" \
   "cexp --export-governance '$TMP/gov' >/dev/null 2>&1"
ck "...schemas, policies AND the offline verifiers, each bound by digest" \
   "python3 -c 'import json,sys
m=json.load(open(sys.argv[1]))
ids={f[\"artifact_class\"] for f in m[\"files\"]}
sys.exit(0 if {\"schemas\",\"policies\",\"verification-tools\"} <= ids and m[\"file_count\"]>0 else 1)' \
      '$TMP/gov/GOVERNANCE-MANIFEST.json'"
ck "...including the schemas this whole path is validated against" \
   "test -f '$TMP/gov/files/schemas/release-evidence-bundle-v1.schema.json' \
    && test -f '$TMP/gov/files/schemas/post-build-authorization-v1.schema.json' \
    && test -f '$TMP/gov/files/schemas/vex-openvex-v1.schema.json'"
ck "...and the policies whose CONTENT decided the verdict" \
   "test -f '$TMP/gov/files/policies/retention.yaml' \
    && test -f '$TMP/gov/files/policies/evidence-classes.yaml'"
ck "the selector lives in policy, not in a second list inside the script" \
   "python3 -c 'import sys,yaml
m=yaml.safe_load(open(\"policies/continuity-mirror.yaml\"))
cl={c[\"id\"]: c for c in m[\"critical_release_inventory\"][\"artifact_classes\"]}
sys.exit(0 if all(cl[i].get(\"paths\") for i in (\"schemas\",\"policies\",\"verification-tools\")) else 1)' \
    && ! grep -q 'schemas/\\*\\.schema\\.json' '$CEXPORT'"
ck "continuity-mirror.yaml now names classes for schemas, policies and tooling" \
   "python3 -c 'import sys,yaml
m=yaml.safe_load(open(\"policies/continuity-mirror.yaml\"))
ids={c[\"id\"] for c in m[\"critical_release_inventory\"][\"artifact_classes\"]}
sys.exit(0 if {\"schemas\",\"policies\",\"verification-tools\"} <= ids else 1)'"
ck "the restored export revalidates against its own aggregate" \
   "cexp --verify-governance '$TMP/gov' >/dev/null 2>&1"
ck "NON-VACUOUS: relocating the COMPLETE export leaves the aggregate unchanged" \
   "cp -R '$TMP/gov' '$TMP/gov-moved' && cexp --verify-governance '$TMP/gov-moved' >/dev/null 2>&1"

# --- C-S1  REQUIRED SABOTAGE: restoration missing one bound artifact -------
cp -R "$TMP/gov" "$TMP/gov-short"
rm -f "$TMP/gov-short/files/schemas/vex-openvex-v1.schema.json"
ck "C-S1 SABOTAGE: a restoration missing ONE bound artifact is REFUSED" \
   "! cexp --verify-governance '$TMP/gov-short' >/dev/null 2>&1"
ck "C-S1 ...naming the artifact that did not come back" \
   "says 'vex-openvex-v1.schema.json' cexp --verify-governance '$TMP/gov-short'"
cp -R "$TMP/gov" "$TMP/gov-extra"
printf 'planted\n' > "$TMP/gov-extra/files/policies/planted.yaml"
ck "C-S1 SABOTAGE: an artifact bound by no digest is REFUSED too" \
   "! cexp --verify-governance '$TMP/gov-extra' >/dev/null 2>&1"
cp -R "$TMP/gov" "$TMP/gov-drift"
printf '\n' >> "$TMP/gov-drift/files/policies/retention.yaml"
ck "C-S1 SABOTAGE: an artifact whose bytes drifted in transit is REFUSED" \
   "! cexp --verify-governance '$TMP/gov-drift' >/dev/null 2>&1"
ck "C-S1 NON-VACUOUS: the intact export still revalidates after all three" \
   "cexp --verify-governance '$TMP/gov' >/dev/null 2>&1"

# --- INTENTIONALLY UNSUPPORTED, WITH AN ENFORCED REFUSAL -------------------
# Every artifact class still carries `mirrored: false`, and that is not an
# oversight to be tidied up by editing the value: no independent mirror is
# provisioned, so `mirrored: true` would be a false statement about where a copy
# is held — and it is the one field a reader checks during an outage. The
# shortfall is real, it is declared, and setting the flag now REFUSES.
ck "the mirror is still honestly declared not-provisioned" \
   "python3 -c 'import sys,yaml
m=yaml.safe_load(open(\"policies/continuity-mirror.yaml\"))
sys.exit(0 if m[\"mirror\"][\"status\"]==\"not-provisioned\"
             and m[\"mirror\"][\"independent\"] is False else 1)'"
ck "...and the policy states the rule under which a class MAY claim to be mirrored" \
   "python3 -c 'import sys,yaml
m=yaml.safe_load(open(\"policies/continuity-mirror.yaml\"))
r=m[\"mirrored_claims\"]
sys.exit(0 if r[\"permitted_only_when\"] and r[\"enforced_by\"]==\"scripts/continuity-verify.sh\" else 1)'"
ck "the committed policy passes its own claim check" \
   "bash '$CVERIFY' --assert-mirror-claims >/dev/null 2>&1"
python3 - "policies/continuity-mirror.yaml" "$TMP/mirror-claimed.yaml" <<'PY'
import sys, yaml
m = yaml.safe_load(open(sys.argv[1]))
for c in m["critical_release_inventory"]["artifact_classes"]:
    if c["id"] in ("evidence-bundle", "vex"):
        c["mirrored"] = True
yaml.safe_dump(m, open(sys.argv[2], "w"))
PY
ck "SABOTAGE: claiming evidence-bundle and vex are mirrored with NO mirror is REFUSED" \
   "! ( MIRROR_POLICY='$TMP/mirror-claimed.yaml' bash '$CVERIFY' --assert-mirror-claims ) >/dev/null 2>&1"
ck "...naming the classes and the status that contradicts them" \
   "grep -q 'evidence-bundle' <<<\"\$( ( MIRROR_POLICY='$TMP/mirror-claimed.yaml' bash '$CVERIFY' --assert-mirror-claims ) 2>&1 )\""
python3 - "policies/continuity-mirror.yaml" "$TMP/mirror-norule.yaml" <<'PY'
import sys, yaml
m = yaml.safe_load(open(sys.argv[1]))
m.pop("mirrored_claims", None)
yaml.safe_dump(m, open(sys.argv[2], "w"))
PY
ck "SABOTAGE: deleting the rule is REFUSED, never read as permission" \
   "! ( MIRROR_POLICY='$TMP/mirror-norule.yaml' bash '$CVERIFY' --assert-mirror-claims ) >/dev/null 2>&1"
ck "NON-VACUOUS: the committed policy still passes after both sabotages" \
   "bash '$CVERIFY' --assert-mirror-claims >/dev/null 2>&1"

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
ck "REVALIDATED: the restored dispositions still re-derive from the run they were built from" \
   "vexv --vex '$TMP/restored/content/vex/openvex.json' --evidence '$ACCEPTED_NATIVE' \
      --evidence-class published-artifact --today '$DAY' >/dev/null 2>&1"
ck "REVALIDATED: the restored manifest still satisfies release-evidence-bundle-v1" \
   "python3 -c 'import json,sys
from jsonschema import Draft202012Validator
s=json.load(open(\"schemas/release-evidence-bundle-v1.schema.json\"))
m=json.load(open(sys.argv[1]))
sys.exit(0 if not list(Draft202012Validator(s).iter_errors(m)) else 1)' '$TMP/restored/manifest.json'"
ck "REVALIDATED: the restored AUTHORIZATION still satisfies post-build-authorization-v1" \
   "bash '$AUTHV' '$TMP/restored/content/authorization/post-build-authorization.json' >/dev/null 2>&1"
ck "REVALIDATED: ...and it still authorises THIS revision and THIS child set" \
   "python3 -c 'import json,sys
m=json.load(open(sys.argv[1]))
a=json.load(open(sys.argv[2]))
sys.exit(0 if a[\"source_revision\"]==m[\"source_revision\"]
             and {c[\"child_key\"] for c in a[\"children\"]}=={c[\"child_key\"] for c in m[\"children\"]} else 1)' \
      '$TMP/restored/manifest.json' '$TMP/restored/content/authorization/post-build-authorization.json'"
ck "REVALIDATED: every restored SBOM still describes the child it is filed under" \
   "python3 -c 'import json,os,sys
d=sys.argv[1]
m=json.load(open(os.path.join(d,\"manifest.json\")))
for c in m[\"children\"]:
    doc=json.load(open(os.path.join(d,c[\"sbom\"][\"file\"])))
    if c[\"manifest_digest\"] not in (doc.get(\"documentDescribes\") or []):
        sys.exit(1)
sys.exit(0)' '$TMP/restored'"
ck "REVALIDATED: the restored evidence class is still one policy promises to keep" \
   "python3 -c 'import json,sys,yaml
m=json.load(open(sys.argv[1]))
p=yaml.safe_load(open(\"policies/retention.yaml\"))
sys.exit(0 if m[\"evidence_class\"] in [c[\"evidence_class\"] for c in p[\"classes\"]] else 1)' \
      '$TMP/restored/manifest.json'"
ck "REVALIDATED: the seal still verifies against the RESTORED bytes" \
   "vsl --seal '$TMP/seal.json' --bundle '$TMP/restored' --pubkey '$TMP/test.pub' \
      --version v2026.08.25 --today '$DAY' >/dev/null 2>&1"

# --- X-S1  REQUIRED SABOTAGE: restoration missing one bound artifact -------
ARCH_DIR="$(dirname "$(grep -m1 "/$BID\$" "$TMP/archive/INDEX.sha256" | awk '{print $2}')")"
chmod -R u+w "$TMP/archive"
cp -R "$TMP/archive" "$TMP/archive-b"
cp -R "$TMP/archive" "$TMP/archive-c"
python3 - "$TMP/archive/$ARCH_DIR/$BID" <<'PY'
import glob, json, os, sys
p = sorted(glob.glob(os.path.join(sys.argv[1], "content/children/*.json")))[0]
d = json.load(open(p))
d["record"]["severity_counts"] = {"HIGH": 0}
json.dump(d, open(p, "w"), indent=2)
PY
ck "X-S1 SABOTAGE: a restored archive whose content drifted is REFUSED at restore" \
   "! arch restore --archive-root '$TMP/archive' --bundle-id '$BID' --dest '$TMP/r2' >/dev/null 2>&1"
ck "X-S1 ...for the restored-copy-does-not-verify diagnostic" \
   "says 'restored copy does not verify' \
      arch restore --archive-root '$TMP/archive' --bundle-id '$BID' --dest '$TMP/r3'"
printf '%s  SHA256SUMS\n' "$(printf '0%.0s' {1..64})" \
  > "$TMP/archive-b/$ARCH_DIR/$BID/BUNDLE.sha256"
ck "X-S1 SABOTAGE: an archived aggregate that no longer matches the index is REFUSED" \
   "! arch restore --archive-root '$TMP/archive-b' --bundle-id '$BID' --dest '$TMP/r4' >/dev/null 2>&1"
ck "X-S1 ...for the changed-after-indexing diagnostic" \
   "says 'changed after it was indexed' \
      arch restore --archive-root '$TMP/archive-b' --bundle-id '$BID' --dest '$TMP/r5'"
# ONE bound artifact simply absent from the archive: the restoration is short,
# not corrupt, which is the case a digest-equality check alone would miss.
rm -f "$TMP/archive-c/$ARCH_DIR/$BID/content/authorization/post-build-authorization.json"
ck "X-S1 SABOTAGE: an archive missing ONE bound artifact cannot be restored" \
   "! arch restore --archive-root '$TMP/archive-c' --bundle-id '$BID' --dest '$TMP/r6' >/dev/null 2>&1"
ck "X-S1 NON-VACUOUS: the untouched restored copy still verifies after all three" \
   "ver '$TMP/restored' >/dev/null 2>&1"

echo
echo "== stage 9: licence gate over the SAME SBOMs the bundle sealed ============"

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
   "says 'GPL-3.0-or-later' bash '$LGATE' --inventory '$TMP/inv-gpl.json'"

# WHAT THIS STAGE USED TO PIN. The gate CAN consume the release path and nothing
# made it: it read a bare directory, so an inventory could be built over any
# SPDX files at all and still satisfy the policy. Nothing tied a licence verdict
# to a shipped artifact, an evidence class or a source revision, no workflow
# invoked it, and the bundle recorded no licence fact — so the two halves never
# met on one artifact.
ck "the licence gate CONSUMES the release artifact now" \
   "bash '$LINV' --bundle '$TMP/cand' --out '$TMP/inv-bound.json' >/dev/null 2>&1"
ck "...and the inventory names the bundle, class and revision it is a verdict FOR" \
   "python3 -c 'import json,sys
i=json.load(open(sys.argv[1])); m=json.load(open(sys.argv[2]))
r=i[\"release_binding\"]
sys.exit(0 if r[\"bundle_id\"]==m[\"bundle_id\"] and r[\"evidence_class\"]==m[\"evidence_class\"]
             and r[\"source_revision\"]==m[\"source_revision\"]
             and r[\"bundle_content_checksum\"]==m[\"checksums\"][\"content_checksum\"] else 1)' \
      '$TMP/inv-bound.json' '$TMP/cand/manifest.json'"
ck "...over exactly the SBOMs the bundle sealed, not a directory somebody chose" \
   "python3 -c 'import json,os,sys
i=json.load(open(sys.argv[1])); m=json.load(open(sys.argv[2]))
sealed={os.path.basename(c[\"sbom\"][\"file\"]) for c in m[\"children\"]}
sys.exit(0 if set(i[\"sbom_files\"])==sealed else 1)' \
      '$TMP/inv-bound.json' '$TMP/cand/manifest.json'"
ck "the bound inventory passes the gate with the binding REQUIRED" \
   "bash '$LGATE' --inventory '$TMP/inv-bound.json' --require-release-binding >/dev/null 2>&1"
ck "SABOTAGE: an UNBOUND inventory is REFUSED once the binding is required" \
   "! bash '$LGATE' --inventory '$TMP/inventory.json' --require-release-binding >/dev/null 2>&1"
ck "...telling the reader what to rebuild it with" \
   "says 'license-inventory.sh --bundle' bash '$LGATE' --inventory '$TMP/inventory.json' --require-release-binding"
ck "SABOTAGE: a candidate's licence verdict presented as a published release is REFUSED" \
   "! bash '$LGATE' --inventory '$TMP/inv-bound.json' --evidence-class published-artifact >/dev/null 2>&1"
ck "NON-VACUOUS: it passes for the class it was actually built for" \
   "bash '$LGATE' --inventory '$TMP/inv-bound.json' --evidence-class staged-candidate >/dev/null 2>&1"
# A --self-test invocation is the gate testing ITSELF. It proves the script
# runs; it proves nothing about any workflow gating a release on licence
# policy. The previous form of this assertion was
#     grep -rq 'scripts/license/' .github/workflows/
# which matched exactly one line — ci.yml's `--self-test` step — so it was
# literally true, substantively false, and green forever regardless of whether
# the gate was ever wired to a real artifact. That is the vacuous-check class
# this suite exists to eliminate, so it does not get to live inside it.
_lic_real() {
  # any invocation of anything under scripts/license/ that is NOT a self-test
  grep -rn 'scripts/license/' .github/workflows/ 2>/dev/null | grep -v -- '--self-test'
}
_lic_policy_real() {
  # any invocation of the IMAGE-SBOM gate specifically that is NOT a self-test
  grep -rn 'scripts/license/assert-license-policy.sh' .github/workflows/ 2>/dev/null \
    | grep -v -- '--self-test'
}
# PROMOTED FROM gap TO ck BY #120's repository-material work. This line used to
# read "no workflow invokes the licence gate against a real inventory" and it
# was true: ci.yml carried exactly one `--self-test` step. ci.yml now runs
# scripts/license/assert-repository-material.sh against the committed
# policies/repository-material.yaml over the real tree, in the REQUIRED
# `repo structure` job. That is a real inventory and a real artifact.
#
# It closes the REPOSITORY half and only the repository half. The image half is
# re-pinned immediately below, narrower and still true, because promoting a gap
# by widening what counts as closing it is how a suite starts lying.
ck "a workflow invokes a licence gate against a REAL inventory, not only --self-test" \
   "[ -n \"\$(_lic_real)\" ]"
ck "...and the real invocation is the repository-material gate over the tree" \
   "_lic_real | grep -q 'assert-repository-material.sh'"
ck "...in the REQUIRED 'repo structure' job, not an optional one" \
   "python3 -c 'import sys
s=open(\".github/workflows/ci.yml\").read()
i=s.find(\"assert-repository-material.sh\")
sys.exit(0 if i>0 and \"repo structure\" in s[:i] else 1)'"
ck "...and that gate REFUSES a tree whose copied material is unaccounted for" \
   "says 'RM-UNINVENTORIED-MATERIAL' bash scripts/license/assert-repository-material.sh --self-test"

# PROMOTED FROM gap TO ck. These two lines used to read
#
#   GAP - no workflow invokes the IMAGE-SBOM licence gate against a real inventory
#   GAP - ...ci.yml runs assert-license-policy.sh ONLY as --self-test, which
#         gates no image
#
# and they were true: ci.yml carried exactly one licence-policy line and it was
# a self-test. .github/workflows/stage-and-authorize.yml now carries a
# licence-authorization job that produces per-child SBOMs against the digests
# the registry resolved, binds each one to image, version, platform, immutable
# digest and source revision, and runs assert-license-policy.sh over the
# resulting inventory with --require-image-binding. That is a real inventory
# over real candidate images.
#
# THE PREDICATE IS UNCHANGED. It is still the same non-self-test search, so the
# promotion cannot be an artefact of widening what counts as closing it — which
# is how a suite starts lying. What is added is the part a grep cannot do:
# tests/license/test_image_sbom_licence_gate.sh EXECUTES the workflow's own
# extracted step bodies against the accepted production run's real immutable
# child digests, and proves that removing the job recreates exactly the two
# lines above. A grep proves a name is present; only execution proves a gate
# runs, is handed inputs, and has its answer read.
ck "a workflow invokes the IMAGE-SBOM licence gate against a real inventory" \
   "[ -n \"\$(_lic_policy_real)\" ]"
# A grep sees ONE line; the invocation spans several. The step body is read
# whole, through the same YAML parser the executed proofs use.
_lic_step() {
  python3 tests/lib/workflow_step.py .github/workflows/stage-and-authorize.yml \
    licence-authorization image_policy --run 2>/dev/null
}
ck "...not as --self-test, and handed an --inventory it did not invent" \
   "_lic_step | grep -q -- '--inventory' \
    && _lic_step | grep -q -- '--require-image-binding' \
    && ! _lic_step | grep -q -- '--self-test'"
ck "...in stage-and-authorize.yml, the release path — CI is buildless and has no image" \
   "_lic_policy_real | grep -q 'stage-and-authorize.yml'"
ck "...while ci.yml's --self-test line survives, unchanged and still gating no image" \
   "grep -rq -- 'scripts/license/assert-license-policy.sh --self-test' .github/workflows/ci.yml"
ck "...and the executed proof of that invocation is itself in the REQUIRED job" \
   "python3 -c 'import sys, yaml
wf = yaml.safe_load(open(\".github/workflows/ci.yml\"))
for jid, job in (wf[\"jobs\"] or {}).items():
    if (job.get(\"name\") or jid) != \"repo structure\":
        continue
    for st in job.get(\"steps\") or []:
        if \"test_image_sbom_licence_gate.sh\" in (st.get(\"run\") or \"\"):
            sys.exit(0)
sys.exit(1)'"
ck "...and the image gate REFUSES an inventory that names no candidate at all" \
   "says 'carries no image_binding' \
      bash '$LGATE' --inventory '$TMP/inventory.json' --require-image-binding"
ck "NON-VACUOUS: the same gate still passes on that inventory without the binding" \
   "bash '$LGATE' --inventory '$TMP/inventory.json' >/dev/null 2>&1"

# WHAT REMAINS PINNED, narrowly. The composed licence authorization runs in the
# RELEASE path, on a dispatch that stages candidate images. The required CI
# path executes the workflow's extracted gate bodies against the accepted
# production evidence — it does not, and buildlessly cannot, execute the
# workflow itself. Closing that would need CI to hold a candidate image, which
# is the boundary trusted-validation.yml exists to keep it away from.
# Structural, not a grep: ci.yml MENTIONS the workflow in a comment (the CI
# gate step explains where the candidate images live). Mentioning is not
# running, and this gap is about running.
gap "the REQUIRED CI path does not itself RUN stage-and-authorize.yml" \
    "python3 -c 'import sys, yaml
wf = yaml.safe_load(open(\".github/workflows/ci.yml\"))
for jid, job in (wf[\"jobs\"] or {}).items():
    if \"stage-and-authorize\" in str(job.get(\"uses\") or \"\"):
        sys.exit(1)
    for st in job.get(\"steps\") or []:
        body = (st.get(\"run\") or \"\") + str(st.get(\"uses\") or \"\")
        if \"workflow run\" in body or \"stage-and-authorize.yml\" in str(st.get(\"uses\") or \"\"):
            sys.exit(1)
sys.exit(0)'"
ck "NON-VACUOUS: the real-invocation search would match a non-self-test call" \
   "printf 'run: bash scripts/license/assert-license-policy.sh --inventory x\n' > '$TMP/wf-probe' &&
    grep -n 'scripts/license/' '$TMP/wf-probe' | grep -vq -- '--self-test'"
ck "the bundle RECORDS a licence fact, so the two meet on one artifact" \
   "grep -qi 'licen' schemas/release-evidence-bundle-v1.schema.json \
    && python3 -c 'import json,sys
m=json.load(open(sys.argv[1]))
l=m[\"licenses\"]
sys.exit(0 if l[\"present\"] and l[\"distinct_licenses\"]
             and l[\"policy_file\"]==\"policies/license-policy.yaml\" else 1)' '$TMP/cand/manifest.json'"
ck "...as a FACT inside checksum coverage, with the verdict left to the gate" \
   "grep -q 'content/licenses/license-facts.json' '$TMP/cand/SHA256SUMS' \
    && python3 -c 'import json,sys
d=json.load(open(sys.argv[1]))
sys.exit(0 if d[\"record_type\"]==\"evidence-bundle-license-facts\"
             and d[\"gate\"]==\"scripts/license/assert-license-policy.sh\" else 1)' \
      '$TMP/cand/content/licenses/license-facts.json'"
ck "...and policies/license-policy.yaml is among the digests the bundle seals" \
   "python3 -c 'import json,sys
m=json.load(open(sys.argv[1]))
sys.exit(0 if \"policies/license-policy.yaml\" in m[\"policy_digests\"] else 1)' '$TMP/cand/manifest.json'"

echo
echo "== stage 10: reproducibility has a value to join on ======================="

ck "the committed build-input lock verifies offline" \
   "bash scripts/repro-lock.sh verify tests/reproducibility/evidence/php-cli-8.4-linux-amd64.lock.json >/dev/null 2>&1"
ck "the guarantee gate passes on the committed tree" \
   "bash scripts/repro-guarantees.sh >/dev/null 2>&1"
ck "the evidence-class contract REQUIRES a build-input identity" \
   "python3 -c 'import json,sys
s=json.load(open(\"schemas/evidence-class-v1.schema.json\"))
sys.exit(0 if \"build_input_digest\" in s[\"required\"] else 1)'"

# WHAT THIS STAGE USED TO PIN. The bundle carried no build-input identity for
# ANY child, and the lock's only image identity is null — so there was no value
# on which a reproducibility lock and a shipped image could ever be joined.
# reproducibility.yaml was not among the policies the bundle digested either, so
# a reproducibility claim could be reworded with no bundle digest changing.
ck "the bundle carries a build-input identity FIELD for every child" \
   "python3 -c 'import json,sys
m=json.load(open(sys.argv[1]))
sys.exit(0 if all(\"build_input_digest\" in c for c in m[\"children\"]) else 1)' \
      '$TMP/restored/manifest.json'"
ck "...and release-evidence-bundle-v1 REQUIRES it, so it cannot be dropped again" \
   "python3 -c 'import json,sys
s=json.load(open(\"schemas/release-evidence-bundle-v1.schema.json\"))
sys.exit(0 if \"build_input_digest\" in s[\"properties\"][\"children\"][\"items\"][\"required\"] else 1)'"
ck "policies/reproducibility.yaml IS among the policies the bundle digests" \
   "python3 -c 'import json,sys
m=json.load(open(sys.argv[1]))
sys.exit(0 if \"policies/reproducibility.yaml\" in m[\"policy_digests\"] else 1)' \
      '$TMP/restored/manifest.json'"
ck "the generator names reproducibility, so the claim cannot be reworded silently" \
   "grep -q 'reproducibility' '$GEN'"

# INTENTIONALLY UNSUPPORTED FOR THIS RUN, WITH AN ENFORCED REFUSAL. The
# acceptance run predates build-input locking, and a lock emitted from a locally
# built image records manifest_digest as an explicit null rather than inventing
# one. Neither is fabricated; both are declared, and the join REFUSES.
ck "the bundle STATES that no child is joinable, and what would close it" \
   "python3 -c 'import json,sys
r=json.load(open(sys.argv[1]))[\"reproducibility\"]
sys.exit(0 if r[\"joinable\"] is False and r[\"children_with_build_input_digest\"]==0
             and r[\"children_total\"]>0 and \"REFUSES\" in r[\"note\"] else 1)' \
      '$TMP/restored/manifest.json'"
ck "SABOTAGE: binding a lock that names NO shipped image is REFUSED" \
   "! bash scripts/repro-lock.sh bind \
      tests/reproducibility/evidence/php-cli-8.4-linux-amd64.lock.json '$TMP/cand' >/dev/null 2>&1"
ck "...saying WHICH side of the join is missing" \
   "says 'manifest_digest = null' bash scripts/repro-lock.sh bind \
      tests/reproducibility/evidence/php-cli-8.4-linux-amd64.lock.json '$TMP/cand'"
python3 - tests/reproducibility/evidence/php-cli-8.4-linux-amd64.lock.json \
         "$TMP/cand/manifest.json" "$TMP/lock-shipped.json" <<'PY'
import json, sys
lock = json.load(open(sys.argv[1]))
man = json.load(open(sys.argv[2]))
c = [x for x in man["children"]
     if x["image_label"] == "php-cli/8.4" and x["platform"] == "linux/amd64"][0]
lock["build_outputs"]["manifest_digest"] = c["manifest_digest"]
json.dump(lock, open(sys.argv[3], "w"), indent=2)
PY
ck "NON-VACUOUS: give the lock a shipped digest and the refusal MOVES to the other side" \
   "says 'build_input_digest = null' bash scripts/repro-lock.sh bind '$TMP/lock-shipped.json' '$TMP/cand'"
python3 - "$TMP/lock-shipped.json" "$TMP/lock-foreign.json" <<'PY'
import json, sys
lock = json.load(open(sys.argv[1]))
lock["build_outputs"]["manifest_digest"] = "sha256:" + "a" * 64
json.dump(lock, open(sys.argv[2], "w"), indent=2)
PY
ck "SABOTAGE: a lock naming a digest this bundle never shipped is REFUSED" \
   "says 'no child with that digest' bash scripts/repro-lock.sh bind '$TMP/lock-foreign.json' '$TMP/cand'"

echo
echo "== stage 11: repository governance REQUIRES the new checks ================"

ck "the required-check policy is internally consistent with the workflows it names" \
   "bash scripts/assert-required-checks.sh >/dev/null 2>&1"
for s in scripts/license/assert-license-policy.sh scripts/cra/assert-cra-controls.sh \
         scripts/continuity-verify.sh scripts/repro-guarantees.sh \
         scripts/release/generate-evidence-bundle.sh; do
  ck "a required check now DIRECTLY produces $s" \
     "grep -rq -- '$s' .github/workflows/"
done
ck "NON-VACUOUS: a script no workflow names is still not found" \
   "! grep -rq 'scripts/this-subsystem-is-not-wired.sh' .github/workflows/"
ck "those direct gates live in the job whose name is a REQUIRED pr check" \
   "python3 -c 'import sys,yaml
w=yaml.safe_load(open(\".github/workflows/ci.yml\"))
p=yaml.safe_load(open(\"policies/required-release-checks.yaml\"))
job=w[\"jobs\"][\"structure\"]
runs=\" \".join(str(s.get(\"run\") or \"\") for s in job[\"steps\"])
need=[\"scripts/license/assert-license-policy.sh\",\"scripts/cra/assert-cra-controls.sh\",
      \"scripts/continuity-verify.sh\",\"scripts/repro-guarantees.sh\",
      \"scripts/release/generate-evidence-bundle.sh\"]
sys.exit(0 if all(n in runs for n in need)
             and job[\"name\"] in p[\"pr_required_checks\"] else 1)'"
# macro-validate stays LOCAL, deliberately. Its own header calls it "the gate a
# maintainer runs before pushing", and it invokes scripts/release-dry-run.sh;
# making it a CI entry point would import that scope into every pull request.
# The real shortfall was that the subsystems it wires were gated only
# transitively, and each is now gated directly above — so the fix is the direct
# wiring, not promoting the local harness.
ck "macro-validate remains the pre-push maintainer harness, not a CI entry point" \
   "grep -q 'the gate a maintainer runs before pushing' scripts/macro-validate.sh \
    && grep -q 'release-dry-run' scripts/macro-validate.sh \
    && python3 -c 'import glob,sys,yaml
# Read the RUN STEPS, not the file text: ci.yml mentions macro-validate in a
# comment explaining why the subsystems are wired individually, and a bare grep
# would read that explanation as an invocation.
for f in glob.glob(\".github/workflows/*.yml\"):
    w=yaml.safe_load(open(f)) or {}
    for j in (w.get(\"jobs\") or {}).values():
        for st in (j.get(\"steps\") or []):
            if \"macro-validate\" in str(st.get(\"run\") or \"\"):
                sys.exit(1)
sys.exit(0)'"
ck "...and every subsystem it gates locally is independently gated in CI" \
   "python3 -c 'import re,sys
mv=open(\"scripts/macro-validate.sh\").read()
import glob
wf=\"\".join(open(f).read() for f in glob.glob(\".github/workflows/*.yml\"))
need=[\"scripts/license/assert-license-policy.sh\",\"scripts/cra/assert-cra-controls.sh\",
      \"scripts/continuity-verify.sh\",\"scripts/repro-guarantees.sh\",
      \"scripts/release/assert-evidence-class.sh\"]
sys.exit(0 if all(n in mv and n in wf for n in need) else 1)'"
ck "the offline suite that transitively covers them is STILL in CI" \
   "grep -rq 'tests/run-all.sh' .github/workflows/"
ck "...so losing either the transitive chain or a direct gate is a red check" \
   "python3 -c 'import sys,yaml
p=yaml.safe_load(open(\"policies/required-release-checks.yaml\"))
sys.exit(0 if \"repo structure\" in p[\"pr_required_checks\"] else 1)'"

# THIS FILE'S OWN PLACE IN THE CHAIN. run-all discovered it by pattern and
# nothing named it, and test_subsystem_ci_coverage.sh deliberately skips
# tests/integration/* so it could not count as coverage either — so nothing
# asserted the presence of the only test that checks the composition.
ck "tests/run-all.sh NAMES this test as required, so a rename cannot be silent" \
   "grep -q 'tests/integration/test_evidence_path_e2e.sh' tests/run-all.sh"
ck "...and run-all's discovery actually finds it" \
   "grep -qx -- 'tests/integration/test_evidence_path_e2e.sh' <<<\"\$(find tests -name 'test_*.sh' | sort)\""
ck "the subsystem CI-coverage control binds this file explicitly" \
   "grep -q 'REQUIRED_INTEGRATION' tests/governance/test_subsystem_ci_coverage.sh \
    && grep -q 'tests/integration/test_evidence_path_e2e.sh' tests/governance/test_subsystem_ci_coverage.sh"
ck "...WITHOUT relaxing the exclusion that stops one file covering every subsystem" \
   "grep -q 'tests/integration/\\*) continue' tests/governance/test_subsystem_ci_coverage.sh"
# NON-VACUITY: removing this file must turn that control red. Proven on a
# DISPOSABLE COPY — the ambient checkout is never touched.
ck "NON-VACUOUS: deleting this test is DETECTED by the coverage control" \
   "d=\$(mktemp -d) && cp -R tests \"\$d/\" \
    && rm -f \"\$d/tests/integration/test_evidence_path_e2e.sh\" \
    && ! ( cd \"\$d\" && bash tests/governance/test_subsystem_ci_coverage.sh ) >/dev/null 2>&1 \
    && ( cd \"\$d\" && bash tests/governance/test_subsystem_ci_coverage.sh 2>&1 ) \
       | grep -q 'FAIL - exists: tests/integration/test_evidence_path_e2e.sh' \
    && rm -rf \"\$d\""

echo
echo "== stage 12: no stale matrix assumption outside a declared boundary ======="

ck "MATRIX_COUNT still agrees with MATRIX_IMAGES" \
   "[ \"\$(matrix_images | wc -l | tr -d ' ')\" = \"\$MATRIX_COUNT\" ]"
ck "the accepted run, the bundle and the seal all derive from MATRIX_COUNT" \
   "[ \"\$(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1]))[\"promoted_digests\"]))' '$TMP/seal.json')\" = '$CHILDREN' ]"
ck "PHP 8.5 is on disk but deliberately outside the shipping matrix" \
   "test -f images/php-cli/8.5/Dockerfile && ! matrix_images | grep -q '8.5'"

# --- M-S1..M-S3  REQUIRED SABOTAGE: PHP 8.5 in a production bundle ---------
# INTENTIONALLY UNSUPPORTED, AND REFUSED AT EVERY LAYER. The 8.5 images exist,
# are contracted and are tested, but they DO NOT BUILD (policies/lifecycle.yaml,
# php-8.5), so an 8.5 line must be unable to enter a release manifest, an
# authorization, or a bundle's bill of materials. The schema's two literals are
# no longer an unchecked assumption: assert-image-matrix.sh compares both
# against MATRIX_IMAGES on every pull request.
ck "M-S1 release-manifest.schema.json still pins the matrix size" \
   "python3 -c 'import json,sys
s=json.load(open(\"schemas/release-manifest.schema.json\"))[\"properties\"][\"images\"]
sys.exit(0 if s.get(\"minProperties\")==s.get(\"maxProperties\")==int(sys.argv[1]) else 1)' \"\$MATRIX_COUNT\""
ck "M-S1 ...and that literal is now ASSERTED against MATRIX_IMAGES by a shipped check" \
   "grep -q 'Release-manifest schema boundary' scripts/assert-image-matrix.sh \
    && bash scripts/assert-image-matrix.sh >/dev/null 2>&1"
ck "M-S2 an 8.5 key stays UNREPRESENTABLE in a release manifest, on purpose" \
   "python3 -c 'import json,re,sys
s=json.load(open(\"schemas/release-manifest.schema.json\"))[\"properties\"][\"images\"]
pat=list(s[\"patternProperties\"])[0]
sys.exit(0 if s.get(\"additionalProperties\") is False
             and not re.match(pat, \"php-cli-8.5\") else 1)'"
ck "M-S2 ...and the schema DOCUMENTS that the exclusion is deliberate" \
   "python3 -c 'import json,sys
d=json.load(open(\"schemas/release-manifest.schema.json\"))[\"properties\"][\"images\"][\"description\"]
sys.exit(0 if \"8.5\" in d and \"assert-image-matrix.sh\" in d else 1)'"
ck "M-S2 NON-VACUOUS: every SHIPPING image key does match that pattern" \
   "python3 -c 'import json,re,sys
s=json.load(open(\"schemas/release-manifest.schema.json\"))[\"properties\"][\"images\"]
pat=list(s[\"patternProperties\"])[0]
toks=sys.argv[1].split()
keys=[(t.split(\":\")[0] if t.endswith(\":prod\") else t.replace(\":\",\"-\")) for t in toks]
sys.exit(0 if all(re.match(pat,k) for k in keys) else 1)' \"\$MATRIX_IMAGES\""
# SABOTAGE at the bundle layer: widening the schema to accept 8.5 must be caught.
python3 - "schemas/release-manifest.schema.json" "$TMP/schema-85.json" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
im = s["properties"]["images"]
old = list(im["patternProperties"])[0]
im["patternProperties"] = {
    r"^(php-(cli|fpm|worker|frankenphp)-8\.[345]|nginx|caddy)$": im["patternProperties"][old]}
json.dump(s, open(sys.argv[2], "w"), indent=2)
PY
ck "M-S3 SABOTAGE: widening the pattern to accept 8.5 is DETECTED, not silent" \
   "python3 -c 'import json,re,sys
s=json.load(open(sys.argv[1]))[\"properties\"][\"images\"]
pat=list(s[\"patternProperties\"])[0]
sys.exit(0 if re.match(pat, \"php-cli-8.5\") else 1)' '$TMP/schema-85.json' \
    && ! grep -q '8\\.\\[345\\]' schemas/release-manifest.schema.json"
ck "M-S3 ...the shipped check refuses that widened schema" \
   "d=\$(mktemp -d) && cp -R scripts images schemas contracts policies \"\$d/\" 2>/dev/null
    cp '$TMP/schema-85.json' \"\$d/schemas/release-manifest.schema.json\"
    ! ( cd \"\$d\" && bash scripts/assert-image-matrix.sh ) >/dev/null 2>&1
    rc=\$?; rm -rf \"\$d\"; [ \"\$rc\" -eq 0 ]"
ck "M-S3 NON-VACUOUS: the committed schema passes the same check" \
   "bash scripts/assert-image-matrix.sh >/dev/null 2>&1"

echo
echo "== ambient safety ========================================================="

ck "the test mutated nothing tracked in the checkout" \
   "[ -z \"\$(git status --porcelain -- policies scripts schemas docs contracts images .github)\" ]"
ck "every byte it wrote is under one disposable root" \
   "[ \"\${TMP#/}\" != \"\$TMP\" ] && [ -d '$TMP' ]"

echo
echo "----"
printf 'assertions: %d proven, %d pinned gaps\n' "$nck" "$ngap"
if [ "$ngap" -ne 0 ]; then
  echo "NOTE: every pinned gap must name what would close it. Zero is the goal;"
  echo "      a gap that silently starts passing is a gap nobody notices was fixed."
fi
[ "$fail" -eq 0 ] && echo "test_evidence_path_e2e: PASS" || echo "test_evidence_path_e2e: FAIL"
exit "$fail"
