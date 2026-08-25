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
