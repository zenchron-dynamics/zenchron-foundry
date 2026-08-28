#!/usr/bin/env bash
# =============================================================================
# scripts/release/validate-authorization-record.sh <record.json> [schema.json]
# -----------------------------------------------------------------------------
# Validate an emitted authorization record against schema v1 AT RUN TIME.
#
# The schema was previously enforced only in offline tests and, hypothetically,
# by a future consumer. The producing workflow ran the aggregator, printed the
# JSON and exited — so every claim of the form "an invalid scope / exposure flag
# / field type / PASS-with-failed-children fails schema validation" was true of
# the tests and NOT of the thing that actually emits records.
#
# The aggregator and the schema check different things and neither subsumes the
# other. The aggregator decides the verdict from the evidence; the schema
# constrains the SHAPE, including fields the aggregator never inspects (an empty
# staging_tag, say). Both must hold.
#
# BOTH PASS AND FAIL RECORDS MUST VALIDATE. A refused authorization is exactly
# when the record gets read, so a malformed FAIL is as useless as a malformed
# PASS.
#
# --require-licence-authorization <file>
# -----------------------------------------------------------------------------
# THE LICENCE VERDICT IS AN INPUT TO THIS DECISION, not a report filed beside it.
#
# The image half of the licence gate used to have no consumer at all: ci.yml ran
# assert-license-policy.sh as `--self-test`, which gates no image. Producing a
# licence verdict and leaving it in an artifact would repeat that shape one layer
# out, because a step whose output nothing reads is indistinguishable from a step
# that did not run. So the canonical record does NOT validate unless a composed
# licence authorization is presented, PASSES, and is BOUND to this exact record:
#
#   AR-LICENCE-EVIDENCE-ABSENT   no licence authorization was presented at all
#   AR-LICENCE-MALFORMED         it is not a licence-authorization v1 record
#   AR-LICENCE-REFUSED           it is present and its verdict is not PASS
#   AR-LICENCE-UNBOUND           it is a verdict about a DIFFERENT record
#   AR-LICENCE-REVISION-MISMATCH it is a verdict about a different source tree
#   AR-LICENCE-INCOMPLETE        it covers fewer children than it expected
#   AR-LICENCE-EXPOSURE          it claims to authorize public exposure
#
# ABSENT IS A REFUSAL, NEVER A SKIP. That is the failure mode this flag exists
# for: a gate that quietly passes when its evidence did not arrive is worse than
# no gate, because it reports coverage it does not have.
#
# --require-notice-bundle <file>
# -----------------------------------------------------------------------------
# A LICENCE VERDICT IS NOT A NOTICE. The licence gate answers "is every component
# accounted for"; #120 also asks for "third-party notices and ... corresponding
# license texts/source-offer obligations", and a candidate can satisfy the first
# while owing every one of the second. So the canonical record ALSO does not
# validate unless a notice bundle is presented, is COMPLETE, PASSES, and is bound
# to this exact record:
#
#   AR-NOTICE-EVIDENCE-ABSENT    no notice bundle was presented at all
#   AR-NOTICE-MALFORMED          it is not a foundry.notice-bundle/v1 manifest
#   AR-NOTICE-DRAFT              it is a draft; a draft satisfies nothing
#   AR-NOTICE-INCOMPLETE         its status is not `complete`
#   AR-NOTICE-REFUSED            its verdict is not PASS
#   AR-NOTICE-UNBOUND            it is a bundle for a DIFFERENT record
#   AR-NOTICE-REVISION-MISMATCH  it is a bundle for a different source tree
#   AR-NOTICE-MATRIX             it covers fewer children than the record declares
#   AR-NOTICE-DIGEST-MISMATCH    it names a digest this record does not stage
#   AR-NOTICE-PLATFORM-MISMATCH  it names a platform this record does not stage
#   AR-NOTICE-ARTIFACT-DRIFT     an emitted artifact is missing or not its hash
#   AR-PUBLICATION-AUTHORITY-MISSING  nobody has authorized distribution (#98)
#
# THE COMPOSITION, in one sentence: a licence PASS is insufficient without a
# complete notice bundle, a notice PASS cannot override a refused licence
# verdict, and publication authority refuses independently of both. The last of
# those is why this validator refuses today and will keep refusing until an owner
# records a decision in policies/license-policy.yaml — which is the fail-closed
# behaviour, not a defect in it.
# =============================================================================
set -euo pipefail
_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

LICENCE=""
LICENCE_REQUIRED=0
NOTICE=""
NOTICE_REQUIRED=0
_args=()
while [ $# -gt 0 ]; do
  case "$1" in
    --require-licence-authorization)
      # An EMPTY value is not "not asked for": the caller asked, and an empty
      # path is exactly the evidence-absent case that must refuse.
      [ $# -ge 2 ] || { echo "REFUSE: --require-licence-authorization needs a path" >&2; exit 2; }
      LICENCE="$2"; LICENCE_REQUIRED=1; shift 2 ;;
    --require-notice-bundle)
      [ $# -ge 2 ] || { echo "REFUSE: --require-notice-bundle needs a path" >&2; exit 2; }
      NOTICE="$2"; NOTICE_REQUIRED=1; shift 2 ;;
    *) _args+=("$1"); shift ;;
  esac
done
set -- ${_args[@]+"${_args[@]}"}

RECORD="${1:?usage: validate-authorization-record.sh <record.json> [schema.json] [--require-licence-authorization FILE] [--require-notice-bundle FILE]}"
SCHEMA="${2:-$_d/../../schemas/post-build-authorization-v1.schema.json}"

[ -s "$RECORD" ] || { echo "REFUSE: no record at '$RECORD'" >&2; exit 1; }
[ -s "$SCHEMA" ] || { echo "REFUSE: no schema at '$SCHEMA'" >&2; exit 1; }

# A missing validator must NOT pass. Turning "the tool is absent" into success is
# the fail-open shape this repository keeps removing.
python3 -c 'import jsonschema' 2>/dev/null \
  || { echo "REFUSE: python jsonschema is required to validate the record" >&2; exit 1; }

python3 - "$SCHEMA" "$RECORD" <<'PY'
import json, sys, jsonschema
schema = json.load(open(sys.argv[1]))
doc = json.load(open(sys.argv[2]))
v = jsonschema.Draft202012Validator(schema)
errs = sorted(v.iter_errors(doc), key=lambda e: list(e.path))
if errs:
    print("REFUSE: authorization record does not satisfy schema v1", file=sys.stderr)
    for e in errs:
        loc = "/".join(str(x) for x in e.path) or "<root>"
        print("  - %s: %s" % (loc, e.message), file=sys.stderr)
    sys.exit(1)
print("record satisfies schema v1 (verdict=%s, children=%d)"
      % (doc.get("verdict"), len(doc.get("children", []))))
PY

# --- the composed licence authorization, CONSUMED -----------------------------
if [ "$LICENCE_REQUIRED" = 1 ]; then
  AR_RECORD="$RECORD" AR_LICENCE="$LICENCE" python3 <<'LICPY'
import hashlib, json, os, sys

rec_p = os.environ["AR_RECORD"]
lic_p = os.environ["AR_LICENCE"]


def refuse(code, msg):
    sys.stderr.write("REFUSE [%s]: %s\n" % (code, msg))
    raise SystemExit(1)


if not lic_p or not os.path.isfile(lic_p) or os.path.getsize(lic_p) == 0:
    refuse("AR-LICENCE-EVIDENCE-ABSENT",
           "a composed licence authorization was REQUIRED and none was presented "
           "(%s). An absent evidence class is a refusal, never a skip: a gate that "
           "passes when its evidence did not arrive reports coverage it does not "
           "have" % (lic_p or "<empty path>"))
try:
    lic = json.load(open(lic_p))
except ValueError as e:
    refuse("AR-LICENCE-MALFORMED", "%s is not readable JSON: %s" % (lic_p, e))

if lic.get("record_type") != "licence-authorization" or lic.get("schema_version") != 1:
    refuse("AR-LICENCE-MALFORMED",
           "%s is not a licence-authorization v1 record (record_type=%r, "
           "schema_version=%r)"
           % (lic_p, lic.get("record_type"), lic.get("schema_version")))

rec = json.load(open(rec_p))
want = hashlib.sha256(open(rec_p, "rb").read()).hexdigest()
if lic.get("authorization_record_sha256") != want:
    refuse("AR-LICENCE-UNBOUND",
           "%s is a licence verdict for authorization record %s; this record "
           "hashes to %s. A verdict about another record decides nothing about "
           "this one"
           % (lic_p, str(lic.get("authorization_record_sha256"))[:16], want[:16]))

if lic.get("source_revision") != rec.get("source_revision"):
    refuse("AR-LICENCE-REVISION-MISMATCH",
           "%s is a licence verdict for source revision %s; this record was "
           "written for %s"
           % (lic_p, lic.get("source_revision"), rec.get("source_revision")))

img = lic.get("image_half") or {}
if not img.get("children_expected") \
        or img.get("children_bound") != img.get("children_expected"):
    refuse("AR-LICENCE-INCOMPLETE",
           "%s binds %s of %s expected children. A licence verdict over a partial "
           "matrix reports clean for the images it happened to see"
           % (lic_p, img.get("children_bound"), img.get("children_expected")))

if lic.get("public_exposure_authorized") is not False:
    refuse("AR-LICENCE-EXPOSURE",
           "%s claims public_exposure_authorized=%r. A licence verdict does not "
           "authorize exposure and must not be able to claim it"
           % (lic_p, lic.get("public_exposure_authorized")))

if lic.get("verdict") != "PASS":
    refuse("AR-LICENCE-REFUSED",
           "the composed licence authorization is %r (image half: binding=%s, "
           "policy=%s; repository half: %s). Both evidence classes are required "
           "and neither compensates for the other"
           % (lic.get("verdict"), img.get("binding"), img.get("policy"),
              (lic.get("repository_half") or {}).get("composed")))

print("licence authorization CONSUMED: %s, %s/%s children bound at %s"
      % (lic["verdict"], img["children_bound"], img["children_expected"],
         lic["source_revision"]))
LICPY
fi

# --- the distribution-notice bundle, CONSUMED ---------------------------------
if [ "$NOTICE_REQUIRED" = 1 ]; then
  AR_RECORD="$RECORD" AR_NOTICE="$NOTICE" \
  AR_SCHEMA="$_d/../../schemas/notice-bundle-v1.schema.json" python3 <<'NBPY'
import hashlib, json, os, sys

rec_p = os.environ["AR_RECORD"]
nb_p = os.environ["AR_NOTICE"]
schema_p = os.environ["AR_SCHEMA"]


def refuse(code, msg):
    sys.stderr.write("REFUSE [%s]: %s\n" % (code, msg))
    raise SystemExit(1)


if not nb_p or not os.path.isfile(nb_p) or os.path.getsize(nb_p) == 0:
    refuse("AR-NOTICE-EVIDENCE-ABSENT",
           "a distribution-notice bundle was REQUIRED and none was presented "
           "(%s). #120 asks for notices and corresponding licence texts and "
           "source obligations, and a candidate can satisfy the LICENCE gate "
           "while owing every one of them. An absent evidence class is a "
           "refusal, never a skip" % (nb_p or "<empty path>"))
try:
    nb = json.load(open(nb_p))
except ValueError as e:
    refuse("AR-NOTICE-MALFORMED", "%s is not readable JSON: %s" % (nb_p, e))

if nb.get("schema") != "foundry.notice-bundle/v1" or nb.get("schema_version") != 1:
    refuse("AR-NOTICE-MALFORMED",
           "%s is not a foundry.notice-bundle/v1 manifest (schema=%r, "
           "schema_version=%r)" % (nb_p, nb.get("schema"), nb.get("schema_version")))

try:
    import jsonschema
    schema = json.load(open(schema_p))
    errs = sorted(jsonschema.Draft202012Validator(schema).iter_errors(nb),
                  key=lambda e: list(e.path))
    if errs:
        refuse("AR-NOTICE-MALFORMED",
               "%s does not satisfy notice-bundle-v1: %s"
               % (nb_p, "; ".join("%s: %s" % ("/".join(str(x) for x in e.path)
                                              or "<root>", e.message)
                                  for e in errs[:4])))
except ImportError:
    refuse("AR-NOTICE-MALFORMED",
           "python jsonschema is required to validate the notice bundle; a "
           "missing validator must not turn into a skipped gate")

rec = json.load(open(rec_p))

# BOUND to this record, not merely filed beside it.
want = hashlib.sha256(open(rec_p, "rb").read()).hexdigest()
if nb.get("authorization_record_sha256") != want:
    refuse("AR-NOTICE-UNBOUND",
           "%s is a notice bundle for authorization record %s; this record "
           "hashes to %s. A bundle about another record describes another set "
           "of images"
           % (nb_p, str(nb.get("authorization_record_sha256"))[:16], want[:16]))

if nb.get("source_revision") != rec.get("source_revision"):
    refuse("AR-NOTICE-REVISION-MISMATCH",
           "%s is a notice bundle for source revision %s; this record was "
           "written for %s. Notice material from another tree describes another "
           "set of components" % (nb_p, nb.get("source_revision"),
                                  rec.get("source_revision")))

cand = nb.get("candidate") or {}
declared = rec.get("expected_matrix") or {}
want_children = declared.get("expected_children") or len(rec.get("children") or [])
if not cand.get("children_expected") or cand.get("children_bound") != cand.get("children_expected"):
    refuse("AR-NOTICE-MATRIX",
           "%s binds notice material for %s of %s children. A notice bundle over "
           "a partial matrix reports complete for the images it happened to see"
           % (nb_p, cand.get("children_bound"), cand.get("children_expected")))
if cand.get("children_expected") != want_children:
    refuse("AR-NOTICE-MATRIX",
           "%s covers %s children and this record declares %s"
           % (nb_p, cand.get("children_expected"), want_children))

by_key = {str(c.get("child_key")): c for c in rec.get("children") or []}
for c in cand.get("children") or []:
    k = str(c.get("child_key"))
    r = by_key.get(k)
    if r is None:
        refuse("AR-NOTICE-MATRIX",
               "%s carries notice material for child %r, which this record does "
               "not stage" % (nb_p, k))
    if c.get("manifest_digest") != r.get("manifest_digest"):
        refuse("AR-NOTICE-DIGEST-MISMATCH",
               "%s: child %s names digest %s and this record stages %s"
               % (nb_p, k, str(c.get("manifest_digest"))[:23],
                  str(r.get("manifest_digest"))[:23]))
    if c.get("platform") != r.get("platform"):
        refuse("AR-NOTICE-PLATFORM-MISMATCH",
               "%s: child %s names platform %r and this record stages %r"
               % (nb_p, k, c.get("platform"), r.get("platform")))

# The emitted artifacts must BE there and BE their recorded bytes. A manifest
# whose artifacts were replaced afterwards is a manifest about other files.
base = os.path.dirname(os.path.abspath(nb_p))
for name in sorted(nb.get("artifacts") or {}):
    want_h = nb["artifacts"][name]
    p = os.path.join(base, name)
    if not os.path.isfile(p) or os.path.getsize(p) == 0:
        refuse("AR-NOTICE-ARTIFACT-DRIFT",
               "%s records the artifact %s and it is absent or empty beside the "
               "manifest" % (nb_p, name))
    h = hashlib.sha256(open(p, "rb").read()).hexdigest()
    if h != want_h:
        refuse("AR-NOTICE-ARTIFACT-DRIFT",
               "%s: %s hashes to %s and the manifest records %s. A substituted "
               "notice artifact is the one thing a checksum exists to catch"
               % (nb_p, name, h[:16], str(want_h)[:16]))

if nb.get("verdict") != "PASS":
    refuse("AR-NOTICE-REFUSED",
           "the notice bundle is %r (%d finding(s): %s). A licence PASS does not "
           "compensate for a notice REFUSE and a notice PASS does not compensate "
           "for a licence REFUSE"
           % (nb.get("verdict"), nb.get("finding_count", 0),
              ", ".join(nb.get("finding_codes") or [])))

# CHECKED BEFORE the status refusal so the diagnostic is the specific one. This
# is the independent axis: the notice and source material can be complete and
# legally clear and there still be nobody who has said the images may be shipped.
if nb.get("publication_authority_present") is not True:
    refuse("AR-PUBLICATION-AUTHORITY-MISSING",
           "%s reports publication_authority_present=%r. Nobody has recorded a "
           "distribution decision in policies/license-policy.yaml, so no notice "
           "bundle can be a DISTRIBUTION notice bundle. This refusal is "
           "INDEPENDENT of the licence and notice verdicts: a complete and "
           "legally clear bundle still does not create the authority to ship it "
           "(#98)" % (nb_p, nb.get("publication_authority_present")))

if nb.get("draft") is not False:
    refuse("AR-NOTICE-DRAFT",
           "%s is a DRAFT bundle. A draft is written so a refusal can be read "
           "afterwards; it must never satisfy authorization, sealing, signing, "
           "promotion or publication" % nb_p)

if nb.get("status") != "complete":
    refuse("AR-NOTICE-INCOMPLETE",
           "%s has status %r (engineering_complete=%r, "
           "legal_review_outstanding=%r, %d finding(s): %s). Only `complete` "
           "authorizes anything"
           % (nb_p, nb.get("status"), nb.get("engineering_complete"),
              nb.get("legal_review_outstanding"), nb.get("finding_count", 0),
              ", ".join(nb.get("finding_codes") or [])))

if nb.get("satisfies_authorization") is not True:
    refuse("AR-NOTICE-REFUSED",
           "%s reports satisfies_authorization=%r with status %r. A bundle that "
           "does not claim to satisfy authorization does not satisfy it"
           % (nb_p, nb.get("satisfies_authorization"), nb.get("status")))

print("notice bundle CONSUMED: %s (%s), %s/%s children, %d artifact(s) at %s"
      % (nb["verdict"], nb["status"], cand["children_bound"],
         cand["children_expected"], len(nb.get("artifacts") or {}),
         nb["source_revision"]))
NBPY
fi
