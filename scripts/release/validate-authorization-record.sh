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
# =============================================================================
set -euo pipefail
_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

LICENCE=""
LICENCE_REQUIRED=0
_args=()
while [ $# -gt 0 ]; do
  case "$1" in
    --require-licence-authorization)
      # An EMPTY value is not "not asked for": the caller asked, and an empty
      # path is exactly the evidence-absent case that must refuse.
      [ $# -ge 2 ] || { echo "REFUSE: --require-licence-authorization needs a path" >&2; exit 2; }
      LICENCE="$2"; LICENCE_REQUIRED=1; shift 2 ;;
    *) _args+=("$1"); shift ;;
  esac
done
set -- ${_args[@]+"${_args[@]}"}

RECORD="${1:?usage: validate-authorization-record.sh <record.json> [schema.json] [--require-licence-authorization FILE]}"
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
