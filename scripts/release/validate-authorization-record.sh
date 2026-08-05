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
# =============================================================================
set -euo pipefail
_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RECORD="${1:?usage: validate-authorization-record.sh <record.json> [schema.json]}"
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
