#!/usr/bin/env bash
# =============================================================================
# tests/release/test_child_evidence_producer.sh
# -----------------------------------------------------------------------------
# EXECUTE the workflow's own "Emit child evidence" step and check what it emits.
#
# Everything else tests the CONSUMER. The authorization harness builds child JSON
# by hand and feeds it to the aggregator, so it validates the reader while the
# writer goes unexercised — and the writer was broken:
#
#     --arg mt "$MTYPE" ... --arg mt "$META"
#     manifest_media_type: $mt, metadata_contract: $mt
#
# One jq variable, two fields, incompatible types. Every child would have carried
# a media type in metadata_contract or PASS in manifest_media_type, and the
# schema would have rejected all ten on the first real run. No amount of
# consumer-side testing could see it, because the consumer never saw this code.
#
# The same blind spot hid the path-dependent checksum: the harness computed and
# verified without ever relocating the directory, which is precisely the step
# the real workflow performs between producing and checking.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
WF=.github/workflows/stage-and-authorize.yml
SCHEMA=schemas/post-build-authorization-v1.schema.json
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# --- extract the real step --------------------------------------------------
python3 - "$WF" "$TMP/emit.sh" <<'PY'
import sys, yaml
wf, out = sys.argv[1], sys.argv[2]
d = yaml.safe_load(open(wf))
steps = d['jobs']['stage']['steps']
run = [s for s in steps if s.get('name') == 'Emit child evidence']
assert len(run) == 1, 'expected exactly one emit step'
body = run[0]['run']
assert '${{' not in body, 'unrendered expression in the emit step: %r' % body
open(out, 'w').write(body)
PY
ck "the emit step was extracted" "test -s '$TMP/emit.sh'"

DIG="sha256:$(printf 'b%.0s' {1..64})"
MT="application/vnd.oci.image.manifest.v1+json"

emit() { # emit <workdir> [META] -> emits into <workdir>/evidence/out
  local w="$1" meta="${2:-PASS}"
  mkdir -p "$w/evidence/child"
  printf 'smoke log\n'  > "$w/evidence/child/smoke.log"
  printf '{"a":1}\n'    > "$w/evidence/child/oci-labels.json"
  ( cd "$w" || exit 1
    ln -sfn "$ROOT/scripts" scripts
    # Run it the way the runner does: bash -e.
    LABEL="php-fpm/8.3" PLATFORM="linux/amd64" TAG="php-fpm-8.3-r7-a1-sabc1234-amd64" \
    DIGEST_REF="ghcr.io/zenchron-dynamics/foundry-staging@${DIG}" \
    DIGEST="$DIG" RESOLVED="$DIG" MTYPE="$MT" \
    VIS="private" CARCH="amd64" DB="db@2026-08-06" \
    SMOKE="PASS" SCAN="PASS" RECON="PASS" META="$meta" \
    GITHUB_SHA="$(printf 'a%.0s' {1..40})" \
    GITHUB_REPOSITORY="zenchron-dynamics/zenchron-foundry" \
    GITHUB_RUN_ID=7 GITHUB_RUN_ATTEMPT=1 \
    bash -e "$TMP/emit.sh" >"$w/emit.log" 2>&1 )
}

W="$TMP/w1"; emit "$W"; rc=$?
ck "the emit step runs to completion under bash -e" "[ $rc -eq 0 ]"
J="$W/evidence/out/php-fpm-8.3.json"
ck "it writes the child record at the slugged path" "test -s '$J'"

# --- THE defect: two fields, two values -------------------------------------
ck "manifest_media_type carries the MEDIA TYPE" \
   "[ \"\$(jq -r .manifest_media_type '$J')\" = '$MT' ]"
ck "metadata_contract carries the VERDICT" \
   "[ \"\$(jq -r .metadata_contract '$J')\" = PASS ]"
ck "the two fields are not aliased to one value" \
   "[ \"\$(jq -r .manifest_media_type '$J')\" != \"\$(jq -r .metadata_contract '$J')\" ]"

# and they move independently
W2="$TMP/w2"; emit "$W2" FAIL
J2="$W2/evidence/out/php-fpm-8.3.json"
ck "metadata_contract follows META, not the media type" \
   "[ \"\$(jq -r .metadata_contract '$J2')\" = FAIL ]"
ck "...while manifest_media_type is unchanged" \
   "[ \"\$(jq -r .manifest_media_type '$J2')\" = '$MT' ]"

# --- the emitted child must satisfy the published schema --------------------
ck "the emitted child validates against the child schema" \
   "python3 -c \"
import json, jsonschema
s=json.load(open('$SCHEMA'))
child=s['\\\$defs']['child']
child['\\\$schema']='https://json-schema.org/draft/2020-12/schema'
jsonschema.validate(json.load(open('$J')), child)\""

for f in image_label platform staging_tag digest_reference manifest_digest \
         manifest_media_type tag_resolved_digest visibility config_architecture \
         trivy_db_identity source_revision workflow_run_id workflow_run_attempt \
         repository smoke_test scan reconciliation metadata_contract evidence_sha256; do
  ck "emits $f" "jq -e 'has(\"$f\")' '$J' >/dev/null"
done

# --- the evidence bundle travels with it ------------------------------------
ck "the evidence directory is copied beside the record" \
   "test -d '$W/evidence/out/php-fpm-8.3-evidence'"

# --- relocation: the exact transition the workflow performs -----------------
# Produce under evidence/child, collect into authorization/child-evidence/, then
# recompute. A path-dependent hash differs here for no real reason, and would
# have refused all ten children on the first run.
SUM="$(jq -r .evidence_sha256 "$J")"
ck "the recorded checksum is 64-hex" "printf '%s' '$SUM' | grep -Eq '^[0-9a-f]{64}$'"

mkdir -p "$TMP/collected/authorization/child-evidence"
cp -r "$W/evidence/out/php-fpm-8.3-evidence" "$TMP/collected/authorization/child-evidence/"
REL="$TMP/collected/authorization/child-evidence/php-fpm-8.3-evidence"
ck "the checksum survives relocation to the collection directory" \
   "[ \"\$(bash scripts/release/evidence-checksum.sh '$REL')\" = '$SUM' ]"

printf 'tampered' >> "$REL/smoke.log"
ck "...and still changes when one byte is altered" \
   "[ \"\$(bash scripts/release/evidence-checksum.sh '$REL')\" != '$SUM' ]"

ck "producer and authorizer use the SAME checksum implementation" \
   "grep -q 'evidence-checksum.sh' $WF && grep -q 'evidence-checksum.sh' scripts/release/authorize-staged-candidates.sh"
ck "neither reimplements it inline" \
   "! grep -q 'find evidence/child -type f | sort' $WF"

echo "----"; [ "$fail" -eq 0 ] && echo "test_child_evidence_producer: PASS" || echo "test_child_evidence_producer: FAIL"
exit $fail
