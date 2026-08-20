#!/usr/bin/env bash
# =============================================================================
# tests/release/test_post_build_authorization.sh
# -----------------------------------------------------------------------------
# Drive scripts/release/authorize-staged-candidates.sh as a REAL SUBPROCESS and
# validate what it emits against schemas/post-build-authorization-v1.schema.json.
#
# The script carries its own --self-test, which runs the function in-process.
# That is not the same thing. This harness checks the parts a function-level
# test cannot see:
#
#   * the CLI contract — argv handling, usage, exit status;
#   * that the emitted record actually VALIDATES against the published schema,
#     so the producer and its contract cannot drift apart silently;
#   * that a FAIL record is written to disk and is itself schema-valid, since a
#     refused authorization is exactly when the record is read;
#   * that the record cannot claim an authorization it does not have.
#
# The ACL probe shipped structurally perfect and behaviourally inverted because
# its tests read arrangement instead of running it. Same lesson applied here.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
SCRIPT="scripts/release/authorize-staged-candidates.sh"
SCHEMA="schemas/post-build-authorization-v1.schema.json"
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

ck "the aggregator exists and is executable by bash" "test -f $SCRIPT"
ck "the schema exists and is valid JSON" "jq -e . $SCHEMA >/dev/null"

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
REV="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
DIG="sha256:$(printf 'b%.0s' {1..64})"
SUM="$(printf 'c%.0s' {1..64})"
PKG="ghcr.io/zenchron-dynamics/foundry-staging"
REPO="zenchron-dynamics/zenchron-foundry"

# The SHARED implementation, not a copy. A local reimplementation is how the
# producer and the authorizer drifted apart in the first place: identical bytes
# under two different directory prefixes hashed differently, and the test never
# noticed because it never relocated anything.
esum_of() { bash scripts/release/evidence-checksum.sh "$1"; }

mk() { # mk <dir> [label] [jq-filter]
  local d="$1" target="${2:-}" filt="${3:-.}" lbl i=0
  mkdir -p "$d"
  while IFS= read -r lbl; do
    i=$((i+1))
    local b slug edir
    # LITERAL platform-bound name, exactly as the producer's child_slug() emits.
    # This fixture used to write the unplatformed "${lbl//\//-}-evidence", which
    # is the same wrong assumption the authorizer itself carried — fixture and
    # production agreed with each other and both disagreed with disk, so run
    # 32150666171 refused all twenty children with a green test suite.
    slug="${lbl//\//-}-linux-amd64"; edir="$d/${slug}-evidence"
    mkdir -p "$edir"; printf 'evidence for %s\n' "$lbl" > "$edir/log.txt"
    SUM="$(esum_of "$edir")"
    b="$(jq -nc --arg l "$lbl" --arg dg "$DIG" --arg s "$SUM" --arg p "$PKG" \
           --arg rev "$REV" --arg repo "$REPO" '{
      image_label:$l, child_key:($l+"/linux/amd64"), platform:"linux/amd64",
      staging_tag:(($l|gsub("/";"-"))+"-r1-a1-saaaaaaa-amd64"),
      digest_reference:($p+"@"+$dg), manifest_digest:$dg, tag_resolved_digest:$dg,
      visibility:"private", config_architecture:"amd64",
      manifest_media_type:"application/vnd.oci.image.manifest.v1+json",
      trivy_db_identity:"db@2026-08-05", source_revision:$rev,
      workflow_run_id:1, workflow_run_attempt:1, repository:$repo,
      smoke_test:"PASS", scan:"PASS", reconciliation:"PASS",
      metadata_contract:"PASS", evidence_sha256:$s}')"
    [ -n "$target" ] && [ "$lbl" = "$target" ] && b="$(jq -c "$filt" <<<"$b")"
    printf '%s' "$b" > "$d/child-$i.json"
  done < <(bash -c '. scripts/lib/common.sh; matrix_image_labels')
}

run() { # run <dir> [extra env assignments...] -> writes $dir/out.json, echoes rc
  local d="$1"; shift
  env EXPECTED_REPOSITORY="$REPO" EXPECTED_REVISION="$REV" \
      EXPECTED_RUN_ID=1 EXPECTED_RUN_ATTEMPT=1 \
      EXPECTED_PLATFORMS="linux/amd64" EXPECTED_STAGING_PACKAGE="$PKG" \
      EXPECTED_TRIVY_DB="db@2026-08-05" \
      WORKFLOW_REF="zenchron-dynamics/zenchron-foundry/.github/workflows/stage-and-authorize.yml@refs/heads/master" GENERATED_AT="2026-08-05T00:00:00Z" \
      BUILD_CREATED="2026-08-06T00:00:00Z" EVIDENCE_ROOT="$d" \
      "$@" bash "$SCRIPT" "$d" "$d/out.json" >"$d/stdout" 2>"$d/stderr"
  echo $?
}

# Validate with python jsonschema when available; otherwise assert the invariants
# the schema pins, so this test never silently degrades into checking nothing.
have_js=0
python3 -c 'import jsonschema' 2>/dev/null && have_js=1
validate() { # validate <record.json> -> rc
  if [ "$have_js" = 1 ]; then
    python3 - "$SCHEMA" "$1" <<'PY'
import json,sys,jsonschema
schema=json.load(open(sys.argv[1])); doc=json.load(open(sys.argv[2]))
jsonschema.validate(doc, schema)
PY
  else
    jq -e '
      .schema_version == 1
      and (.source_revision|test("^[0-9a-f]{40}$"))
      and .authorization_scope == "immutable-rc-manifest-input"
      and .public_exposure_authorized == false
      and (.verdict == "PASS" or .verdict == "FAIL")
      and (.trivy_db_snapshot.frozen == true)
      and (.staging_package|test("^ghcr\\.io/"))
      and (.children|type == "array")
      and (all(.children[]; .visibility == "private"
                 and (.digest_reference|test("@sha256:[0-9a-f]{64}$"))
                 and (.evidence_sha256|test("^[0-9a-f]{64}$"))))' "$1" >/dev/null
  fi
}
[ "$have_js" = 1 ] && echo "note - validating with python jsonschema" \
                   || echo "note - jsonschema unavailable; asserting the schema's pinned invariants directly"

# --- 1. CLI contract --------------------------------------------------------
# shellcheck disable=SC2034  # read inside the string ck() evals
out="$(bash "$SCRIPT" 2>&1)"; rc=$?
ck "no arguments exits 2 with usage" "[ $rc -eq 2 ] && printf '%s' \"\$out\" | grep -q usage"

# --- 2. the authorized path -------------------------------------------------
D="$TMP/pass"; mk "$D"; RC="$(run "$D")"
ck "a complete consistent matrix exits 0" "[ '$RC' = 0 ]"
ck "...and writes a record" "test -s '$D/out.json'"
ck "...that validates against the published schema" "validate '$D/out.json'"
ck "...with verdict PASS" "[ \"\$(jq -r .verdict '$D/out.json')\" = PASS ]"
ck "...covering all 10 images" "[ \"\$(jq '.children|length' '$D/out.json')\" = 10 ]"
ck "...declaring expected_children explicitly" \
   "[ \"\$(jq -r .expected_matrix.expected_children '$D/out.json')\" = 10 ]"

# The record must not be able to claim more than it proved.
ck "the record never authorizes public exposure" \
   "[ \"\$(jq -r .public_exposure_authorized '$D/out.json')\" = false ]"
ck "the record carries exactly one authorization scope" \
   "[ \"\$(jq -r .authorization_scope '$D/out.json')\" = 'immutable-rc-manifest-input' ]"
ck "the record contains no generic 'authorized' flag to misread" \
   "! jq -e 'has(\"authorized\")' '$D/out.json' >/dev/null"
ck "every child is bound by digest, not by tag" \
   "[ \"\$(jq '[.children[]|select(.digest_reference|test(\"@sha256:[0-9a-f]{64}\$\"))]|length' '$D/out.json')\" = 10 ]"
ck "the frozen database snapshot is recorded once for the run" \
   "[ \"\$(jq -r .trivy_db_snapshot.identity '$D/out.json')\" = 'db@2026-08-05' ]"
ck "every child names that same snapshot" \
   "[ \"\$(jq '[.children[].trivy_db_identity]|unique|length' '$D/out.json')\" = 1 ]"

# --- 3. a refusal still produces a usable record ---------------------------
D="$TMP/fail"; mk "$D"; rm -f "$D/child-1.json"; RC="$(run "$D")"
ck "an incomplete matrix exits non-zero" "[ '$RC' != 0 ]"
ck "...but still writes the record" "test -s '$D/out.json'"
ck "...which is itself schema-valid" "validate '$D/out.json'"
ck "...with verdict FAIL and stated reasons" \
   "[ \"\$(jq -r .verdict '$D/out.json')\" = FAIL ] && [ \"\$(jq '.refusals|length' '$D/out.json')\" -gt 0 ]"
ck "...naming the missing child" "grep -q 'missing expected child' '$D/stderr'"

# --- 4. the refusals that matter, driven end to end ------------------------
declare -a CASES=(
  "another run|nginx/prod|.workflow_run_id=999"
  "another attempt|nginx/prod|.workflow_run_attempt=2"
  "another repository|nginx/prod|.repository=\"someone/else\""
  "another revision|nginx/prod|.source_revision=\"0000000000000000000000000000000000000000\""
  "a mutable reference|nginx/prod|.digest_reference=\"$PKG:sometag\""
  "a production package reference|nginx/prod|.digest_reference=(\"ghcr.io/zenchron-dynamics/php-fpm@\"+.manifest_digest)"
  "tag/digest disagreement|nginx/prod|.tag_resolved_digest=\"sha256:$(printf 'd%.0s' {1..64})\""
  "public staging visibility|nginx/prod|.visibility=\"public\""
  "architecture mismatch|nginx/prod|.config_architecture=\"arm64\""
  "a second database snapshot|nginx/prod|.trivy_db_identity=\"db@2026-01-01\""
  "a failed smoke test|nginx/prod|.smoke_test=\"FAIL\""
  "a failed scan|nginx/prod|.scan=\"FAIL\""
  "an ungoverned finding|nginx/prod|.reconciliation=\"FAIL\""
  "a metadata contract mismatch|nginx/prod|.metadata_contract=\"FAIL\""
  "a missing evidence checksum|nginx/prod|del(.evidence_sha256)"
)
i=0
for c in "${CASES[@]}"; do
  i=$((i+1)); name="${c%%|*}"; rest="${c#*|}"; lbl="${rest%%|*}"; filt="${rest#*|}"
  D="$TMP/case$i"; mk "$D" "$lbl" "$filt"; RC="$(run "$D")"
  ck "$name refuses" "[ '$RC' != 0 ]"
done

# duplicates and extras need a second file, not a mutation
D="$TMP/dup"; mk "$D"; cp "$D/child-1.json" "$D/child-dup.json"; RC="$(run "$D")"
ck "a duplicate image/platform refuses" "[ '$RC' != 0 ]"
D="$TMP/extra"; mk "$D"; jq -c '.image_label="rogue/prod"' "$D/child-1.json" > "$D/child-99.json"; RC="$(run "$D")"
ck "an image outside the matrix refuses" "[ '$RC' != 0 ]"
D="$TMP/empty"; mkdir -p "$D"; RC="$(run "$D")"
ck "empty evidence discovery refuses, never an empty PASS" "[ '$RC' != 0 ]"

# --- 4b. corrections: media type, evidence binding, workflow identity ------
D="$TMP/index"; mk "$D" "nginx/prod" '.manifest_media_type="application/vnd.oci.image.index.v1+json"'; RC="$(run "$D")"
ck "an INDEX digest refuses (not a platform child)" "[ '$RC' != 0 ]"
ck "...and says the object is an index" "grep -qi 'INDEX' '$D/stderr'"

D="$TMP/nomt"; mk "$D" "nginx/prod" 'del(.manifest_media_type)'; RC="$(run "$D")"
ck "a missing manifest media type refuses" "[ '$RC' != 0 ]"

# The case that made the checksum decorative: well-formed, plausible, wrong.
D="$TMP/badsum"; mk "$D" "nginx/prod" '.evidence_sha256="'"$(printf 'e%.0s' {1..64})"'"'; RC="$(run "$D")"
ck "a well-formed but INCORRECT evidence checksum refuses" "[ '$RC' != 0 ]"
ck "...naming the recomputation" "grep -q 'does not match the evidence directory' '$D/stderr'"

D="$TMP/tampered"; mk "$D"; printf 'tampered\n' >> "$D/nginx-prod-linux-amd64-evidence/log.txt"; RC="$(run "$D")"
ck "evidence altered after the checksum was taken refuses" "[ '$RC' != 0 ]"

D="$TMP/wfref"; mk "$D"; RC="$(run "$D" WORKFLOW_REF="zenchron-dynamics/zenchron-foundry/.github/workflows/stage-and-authorize.yml@refs/heads/attacker")"
ck "a non-canonical workflow identity refuses" "[ '$RC' != 0 ]"

D="$TMP/schemapass"; mk "$D"; run "$D" >/dev/null
ck "the record pins the canonical workflow identity" \
   "[ \"\$(jq -r .workflow_ref '$D/out.json')\" = 'zenchron-dynamics/zenchron-foundry/.github/workflows/stage-and-authorize.yml@refs/heads/master' ]"
ck "the record carries one frozen build timestamp" \
   "[ \"\$(jq -r .build_created '$D/out.json')\" = '2026-08-06T00:00:00Z' ]"
ck "every child records an image-manifest media type" \
   "[ \"\$(jq '[.children[]|select(.manifest_media_type|test(\"manifest\"))]|length' '$D/out.json')\" = 10 ]"

# --- 4c. the schema now ties the verdict to the child gates ----------------
ck "the schema rejects PASS alongside a failed child gate" \
   "python3 -c \"
import json,jsonschema,sys
s=json.load(open('$SCHEMA')); d=json.load(open('$D/out.json'))
d['children'][0]['smoke_test']='FAIL'
try:
    jsonschema.validate(d,s); sys.exit(1)
except jsonschema.ValidationError: pass\""
ck "the schema requires reasons on FAIL" \
   "python3 -c \"
import json,jsonschema,sys
s=json.load(open('$SCHEMA')); d=json.load(open('$D/out.json'))
d['verdict']='FAIL'
try:
    jsonschema.validate(d,s); sys.exit(1)
except jsonschema.ValidationError: pass\""

# --- 4d. the runtime schema gate ------------------------------------------
# The aggregator and the schema check different things and neither subsumes the
# other. This proves the runtime gate catches something the aggregator does NOT
# independently validate: an empty staging_tag. The aggregator never inspects it;
# the schema requires minLength 1.
D="$TMP/schemagate"; mk "$D"; run "$D" >/dev/null
ck "the aggregator alone accepts an empty staging_tag" \
   "python3 -c \"
import json
d=json.load(open('$D/out.json'))
d['children'][0]['staging_tag']=''
json.dump(d, open('$D/mutated.json','w'))\" && test -s '$D/mutated.json'"
ck "the runtime schema gate refuses it" \
   "! bash scripts/release/validate-authorization-record.sh '$D/mutated.json' >/dev/null 2>&1"
# Captured, not piped: pipefail makes `validator | grep` fail on the validator's
# non-zero exit even when grep matched.
bash scripts/release/validate-authorization-record.sh "$D/mutated.json" > "$D/verr" 2>&1 || true
ck "...naming the offending field" "grep -q staging_tag '$D/verr'"
ck "the runtime gate accepts the real PASS record" \
   "bash scripts/release/validate-authorization-record.sh '$D/out.json' >/dev/null 2>&1"

# A FAIL record must validate too — a refusal is exactly when it gets read.
D="$TMP/failrec"; mk "$D"; rm -f "$D/child-1.json"; run "$D" >/dev/null
ck "a FAIL record is also schema-valid at run time" \
   "bash scripts/release/validate-authorization-record.sh '$D/out.json' >/dev/null 2>&1"

# A missing validator must not pass.
ck "the runtime gate refuses a missing record rather than passing" \
   "! bash scripts/release/validate-authorization-record.sh '$TMP/nope.json' >/dev/null 2>&1"

# --- 4e. media-type classification, by SENTENCE not by the word 'index' ----
# The media-type string itself contains "index", so grepping for it proved
# nothing about which branch fired.
D="$TMP/idx2"; mk "$D" "nginx/prod" '.manifest_media_type="application/vnd.oci.image.index.v1+json"'; RC="$(run "$D")"
ck "an OCI index is classified as an index" \
   "grep -q 'refusing an INDEX digest' '$D/stderr'"
D="$TMP/mlist2"; mk "$D" "nginx/prod" '.manifest_media_type="application/vnd.docker.distribution.manifest.list.v2+json"'; RC="$(run "$D")"
ck "a docker manifest list is classified as an index" \
   "grep -q 'refusing an INDEX digest' '$D/stderr'"
D="$TMP/junk"; mk "$D" "nginx/prod" '.manifest_media_type="application/octet-stream"'; RC="$(run "$D")"
ck "an unrecognised media type is classified as unknown, not as an index" \
   "grep -q 'unknown media type' '$D/stderr' && ! grep -q 'refusing an INDEX' '$D/stderr'"

# --- 5. architecture policy applies to the requested matrix ----------------
# linux/arm64 was the example here until #139 evidenced it (run 31941819983).
# It would still refuse — on the child-count mismatch — so this assertion would
# have kept passing for the wrong reason. linux/s390x has no evidence, so the
# refusal can only come from the architecture policy itself.
D="$TMP/arm"; mk "$D"; RC="$(run "$D" EXPECTED_PLATFORMS="linux/s390x")"
ck "an unevidenced architecture refuses the whole matrix" "[ '$RC' != 0 ]"
ck "...and says so, citing the missing evidence" \
   "grep -q 'unsupported architecture' '$D/stderr'"
ck "...rather than emitting a PASS that silently excludes it" \
   "[ \"\$(jq -r .verdict '$D/out.json')\" = FAIL ]"

# --- 6. mandatory expectations ---------------------------------------------
for v in EXPECTED_REPOSITORY EXPECTED_REVISION EXPECTED_RUN_ID EXPECTED_TRIVY_DB \
         EXPECTED_STAGING_PACKAGE EXPECTED_PLATFORMS WORKFLOW_REF GENERATED_AT \
         BUILD_CREATED EVIDENCE_ROOT; do
  D="$TMP/omit_$v"; mk "$D"; RC="$(run "$D" "$v=")"
  ck "omitting $v refuses" "[ '$RC' != 0 ]"
done

echo "----"; [ "$fail" -eq 0 ] && echo "test_post_build_authorization: PASS" || echo "test_post_build_authorization: FAIL"
exit $fail
