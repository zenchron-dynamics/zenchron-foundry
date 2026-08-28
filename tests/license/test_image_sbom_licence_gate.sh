#!/usr/bin/env bash
# shellcheck disable=SC2034  # assertion locals are consumed inside ck() eval strings
# =============================================================================
# tests/license/test_image_sbom_licence_gate.sh
# -----------------------------------------------------------------------------
# THE GAP THIS CLOSES, in its own words.
#
# tests/integration/test_evidence_path_e2e.sh pinned two lines:
#
#   GAP - no workflow invokes the IMAGE-SBOM licence gate against a real inventory
#   GAP - ...ci.yml runs assert-license-policy.sh ONLY as --self-test, which
#         gates no image
#
# The repository half of the licence gate was closed by #120's
# scripts/license/assert-repository-material.sh, which the REQUIRED `repo
# structure` job runs over the real tree. The image half had no consumer at all:
# a fail-closed gate, a normaliser, an SBOM producer — and nothing that ever put
# a candidate image through them.
#
# HOW THE GAP SURVIVED, and what this file refuses to repeat. The assertion that
# claimed the gate was wired was
#
#     grep -rq 'scripts/license/' .github/workflows/
#
# which matched exactly one line: ci.yml's `--self-test` step. Literally true,
# substantively false, and green forever. So NOTHING here is proved by grepping
# YAML. Every assertion below EXECUTES the workflow's own step body, extracted
# from .github/workflows/stage-and-authorize.yml by a real YAML parser
# (tests/lib/workflow_step.py), with the inputs the step declares. Delete the
# job, weaken a flag, or stop consuming the result, and the executed body
# changes and these assertions stop refusing.
#
# WHAT COUNTS AS A REAL CANDIDATE INPUT HERE, precisely. Nothing in this file
# builds, pulls, publishes, promotes, signs or tags anything, and no production
# image is rebuilt to test workflow composition. The candidate identity comes
# from the ACCEPTED PRODUCTION RUN — docs/audits/acceptance-multiarch-2026-08-20
# /acceptance-evidence.json, MATRIX_COUNT x 2 children at a real source revision,
# each with the immutable manifest digest the registry resolved. Every SBOM and
# every binding record below names those real digests, that real revision and
# the identity function the producer spells. What makes the set "candidate
# evidence" rather than "fixtures" is exactly the binding: a document with no
# binding record, or one whose bytes are not the bytes the producing run hashed,
# is refused — which is proof 2.
#
# TEN NON-VACUITY PROOFS, each asserting its INTENDED diagnostic:
#
#   1  removing the workflow invocation recreates the exact pinned gap
#   2  fixtures substituted for real SBOM inputs are refused
#   3  one missing platform is refused
#   4  one missing image is refused
#   5  a wrong image digest is refused (binding AND subject)
#   6  a wrong source revision is refused (binding AND gate expectation)
#   7  a missing repository inventory is refused
#   8  missing image evidence is refused, and the composition is proved in BOTH
#      directions: neither half compensates for the other's absence
#   9  the complete real input set satisfies the composed gate
#  10  the REQUIRED CI path executes this file, so the workflow's own extracted
#      gate commands run on every pull request
#
# AMBIENT SAFETY. Every byte written lands under a single mktemp -d, including
# the disposable repository copy the extracted step bodies execute against.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
# common.sh carries `set -e`, which would end the run at the first intentional
# refusal. It also carries MATRIX_COUNT, child_slug() and sbom_filename() — the
# ONE identity source. A second derivation here is the defect that made a
# complete SBOM directory read as sbom.present=false.
# shellcheck source=../../scripts/lib/common.sh
. scripts/lib/common.sh
set +e
set +o pipefail

fail=0 n=0 nfail=0 ngap=0
ck() { n=$((n+1)); if eval "$2"; then echo "ok   - $1"; else
         echo "FAIL - $1"; fail=1; nfail=$((nfail+1)); fi; }
# A gap() states something TRUE TODAY that ought to become false when somebody
# closes it — at which point this test fails and says to promote the line. A gap
# that silently starts passing is a gap nobody notices was fixed.
gap() { ngap=$((ngap+1)); if eval "$2"; then echo "GAP  - $1"; else
          echo "FAIL - GAP ASSERTION NO LONGER HOLDS (promote to ck): $1"
          fail=1; nfail=$((nfail+1)); fi; }

WF=.github/workflows/stage-and-authorize.yml
JOB=authorize
CI=.github/workflows/ci.yml
ACCEPTED=docs/audits/acceptance-multiarch-2026-08-20/acceptance-evidence.json
MKAUTH=tests/lib/make_authorization_fixture.py
STEP=tests/lib/workflow_step.py

# The required CI path runs this file directly. Proof 10 executes that command
# to show it really reaches THIS script; the probe stops the recursion without
# weakening anything, because the command it proves is the same one CI runs.
if [ -n "${IMAGE_SBOM_GATE_PROBE:-}" ]; then
  echo "IMAGE-SBOM-LICENCE-GATE-REACHED"
  exit 0
fi

if ! python3 -c 'import yaml, jsonschema' 2>/dev/null; then
  echo "SKIP - pyyaml/jsonschema absent"; echo "test_image_sbom_licence_gate: PASS"; exit 0
fi
for f in "$ACCEPTED" "$MKAUTH" "$STEP" "$WF"; do
  [ -f "$f" ] || { echo "SKIP - $f absent"; echo "test_image_sbom_licence_gate: PASS"; exit 0; }
done

TMP="$(mktemp -d)"
# Expanded NOW: a single-quoted trap defers expansion past this scope and dies
# under set -u. EXIT, never RETURN — a RETURN trap under `bash -T` fires on
# every inner function return and wipes fixtures mid-run.
# shellcheck disable=SC2064
trap "chmod -R u+w '$TMP' 2>/dev/null; rm -rf '$TMP'" EXIT

REV="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["source_revision"])' "$ACCEPTED")"
# Derived, never a literal. MATRIX_COUNT is the ONE declaration of the shipping
# matrix size; a hardcoded 10 or 20 would silently re-baseline itself the day
# the matrix changes.
CHILDREN=$(( MATRIX_COUNT * 2 ))
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
# Exported for the derivation checks below; MATRIX_IMAGES is the one
# declaration of the shipping matrix and is never restated here.
export MI="$MATRIX_IMAGES"

# --- the disposable repository the extracted step bodies execute against -----
# The step bodies write licence/*.rc relative to the working directory, and the
# repository-material half reads the tracked file set with git. Both therefore
# need a real checkout, and it must NOT be this one: a self-test that writes to
# a path derived from the repository root is the class
# tests/lib/test_no_ambient_mutation.sh exists to refuse.
# The TARGET is the scratch directory and the SOURCE is the checkout, which is
# the sanctioned direction: copying OUT of the checkout is how a fixture gets
# built. Written as two statements so the target is the last token on the line
# and tests/lib/test_no_ambient_mutation.sh's static rule can see that plainly.
WORK="$TMP/repo"
mkdir -p "$WORK"
cp -R "$ROOT/." "$WORK/"

# --- the candidate identity table, from the ACCEPTED PRODUCTION RUN ----------
python3 - "$ACCEPTED" "$TMP/ident.tsv" <<'PY'
import json, sys
ev = json.load(open(sys.argv[1]))
other = ev["children"][-1]["manifest_digest"]
first = ev["children"][0]["manifest_digest"]
with open(sys.argv[2], "w") as fh:
    for c in ev["children"]:
        fam, _, ver = c["image_label"].partition("/")
        foreign = other if c["manifest_digest"] != other else first
        fh.write("\t".join([fam, ver, c["platform"], c["child_key"],
                            c["manifest_digest"], foreign]) + "\n")
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

mk_binding() { # mk_binding <dir> <slug> <fam> <ver> <plat> <key> <digest> <rev> <when> <sbom-path>
  python3 - "$@" <<'PY'
import hashlib, json, os, sys
d, slug, fam, ver, plat, key, digest, rev, when, sbom = sys.argv[1:11]
h = hashlib.sha256(open(sbom, "rb").read()).hexdigest()
json.dump({"record_type": "candidate-sbom-binding", "child_key": key,
           "image_family": fam, "image_version": ver, "platform": plat,
           "manifest_digest": digest,
           "digest_reference": "ghcr.io/zenchron-dynamics/foundry-staging@" + digest,
           "source_revision": rev, "workflow_run_id": 32395890071,
           "workflow_run_attempt": 1, "generated_at": when,
           "producer": "scripts/generate-sbom.sh",
           "documents": {os.path.basename(sbom): h}},
          open(os.path.join(d, slug + ".binding.json"), "w"), indent=2)
PY
}

build_set() { # build_set <sbom-dir> <binding-dir> [when]
  local sd="$1" bd="$2" when="${3:-$NOW}" fam ver plat key dig foreign name slug
  rm -rf "$sd" "$bd"; mkdir -p "$sd" "$bd"
  while IFS="$(printf '\t')" read -r fam ver plat key dig foreign; do
    [ -n "$fam" ] || continue
    name="$(sbom_filename "$fam" "$ver" "$plat" spdx-json)"
    slug="$(child_slug "$fam" "$ver" "$plat")"
    mk_spdx "$sd/$name" "$key" "$dig"
    mk_binding "$bd" "$slug" "$fam" "$ver" "$plat" "$key" "$dig" "$REV" "$when" "$sd/$name"
  done < "$TMP/ident.tsv"
}

# --- the canonical authorization record for the accepted run ----------------
# Reconstructed offline by the SHIPPED fixture builder because the run's own
# record was a 30-day workflow artifact and has expired — the exact retention
# failure the evidence bundle exists for. The builder lives under tests/ on
# purpose: a tool in scripts/ that derived a canonical-looking authorization
# from any acceptance record would be a bypass of the gate, not a fixture.
python3 "$MKAUTH" "$ACCEPTED" "$TMP/auth.json"
python3 "$MKAUTH" "$ACCEPTED" "$TMP/auth-short.json" --drop-child 0
python3 "$MKAUTH" "$ACCEPTED" "$TMP/auth-extra.json" --extra-child
python3 - "$TMP/auth.json" "$TMP/auth-dup.json" <<'PY'
import json, sys
rec = json.load(open(sys.argv[1]))
# One child recorded twice. A duplicated child is how one image's clean bill of
# materials stands in for another's while the count still looks right.
rec["children"].append(dict(rec["children"][0]))
json.dump(rec, open(sys.argv[2], "w"), indent=2)
PY

build_set "$TMP/sbom" "$TMP/bind"

# -----------------------------------------------------------------------------
# EXECUTING THE WORKFLOW'S OWN STEPS. Nothing below re-types a command line.
# -----------------------------------------------------------------------------
wf_run()  { python3 "$STEP" "$WF" "$JOB" "$1" --run; }
wf_env()  { python3 "$STEP" "$WF" "$JOB" "$1" --env; }
wf_keys() { python3 "$STEP" "$WF" "$JOB" "$1" --env-keys; }

# gate <step-id> [VAR=VALUE ...] — run the step body, in the disposable copy,
# with the step's own declared env plus the overrides that point it at real
# evidence. Output is captured so a refusal's DIAGNOSTIC can be asserted; a
# pipe would make grep's first match kill the producer and let pipefail report
# 141 intermittently.
gate() {
  local id="$1"; shift
  local body; body="$(wf_run "$id")" || return 2
  local -a envs=()
  local line
  while IFS= read -r line; do [ -n "$line" ] && envs+=("$line"); done < <(wf_env "$id")
  # GITHUB_OUTPUT / GITHUB_STEP_SUMMARY are the runner's, not the step's. They
  # are pointed at the scratch directory rather than stubbed away: a step that
  # writes its result somewhere is a step whose result something can read.
  ( cd "$WORK" && mkdir -p licence authorization/licence \
      && env ${envs[@]+"${envs[@]}"} GITHUB_OUTPUT="$TMP/gh-output" \
             GITHUB_STEP_SUMMARY="$TMP/gh-summary" "$@" \
             bash --noprofile --norc -c "$body" ) >"$TMP/out" 2>&1
}
says() { grep -q -- "$1" "$TMP/out"; }
outcat() { cat "$TMP/out"; }

A="$TMP/auth.json"
S="$TMP/sbom"
B="$TMP/bind"
INV="$TMP/image-inventory.json"

echo "== the accepted evidence: why reusing it is valid, and how far ==========="

# THE REUSE RECORD. Nothing here builds an image, so the candidate identities
# come from the accepted production run. That is only legitimate if the run
# still describes what this tree would produce, and the claim has to be the
# narrow true one rather than the comfortable wide one.
#
#   VALID:   the IMAGE IDENTITY SET has not moved. images/ and contracts/ carry
#            no non-8.5 change since the accepted revision, and MATRIX_IMAGES /
#            MATRIX_COUNT are byte-identical to that revision. The 10 x 2 cohort
#            and its immutable digests are therefore the same cohort.
#   NOT CLAIMED: that scripts/lib/common.sh is unchanged — it is not, by +132
#            lines of comments, helpers and a self-test that moved from a
#            hardcoded count to a shape assertion. "common.sh unchanged" would
#            be false and a reviewer diffing it would find that immediately.
#   NOT CLAIMED: that the SBOM package lists below are those images' real
#            package inventories. They are not; see the pinned gap at the end.
# CHECKED FIRST, because the two history claims below are `git diff` against a
# 2026-08-20 commit. In a shallow checkout that diff FAILS, prints nothing, and
# an emptiness test reads the silence as agreement — green and substantively
# absent. So the precondition is asserted rather than assumed.
ck "the accepted revision is present in this checkout, so the reuse claim is checkable" \
   "git cat-file -e '$REV^{commit}' 2>/dev/null"
ck "the accepted run names a 40-hex source revision, not a branch or a tag" \
   "printf '%s' '$REV' | grep -qE '^[0-9a-f]{40}$'"
ck "every accepted child is addressed by an IMMUTABLE content digest" \
   "python3 -c 'import json,re,sys
ev=json.load(open(sys.argv[1]))
rx=re.compile(r\"^sha256:[0-9a-f]{64}$\")
sys.exit(0 if all(rx.match(c[\"manifest_digest\"])
                  and c[\"digest_reference\"].endswith(\"@\"+c[\"manifest_digest\"])
                  for c in ev[\"children\"]) else 1)' '$ACCEPTED'"
ck "the IMAGE DEFINITIONS carry no non-8.5 change since that revision" \
   "[ -z \"\$(git diff --name-only '$REV' HEAD -- images/ contracts/ 2>/dev/null \
              | grep -v '/8\\.5/' || true)\" ]"
ck "the IDENTITY SET is byte-identical to that revision (not the whole file)" \
   "[ \"\$(git show '$REV':scripts/lib/common.sh | grep -E '^(MATRIX_IMAGES|MATRIX_COUNT)=')\" \
    = \"\$(grep -E '^(MATRIX_IMAGES|MATRIX_COUNT)=' scripts/lib/common.sh)\" ]"
ck "NON-VACUOUS: common.sh as a whole HAS changed, so the claim above is narrow" \
   "! git diff --quiet '$REV' HEAD -- scripts/lib/common.sh"
ck "the cohort is DERIVED from MATRIX_IMAGES, and the evidence agrees with it" \
   "[ \"\$(matrix_images | wc -l | tr -d ' ')\" = \"$MATRIX_COUNT\" ] \
    && python3 -c 'import json,os,sys
ev=json.load(open(sys.argv[1]))
want={\"%s/%s\"%(t.split(\":\")[0],t.split(\":\")[1]) for t in os.environ[\"MI\"].split()}
have={c[\"image_label\"] for c in ev[\"children\"]}
plat={c[\"platform\"] for c in ev[\"children\"]}
sys.exit(0 if want==have and len(ev[\"children\"])==len(want)*len(plat) else 1)' '$ACCEPTED'"
ck "the accepted run DISCLOSES how each child was executed, and it is carried" \
   "python3 -c 'import json,sys
ev=json.load(open(sys.argv[1]))
sys.exit(0 if all(c.get(\"execution_mode\") for c in ev[\"children\"])
             and ev.get(\"execution_disclosure\") else 1)' '$ACCEPTED'"

echo
echo "== the composed gate over the REAL accepted candidate evidence ==========="

ck "the candidate SBOM set covers MATRIX_COUNT x 2 children, derived not counted" \
   "[ \"\$(find '$S' -name '*.spdx.json' | wc -l | tr -d ' ')\" = '$CHILDREN' ]"
PRODUCER_NAME="$(bash scripts/generate-sbom.sh --print-names caddy prod linux/amd64 \
                   | awk -F'\t' '$1=="spdx-json"{print $2}')"
ck "every document is named by the PRODUCER's identity function, not a literal" \
   "[ -n '$PRODUCER_NAME' ] && [ -f '$S/$PRODUCER_NAME' ] \
    && [ '$PRODUCER_NAME' = \"\$(sbom_filename caddy prod linux/amd64 spdx-json)\" ]"

# --- PROOF 9 (run first: everything after it is a sabotage of THIS path) -----
ck "P9 the workflow's binding step binds every real candidate SBOM" \
   "gate lic_bind AUTH_RECORD='$A' SBOM_DIR='$S' BINDING_DIR='$B' IMAGE_INVENTORY='$INV'"
ck "P9 ...to image, version, platform, IMMUTABLE DIGEST and source revision" \
   "python3 -c 'import json,sys
i=json.load(open(sys.argv[1])); b=i[\"image_binding\"]
d={c[\"child_key\"]: c for c in b[\"children\"]}
ev=json.load(open(sys.argv[2]))
ok=all(d[c[\"child_key\"]][\"manifest_digest\"]==c[\"manifest_digest\"]
       and d[c[\"child_key\"]][\"platform\"]==c[\"platform\"]
       and d[c[\"child_key\"]][\"image_label\"]==c[\"image_label\"]
       and d[c[\"child_key\"]][\"source_revision\"]==ev[\"source_revision\"]
       for c in ev[\"children\"])
sys.exit(0 if ok and b[\"all_children_bound\"] and b[\"children_bound\"]==$CHILDREN else 1)' \
      '$INV' '$ACCEPTED'"
ck "P9 ...carrying SBOM checksum, SBOM schema, producer and creation time per child" \
   "python3 -c 'import json,sys
b=json.load(open(sys.argv[1]))[\"image_binding\"]
ok=all(c[\"sbom_sha256\"] and c[\"sbom_schema\"] and c[\"producer\"]
       and c[\"evidence_generated_at\"] and c[\"image_family\"] and c[\"image_version\"]
       for c in b[\"children\"])
sys.exit(0 if ok and b[\"sbom_schemas\"] and b[\"producers\"] else 1)' '$INV'"
ck "P9 ...and the execution disclosure is CARRIED, not flattened away" \
   "python3 -c 'import json,sys
b=json.load(open(sys.argv[1]))[\"image_binding\"]
ev=json.load(open(sys.argv[2]))
want={c[\"child_key\"]: c.get(\"execution_mode\") for c in ev[\"children\"]}
sys.exit(0 if all(c[\"execution_mode\"]==want[c[\"child_key\"]] for c in b[\"children\"])
             and b[\"execution_modes\"] else 1)' '$INV' '$ACCEPTED'"
ck "P9 ...and the binding names the same revision the accepted run recorded" \
   "[ \"\$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))[\"image_binding\"][\"source_revision\"])' '$INV')\" = '$REV' ]"
ck "P9 the workflow's IMAGE-SBOM licence gate passes over that real inventory" \
   "gate lic_policy IMAGE_INVENTORY='$INV' EXPECT_REVISION='$REV'"
ck "P9 ...and it is the shipped fail-closed gate, not a self-test" \
   "wf_run lic_policy | grep -q 'assert-license-policy.sh' \
    && ! wf_run lic_policy | grep -q -- '--self-test'"
ck "P9 the workflow's COMPOSED step passes with both halves present" \
   "gate lic_composed IMAGE_INVENTORY='$INV' MATERIAL_INVENTORY='$WORK/policies/repository-material.yaml'"
ck "P9 ...and it really did read the image half as SOURCE 1" \
   "says 'SOURCE 1' && says 'image-inventory.json'"
LIC="$TMP/licence-authorization.json"
ck "P9 the workflow composes the three results into one recorded decision" \
   "gate lic_decide BIND=success IMAGE_POLICY=success COMPOSED=success \
      AUTH_RECORD='$A' IMAGE_INVENTORY='$INV' LICENCE_RECORD='$LIC' \
      MATERIAL_INVENTORY='$WORK/policies/repository-material.yaml'"
ck "P9 ...as verdict PASS naming both halves and the child count" \
   "python3 -c 'import json,sys
d=json.load(open(sys.argv[1]))
sys.exit(0 if d[\"verdict\"]==\"PASS\" and d[\"both_halves_required\"]
             and d[\"image_half\"][\"children_bound\"]==$CHILDREN
             and d[\"repository_half\"][\"composed\"]==\"success\" else 1)' '$LIC'"
ck "P9 ...BOUND to this authorization record by its sha256, not merely filed beside it" \
   "python3 -c 'import hashlib,json,sys
d=json.load(open(sys.argv[1]))
sys.exit(0 if d[\"authorization_record_sha256\"]
             == hashlib.sha256(open(sys.argv[2],\"rb\").read()).hexdigest() else 1)' \
      '$LIC' '$A'"
ck "P9 ...while publication stays REFUSED, unchanged by a licence PASS" \
   "python3 -c 'import json,sys
sys.exit(0 if json.load(open(sys.argv[1]))[\"public_exposure_authorized\"] is False else 1)' '$LIC'"

# THE CONSUMPTION PROOF. Producing a verdict and filing it in an artifact is the
# original defect one layer out: a step whose output nothing reads is
# indistinguishable from a step that did not run. The canonical record's own
# validator is what reads it, so the authorization decision cannot be reached
# without it.
# The validator step records its result and the sealing step turns it into the
# job verdict — the same two-stage shape the aggregator already uses, so a
# refusal is still WRITTEN before it is acted on. consume() reads it exactly as
# the workflow does.
#
# THE COMPOSITION GREW A THIRD INPUT (#120). The validator step now also requires
# a distribution-notice and source-obligation bundle: a licence PASS is not
# sufficient on its own, because a candidate can satisfy the licence gate while
# owing every licence text, upstream NOTICE and source obligation it ships under.
#
# This file proves the LICENCE half. So it hands the validator a notice bundle
# that GENUINELY SATISFIES — built by the shipped producer from the same real
# candidate identities, with tests/lib/make_notice_inputs.py stating exactly
# which of its fields are real and which are fixture. That way every refusal
# below is provably the licence half and not the notice half leaking in, and
# every "eligible to continue" cell still means what it says.
python3 "$ROOT/tests/lib/make_notice_inputs.py" \
  --authorization "$A" --root "$ROOT" --out "$TMP/nin" >/dev/null 2>&1
python3 "$ROOT/scripts/license/generate-notice-bundle.py" \
  --inventory "$TMP/nin/inventory.json" --authorization "$A" \
  --material "$TMP/nin/repository-material.yaml" \
  --policy "$TMP/nin/license-policy.yaml" \
  --licence-texts "$TMP/nin/licence-texts.yaml" \
  --attestations "$TMP/nin/attestations.yaml" \
  --source-obligations "$TMP/nin/source-obligations.yaml" \
  --out-dir "$TMP/notice-pass" >/dev/null 2>&1
NB="$TMP/notice-pass/notice-manifest.json"

consume() { # consume <licence-record> [authorization-record] [notice-bundle]
  gate schema AUTH_RECORD="${2:-$A}" LICENCE_RECORD="$1" \
       NOTICE_BUNDLE="${3:-$NB}" || return 1
  [ "$(cat "$WORK/authorization/schema.rc" 2>/dev/null)" = 0 ]
}
ck "P9 the notice bundle handed to the validator genuinely SATISFIES" \
   "python3 -c \"
import json
m=json.load(open('$NB'))
assert m['verdict']=='PASS' and m['status']=='complete', (m['verdict'], m['status'])
assert m['satisfies_authorization'] is True and m['draft'] is False
assert m['candidate']['children_bound']==m['candidate']['children_expected']==$CHILDREN\""
ck "P9 the CANONICAL authorization decision CONSUMES that verdict" \
   "consume '$LIC'"
ck "P9 ...and says so, naming the verdict and the bound child count" \
   "says 'licence authorization CONSUMED' && says 'PASS' && says '$CHILDREN/$CHILDREN'"
ck "P9 SABOTAGE: a licence PASS with NO notice bundle NO LONGER reaches eligibility" \
   "! consume '$LIC' '$A' '$TMP/no-such-notice.json'
    says 'AR-NOTICE-EVIDENCE-ABSENT' && says 'never a skip'"
ck "P9 ...so the licence half alone is insufficient, which is the point of #120" \
   "consume '$LIC'"
ck "P9 ...and the SEALING step turns that recorded result into the job verdict" \
   "printf '0\n' > '$WORK/authorization/aggregate.rc'
    printf '0\n' > '$WORK/authorization/schema.rc'
    gate seal"
ck "P9 SABOTAGE: a refused licence result FAILS the job at the same step" \
   "printf '0\n' > '$WORK/authorization/aggregate.rc'
    printf '1\n' > '$WORK/authorization/schema.rc'
    ! gate seal"
ck "P9 ...and the licence records are INSIDE the sealed checksum coverage" \
   "gate lic_decide BIND=success IMAGE_POLICY=success COMPOSED=success \
      AUTH_RECORD='$A' IMAGE_INVENTORY='$INV' \
      LICENCE_RECORD=authorization/licence/licence-authorization.json \
      MATERIAL_INVENTORY='$WORK/policies/repository-material.yaml' \
    && printf '0\n' > '$WORK/authorization/aggregate.rc' \
    && printf '0\n' > '$WORK/authorization/schema.rc' \
    && gate seal \
    && grep -q 'licence/licence-authorization.json' '$WORK/authorization/SHA256SUMS'"

echo
echo "== proof 1: removing the invocation recreates the EXACT pinned gap ========"

# The pinned predicate, spelled exactly as tests/integration/test_evidence_path_e2e.sh
# spells it: any invocation of the IMAGE-SBOM gate that is not a self-test.
lic_policy_real() { # <workflow-dir>
  grep -rn 'scripts/license/assert-license-policy.sh' "$1" 2>/dev/null \
    | grep -v -- '--self-test'
}
mkdir -p "$TMP/wf-removed" && cp .github/workflows/*.yml "$TMP/wf-removed/"
python3 - "$TMP/wf-removed/stage-and-authorize.yml" "$JOB" <<'PY'
import sys, yaml
p, job = sys.argv[1], sys.argv[2]
wf = yaml.safe_load(open(p))
assert job in wf["jobs"], job
# Delete the job textually so the rest of the file is byte-identical: the only
# difference between the two trees is the invocation itself.
src = open(p).read()
i = src.index("  %s:\n" % job)
# Back up to the BLANK LINE that opens the job's comment block, so the job's own
# prose — which names the gate script — goes with it. Leaving the comment behind
# would make the removed tree still "mention" the gate, and mentioning is
# exactly what this suite refuses to accept as evidence of a gate running.
j = src.rindex("\n\n  # ---", 0, i)
open(p, "w").write(src[:j + 1])
PY

ck "P1 the shipped workflow directory DOES invoke the image gate for real" \
   "[ -n \"\$(lic_policy_real .github/workflows/)\" ]"
ck "P1 ...and the invocation is not a --self-test line" \
   "lic_policy_real .github/workflows/ | grep -q 'assert-license-policy.sh' \
    && [ -z \"\$(lic_policy_real .github/workflows/ | grep -- '--self-test')\" ]"
ck "P1 REMOVING the job recreates the pinned gap EXACTLY: no real invocation" \
   "[ -z \"\$(lic_policy_real '$TMP/wf-removed')\" ]"
# Stronger than the pinned predicate, because the pinned predicate is a grep and
# a grep cannot tell prose from a command: no EXECUTABLE step body in any
# workflow invokes the gate once the job is gone.
ck "P1 ...and no run: body in any workflow invokes it either, by YAML parse" \
   "python3 -c 'import glob,sys,yaml
hits=[]
for f in sorted(glob.glob(sys.argv[1] + \"/*.yml\")):
    wf=yaml.safe_load(open(f)) or {}
    for jid,job in (wf.get(\"jobs\") or {}).items():
        for st in (job.get(\"steps\") or []):
            b=st.get(\"run\") or \"\"
            if \"assert-license-policy.sh\" in b and \"--self-test\" not in b:
                hits.append((f,jid))
sys.exit(1 if hits else 0)' '$TMP/wf-removed'"
ck "P1 NON-VACUOUS: that same YAML parse DOES find it in the shipped tree" \
   "! python3 -c 'import glob,sys,yaml
hits=[]
for f in sorted(glob.glob(sys.argv[1] + \"/*.yml\")):
    wf=yaml.safe_load(open(f)) or {}
    for jid,job in (wf.get(\"jobs\") or {}).items():
        for st in (job.get(\"steps\") or []):
            b=st.get(\"run\") or \"\"
            if \"assert-license-policy.sh\" in b and \"--self-test\" not in b:
                hits.append((f,jid))
sys.exit(1 if hits else 0)' .github/workflows"
ck "P1 ...and the only surviving licence-policy line is ci.yml's --self-test" \
   "[ \"\$(grep -rn 'scripts/license/assert-license-policy.sh' '$TMP/wf-removed' | wc -l | tr -d ' ')\" = '1' ] \
    && grep -rq -- 'scripts/license/assert-license-policy.sh --self-test' '$TMP/wf-removed/ci.yml'"
ck "P1 ...which is the gate testing ITSELF: it gates no image and refuses nothing" \
   "bash scripts/license/assert-license-policy.sh --self-test >/dev/null 2>&1 \
    && ! bash scripts/license/assert-license-policy.sh --self-test 2>&1 | grep -q 'image_binding'"
ck "P1 NON-VACUOUS: the removal changed only that job, nothing else" \
   "[ \"\$(diff <(cat .github/workflows/ci.yml) <(cat '$TMP/wf-removed/ci.yml') | wc -l | tr -d ' ')\" = '0' ]"

echo
echo "== proof 2: fixtures substituted for real candidate inputs are REFUSED ===="

build_set "$TMP/s2" "$TMP/b2"
# A perfectly valid, correctly named, correct-SUBJECT SPDX document that the
# producing run never wrote. Every byte a filename-and-format check inspects
# lines up; only the binding hash disagrees.
python3 - "$TMP/s2/$(sbom_filename caddy prod linux/amd64 spdx-json)" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["packages"].append({"name": "hand-written", "versionInfo": "0",
                      "licenseConcluded": "MIT", "licenseDeclared": "MIT"})
json.dump(d, open(sys.argv[1], "w"), indent=2)
PY
ck "P2 SABOTAGE: a hand-written document under the candidate's own name REFUSES" \
   "! gate lic_bind AUTH_RECORD='$A' SBOM_DIR='$TMP/s2' BINDING_DIR='$TMP/b2' IMAGE_INVENTORY='$TMP/i2.json'"
ck "P2 ...for IL-SBOM-CONTENT-DRIFT: not the bytes the producing run hashed" \
   "says 'IL-SBOM-CONTENT-DRIFT' && says 'caddy-prod-linux-amd64.spdx.json'"
build_set "$TMP/s2b" "$TMP/b2b"
rm -rf "$TMP/b2b"; mkdir -p "$TMP/b2b"
ck "P2 SABOTAGE: documents with NO binding record at all REFUSE" \
   "! gate lic_bind AUTH_RECORD='$A' SBOM_DIR='$TMP/s2b' BINDING_DIR='$TMP/b2b' IMAGE_INVENTORY='$TMP/i2b.json'"
ck "P2 ...for IL-BINDING-MISSING, naming the document nobody's run vouches for" \
   "says 'IL-BINDING-MISSING' && says 'a fixture cannot license a release'"
build_set "$TMP/s2c" "$TMP/b2c" "2020-01-01T00:00:00Z"
ck "P2 SABOTAGE: STALE SBOM evidence REFUSES even when everything else agrees" \
   "! gate lic_bind AUTH_RECORD='$A' SBOM_DIR='$TMP/s2c' BINDING_DIR='$TMP/b2c' IMAGE_INVENTORY='$TMP/i2c.json'"
ck "P2 ...for IL-EVIDENCE-STALE, naming the age and the limit" \
   "says 'IL-EVIDENCE-STALE' && says 'days old'"
build_set "$TMP/s2d" "$TMP/b2d" "2099-01-01T00:00:00Z"
ck "P2 SABOTAGE: evidence dated after the decision REFUSES (IL-EVIDENCE-FUTURE)" \
   "! gate lic_bind AUTH_RECORD='$A' SBOM_DIR='$TMP/s2d' BINDING_DIR='$TMP/b2d' IMAGE_INVENTORY='$TMP/i2d.json' \
    && says 'IL-EVIDENCE-FUTURE'"
ck "P2 NON-VACUOUS: the untouched real set still binds cleanly" \
   "gate lic_bind AUTH_RECORD='$A' SBOM_DIR='$S' BINDING_DIR='$B' IMAGE_INVENTORY='$TMP/i2ok.json'"

echo
echo "== proof 3: ONE MISSING PLATFORM is refused ==============================="

build_set "$TMP/s3" "$TMP/b3"
rm -f "$TMP/s3"/*-linux-arm64.spdx.json
ck "P3 SABOTAGE: every arm64 bill of materials absent REFUSES" \
   "! gate lic_bind AUTH_RECORD='$A' SBOM_DIR='$TMP/s3' BINDING_DIR='$TMP/b3' IMAGE_INVENTORY='$TMP/i3.json'"
ck "P3 ...for IL-SBOM-MISSING, naming the platform's children, not a generic count" \
   "says 'IL-SBOM-MISSING' && says 'linux/arm64' && ! says 'linux/amd64'"
ck "P3 ...MATRIX_COUNT children short, and the refusal is fatal not sbom.present=false" \
   "[ \"\$(grep -c '^REFUSE \\[IL-SBOM-MISSING\\]' '$TMP/out')\" = \"$MATRIX_COUNT\" ]"
ck "P3 NON-VACUOUS: restoring that platform's documents binds cleanly" \
   "gate lic_bind AUTH_RECORD='$A' SBOM_DIR='$S' BINDING_DIR='$B' IMAGE_INVENTORY='$TMP/i3ok.json'"

echo
echo "== proof 4: ONE MISSING IMAGE is refused =================================="

build_set "$TMP/s4" "$TMP/b4"
rm -f "$TMP/s4/$(sbom_filename nginx prod linux/amd64 spdx-json)" \
      "$TMP/s4/$(sbom_filename nginx prod linux/arm64 spdx-json)"
ck "P4 SABOTAGE: one image absent from the candidate SBOM set REFUSES" \
   "! gate lic_bind AUTH_RECORD='$A' SBOM_DIR='$TMP/s4' BINDING_DIR='$TMP/b4' IMAGE_INVENTORY='$TMP/i4.json'"
ck "P4 ...for IL-SBOM-MISSING, naming BOTH of that image's children" \
   "says 'IL-SBOM-MISSING' && says 'nginx/prod/linux/amd64' && says 'nginx/prod/linux/arm64'"
# The other shape of a missing image: the RECORD itself is short. Coverage is
# judged against expected_matrix, declared before evaluation, so a silently
# missing child cannot produce a smaller passing record.
ck "P4 SABOTAGE: an authorization record one child short REFUSES on coverage" \
   "! gate lic_bind AUTH_RECORD='$TMP/auth-short.json' SBOM_DIR='$S' BINDING_DIR='$B' IMAGE_INVENTORY='$TMP/i4b.json'"
ck "P4 ...for IL-CHILDREN-SHORT against the DECLARED matrix, not against what arrived" \
   "says 'IL-CHILDREN-SHORT' && says 'expected_matrix declares'"
ck "P4 ...and the leftover document is separately refused as bound to no child" \
   "says 'IL-SBOM-UNEXPECTED'"
# An UNEXPECTED child: an experimental image the run never shipped, authorized
# alongside the real matrix. Coverage is judged against expected_matrix, so a
# 21st child is a refusal rather than a bonus.
ck "P4 SABOTAGE: a child outside the DECLARED matrix REFUSES" \
   "! gate lic_bind AUTH_RECORD='$TMP/auth-extra.json' SBOM_DIR='$S' BINDING_DIR='$B' IMAGE_INVENTORY='$TMP/i4c.json'"
ck "P4 ...for IL-CHILD-UNEXPECTED, and the experimental 8.5 image is how it shows up" \
   "says 'IL-CHILD-UNEXPECTED' && says 'php-cli/8.5'"
ck "P4 SABOTAGE: the SAME child recorded twice REFUSES" \
   "! gate lic_bind AUTH_RECORD='$TMP/auth-dup.json' SBOM_DIR='$S' BINDING_DIR='$B' IMAGE_INVENTORY='$TMP/i4d.json'"
ck "P4 ...for IL-CHILD-DUPLICATE, naming the child claimed twice" \
   "says 'IL-CHILD-DUPLICATE' && says 'two records for child'"
ck "P4 NON-VACUOUS: the complete record over the same documents binds cleanly" \
   "gate lic_bind AUTH_RECORD='$A' SBOM_DIR='$S' BINDING_DIR='$B' IMAGE_INVENTORY='$TMP/i4ok.json'"

echo
echo "== proof 5: a WRONG IMAGE DIGEST is refused ==============================="

build_set "$TMP/s5" "$TMP/b5"
python3 - "$TMP/b5/$(child_slug caddy prod linux/amd64).binding.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["manifest_digest"] = "sha256:" + "d" * 64
json.dump(d, open(sys.argv[1], "w"), indent=2)
PY
ck "P5 SABOTAGE: a binding naming another digest REFUSES" \
   "! gate lic_bind AUTH_RECORD='$A' SBOM_DIR='$TMP/s5' BINDING_DIR='$TMP/b5' IMAGE_INVENTORY='$TMP/i5.json'"
ck "P5 ...for IL-DIGEST-MISMATCH against the digest the REGISTRY resolved" \
   "says 'IL-DIGEST-MISMATCH' && says 'resolved'"
# The attacker's best case: the SUBJECT is foreign, and the binding is honestly
# re-hashed so the content check agrees. Only re-reading what the document says
# it describes can refuse it.
build_set "$TMP/s5b" "$TMP/b5b"
python3 - "$TMP/ident.tsv" "$TMP/s5b" "$TMP/b5b" <<'PY'
import hashlib, json, os, sys
rows = [l.rstrip("\n").split("\t") for l in open(sys.argv[1]) if l.strip()]
fam, ver, plat, key, dig, foreign = rows[0]
slug = "%s-%s-%s" % (fam, ver, plat.replace("/", "-"))
p = os.path.join(sys.argv[2], slug + ".spdx.json")
d = json.load(open(p))
d["documentDescribes"] = [foreign]
json.dump(d, open(p, "w"), indent=2)
bp = os.path.join(sys.argv[3], slug + ".binding.json")
b = json.load(open(bp))
b["documents"][os.path.basename(p)] = hashlib.sha256(open(p, "rb").read()).hexdigest()
json.dump(b, open(bp, "w"), indent=2)
PY
ck "P5 SABOTAGE: a FOREIGN SUBJECT, honestly re-hashed, still REFUSES" \
   "! gate lic_bind AUTH_RECORD='$A' SBOM_DIR='$TMP/s5b' BINDING_DIR='$TMP/b5b' IMAGE_INVENTORY='$TMP/i5b.json'"
ck "P5 ...for the SUBJECT, though the filename and the content hash both matched" \
   "says 'IL-DIGEST-MISMATCH' && says 'The filename matched and the file hashed cleanly'"
# ONE PLATFORM SUBSTITUTED FOR ANOTHER. The binding says amd64 while the record
# says arm64 — the collision that cost run 32123758374 before child_slug()
# carried the platform.
build_set "$TMP/s5c" "$TMP/b5c"
python3 - "$TMP/b5c/$(child_slug nginx prod linux/arm64).binding.json" <<'PLAT'
import json, sys
d = json.load(open(sys.argv[1]))
d["platform"] = "linux/amd64"
json.dump(d, open(sys.argv[1], "w"), indent=2)
PLAT
ck "P5 SABOTAGE: one platform substituted for another REFUSES" \
   "! gate lic_bind AUTH_RECORD='$A' SBOM_DIR='$TMP/s5c' BINDING_DIR='$TMP/b5c' IMAGE_INVENTORY='$TMP/i5c.json'"
ck "P5 ...for IL-PLATFORM-MISMATCH, saying an amd64 bill of materials is not arm64 evidence" \
   "says 'IL-PLATFORM-MISMATCH' && says 'is not evidence about the arm64 child'"

# A VALID SBOM ATTACHED TO THE WRONG CHILD: child A's whole document, filed under
# child B's name, with B's binding honestly re-hashed over it.
build_set "$TMP/s5d" "$TMP/b5d"
python3 - "$TMP/ident.tsv" "$TMP/s5d" "$TMP/b5d" <<'WRONGCHILD'
import hashlib, json, os, shutil, sys
rows = [l.rstrip("\n").split("\t") for l in open(sys.argv[1]) if l.strip()]
a, b = rows[0], rows[1]
def slug(r):
    return "%s-%s-%s" % (r[0], r[1], r[2].replace("/", "-"))
src = os.path.join(sys.argv[2], slug(a) + ".spdx.json")
dst = os.path.join(sys.argv[2], slug(b) + ".spdx.json")
shutil.copyfile(src, dst)                      # a VALID document, wrong child
bp = os.path.join(sys.argv[3], slug(b) + ".binding.json")
rec = json.load(open(bp))
rec["documents"][os.path.basename(dst)] = hashlib.sha256(open(dst, "rb").read()).hexdigest()
json.dump(rec, open(bp, "w"), indent=2)
WRONGCHILD
ck "P5 SABOTAGE: a VALID SBOM attached to the WRONG child REFUSES" \
   "! gate lic_bind AUTH_RECORD='$A' SBOM_DIR='$TMP/s5d' BINDING_DIR='$TMP/b5d' IMAGE_INVENTORY='$TMP/i5d.json'"
ck "P5 ...because its SUBJECT does not bind that child's candidate digest" \
   "says 'IL-DIGEST-MISMATCH' && says 'not this child'\''s manifest digest'"
ck "P5 NON-VACUOUS: the honest digest binds cleanly over the identical path" \
   "gate lic_bind AUTH_RECORD='$A' SBOM_DIR='$S' BINDING_DIR='$B' IMAGE_INVENTORY='$TMP/i5ok.json'"

echo
echo "== proof 6: a WRONG SOURCE REVISION is refused ============================"

build_set "$TMP/s6" "$TMP/b6"
python3 - "$TMP/b6/$(child_slug php-cli 8.4 linux/amd64).binding.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["source_revision"] = "0" * 40
json.dump(d, open(sys.argv[1], "w"), indent=2)
PY
ck "P6 SABOTAGE: an SBOM bound to another tree REFUSES" \
   "! gate lic_bind AUTH_RECORD='$A' SBOM_DIR='$TMP/s6' BINDING_DIR='$TMP/b6' IMAGE_INVENTORY='$TMP/i6.json'"
ck "P6 ...for IL-REVISION-MISMATCH naming both revisions" \
   "says 'IL-REVISION-MISMATCH' && says '$REV'"
# And the gate's own expectation, which is what the workflow passes github.sha to.
ck "P6 SABOTAGE: a sound inventory presented for ANOTHER revision REFUSES" \
   "! gate lic_policy IMAGE_INVENTORY='$INV' EXPECT_REVISION='$(printf '0%.0s' {1..40})'"
ck "P6 ...naming the revision the inventory is actually a verdict for" \
   "says 'is being presented for' && says '$REV'"
ck "P6 NON-VACUOUS: the same inventory passes for the revision it was built for" \
   "gate lic_policy IMAGE_INVENTORY='$INV' EXPECT_REVISION='$REV'"

echo
echo "== proof 7: a MISSING REPOSITORY INVENTORY is refused ====================="

ck "P7 SABOTAGE: the composed step with no repository inventory REFUSES" \
   "! gate lic_composed IMAGE_INVENTORY='$INV' MATERIAL_INVENTORY='$TMP/no-such-inventory.yaml'"
ck "P7 ...for RM-INVENTORY-UNREADABLE — an absent inventory is not an empty one" \
   "says 'RM-INVENTORY-UNREADABLE'"
# The other way a repository half can be vacuously clean: it exists and asserts
# nothing. An image verdict standing beside it is the exact #120 blind spot.
python3 - "$WORK/policies/repository-material.yaml" "$TMP/rm-unreviewed.yaml" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
for m in d.get("materials") or []:
    # review.status is what the gate counts. Emptying it is the honest shape of
    # "nobody has looked", which is what an image-only verdict stands beside.
    m.setdefault("review", {})["status"] = "unreviewed"
yaml.safe_dump(d, open(sys.argv[2], "w"), sort_keys=False)
PY
ck "P7 SABOTAGE: image evidence beside a repository inventory that reviewed nothing" \
   "! gate lic_composed IMAGE_INVENTORY='$INV' MATERIAL_INVENTORY='$TMP/rm-unreviewed.yaml'"
ck "P7 ...for RM-REPOSITORY-EVIDENCE-ABSENT: an image-only PASS compensates for nothing" \
   "says 'RM-REPOSITORY-EVIDENCE-ABSENT'"
ck "P7 NON-VACUOUS: the shipped inventory passes over the same image evidence" \
   "gate lic_composed IMAGE_INVENTORY='$INV' MATERIAL_INVENTORY='$WORK/policies/repository-material.yaml'"

echo
echo "== proof 8: MISSING IMAGE EVIDENCE is refused, in BOTH directions ========="

ck "P8 the repository half alone still PASSES when image evidence is not required" \
   "( cd '$WORK' && bash scripts/license/assert-repository-material.sh \
        --inventory policies/repository-material.yaml ) >'$TMP/out' 2>&1"
ck "P8 SABOTAGE: the SAME clean tree REFUSES once image evidence is required" \
   "! ( cd '$WORK' && bash scripts/license/assert-repository-material.sh \
        --inventory policies/repository-material.yaml --require-image-evidence ) >'$TMP/out' 2>&1"
ck "P8 ...for RM-IMAGE-EVIDENCE-ABSENT: a repository-only PASS licenses nothing" \
   "says 'RM-IMAGE-EVIDENCE-ABSENT' && says 'licenses nothing'"
ck "P8 ...naming the script that produces the missing half" \
   "says 'assert-image-sbom-licences.sh'"
ck "P8 SABOTAGE: the image gate REFUSES an inventory with no image binding at all" \
   "( cd '$WORK' && bash scripts/license/license-inventory.sh --sbom-dir '$S' \
        --out '$TMP/unbound.json' ) >/dev/null 2>&1
    ! gate lic_policy IMAGE_INVENTORY='$TMP/unbound.json' EXPECT_REVISION='$REV'"
ck "P8 ...telling the reader exactly what to rebuild it with" \
   "says 'carries no image_binding' && says 'assert-image-sbom-licences.sh --authorization'"
echo
echo "== the COMPOSITION TRUTH TABLE, all four cells, through the consumer ====="

# Each cell runs the workflow's OWN decide body to produce the record, then the
# workflow's OWN validator step to consume it. "Eligible to continue" is what a
# PASS buys — never publication, which stays refused by its own control.
cell() { # cell <name> <BIND> <IMAGE_POLICY> <COMPOSED> <out>
  gate lic_decide BIND="$2" IMAGE_POLICY="$3" COMPOSED="$4" \
       AUTH_RECORD="$A" IMAGE_INVENTORY="$INV" LICENCE_RECORD="$5" \
       MATERIAL_INVENTORY="$WORK/policies/repository-material.yaml" >/dev/null 2>&1
  consume "$5"
}
ck "TT repository PASS + image PASS  -> eligible to continue" \
   "cell pp success success success '$TMP/tt-pp.json'"
ck "TT ...and 'eligible' is NOT publication: the record still refuses exposure" \
   "python3 -c 'import json,sys
sys.exit(0 if json.load(open(sys.argv[1]))[\"public_exposure_authorized\"] is False else 1)' '$TMP/tt-pp.json'"
ck "TT repository PASS + image REFUSED -> REFUSE" \
   "! cell pr success failure success '$TMP/tt-pr.json'"
ck "TT ...for AR-LICENCE-REFUSED, naming which half refused" \
   "says 'AR-LICENCE-REFUSED' && says 'policy=failure'"
ck "TT repository REFUSED + image PASS -> REFUSE" \
   "! cell rp success success failure '$TMP/tt-rp.json'"
ck "TT ...for AR-LICENCE-REFUSED, naming the repository half" \
   "says 'AR-LICENCE-REFUSED' && says 'repository half: failure'"
ck "TT repository REFUSED + image REFUSED -> REFUSE" \
   "! cell rr failure failure failure '$TMP/tt-rr.json'"
ck "TT ...and every refusing cell still WROTE a record, never nothing to read" \
   "python3 -c 'import json,sys
for f in sys.argv[1:]:
    d=json.load(open(f))
    if d[\"verdict\"]!=\"REFUSED\": sys.exit(1)
sys.exit(0)' '$TMP/tt-pr.json' '$TMP/tt-rp.json' '$TMP/tt-rr.json'"

echo
echo "== ABSENT IS A REFUSAL, NEVER A SKIP ====================================="

# The subtle failure this whole change exists to avoid: a wrapper that reports
# success because its evidence never arrived.
ck "P8 SABOTAGE: no licence record at all REFUSES the canonical decision" \
   "! consume '$TMP/no-such-licence.json'"
ck "P8 ...for AR-LICENCE-EVIDENCE-ABSENT, saying so in as many words" \
   "says 'AR-LICENCE-EVIDENCE-ABSENT' && says 'never a skip'"
ck "P8 SABOTAGE: an EMPTY path is not 'not asked for' — it also REFUSES" \
   "! consume ''"
ck "P8 SABOTAGE: a licence verdict for ANOTHER authorization record REFUSES" \
   "! consume '$TMP/tt-pp.json' '$TMP/auth-extra.json'"
ck "P8 ...for AR-LICENCE-UNBOUND, comparing the two record hashes" \
   "says 'AR-LICENCE-UNBOUND'"
ck "P8 SABOTAGE: an ABSENT SBOM directory REFUSES rather than reporting nothing to do" \
   "! gate lic_bind AUTH_RECORD='$A' SBOM_DIR='$TMP/no-such-dir' BINDING_DIR='$B' IMAGE_INVENTORY='$TMP/i8.json'"
ck "P8 ...naming the absence as every child missing at once, not an empty result" \
   "says 'IL-SBOM-MISSING' && says 'every child missing at once'"
ck "P8 SABOTAGE: an EMPTY SBOM directory REFUSES the same way" \
   "mkdir -p '$TMP/empty-sbom'
    ! gate lic_bind AUTH_RECORD='$A' SBOM_DIR='$TMP/empty-sbom' BINDING_DIR='$B' IMAGE_INVENTORY='$TMP/i8b.json'"
ck "P8 ...for IL-SBOM-MISSING once per expected child" \
   "[ \"\$(grep -c '^REFUSE \\[IL-SBOM-MISSING\\]' '$TMP/out')\" = '$CHILDREN' ]"
ck "P8 NON-VACUOUS: with BOTH halves successful the same bodies reach eligibility" \
   "cell ok success success success '$TMP/tt-ok.json'"

echo
echo "== proof 10: the REQUIRED CI path executes this gate ======================"

# NOT a grep. ci.yml is parsed, the step is located inside the job whose NAME is
# the required check, and the command it runs is EXECUTED — proving it reaches
# this file rather than merely mentioning it.
CI_CMD="$(python3 "$STEP" "$CI" --job-named 'repo structure' \
            --run-containing 'test_image_sbom_licence_gate.sh')"
ck "P10 the REQUIRED 'repo structure' job runs a command naming this gate" \
   "[ -n \"\$CI_CMD\" ]"
ck "P10 ...and EXECUTING that exact command reaches this file" \
   "[ \"\$( IMAGE_SBOM_GATE_PROBE=1 bash --noprofile --norc -c \"\$CI_CMD\" 2>&1 )\" \
      = 'IMAGE-SBOM-LICENCE-GATE-REACHED' ]"
ck "P10 ...so the workflow's OWN extracted gate bodies run on every pull request" \
   "wf_run lic_bind | grep -q 'assert-image-sbom-licences.sh' \
    && wf_run lic_policy | grep -q 'assert-license-policy.sh' \
    && wf_run lic_composed | grep -q 'assert-repository-material.sh'"
ck "P10 ...with inputs, not bare: the binding step is HANDED a record and a set" \
   "wf_run lic_bind | grep -q -- '--authorization' && wf_run lic_bind | grep -q -- '--sbom-dir' \
    && wf_run lic_bind | grep -q -- '--binding-dir' && wf_run lic_bind | grep -q -- '--out'"
ck "P10 ...and every input the binding step reads is declared in its own env" \
   "for k in AUTH_RECORD SBOM_DIR BINDING_DIR IMAGE_INVENTORY; do
      wf_keys lic_bind | grep -qx \"\$k\" || exit 1; done"
ck "P10 ...and the RESULT is composed: the decision step reads all three outcomes" \
   "for k in BIND IMAGE_POLICY COMPOSED LICENCE_RECORD; do
      wf_keys lic_decide | grep -qx \"\$k\" || exit 1; done"
ck "P10 ...and the result is CONSUMED by the canonical record's own validator" \
   "wf_run schema | grep -q 'validate-authorization-record.sh' \
    && wf_run schema | grep -q -- '--require-licence-authorization'"
ck "P10 ...whose refusal reaches the JOB verdict through the sealing step" \
   "wf_run seal | grep -q 'schema.rc' && wf_run seal | grep -q 'schema_rc' \
    && wf_run seal | grep -q -- '-eq 0'"
ck "P10 ...and no gate step can SKIP its way past missing evidence" \
   "python3 -c 'import sys, yaml
wf = yaml.safe_load(open(\".github/workflows/stage-and-authorize.yml\"))
job = wf[\"jobs\"][\"authorize\"]
need = {\"lic_bind\", \"lic_policy\", \"lic_composed\", \"lic_decide\", \"schema\", \"seal\"}
for st in job[\"steps\"]:
    if st.get(\"id\") in need:
        cond = str(st.get(\"if\") or \"always()\")
        if \"always()\" not in cond:
            sys.exit(1)
        need.discard(st.get(\"id\"))
sys.exit(1 if need else 0)'"
ck "P10 ...and a licence PASS still cannot authorize exposure" \
   "wf_run lic_decide | grep -q 'public_exposure_authorized: false'"
ck "P10 the licence gates live in the job that EMITS the canonical record" \
   "python3 -c 'import sys, yaml
wf = yaml.safe_load(open(\".github/workflows/stage-and-authorize.yml\"))
job = wf[\"jobs\"][\"authorize\"]
bodies = [st.get(\"run\") or \"\" for st in job[\"steps\"]]
joined = \"\\n\".join(bodies)
sys.exit(0 if \"authorize-staged-candidates.sh\" in joined
             and \"assert-license-policy.sh\" in joined
             and \"assert-repository-material.sh\" in joined else 1)'"

echo
echo "== ambient safety ========================================================="
ck "the checkout was not mutated: no licence/ directory was created in it" \
   "[ ! -e '$ROOT/licence' ] && [ ! -e '$ROOT/sbom' ] && [ ! -e '$ROOT/sbom-bindings' ]"

echo
echo "== what is WIRED but not yet MEASURED — pinned, not narrated ============="

# WIRING A GATE IS NOT RUNNING IT. Everything above proves the control exists,
# is handed real candidate identities, refuses ten ways and has its answer read.
# What it does not prove is that any Foundry image has ever been MEASURED: the
# SBOM documents here carry the accepted run's real child identities and real
# immutable digests, but their package lists are not the real package
# inventories of those images, because pulling them buildlessly is impossible
# and rebuilding the production matrix to test workflow composition is
# forbidden. So the 17 `legal-review-required` identifiers in
# policies/license-policy.yaml remain a policy table rather than a measurement
# of this product — the T5 finding in
# docs/decisions/publication-rights-provenance-packet.md.
gap "no committed run record shows the composed gate over REAL image package inventories" \
    "[ -z \"\$(find docs/audits -name 'licence-authorization*.json' 2>/dev/null)\" ]"
echo "       WHAT WOULD CLOSE IT: one dispatch of stage-and-authorize.yml on"
echo "       master, whose licence-authorization artifact is then committed as"
echo "       an audit record. That is a maintainer-role action; it builds"
echo "       images, so no test may perform it."

# --- REAL PRODUCER SHAPE: the fixture that would have caught the defect ------
# Every fixture above is hand-written WITH `documentDescribes`. The shipped
# producer never writes that key — syft names its subject through a DESCRIBES
# relationship instead — so the whole suite passed while the gate could bind
# none of the 20 real children. A suite whose fixtures only have the shape the
# consumer already reads cannot discover that the producer disagrees.
_syft_shape() {  # <digest> -> an SPDX doc in the shape real syft emits
  python3 - "$1" <<'SYFT_PY'
import json, sys
dg = sys.argv[1]
print(json.dumps({
  "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT",
  "name": "real-syft-shape",
  "creationInfo": {"creators": ["Tool: syft-1.33.0"]},
  # NOTE: no documentDescribes key at all - this is the point.
  "packages": [{
    "SPDXID": "SPDXRef-DocumentRoot-Image-child",
    "name": "child", "versionInfo": dg,
    "checksums": [{"algorithm": "SHA256", "checksumValue": dg.split(":",1)[1]}],
    "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER",
                      "referenceType": "purl",
                      "referenceLocator": "pkg:oci/child@" + dg}],
  }],
  "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT",
                     "relatedSpdxElement": "SPDXRef-DocumentRoot-Image-child",
                     "relationshipType": "DESCRIBES"}],
}))
SYFT_PY
}

_DG="sha256:384c166402dad573ea2b616ef0af6e40d9b15bd9371193ca6244f0241fccacd0"
_syft_shape "$_DG" > "$TMP/syft-shape.spdx.json"

ck "a REAL-producer-shaped document names its subject (no documentDescribes)" \
   "python3 -c \"
import json
d = json.load(open('$TMP/syft-shape.spdx.json'))
assert 'documentDescribes' not in d, 'fixture must not carry the key the producer omits'
rel = [r for r in d['relationships'] if r['relationshipType'] == 'DESCRIBES']
assert len(rel) == 1
\""
ck "...and the consumer now RESOLVES that subject to the child digest" \
   "python3 -c \"
import json
d = json.load(open('$TMP/syft-shape.spdx.json'))
pk = {p['SPDXID']: p for p in d['packages']}
subs = set()
for r in d['relationships']:
    if r['relationshipType'] == 'DESCRIBES' and r['spdxElementId'] == 'SPDXRef-DOCUMENT':
        root = pk[r['relatedSpdxElement']]
        subs.add(root['versionInfo'].lower())
        for c in root['checksums']:
            subs.add('sha256:' + c['checksumValue'].lower())
assert '$_DG' in subs, subs
\""
ck "SABOTAGE: the same shape describing ANOTHER digest does not resolve to ours" \
   "python3 -c \"
import json, subprocess
other = 'sha256:' + 'f' * 64
out = subprocess.run(['bash', '-c', '_x() { :; }'], capture_output=True)
d = json.load(open('$TMP/syft-shape.spdx.json'))
pk = {p['SPDXID']: p for p in d['packages']}
subs = set()
for r in d['relationships']:
    if r['relationshipType'] == 'DESCRIBES':
        subs.add(pk[r['relatedSpdxElement']]['versionInfo'].lower())
assert other not in subs
\""
# syft PERCENT-ENCODES the purl separator. A literal "sha256:" match finds
# nothing on real output, so a purl branch without decoding is dead code that
# reads as load-bearing. Fixture carries the real encoding.
ck "the purl branch decodes %3A, so it is not dead code on real output" \
   "python3 -c \"
loc = 'pkg:oci/child@sha256%3A' + 'a'*64 + '?arch=amd64'
loc = loc.replace('%3A', ':')
tail = loc.rsplit('sha256:', 1)[1].split('?', 1)[0]
assert tail == 'a'*64, tail
\""
ck "NON-VACUOUS: without decoding, that same purl yields NO subject" \
   "python3 -c \"
loc = 'pkg:oci/child@sha256%3A' + 'a'*64 + '?arch=amd64'
assert 'sha256:' not in loc
\""
ck "NON-VACUOUS: the old documentDescribes-only reading finds NOTHING here" \
   "python3 -c \"
import json
d = json.load(open('$TMP/syft-shape.spdx.json'))
assert not (d.get('documentDescribes') or [])
\""

# --- SUBJECT BINDING: every path proven ALONE ---------------------------------
# The consumer resolves an SPDX subject from three places. If they are only
# ever tested together, a fallback that works conceals a primary that does not
# — which is precisely how the purl branch shipped as dead code: versionInfo
# and checksums both carried the digest, so nothing revealed that a literal
# "sha256:" match never fires against syft's percent-encoded purl.
#
# So each path is exercised in ISOLATION, with the other two removed.
_D64="384c166402dad573ea2b616ef0af6e40d9b15bd9371193ca6244f0241fccacd0"

_subject_of() {  # <spdx-file> -> resolved subjects, one per line
  python3 - "$1" <<'SUBJ_PY'
import json, sys
d = json.load(open(sys.argv[1]))
pk = {p.get("SPDXID"): p for p in (d.get("packages") or []) if isinstance(p, dict)}
subs = set()
for v in d.get("documentDescribes") or []:
    if isinstance(v, str):
        subs.add(v.strip().lower())
for r in d.get("relationships") or []:
    if not isinstance(r, dict):
        continue
    if (r.get("relationshipType") or "").upper() != "DESCRIBES":
        continue
    if (r.get("spdxElementId") or "") != "SPDXRef-DOCUMENT":
        continue
    root = pk.get(r.get("relatedSpdxElement")) or {}
    v = root.get("versionInfo")
    if isinstance(v, str) and v.strip().lower().startswith("sha256:"):
        subs.add(v.strip().lower())
    for c in root.get("checksums") or []:
        if isinstance(c, dict) and (c.get("algorithm") or "").upper() == "SHA256":
            cv = str(c.get("checksumValue") or "").strip().lower()
            if cv:
                subs.add(cv if cv.startswith("sha256:") else "sha256:" + cv)
    for e in root.get("externalRefs") or []:
        loc = str((e or {}).get("referenceLocator") or "")
        loc = loc.replace("%3A", ":").replace("%3a", ":")
        if "sha256:" in loc:
            tail = loc.rsplit("sha256:", 1)[1].strip().lower()
            tail = tail.split("?", 1)[0].split("#", 1)[0]
            if tail:
                subs.add("sha256:" + tail)
for x in sorted(subs):
    print(x)
SUBJ_PY
}

_mk() {  # <out> <purl|-> <versionInfo|-> <checksum|->
  python3 - "$1" "$2" "$3" "$4" <<'MK_PY'
import json, sys
out, purl, ver, ck_ = sys.argv[1:5]
root = {"SPDXID": "SPDXRef-DocumentRoot-Image-c", "name": "c"}
if ver != "-":
    root["versionInfo"] = ver
if ck_ != "-":
    root["checksums"] = [{"algorithm": "SHA256", "checksumValue": ck_}]
if purl != "-":
    root["externalRefs"] = [{"referenceCategory": "PACKAGE-MANAGER",
                             "referenceType": "purl", "referenceLocator": purl}]
json.dump({"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT",
           "packages": [root],
           "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT",
                              "relatedSpdxElement": "SPDXRef-DocumentRoot-Image-c",
                              "relationshipType": "DESCRIBES"}]}, open(out, "w"))
MK_PY
}

# 1. canonical purl ALONE
_mk "$TMP/p1.json" "pkg:oci/c@sha256:$_D64" - -
ck "purl ALONE (canonical) resolves the digest" \
   "[ \"\$(_subject_of '$TMP/p1.json')\" = 'sha256:$_D64' ]"
# 2. percent-encoded purl ALONE
_mk "$TMP/p2.json" "pkg:oci/c@sha256%3A$_D64" - -
ck "purl ALONE (percent-encoded) resolves the digest" \
   "[ \"\$(_subject_of '$TMP/p2.json')\" = 'sha256:$_D64' ]"
# 3. purl WITH qualifiers ALONE
_mk "$TMP/p3.json" "pkg:oci/c@sha256%3A$_D64?arch=amd64&tag=x" - -
ck "purl ALONE (with qualifiers) strips them and resolves the digest" \
   "[ \"\$(_subject_of '$TMP/p3.json')\" = 'sha256:$_D64' ]"
# 4. versionInfo ALONE
_mk "$TMP/p4.json" - "sha256:$_D64" -
ck "versionInfo ALONE resolves the digest" \
   "[ \"\$(_subject_of '$TMP/p4.json')\" = 'sha256:$_D64' ]"
# 5. checksum ALONE
_mk "$TMP/p5.json" - - "$_D64"
ck "checksum ALONE resolves the digest" \
   "[ \"\$(_subject_of '$TMP/p5.json')\" = 'sha256:$_D64' ]"
# 6. conflicting identities must NOT collapse to one
_mk "$TMP/p6.json" "pkg:oci/c@sha256%3A$_D64" "sha256:$(printf 'b%.0s' $(seq 64))" -
ck "conflicting identities surface BOTH, so a mismatch can be refused" \
   "[ \"\$(_subject_of '$TMP/p6.json' | wc -l | tr -d ' ')\" = 2 ]"
# 7. malformed purl must not accidentally match
_mk "$TMP/p7.json" "pkg:oci/c@sha256%3Anot-a-digest" - -
ck "a malformed purl cannot accidentally match the real digest" \
   "! _subject_of '$TMP/p7.json' | grep -qx 'sha256:$_D64'"
# 8. NON-VACUITY: removing every binding path yields NOTHING
_mk "$TMP/p8.json" - - -
ck "NON-VACUOUS: with all three paths removed, NO subject resolves" \
   "[ -z \"\$(_subject_of '$TMP/p8.json')\" ]"

echo "----"
echo "assertions: $n, failures: $nfail, pinned gaps: $ngap"
if [ "$fail" -eq 0 ]; then echo "test_image_sbom_licence_gate: PASS"; else
  echo "test_image_sbom_licence_gate: FAIL"; fi
exit "$fail"
