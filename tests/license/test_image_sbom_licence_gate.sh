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

fail=0 n=0 nfail=0
ck() { n=$((n+1)); if eval "$2"; then echo "ok   - $1"; else
         echo "FAIL - $1"; fail=1; nfail=$((nfail+1)); fi; }

WF=.github/workflows/stage-and-authorize.yml
JOB=licence-authorization
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

# --- the disposable repository the extracted step bodies execute against -----
# The step bodies write licence/*.rc relative to the working directory, and the
# repository-material half reads the tracked file set with git. Both therefore
# need a real checkout, and it must NOT be this one: a self-test that writes to
# a path derived from the repository root is the class
# tests/lib/test_no_ambient_mutation.sh exists to refuse.
WORK="$TMP/repo"
mkdir -p "$WORK" && cp -R "$ROOT/." "$WORK/" 2>/dev/null

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
  ( cd "$WORK" && mkdir -p licence \
      && env "${envs[@]}" GITHUB_OUTPUT="$TMP/gh-output" \
             GITHUB_STEP_SUMMARY="$TMP/gh-summary" "$@" \
             bash --noprofile --norc -c "$body" ) >"$TMP/out" 2>&1
}
says() { grep -q -- "$1" "$TMP/out"; }
outcat() { cat "$TMP/out"; }

A="$TMP/auth.json"
S="$TMP/sbom"
B="$TMP/bind"
INV="$TMP/image-inventory.json"

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
   "gate bind AUTH_RECORD='$A' SBOM_DIR='$S' BINDING_DIR='$B' IMAGE_INVENTORY='$INV'"
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
ck "P9 ...and the binding names the same revision the accepted run recorded" \
   "[ \"\$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))[\"image_binding\"][\"source_revision\"])' '$INV')\" = '$REV' ]"
ck "P9 the workflow's IMAGE-SBOM licence gate passes over that real inventory" \
   "gate image_policy IMAGE_INVENTORY='$INV' EXPECT_REVISION='$REV'"
ck "P9 ...and it is the shipped fail-closed gate, not a self-test" \
   "wf_run image_policy | grep -q 'assert-license-policy.sh' \
    && ! wf_run image_policy | grep -q -- '--self-test'"
ck "P9 the workflow's COMPOSED step passes with both halves present" \
   "gate composed IMAGE_INVENTORY='$INV' MATERIAL_INVENTORY='$WORK/policies/repository-material.yaml'"
ck "P9 ...and it really did read the image half as SOURCE 1" \
   "says 'SOURCE 1' && says 'image-inventory.json'"
ck "P9 the workflow CONSUMES the three results into one recorded decision" \
   "gate decide BIND=success IMAGE_POLICY=success COMPOSED=success \
      AUTH_RECORD='$A' IMAGE_INVENTORY='$INV' \
      MATERIAL_INVENTORY='$WORK/policies/repository-material.yaml'"
ck "P9 ...as verdict PASS naming both halves and the child count" \
   "python3 -c 'import json,sys
d=json.load(open(sys.argv[1]))
sys.exit(0 if d[\"verdict\"]==\"PASS\" and d[\"both_halves_required\"]
             and d[\"image_half\"][\"children_bound\"]==$CHILDREN
             and d[\"repository_half\"][\"composed\"]==\"success\" else 1)' \
      '$WORK/licence/licence-authorization.json'"
ck "P9 ...while publication stays REFUSED, unchanged by a licence PASS" \
   "python3 -c 'import json,sys
d=json.load(open(sys.argv[1]))
sys.exit(0 if d[\"public_exposure_authorized\"] is False
             and d[\"authorization_record_public_exposure\"]==\"false\" else 1)' \
      '$WORK/licence/licence-authorization.json'"

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
   "! gate bind AUTH_RECORD='$A' SBOM_DIR='$TMP/s2' BINDING_DIR='$TMP/b2' IMAGE_INVENTORY='$TMP/i2.json'"
ck "P2 ...for IL-SBOM-CONTENT-DRIFT: not the bytes the producing run hashed" \
   "says 'IL-SBOM-CONTENT-DRIFT' && says 'caddy-prod-linux-amd64.spdx.json'"
build_set "$TMP/s2b" "$TMP/b2b"
rm -rf "$TMP/b2b"; mkdir -p "$TMP/b2b"
ck "P2 SABOTAGE: documents with NO binding record at all REFUSE" \
   "! gate bind AUTH_RECORD='$A' SBOM_DIR='$TMP/s2b' BINDING_DIR='$TMP/b2b' IMAGE_INVENTORY='$TMP/i2b.json'"
ck "P2 ...for IL-BINDING-MISSING, naming the document nobody's run vouches for" \
   "says 'IL-BINDING-MISSING' && says 'a fixture cannot license a release'"
build_set "$TMP/s2c" "$TMP/b2c" "2020-01-01T00:00:00Z"
ck "P2 SABOTAGE: STALE SBOM evidence REFUSES even when everything else agrees" \
   "! gate bind AUTH_RECORD='$A' SBOM_DIR='$TMP/s2c' BINDING_DIR='$TMP/b2c' IMAGE_INVENTORY='$TMP/i2c.json'"
ck "P2 ...for IL-EVIDENCE-STALE, naming the age and the limit" \
   "says 'IL-EVIDENCE-STALE' && says 'days old'"
build_set "$TMP/s2d" "$TMP/b2d" "2099-01-01T00:00:00Z"
ck "P2 SABOTAGE: evidence dated after the decision REFUSES (IL-EVIDENCE-FUTURE)" \
   "! gate bind AUTH_RECORD='$A' SBOM_DIR='$TMP/s2d' BINDING_DIR='$TMP/b2d' IMAGE_INVENTORY='$TMP/i2d.json' \
    && says 'IL-EVIDENCE-FUTURE'"
ck "P2 NON-VACUOUS: the untouched real set still binds cleanly" \
   "gate bind AUTH_RECORD='$A' SBOM_DIR='$S' BINDING_DIR='$B' IMAGE_INVENTORY='$TMP/i2ok.json'"

echo
echo "== proof 3: ONE MISSING PLATFORM is refused ==============================="

build_set "$TMP/s3" "$TMP/b3"
rm -f "$TMP/s3"/*-linux-arm64.spdx.json
ck "P3 SABOTAGE: every arm64 bill of materials absent REFUSES" \
   "! gate bind AUTH_RECORD='$A' SBOM_DIR='$TMP/s3' BINDING_DIR='$TMP/b3' IMAGE_INVENTORY='$TMP/i3.json'"
ck "P3 ...for IL-SBOM-MISSING, naming the platform's children, not a generic count" \
   "says 'IL-SBOM-MISSING' && says 'linux/arm64' && ! says 'linux/amd64'"
ck "P3 ...MATRIX_COUNT children short, and the refusal is fatal not sbom.present=false" \
   "[ \"\$(grep -c '^REFUSE \\[IL-SBOM-MISSING\\]' '$TMP/out')\" = \"$MATRIX_COUNT\" ]"
ck "P3 NON-VACUOUS: restoring that platform's documents binds cleanly" \
   "gate bind AUTH_RECORD='$A' SBOM_DIR='$S' BINDING_DIR='$B' IMAGE_INVENTORY='$TMP/i3ok.json'"

echo
echo "== proof 4: ONE MISSING IMAGE is refused =================================="

build_set "$TMP/s4" "$TMP/b4"
rm -f "$TMP/s4/$(sbom_filename nginx prod linux/amd64 spdx-json)" \
      "$TMP/s4/$(sbom_filename nginx prod linux/arm64 spdx-json)"
ck "P4 SABOTAGE: one image absent from the candidate SBOM set REFUSES" \
   "! gate bind AUTH_RECORD='$A' SBOM_DIR='$TMP/s4' BINDING_DIR='$TMP/b4' IMAGE_INVENTORY='$TMP/i4.json'"
ck "P4 ...for IL-SBOM-MISSING, naming BOTH of that image's children" \
   "says 'IL-SBOM-MISSING' && says 'nginx/prod/linux/amd64' && says 'nginx/prod/linux/arm64'"
# The other shape of a missing image: the RECORD itself is short. Coverage is
# judged against expected_matrix, declared before evaluation, so a silently
# missing child cannot produce a smaller passing record.
ck "P4 SABOTAGE: an authorization record one child short REFUSES on coverage" \
   "! gate bind AUTH_RECORD='$TMP/auth-short.json' SBOM_DIR='$S' BINDING_DIR='$B' IMAGE_INVENTORY='$TMP/i4b.json'"
ck "P4 ...for IL-CHILDREN-SHORT against the DECLARED matrix, not against what arrived" \
   "says 'IL-CHILDREN-SHORT' && says 'expected_matrix declares'"
ck "P4 ...and the leftover document is separately refused as bound to no child" \
   "says 'IL-SBOM-UNEXPECTED'"
ck "P4 NON-VACUOUS: the complete record over the same documents binds cleanly" \
   "gate bind AUTH_RECORD='$A' SBOM_DIR='$S' BINDING_DIR='$B' IMAGE_INVENTORY='$TMP/i4ok.json'"

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
   "! gate bind AUTH_RECORD='$A' SBOM_DIR='$TMP/s5' BINDING_DIR='$TMP/b5' IMAGE_INVENTORY='$TMP/i5.json'"
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
   "! gate bind AUTH_RECORD='$A' SBOM_DIR='$TMP/s5b' BINDING_DIR='$TMP/b5b' IMAGE_INVENTORY='$TMP/i5b.json'"
ck "P5 ...for the SUBJECT, though the filename and the content hash both matched" \
   "says 'IL-DIGEST-MISMATCH' && says 'The filename matched and the file hashed cleanly'"
ck "P5 NON-VACUOUS: the honest digest binds cleanly over the identical path" \
   "gate bind AUTH_RECORD='$A' SBOM_DIR='$S' BINDING_DIR='$B' IMAGE_INVENTORY='$TMP/i5ok.json'"

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
   "! gate bind AUTH_RECORD='$A' SBOM_DIR='$TMP/s6' BINDING_DIR='$TMP/b6' IMAGE_INVENTORY='$TMP/i6.json'"
ck "P6 ...for IL-REVISION-MISMATCH naming both revisions" \
   "says 'IL-REVISION-MISMATCH' && says '$REV'"
# And the gate's own expectation, which is what the workflow passes github.sha to.
ck "P6 SABOTAGE: a sound inventory presented for ANOTHER revision REFUSES" \
   "! gate image_policy IMAGE_INVENTORY='$INV' EXPECT_REVISION='$(printf '0%.0s' {1..40})'"
ck "P6 ...naming the revision the inventory is actually a verdict for" \
   "says 'is being presented for' && says '$REV'"
ck "P6 NON-VACUOUS: the same inventory passes for the revision it was built for" \
   "gate image_policy IMAGE_INVENTORY='$INV' EXPECT_REVISION='$REV'"

echo
echo "== proof 7: a MISSING REPOSITORY INVENTORY is refused ====================="

ck "P7 SABOTAGE: the composed step with no repository inventory REFUSES" \
   "! gate composed IMAGE_INVENTORY='$INV' MATERIAL_INVENTORY='$TMP/no-such-inventory.yaml'"
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
   "! gate composed IMAGE_INVENTORY='$INV' MATERIAL_INVENTORY='$TMP/rm-unreviewed.yaml'"
ck "P7 ...for RM-REPOSITORY-EVIDENCE-ABSENT: an image-only PASS compensates for nothing" \
   "says 'RM-REPOSITORY-EVIDENCE-ABSENT'"
ck "P7 NON-VACUOUS: the shipped inventory passes over the same image evidence" \
   "gate composed IMAGE_INVENTORY='$INV' MATERIAL_INVENTORY='$WORK/policies/repository-material.yaml'"

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
    ! gate image_policy IMAGE_INVENTORY='$TMP/unbound.json' EXPECT_REVISION='$REV'"
ck "P8 ...telling the reader exactly what to rebuild it with" \
   "says 'carries no image_binding' && says 'assert-image-sbom-licences.sh --authorization'"
# The composition rule itself, executed through the workflow's own decide body:
# a success in one half is never enough.
ck "P8 SABOTAGE: the workflow REFUSES the decision when the image half failed" \
   "! gate decide BIND=failure IMAGE_POLICY=skipped COMPOSED=skipped \
        AUTH_RECORD='$A' IMAGE_INVENTORY='$INV' \
        MATERIAL_INVENTORY='$WORK/policies/repository-material.yaml'"
ck "P8 ...stating that neither half compensates for the other" \
   "says 'Neither compensates for the other' && says 'licence authorization REFUSED'"
ck "P8 SABOTAGE: and it REFUSES when the repository half failed" \
   "! gate decide BIND=success IMAGE_POLICY=success COMPOSED=failure \
        AUTH_RECORD='$A' IMAGE_INVENTORY='$INV' \
        MATERIAL_INVENTORY='$WORK/policies/repository-material.yaml'"
ck "P8 ...recording verdict REFUSED rather than skipping the record entirely" \
   "python3 -c 'import json,sys
d=json.load(open(sys.argv[1]))
sys.exit(0 if d[\"verdict\"]==\"REFUSED\" and d[\"repository_half\"][\"composed\"]==\"failure\" else 1)' \
      '$WORK/licence/licence-authorization.json'"
ck "P8 NON-VACUOUS: with BOTH halves successful the same body records PASS" \
   "gate decide BIND=success IMAGE_POLICY=success COMPOSED=success \
        AUTH_RECORD='$A' IMAGE_INVENTORY='$INV' \
        MATERIAL_INVENTORY='$WORK/policies/repository-material.yaml'"

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
   "wf_run bind | grep -q 'assert-image-sbom-licences.sh' \
    && wf_run image_policy | grep -q 'assert-license-policy.sh' \
    && wf_run composed | grep -q 'assert-repository-material.sh'"
ck "P10 ...with inputs, not bare: the binding step is HANDED a record and a set" \
   "wf_run bind | grep -q -- '--authorization' && wf_run bind | grep -q -- '--sbom-dir' \
    && wf_run bind | grep -q -- '--binding-dir' && wf_run bind | grep -q -- '--out'"
ck "P10 ...and every input the binding step reads is declared in its own env" \
   "for k in AUTH_RECORD SBOM_DIR BINDING_DIR IMAGE_INVENTORY; do
      wf_keys bind | grep -qx \"\$k\" || exit 1; done"
ck "P10 ...and the RESULT is consumed: the decision step reads all three outcomes" \
   "wf_run decide | grep -q 'BIND' && wf_run decide | grep -q 'IMAGE_POLICY' \
    && wf_run decide | grep -q 'COMPOSED' && wf_run decide | grep -q 'licence-authorization.json'"
ck "P10 ...and a licence PASS still cannot authorize exposure" \
   "wf_run decide | grep -q 'public_exposure_authorized'"

echo
echo "== ambient safety ========================================================="
ck "the checkout was not mutated: no licence/ directory was created in it" \
   "[ ! -e '$ROOT/licence' ] && [ ! -e '$ROOT/sbom' ] && [ ! -e '$ROOT/sbom-bindings' ]"

echo "----"
echo "assertions: $n, failures: $nfail"
if [ "$fail" -eq 0 ]; then echo "test_image_sbom_licence_gate: PASS"; else
  echo "test_image_sbom_licence_gate: FAIL"; fi
exit "$fail"
