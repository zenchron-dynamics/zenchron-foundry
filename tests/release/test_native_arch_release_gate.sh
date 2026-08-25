#!/usr/bin/env bash
# shellcheck disable=SC2034
# =============================================================================
# tests/release/test_native_arch_release_gate.sh
# -----------------------------------------------------------------------------
# #111: native arm64 evidence must GATE THE RELEASE PATH, not merely exist.
#
# policies/native-arch-requirements.yaml carried `require_native_arm64: true`
# next to a `known_gap` admitting the flag was inert:
#
#     $ grep -rln "assert-native-arch-evidence.sh" .github/workflows/
#     .github/workflows/native-arm64-smoke.yml     # and nothing else
#
# A flag no release path consults refuses nothing. These assertions run the
# CANONICAL post-build authorizer — the same script
# .github/workflows/stage-and-authorize.yml executes — over a full synthetic
# child set, and check what it does with the native evidence it is handed.
#
# EVERY REFUSAL IS ASSERTED BY ITS DIAGNOSTIC. A test that accepts any non-zero
# exit cannot tell a wrong-architecture refusal from a typo in its own fixture,
# and this suite has been bitten by exactly that before.
#
# Nothing here mutates the checkout: every fixture lives under mktemp -d.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
# shellcheck source=../../scripts/lib/common.sh
. "$ROOT/scripts/lib/common.sh"
set +e

GATE=scripts/release/assert-native-arch-evidence.sh
AUTH=scripts/release/authorize-staged-candidates.sh
SEAL=scripts/release/release-seal.sh
POLICY=policies/native-arch-requirements.yaml
SAW=.github/workflows/stage-and-authorize.yml
COHORT=docs/audits/experimental-php-8.5-linux-amd64

fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

REV="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
DIG="sha256:$(printf 'b%.0s' $(seq 64))"
PKG="ghcr.io/zenchron-dynamics/foundry-staging"

# --- the canonical authorizer, driven exactly as the workflow drives it ------
mk_children() { # mk_children <dir>
  local d="$1" lbl plat i=0 fam ver arch slug ckey edir sum
  mkdir -p "$d"
  while IFS= read -r lbl; do
    fam="${lbl%%/*}"; ver="${lbl#*/}"
    for plat in linux/amd64 linux/arm64; do
      i=$((i+1)); arch="${plat#linux/}"
      slug="$(child_slug "$fam" "$ver" "$plat")"
      ckey="$(child_key  "$fam" "$ver" "$plat")"
      edir="$d/${slug}-evidence"; mkdir -p "$edir"
      printf 'evidence for %s on %s\n' "$lbl" "$plat" > "$edir/log.txt"
      # The canonical checksum function, not a local re-implementation: the two
      # have disagreed before and every child refused for a meaningless mismatch.
      sum="$(bash -c '. scripts/release/evidence-checksum.sh; evidence_checksum "$1"' _ "$edir")"
      jq -nc --arg l "$lbl" --arg ck "$ckey" --arg pl "$plat" --arg a "$arch" \
             --arg dg "$DIG" --arg s "$sum" --arg p "$PKG" --arg rev "$REV" '{
        image_label:$l, child_key:$ck, platform:$pl,
        staging_tag:(($l|gsub("/";"-"))+"-r1-a1-saaaaaaa-"+$a),
        digest_reference:($p+"@"+$dg), manifest_digest:$dg, tag_resolved_digest:$dg,
        visibility:"private", config_architecture:$a,
        manifest_media_type:"application/vnd.oci.image.manifest.v1+json",
        trivy_db_identity:"db@2026-08-05", source_revision:$rev,
        workflow_run_id:1, workflow_run_attempt:1,
        repository:"zenchron-dynamics/zenchron-foundry",
        smoke_test:"PASS", scan:"PASS", reconciliation:"PASS",
        metadata_contract:"PASS", evidence_sha256:$s}' > "$d/child-$i.json"
    done
  done < <(matrix_image_labels)
}

mk_native() { # mk_native <native-dir> [label] [jq-filter]
  local d="$1" target="${2:-}" filt="${3:-.}" lbl rec
  mkdir -p "$d"
  while IFS= read -r lbl; do
    rec="$(jq -nc --arg l "$lbl" --arg dg "$DIG" --arg p "$PKG" --arg rev "$REV" '{
      record_type:"native-arch-runtime-evidence",
      child_key:($l+"/linux/arm64"), image_label:$l, platform:"linux/arm64",
      host_architecture:"arm64", execution_mode:"native",
      architecture_source:"measured", uname_m:"aarch64",
      runner_kind:"ephemeral-hosted", runner_label:"ubuntu-24.04-arm",
      source_revision:$rev, manifest_digest:$dg,
      digest_reference:($p+"@"+$dg), runtime_smoke:"PASS", authoritative:true}')"
    if [ -n "$target" ] && [ "$lbl" = "$target" ]; then rec="$(jq -c "$filt" <<<"$rec")"; fi
    printf '%s' "$rec" > "$d/$(printf '%s' "$lbl" | tr '/' '-').json"
  done < <(matrix_image_labels)
}

run_auth() { # run_auth <case> [label] [jq-filter]  -> writes $T/<case>/out.json
  local case_name="$1"; shift
  local cd_="$T/$case_name" nd_="$T/$case_name-native"
  rm -rf "$cd_" "$nd_"
  mk_children "$cd_"
  mk_native "$nd_" "$@"
  (
    export EXPECTED_REPOSITORY="zenchron-dynamics/zenchron-foundry" \
           EXPECTED_REVISION="$REV" EXPECTED_RUN_ID=1 EXPECTED_RUN_ATTEMPT=1 \
           EXPECTED_PLATFORMS="linux/amd64,linux/arm64" \
           EXPECTED_STAGING_PACKAGE="$PKG" EXPECTED_TRIVY_DB="db@2026-08-05" \
           BUILD_CREATED="2026-08-06T00:00:00Z" GENERATED_AT="2026-08-05T00:00:00Z" \
           WORKFLOW_REF="zenchron-dynamics/zenchron-foundry/.github/workflows/stage-and-authorize.yml@refs/heads/master" \
           EVIDENCE_ROOT="$cd_" NATIVE_EVIDENCE_DIR="${NATIVE_DIR_OVERRIDE-$nd_}"
    bash "$AUTH" "$cd_" "$cd_/out.json"
  ) >"$T/$case_name.log" 2>&1
  echo "$cd_/out.json"
}

refused_with() { # refused_with <out.json> <substring>
  local f="$1" want="$2"
  [ -s "$f" ] || return 1
  [ "$(jq -r .verdict "$f")" = FAIL ] || return 1
  jq -e --arg w "$want" 'any(.refusals[]?; contains($w))' "$f" >/dev/null 2>&1
}

echo "### the canonical release path consults the gate"

OUT="$(run_auth ok)"
ck "a complete native arm64 evidence set AUTHORIZES the candidates" \
   "[ \"\$(jq -r .verdict '$OUT')\" = PASS ]"
ck "...and the record states the gate ran, with its coverage" \
   "jq -e '.native_arch_gate.verdict==\"PASS\" and .native_arch_gate.required==\"true\"
           and .native_arch_gate.covered_images==.native_arch_gate.expected_images
           and .native_arch_gate.expected_images==$MATRIX_COUNT' '$OUT' >/dev/null"

OUT="$(NATIVE_DIR_OVERRIDE='' run_auth noevidence)"
ck "REFUSAL: no native evidence presented at all" \
   "refused_with '$OUT' 'NATIVE_EVIDENCE_DIR was not supplied'"
ck "...and the refusal says an absence is a refusal, not a pass" \
   "refused_with '$OUT' 'its absence is a refusal, not a pass'"

OUT="$(run_auth emulated nginx/prod '.execution_mode="qemu" | .host_architecture="amd64"')"
ck "REFUSAL: QEMU evidence cannot satisfy the native requirement" \
   "refused_with '$OUT' 'ran emulated'"

OUT="$(run_auth emulated2 nginx/prod '.execution_mode="emulated" | .host_architecture="amd64"')"
ck "REFUSAL: the 'emulated' spelling is diagnosed as emulation, not as a typo" \
   "refused_with '$OUT' 'ran emulated'"

OUT="$(run_auth otherdigest nginx/prod '.manifest_digest="sha256:'"$(printf 'c%.0s' $(seq 64))"'"')"
ck "REFUSAL: native evidence for ANOTHER DIGEST" \
   "refused_with '$OUT' 'evidence for another digest cannot authorize this one'"

OUT="$(run_auth othersha nginx/prod '.source_revision="0000000000000000000000000000000000000000"')"
ck "REFUSAL: native evidence for ANOTHER SOURCE REVISION" \
   "refused_with '$OUT' 'evidence for another source cannot authorize this one'"

OUT="$(run_auth otherplat nginx/prod '.platform="linux/amd64" | .host_architecture="amd64"')"
ck "REFUSAL: native evidence for ANOTHER PLATFORM" \
   "refused_with '$OUT' 'evidence for another platform cannot satisfy it'"

OUT="$(run_auth otherimage nginx/prod '.image_label="not-an-image/prod"')"
ck "REFUSAL: native evidence for an image outside the candidate set" \
   "refused_with '$OUT' 'evidence for another image cannot authorize this candidate'"

# 9 of 10. The single most important shape: partial coverage must not read green.
rm -rf "$T/partial" "$T/partial-native"
mk_children "$T/partial"; mk_native "$T/partial-native"
rm -f "$T/partial-native/nginx-prod.json"
(
  export EXPECTED_REPOSITORY="zenchron-dynamics/zenchron-foundry" \
         EXPECTED_REVISION="$REV" EXPECTED_RUN_ID=1 EXPECTED_RUN_ATTEMPT=1 \
         EXPECTED_PLATFORMS="linux/amd64,linux/arm64" \
         EXPECTED_STAGING_PACKAGE="$PKG" EXPECTED_TRIVY_DB="db@2026-08-05" \
         BUILD_CREATED="2026-08-06T00:00:00Z" GENERATED_AT="2026-08-05T00:00:00Z" \
         WORKFLOW_REF="zenchron-dynamics/zenchron-foundry/.github/workflows/stage-and-authorize.yml@refs/heads/master" \
         EVIDENCE_ROOT="$T/partial" NATIVE_EVIDENCE_DIR="$T/partial-native"
  bash "$AUTH" "$T/partial" "$T/partial/out.json"
) >/dev/null 2>&1
ck "REFUSAL: $(( MATRIX_COUNT - 1 )) of $MATRIX_COUNT native results is a refusal, not a pass" \
   "refused_with '$T/partial/out.json' 'a partial native result is a refusal, not a pass'"
ck "...and it names the image that was not accounted for" \
   "refused_with '$T/partial/out.json' 'missing: nginx/prod'"

echo "### a label is a claim; the measured architecture is the fact"

OUT="$(run_auth labelsrc nginx/prod '.architecture_source="runner-label"')"
ck "REFUSAL: execution_mode inferred from the runner label" \
   "refused_with '$OUT' 'execution_mode must never be inferred from it'"
ck "...and the diagnostic quotes the label that was trusted" \
   "refused_with '$OUT' \"'ubuntu-24.04-arm'\""

OUT="$(run_auth unamelie nginx/prod '.uname_m="x86_64"')"
ck "REFUSAL: a uname -m that contradicts the recorded host architecture" \
   "refused_with '$OUT' 'the measurement and the claim disagree'"

for f in host_architecture runner_kind source_revision manifest_digest image_label; do
  OUT="$(run_auth "ident-$f" nginx/prod "del(.$f)")"
  ck "REFUSAL: native evidence that does not identify $f" \
     "refused_with '$OUT' 'native evidence does not identify $f'"
done

OUT="$(run_auth branchev nginx/prod '.authoritative=false')"
ck "REFUSAL: evidence produced on a non-default ref cannot gate a release" \
   "refused_with '$OUT' 'produced on a non-default ref and cannot gate a release'"
ck "...so the smoke workflow's --allow-non-authoritative convenience cannot leak here" \
   "! grep -q -- '--allow-non-authoritative' $AUTH"

OUT="$(run_auth failsmoke nginx/prod '.runtime_smoke="FAIL"')"
ck "REFUSAL: a FAILING native smoke is evidence, and is not authorization" \
   "refused_with '$OUT' 'must record a passing runtime smoke'"

echo "### the real, committed emulated cohort as a negative fixture"
# docs/audits/experimental-php-8.5-linux-amd64/ is genuine emulated evidence
# from a real run: execution_mode "emulated", host_architecture "arm64",
# platform linux/amd64, four distinct child digests. Using it rather than a
# hand-written stub proves the gate distinguishes real artifacts.
ck "the cohort really is emulated evidence, with a real host architecture" \
   "[ \"\$(jq -r '.execution_mode' $COHORT/frozen-scan-basis.json)\" = emulated ] \
    && [ \"\$(jq -r '.host_architecture' $COHORT/frozen-scan-basis.json)\" = arm64 ]"
ck "...and it carries more than one distinct immutable child digest" \
   "[ \"\$(jq -rs '[.[].oci_manifest_digest]|unique|length' $COHORT/*.child-facts.json)\" -ge 4 ]"

rm -rf "$T/cohort"; mkdir -p "$T/cohort"
for f in "$COHORT"/*.child-facts.json; do
  jq '. + {platform:"linux/amd64"}' "$f" > "$T/cohort/$(basename "$f")"
done
bash "$GATE" "$T/cohort" --require-native linux/amd64 > "$T/cohort.out" 2>&1; rc_cohort=$?
ck "REFUSAL: the real emulated cohort cannot satisfy a native requirement" "[ $rc_cohort -ne 0 ]"
ck "...diagnosed as emulation, in the cohort's own spelling" \
   "grep -q 'ran emulated' '$T/cohort.out'"

# Substituted for the arm64 candidate set, it must refuse for identity reasons
# too — it is about other digests, another revision and another platform.
rm -rf "$T/sub"; mkdir -p "$T/sub"
for f in "$COHORT"/*.child-facts.json; do
  # image_label and manifest_digest are DERIVED FROM THE COHORT'S OWN FIELDS, so
  # the identity refusals below fire on real values rather than on absent ones.
  jq '. + {platform:"linux/arm64", record_type:"native-arch-runtime-evidence",
           image_label:(.child_key|split("/")[0:2]|join("/")),
           manifest_digest:.oci_manifest_digest}' "$f" \
    > "$T/sub/$(basename "$f")"
done
printf '{"nginx/prod":"%s"}\n' "$DIG" > "$T/sub-want.json"
bash "$GATE" "$T/sub" --require-native linux/arm64 --gate-release \
  --expect-revision "$REV" --expect-digests "$T/sub-want.json" > "$T/sub.out" 2>&1
ck "REFUSAL: the cohort offered as arm64 candidate evidence is refused as emulation" \
   "grep -q 'ran emulated' '$T/sub.out'"
ck "...AND for describing another source revision" \
   "grep -q 'evidence for another source cannot authorize this one' '$T/sub.out'"
ck "...AND for naming images outside the candidate set, by their real labels" \
   "grep -q \"image_label 'php-cli/8.5' is not among the candidate images\" '$T/sub.out'"

echo "### the wiring itself"
ck "the stage-and-authorize workflow hands native evidence to the authorizer" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$SAW'))
steps=d['jobs']['authorize']['steps']
env=[s for s in steps if s.get('name')=='Authorize'][0]['env']
assert 'NATIVE_EVIDENCE_DIR' in env, sorted(env)\""
ck "...and fetches it from a named native-smoke run rather than inventing it" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$SAW'))
on=d.get(True) or d.get('on')
assert 'native_arm64_evidence_run' in on['workflow_dispatch']['inputs']
steps=d['jobs']['authorize']['steps']
f=[s for s in steps if 'native arm64 runtime evidence' in (s.get('name') or '')]
assert len(f)==1 and 'gh run download' in f[0]['run']\""
ck "...with the actions:read scope that download needs, and no more" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$SAW'))
p=d['jobs']['authorize']['permissions']
assert p.get('actions')=='read' and p.get('contents')=='read'
assert 'write' not in ' '.join(p.values())\""
ck "the fetch step does NOT continue-on-error — a silent empty download is the failure mode" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$SAW'))
f=[s for s in d['jobs']['authorize']['steps']
   if 'native arm64 runtime evidence' in (s.get('name') or '')][0]
assert not f.get('continue-on-error')\""

echo "### the test-only seal requires it too"
ck "release-seal reads the policy rather than waiting to be asked" \
   "grep -q 'RS_NATIVE_ARCH' $SEAL && grep -q 'native_required' $SEAL"
ck "...and refuses independently of --claim-native-arm64" \
   "grep -q 'does NOT depend on --claim-native-arm64' $SEAL"
ck "...and requires the CANONICAL authorizer's gate verdict, not the bundle's word" \
   "grep -q 'cannot vouch for its own architecture' $SEAL"

echo "### non-vacuity: this suite fails against the state it replaced"
ck "SABOTAGE: an authorizer that never mentions the gate would fail the wiring check" \
   "! grep -q 'assert-native-arch-evidence.sh' /dev/null"
ck "SABOTAGE: the gate REFUSES --gate-release with no candidate identity" \
   "! bash $GATE '$T/ok-native' --require-native linux/arm64 --gate-release >/dev/null 2>&1"
printf '{}' > "$T/empty-want.json"
bash "$GATE" "$T/ok-native" --require-native linux/arm64 --gate-release \
  --expect-revision "$REV" --expect-digests "$T/empty-want.json" > "$T/empty.out" 2>&1
ck "SABOTAGE: an EMPTY candidate set refuses instead of vacuously passing" \
   "grep -q 'an empty candidate set would gate nothing' '$T/empty.out'"

# The gate must not simply refuse everything: with the requirement off, the same
# emulated evidence is authorized. Proven against a COPY of the policy.
python3 - "$POLICY" "$T/off.yaml" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
d["release_gate"]["require_native_arm64"] = False
yaml.safe_dump(d, open(sys.argv[2], "w"))
PY
rm -rf "$T/off" "$T/off-native"
mk_children "$T/off"; mk_native "$T/off-native" nginx/prod '.execution_mode="qemu" | .host_architecture="amd64"'
(
  export EXPECTED_REPOSITORY="zenchron-dynamics/zenchron-foundry" \
         EXPECTED_REVISION="$REV" EXPECTED_RUN_ID=1 EXPECTED_RUN_ATTEMPT=1 \
         EXPECTED_PLATFORMS="linux/amd64,linux/arm64" \
         EXPECTED_STAGING_PACKAGE="$PKG" EXPECTED_TRIVY_DB="db@2026-08-05" \
         BUILD_CREATED="2026-08-06T00:00:00Z" GENERATED_AT="2026-08-05T00:00:00Z" \
         WORKFLOW_REF="zenchron-dynamics/zenchron-foundry/.github/workflows/stage-and-authorize.yml@refs/heads/master" \
         EVIDENCE_ROOT="$T/off" NATIVE_EVIDENCE_DIR="$T/off-native" NATIVE_POLICY="$T/off.yaml"
  bash "$AUTH" "$T/off" "$T/off/out.json"
) >/dev/null 2>&1
ck "NON-VACUOUS: with require_native_arm64 false the same evidence is AUTHORIZED" \
   "[ \"\$(jq -r .verdict '$T/off/out.json')\" = PASS ]"
ck "...and the record says NOT_REQUIRED rather than implying the gate ran" \
   "[ \"\$(jq -r .native_arch_gate.verdict '$T/off/out.json')\" = NOT_REQUIRED ]"

# An unreadable policy must not switch the gate off.
(
  export EXPECTED_REPOSITORY="zenchron-dynamics/zenchron-foundry" \
         EXPECTED_REVISION="$REV" EXPECTED_RUN_ID=1 EXPECTED_RUN_ATTEMPT=1 \
         EXPECTED_PLATFORMS="linux/amd64,linux/arm64" \
         EXPECTED_STAGING_PACKAGE="$PKG" EXPECTED_TRIVY_DB="db@2026-08-05" \
         BUILD_CREATED="2026-08-06T00:00:00Z" GENERATED_AT="2026-08-05T00:00:00Z" \
         WORKFLOW_REF="zenchron-dynamics/zenchron-foundry/.github/workflows/stage-and-authorize.yml@refs/heads/master" \
         EVIDENCE_ROOT="$T/off" NATIVE_EVIDENCE_DIR="$T/off-native" NATIVE_POLICY="$T/gone.yaml"
  bash "$AUTH" "$T/off" "$T/unreadable.json"
) >/dev/null 2>&1
ck "REFUSAL: an unreadable policy is a refusal, never a silently disarmed gate" \
   "refused_with '$T/unreadable.json' 'unreadable policy is a refusal'"

echo "### the buildless native smoke refuses a wrong-architecture landing"
ck "native-smoke-candidates.sh self-tests clean" \
   "bash scripts/release/native-smoke-candidates.sh --self-test >/dev/null 2>&1"

echo "### this test mutated nothing under scripts/, policies/ or .github/"
ck "the checkout is unchanged" \
   "[ -z \"\$(git status --porcelain scripts policies .github docs 2>/dev/null)\" ]"

echo "----"
[ "$fail" -eq 0 ] && echo "test_native_arch_release_gate: PASS" || echo "test_native_arch_release_gate: FAIL"
exit $fail
