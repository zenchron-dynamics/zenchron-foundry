#!/usr/bin/env bash
# shellcheck disable=SC2034
# ^ ck() evals its second argument; uses inside those strings are invisible here.
# =============================================================================
# tests/experimental/test_experimental_plan.sh
# -----------------------------------------------------------------------------
# THE DEFECT THIS EXISTS FOR.
#
# Four PHP 8.5 image definitions exist under images/php-{cli,fpm,worker,
# frankenphp}/8.5, are digest-pinned to official bases, and build on
# linux/amd64. The only thing that recorded their status was `used_by: []` on
# the php-8.5 line in policies/lifecycle.yaml.
#
# `used_by: []` says "no SHIPPING image consumes this line". It says nothing
# whatsoever about the four Dockerfiles, and it left them as UNREACHABLE DEAD
# CONFIGURATION: nothing enumerated them, nothing built them, nothing scanned
# them, and nothing would have noticed a fifth appearing or one of the four
# rotting. In a repository whose whole thesis is that unaccountable artifacts
# are the hazard, four maintained-looking but unreached Dockerfiles ARE that
# hazard.
#
# The fix is a canonical experimental plan. This suite proves BOTH halves of it,
# because either one alone is worthless:
#
#   REACHABILITY  all four definitions are reachable through the plan, on the
#                 one platform they were proved on, with their real contexts.
#   ISOLATION     no experimental child is reachable through the PRODUCTION
#                 plan, the production contracts, the production workflows or
#                 the 8.3/8.4 governance selectors.
#
# and both refusal directions:
#
#   an experimental image directory that is NOT REGISTERED is refused;
#   an experimental image added to PRODUCTION without lifecycle authorization
#   is refused.
#
# Every sabotage below runs against a DISPOSABLE COPY. This repository has
# already destroyed policies/required-release-checks.yaml with a self-test that
# mutated the real files in place (tests/lib/test_no_ambient_mutation.sh).
#
# Runs offline. No docker, no network.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

TMP="$(mktemp -d)"
# EXIT, never RETURN: under `bash -T` a RETURN trap fires on the return of every
# inner function and would delete the fixture after the first assertion
# (tests/lib/test_functrace_safety.sh).
# shellcheck disable=SC2064
trap "rm -rf '$TMP'" EXIT

PLAN=scripts/experimental/experimental-plan.sh
ISO=scripts/experimental/assert-experimental-isolation.sh
RUN=scripts/experimental/experimental-run.sh
REG=policies/experimental-cohorts.yaml
LIFE=policies/lifecycle.yaml
ACC=scripts/release/build-acceptance-matrix.sh

# common.sh sets -e for its callers. This suite deliberately runs commands that
# exit non-zero — every refusal is one — and without restoring +e the first
# intentional refusal would kill the run and every later assertion would
# silently never execute, which looks exactly like a pass.
. scripts/lib/common.sh
set +e

# Refusal DIAGNOSTICS are matched against CAPTURED output, never piped into a
# quiet matcher. Two traps meet in `cmd | grep -q`: `pipefail` reports the
# deliberately-failing producer, and the matcher exits at the first hit, closing
# the pipe and killing the producer with SIGPIPE (exit 141) — a RACE that passes
# until it does not.
says() { # says <needle> <cmd...>
  local needle="$1"; shift
  case "$("$@" 2>&1)" in *"$needle"*) return 0 ;; *) return 1 ;; esac
}

# =============================================================================
# 1. REACHABILITY — all four 8.5 definitions are reachable through the plan
# =============================================================================
ck "the plan self-test passes"           "bash $PLAN --self-test >/dev/null 2>&1"
ck "the isolation gate self-test passes" "bash $ISO  --self-test >/dev/null 2>&1"
ck "the runner self-test passes"         "bash $RUN  --self-test >/dev/null 2>&1"

PLANJSON="$TMP/plan.json"
bash "$PLAN" plan php-8.5 linux/amd64 > "$PLANJSON" 2>/dev/null
ck "the plan emits JSON for the php-8.5 cohort" "jq -e . '$PLANJSON' >/dev/null"

# The count is DERIVED from the registry, not written as a literal here: a
# literal would have to be edited every time the cohort changes and would
# silently become the thing under test.
N_REG="$(python3 -c "
import yaml;d=yaml.safe_load(open('$REG'))
print(len([c for c in d['cohorts'] if c['id']=='php-8.5'][0]['images']))")"
ck "the registry declares a non-empty image set (an empty one passes vacuously)" \
   "[ '$N_REG' -ge 4 ]"
ck "the plan enumerates every registered image" \
   "[ \"\$(jq '.include|length' '$PLANJSON')\" = '$N_REG' ]"

for f in php-cli php-fpm php-worker php-frankenphp; do
  ck "$f/8.5 is REACHABLE through the experimental plan" \
     "[ \"\$(jq -r --arg f $f '[.include[]|select(.fam==\$f)]|length' '$PLANJSON')\" = 1 ]"
  ck "...and its context is images/$f/8.5, with a Dockerfile on disk" \
     "[ \"\$(jq -r --arg f $f '.include[]|select(.fam==\$f).ctx' '$PLANJSON')\" = 'images/$f/8.5' ] &&
      [ -f 'images/$f/8.5/Dockerfile' ]"
  ck "...and it is digest-pinned to an official 8.5 base" \
     "grep -qE '(php|dunglas/frankenphp):[^ ]*8\.5[^ ]*@sha256:[a-f0-9]{64}' 'images/$f/8.5/Dockerfile'"
done

ck "every child carries the canonical child_key from common.sh (ONE derivation)" \
   "python3 - <<'PY' >/dev/null 2>&1
import json,subprocess
p=json.load(open('$PLANJSON'))
for c in p['include']:
    want=subprocess.run(['bash','-c','. scripts/lib/common.sh; child_key \"\$1\" \"\$2\" \"\$3\"',
                         '_',c['fam'],c['ver'],c['platform']],capture_output=True,text=True).stdout.strip()
    assert c['child_key']==want,(c['child_key'],want)
PY"
ck "every child carries a distinct build-context digest" \
   "[ \"\$(jq -r '[.include[].build_input_digest]|unique|length' '$PLANJSON')\" = '$N_REG' ]"
ck "the plan REUSES the foundry-child evidence class (it defines no new one)" \
   "[ \"\$(jq -r .evidence_class '$PLANJSON')\" = foundry-child ] &&
    python3 -c \"
import json;s=json.load(open('schemas/evidence-class-v1.schema.json'))
assert 'foundry-child' in s['properties']['evidence_class']['enum']\" &&
    [ \"\$(ls schemas/ | grep -c experimental)\" = 0 ]"

# Every declared capability is invocable, and the allow-list is not empty.
for cap in build smoke extensions sbom scan evidence; do
  ck "the plan is explicitly invocable for '$cap'" \
     "bash $PLAN capability php-8.5 $cap >/dev/null 2>&1"
done

# =============================================================================
# 2. ISOLATION — no experimental child is reachable through PRODUCTION
# =============================================================================
ck "the isolation gate PASSES on this checkout" "bash $ISO >/dev/null 2>&1"

ACCJSON="$TMP/acc.json"
bash "$ACC" linux/amd64,linux/arm64 > "$ACCJSON" 2>/dev/null
ck "the PRODUCTION plan enumerates ZERO experimental children" \
   "[ \"\$(jq '[.include[]|select(.ver==\"8.5\")]|length' '$ACCJSON')\" = 0 ]"
# Non-vacuity: the production plan must actually enumerate something, or the
# line above proves nothing at all.
ck "...and it is NOT VACUOUS — production still yields 2 x MATRIX_COUNT children" \
   "[ \"\$(jq '.include|length' '$ACCJSON')\" = \"$(( MATRIX_COUNT * 2 ))\" ]"
ck "MATRIX_IMAGES is untouched: exactly MATRIX_COUNT tokens, none of them 8.5" \
   "[ \"\$(matrix_images | wc -l | tr -d ' ')\" = \"\$MATRIX_COUNT\" ] &&
    [ \"\$(matrix_images | grep -c ':8.5\$')\" = 0 ]"
ck "the experimental and production enumerations are DISJOINT" \
   "[ -z \"\$(comm -12 <(jq -r '.include[]|\"\\(.fam):\\(.ver)\"' '$PLANJSON' | sort -u) \
                      <(matrix_images | sort -u))\" ]"

# The seven production capabilities, each refused for its OWN reason.
ck "production ACCEPTANCE is refused"        "! bash $PLAN capability php-8.5 acceptance >/dev/null 2>&1"
ck "...naming the MATRIX_COUNT-derived child count" \
   "says MATRIX_COUNT bash $PLAN capability php-8.5 acceptance"
ck "production RELEASE MANIFESTS are refused" \
   "says 'assert guarantees nothing verified' bash $PLAN capability php-8.5 release-manifest"
ck "PROMOTION is refused"                    "says 'never published' bash $PLAN capability php-8.5 promotion"
ck "production SEALING is refused"           "says 'required-release-checks' bash $PLAN capability php-8.5 seal"
ck "SIGNING is refused"                      "says 'indistinguishable from a released one' bash $PLAN capability php-8.5 sign"
ck "PUBLICATION is refused"                  "says 'no support commitment' bash $PLAN capability php-8.5 publish"
ck "the 8.3/8.4 GOVERNANCE SELECTORS are refused" \
   "says 'php-8.3-8.4' bash $PLAN capability php-8.5 governance-selector"
ck "an INVENTED capability is refused rather than defaulted" \
   "says 'closed capability vocabulary' bash $PLAN capability php-8.5 teleport"

# arm64 is not claimed. No arm64 8.5 child has ever been built.
ck "linux/arm64 is REFUSED for this cohort — no arm64 child exists" \
   "says 'has ever been built' bash $PLAN --count php-8.5 linux/arm64"
ck "the registry authorizes linux/amd64 ONLY" \
   "[ \"\$(python3 -c \"
import yaml;d=yaml.safe_load(open('$REG'))
print(','.join([c for c in d['cohorts'] if c['id']=='php-8.5'][0]['platforms']))\")\" = 'linux/amd64' ]"

# The governance boundary, exercised through the REAL reconciler rather than
# asserted about it. libssl3 / CVE-2026-14456 is governed for the 8.3-8.4 cohort
# at exactly this version.
cat > "$TMP/ssl.json" <<'JSON'
{"SchemaVersion":2,"ArtifactName":"t","Metadata":{"OS":{"Family":"debian","Name":"12.15"}},
 "Results":[{"Target":"t","Class":"os-pkgs","Type":"debian","Vulnerabilities":[
   {"VulnerabilityID":"CVE-2026-14456","PkgName":"libssl3",
    "InstalledVersion":"3.0.20-1~deb12u2","Severity":"HIGH","DataSource":{"ID":"debian"}}]}]}
JSON
for f in php-cli php-fpm php-worker php-frankenphp; do
  TODAY=2026-08-21 bash scripts/reconcile-vulnerabilities.sh "$TMP/ssl.json" "$f" 8.4 \
      --arch linux/amd64 --today 2026-08-21 >/dev/null 2>&1; rc84=$?
  ck "fixture sanity: $f/8.4 IS governed by the php-8.3-8.4 cohort" "[ '$rc84' -eq 0 ]"
  TODAY=2026-08-21 bash scripts/reconcile-vulnerabilities.sh "$TMP/ssl.json" "$f" 8.5 \
      --arch linux/amd64 --today 2026-08-21 > "$TMP/g-$f.txt" 2>&1; rc85=$?
  ck "$f/8.5 is UNGOVERNED — the experimental cohort widened no decision" \
     "[ '$rc85' -ne 0 ] && grep -q 'no in-scope exception' '$TMP/g-$f.txt'"
done

# =============================================================================
# 3. THE TWO REFUSALS, sabotaged against a DISPOSABLE COPY
# =============================================================================
COPY="$TMP/tree"; mkdir -p "$COPY"
tar cf - policies scripts contracts images .github | ( cd "$COPY" && tar xf - )
# tar preserves modes. This suite must stay runnable from a write-protected
# checkout (tests/lib/test_no_ambient_mutation.sh freezes one), so the fixture's
# write bits are restored explicitly — otherwise every sabotage below fails with
# EPERM on its OWN fixture, which is indistinguishable from a real refusal.
reset_copy() { tar cf - policies scripts contracts .github | ( cd "$COPY" && tar xf - ); chmod -R u+w "$COPY"; }
chmod -R u+w "$COPY"

ck "the disposable copy reproduces BOTH clean verdicts (sabotage baseline)" \
   "EXP_AUDIT_ROOT='$COPY' bash $PLAN --count php-8.5 linux/amd64 >/dev/null 2>&1 &&
    EXP_AUDIT_ROOT='$COPY' bash $ISO >/dev/null 2>&1"

# --- 3a. an experimental image directory that nobody registered ------------
mkdir -p "$COPY/images/php-shadow/8.5"
printf 'FROM scratch\nUSER 10001:10001\n' > "$COPY/images/php-shadow/8.5/Dockerfile"
ck "SABOTAGE: an UNREGISTERED 8.5 image directory is REFUSED" \
   "! EXP_AUDIT_ROOT='$COPY' bash $PLAN --count php-8.5 linux/amd64 >/dev/null 2>&1"
ck "...and the refusal NAMES the directory it will not accept" \
   "EXP_AUDIT_ROOT='$COPY' says 'images/php-shadow/8.5' bash $PLAN --count php-8.5 linux/amd64"
ck "...and states WHY: it would be unreachable dead configuration" \
   "EXP_AUDIT_ROOT='$COPY' says 'dead configuration' bash $PLAN --count php-8.5 linux/amd64"
# THE SABOTAGE FAILS ON THE PRE-CHANGE STATE. Registering the directory — the
# only sanctioned way to add one — makes the same tree pass again, so the
# refusal is caused by the omission and not by the extra directory existing.
python3 - "$COPY/$REG" <<'PY'
import sys, yaml
p = sys.argv[1]
d = yaml.safe_load(open(p))
c = [x for x in d["cohorts"] if x["id"] == "php-8.5"][0]
c["images"].append({"family": "php-shadow", "context": "images/php-shadow/8.5",
                    "required_extensions": "core", "forbidden_tools": ["gcc"]})
c["opcache_provenance"]["php-shadow"] = "base-builtin"
yaml.safe_dump(d, open(p, "w"), sort_keys=False, allow_unicode=True)
PY
ck "...and REGISTERING it restores the clean verdict (the omission was the cause)" \
   "EXP_AUDIT_ROOT='$COPY' bash $PLAN --count php-8.5 linux/amd64 >/dev/null 2>&1"
ck "...whereupon the plan enumerates it too (registration is what makes it reachable)" \
   "[ \"\$(EXP_AUDIT_ROOT='$COPY' bash $PLAN --count php-8.5 linux/amd64)\" = \"$(( N_REG + 1 ))\" ]"
reset_copy; rm -rf "$COPY/images/php-shadow"

# --- 3b. an experimental image promoted into PRODUCTION -------------------
sed -i.bak 's|^MATRIX_IMAGES="|MATRIX_IMAGES="php-cli:8.5 |' "$COPY/scripts/lib/common.sh"
rm -f "$COPY/scripts/lib/common.sh.bak"
ck "SABOTAGE: adding 8.5 to MATRIX_IMAGES is REFUSED by the plan" \
   "! EXP_AUDIT_ROOT='$COPY' bash $PLAN --count php-8.5 linux/amd64 >/dev/null 2>&1"
ck "...and by the production-side isolation gate, independently" \
   "! EXP_AUDIT_ROOT='$COPY' bash $ISO >/dev/null 2>&1"
ck "...and the refusal says promotion needs LIFECYCLE authorization, not a matrix edit" \
   "EXP_AUDIT_ROOT='$COPY' says 'not a matrix edit' bash $PLAN --count php-8.5 linux/amd64"
# The lifecycle authorization is what is missing — and changing ONLY the
# lifecycle is refused too, so neither file can move an image on its own.
python3 - "$COPY/$LIFE" <<'PY'
import sys, yaml
p = sys.argv[1]
d = yaml.safe_load(open(p))
for line in d["lines"]:
    if line["id"] == "php-8.5":
        line["foundry_release_state"] = "production"
yaml.safe_dump(d, open(p, "w"), sort_keys=False, allow_unicode=True)
PY
ck "...and a lifecycle state change ALONE is refused as well" \
   "! EXP_AUDIT_ROOT='$COPY' bash $PLAN --count php-8.5 linux/amd64 >/dev/null 2>&1"
ck "...naming both files, so no single edit can promote a cohort" \
   "EXP_AUDIT_ROOT='$COPY' says 'Neither file can move an image on its own' \
      bash $PLAN --count php-8.5 linux/amd64"
reset_copy
ck "...and reverting both restores the clean verdict" \
   "EXP_AUDIT_ROOT='$COPY' bash $PLAN --count php-8.5 linux/amd64 >/dev/null 2>&1 &&
    EXP_AUDIT_ROOT='$COPY' bash $ISO >/dev/null 2>&1"

# --- 3c. a production contract that would claim an experimental image -----
cp "$COPY/contracts/images/php-cli-8.4.yaml" "$COPY/contracts/images/php-cli-8.5.yaml"
ck "SABOTAGE: a contracts/ entry for 8.5 is REFUSED" \
   "! EXP_AUDIT_ROOT='$COPY' bash $ISO >/dev/null 2>&1"
ck "...and the refusal says it claims production support the cohort lacks" \
   "EXP_AUDIT_ROOT='$COPY' says 'claims production support' bash $ISO"
reset_copy; rm -f "$COPY/contracts/images/php-cli-8.5.yaml"

# --- 3d. a governance selector widened to reach the cohort ----------------
python3 - "$COPY/policies/vulnerability-exceptions.yaml" <<'PY'
import sys, yaml
p = sys.argv[1]
d = yaml.safe_load(open(p))
for e in d["exceptions"]:
    if e["image"] == "php-8.3-8.4":
        e["image"] = "php-8.3-8.4-8.5"
        break
yaml.safe_dump(d, open(p, "w"), sort_keys=False, allow_unicode=True)
PY
ck "SABOTAGE: a ledger selector widened to 8.5 is REFUSED" \
   "! EXP_AUDIT_ROOT='$COPY' bash $ISO >/dev/null 2>&1"
ck "...and the refusal says the decision was never made from that artifact" \
   "EXP_AUDIT_ROOT='$COPY' says 'decision was never made from' bash $ISO"
reset_copy

# =============================================================================
# 4. THE COMMITTED EVIDENCE — real children, correctly classed
# =============================================================================
EVDIR="$(python3 -c "
import yaml;d=yaml.safe_load(open('$REG'))
print([c for c in d['cohorts'] if c['id']=='php-8.5'][0]['evidence_dir'])")"
ck "the cohort declares an evidence directory that exists" "[ -d '$EVDIR' ]"
ck "one foundry-child record exists per registered image" \
   "[ \"\$(ls '$EVDIR'/*.evidence.json 2>/dev/null | wc -l | tr -d ' ')\" = '$N_REG' ]"
ck "every record validates as foundry-child under the EXISTING class gate" \
   "for r in '$EVDIR'/*.evidence.json; do
      bash scripts/release/assert-evidence-class.sh require-class foundry-child \"\$r\" >/dev/null || exit 1
    done"
ck "every record's inventory is image-child — NOT image-base (the 241-vs-47 rule)" \
   "[ \"\$(jq -r -s '[.[].package_inventory_source.kind]|unique|join(\",\")' '$EVDIR'/*.evidence.json)\" = 'image-child' ]"
ck "SABOTAGE: flipping one record to an image-base inventory is REFUSED" \
   "jq '.package_inventory_source.kind=\"image-base\"' \
        \"\$(ls '$EVDIR'/*.evidence.json | head -1)\" > '$TMP/base.json' &&
    ! bash scripts/release/assert-evidence-class.sh require-class foundry-child '$TMP/base.json' >/dev/null 2>&1"
ck "...and the refusal cites the 241-vs-47 defect by name" \
   "says '241-vs-47' bash scripts/release/assert-evidence-class.sh require-class foundry-child '$TMP/base.json'"
ck "all four children share ONE frozen vulnerability database" \
   "[ \"\$(jq -r -s '[.[].vulnerability_db_identity]|unique|length' '$EVDIR'/*.evidence.json)\" = 1 ]"
ck "...and ONE digest-pinned scanner identity" \
   "[ \"\$(jq -r -s '[.[].scanner_identity]|unique|length' '$EVDIR'/*.evidence.json)\" = 1 ]"
ck "every record is linux/amd64 — arm64 is never claimed" \
   "[ \"\$(jq -r -s '[.[].platform]|unique|join(\",\")' '$EVDIR'/*.evidence.json)\" = 'linux/amd64' ]"
ck "every record names its upstream base as parent, by immutable digest" \
   "jq -e -s 'all(.[]; .parent.evidence_class==\"upstream-base\" and
                       (.parent.image_digest|test(\"^sha256:[0-9a-f]{64}\$\")))' \
      '$EVDIR'/*.evidence.json >/dev/null"
ck "child digests are distinct — four artifacts, not one recorded four times" \
   "[ \"\$(jq -r -s '[.[].image_digest]|unique|length' '$EVDIR'/*.evidence.json)\" = '$N_REG' ]"
ck "the run's evidence checksums verify" \
   "( cd '$EVDIR' && shasum -a 256 -c SHA256SUMS >/dev/null 2>&1 )"
# THE EVIDENCE STILL DESCRIBES THE CURRENT CONTEXTS.
# source_revision names the commit the children were built from; commits landing
# after it (this packet, this README) do not touch images/. That is a claim, so
# it is checked: the plan recomputes each build-context digest at HEAD and it must
# equal the one recorded in the evidence. If a Dockerfile changes, this fails and
# the evidence must be regenerated rather than quietly re-used.
ck "every record's build_input_digest matches the context digest at HEAD" \
   "python3 - <<'PY' >/dev/null 2>&1
import json,glob,subprocess
plan=json.loads(subprocess.check_output(['bash','$PLAN','plan','php-8.5','linux/amd64'],text=True))
now={c['fam']:c['build_input_digest'] for c in plan['include']}
seen=0
for f in glob.glob('$EVDIR/*.evidence.json'):
    r=json.load(open(f)); seen+=1
    assert r['build_input_digest']==now[r['image_family']], (r['image_family'], r['build_input_digest'], now[r['image_family']])
assert seen, 'no records examined — the check would be vacuous'
PY"

# THE DECISION PACKET DECIDED NOTHING. Its Group B advisories must still be
# ungoverned for every family, including production 8.3/8.4 — writing the packet
# must not have quietly added a ledger entry.
cat > "$TMP/kin.json" <<'JSON'
{"SchemaVersion":2,"ArtifactName":"t","Metadata":{"OS":{"Family":"debian","Name":"12.15"}},
 "Results":[{"Target":"t","Class":"lang-pkgs","Type":"gobinary","Vulnerabilities":[
   {"VulnerabilityID":"CVE-2026-76905","PkgName":"github.com/getkin/kin-openapi",
    "InstalledVersion":"v0.140.0","FixedVersion":"0.141.0","Severity":"HIGH",
    "DataSource":{"ID":"go"}}]}]}
JSON
for v in 8.4 8.5; do
  TODAY=2026-08-24 bash scripts/reconcile-vulnerabilities.sh "$TMP/kin.json" php-frankenphp "$v" \
      --arch linux/amd64 --today 2026-08-24 > "$TMP/kin-$v.txt" 2>&1; rc_kin=$?
  ck "the packet added NO exception: CVE-2026-76905 is still ungoverned on frankenphp/$v" \
     "[ '$rc_kin' -ne 0 ] && grep -q 'no in-scope exception' '$TMP/kin-$v.txt'"
done

# The proofs the evidence claims must actually be in it.
ck "every child proves OPcache at RUNTIME, not merely in php -m" \
   "jq -e -s 'all(.[]; .opcache.runtime_proof.opcache_enabled==true and
                       .opcache.runtime_proof.compile_succeeded==true and
                       .opcache.runtime_proof.num_cached_scripts>0)' \
      '$EVDIR'/*.child-facts.json >/dev/null"
ck "...and records its PROVENANCE, which differs by family" \
   "[ \"\$(jq -r -s '[.[].opcache.declared_provenance]|unique|sort|join(\",\")' '$EVDIR'/*.child-facts.json)\" \
      = 'base-builtin,helper-installed' ]"
ck "every child proves redis by version AND by its client class" \
   "jq -e -s 'all(.[]; .redis.loaded==true and .redis.class_present==true and
                       (.redis.version|test(\"^[0-9]+\\\\.[0-9]+\\\\.[0-9]+\$\")))' \
      '$EVDIR'/*.child-facts.json >/dev/null"
ck "every child proves the build toolchain was purged" \
   "jq -e -s 'all(.[]; (.build_tools_purged|index(\"gcc\")) and (.build_tools_purged|index(\"make\")) and
                       (.build_tools_purged|index(\"phpize\")))' '$EVDIR'/*.child-facts.json >/dev/null"
ck "every child satisfied its declared extension set" \
   "jq -e -s 'all(.[]; (.extensions.missing|length)==0 and (.extensions.loaded|length)>0)' \
      '$EVDIR'/*.child-facts.json >/dev/null"
ck "emulation is DISCLOSED, never blurred into a native claim" \
   "jq -e -s 'all(.[]; .execution_mode==\"emulated\" or .execution_mode==\"native\")' \
      '$EVDIR'/*.child-facts.json >/dev/null &&
    jq -e '.execution_mode and .host_architecture' '$EVDIR/frozen-scan-basis.json' >/dev/null"

ck "the committed evidence is NOT reachable by production authorization" \
   "for r in '$EVDIR'/*.evidence.json; do
      bash scripts/release/assert-evidence-class.sh consumer production-authorization \"\$r\" >/dev/null 2>&1 && exit 1
    done; true"

echo "----"
[ "$fail" -eq 0 ] && echo "test_experimental_plan: PASS" || echo "test_experimental_plan: FAIL"
exit $fail
