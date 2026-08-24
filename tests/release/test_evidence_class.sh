#!/usr/bin/env bash
# shellcheck disable=SC2034  # assertion vars are consumed inside eval'd assertion strings
# =============================================================================
# tests/release/test_evidence_class.sh
# -----------------------------------------------------------------------------
# Regression for the artifact/evidence CLASS contract.
#
# THE REAL DEFECT ENCODED HERE: an upstream-base scan was reported as Foundry
# child evidence. The php:8.4 BASE carries 241 CRITICAL/HIGH of which 170 are
# linux-libc-dev; the accepted php-fpm/8.4 CHILD carries 47 and ZERO
# linux-libc-dev, because the Dockerfile runs `apt-get purge -y --auto-remove`.
# The base record therefore describes an inventory the shipped artifact does not
# have. It was never a conservative over-estimate — it was evidence about a
# different artifact.
#
# This file asserts the CONTRACT, from outside the script that implements it,
# and validates against the REAL COMMITTED accepted evidence, not only fixtures.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
# common.sh carries `set -e`; intentional-refusal assertions must survive it.
# shellcheck source=../../scripts/lib/common.sh
. scripts/lib/common.sh
set +e

fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

A="scripts/release/assert-evidence-class.sh"
SCHEMA="schemas/evidence-class-v1.schema.json"
POLICY="policies/evidence-classes.yaml"
ACCEPTED="docs/audits/acceptance-multiarch-2026-08-20/acceptance-evidence.json"
AUTHREC="docs/audits/acceptance-amd64-2026-08-14/post-build-authorization.json"

TMP="$(mktemp -d)"
# Expand NOW: a single-quoted EXIT trap defers expansion past this scope.
# shellcheck disable=SC2064
trap "rm -rf '$TMP'" EXIT

if ! python3 -c 'import yaml, jsonschema' 2>/dev/null; then
  echo "SKIP - pyyaml/jsonschema absent"; echo "test_evidence_class: PASS"; exit 0
fi

# --- the artefacts exist and are well-formed --------------------------------
ck "the class schema exists and is valid JSON"  "python3 -c 'import json;json.load(open(\"$SCHEMA\"))'"
ck "the class policy exists and is valid YAML"  "python3 -c 'import yaml;yaml.safe_load(open(\"$POLICY\"))'"
ck "the class gate is executable"               "test -x '$A'"

# --- exactly the four declared classes, in lifecycle order ------------------
ck "the policy declares exactly the four artifact classes" \
   "[ \"\$(python3 -c 'import yaml;print(\" \".join(c[\"name\"] for c in yaml.safe_load(open(\"$POLICY\"))[\"classes\"]))')\" \
     = 'upstream-base foundry-child staged-candidate published-artifact' ]"
ck "the schema enum agrees with the policy class list" \
   "[ \"\$(python3 -c 'import json,yaml;s=json.load(open(\"$SCHEMA\"));p=yaml.safe_load(open(\"$POLICY\"));print(sorted(s[\"properties\"][\"evidence_class\"][\"enum\"])==sorted(c[\"name\"] for c in p[\"classes\"]))')\" = True ]"

# --- every binding the contract names is REQUIRED by the schema -------------
# Twelve facts plus the class itself. If the schema stops requiring one, the
# field becomes optional exactly where nobody is looking.
for f in evidence_class image_digest platform image_family image_version \
         source_revision build_input_digest build_completed scanner_identity \
         vulnerability_db_identity package_inventory_source created_at parent; do
  ck "schema REQUIRES the '$f' binding" \
     "python3 -c 'import json,sys;sys.exit(0 if \"$f\" in json.load(open(\"$SCHEMA\"))[\"required\"] else 1)'"
  ck "...and policy required_binding lists '$f'" \
     "python3 -c 'import yaml,sys;sys.exit(0 if \"$f\" in yaml.safe_load(open(\"$POLICY\"))[\"required_binding\"] else 1)'"
done

# --- the gate's own sabotage suite must be green ----------------------------
bash "$A" --self-test >"$TMP/self.out" 2>&1; selfrc=$?
ck "the class gate's sabotage suite passes" "[ '$selfrc' -eq 0 ]"
for s in S1 S2 S3 S4 S5 S6 S7 S8 S9; do
  ck "sabotage $s is exercised and refused with its own diagnostic" \
     "grep -q \"^ok   - $s .*\" '$TMP/self.out'"
done

# --- NON-VACUITY: the validator can actually reject -------------------------
# A gate that accepts everything would pass every assertion above.
printf '{"schema_version":1}\n' > "$TMP/empty.json"
ck "NON-VACUOUS: a record with no bindings is REFUSED" \
   "! bash '$A' validate '$TMP/empty.json' >/dev/null 2>&1"
out="$(bash "$A" validate "$TMP/empty.json" 2>&1)"
ck "...and it names the missing binding fields, not a generic error" \
   "printf '%s' \"\$out\" | grep -q 'missing required binding field' &&
    printf '%s' \"\$out\" | grep -q 'image_digest'"
ck "NON-VACUOUS: an undeclared class value is REFUSED" \
   "! bash '$A' require-class not-a-class '$TMP/empty.json' >/dev/null 2>&1"

# --- THE REAL COMMITTED EVIDENCE must keep validating -----------------------
# Fixtures prove the rules; these prove the rules did not break the repository.
ck "the REAL accepted multiarch evidence is present" "test -s '$ACCEPTED'"
ck "the REAL accepted multiarch evidence validates under the compatibility rule" \
   "bash '$A' legacy '$ACCEPTED' >/dev/null"
ck "the REAL accepted amd64 authorization record validates too" \
   "bash '$A' legacy '$AUTHREC' >/dev/null"
ck "...and it is admitted as staged-candidate, the class that may authorize" \
   "bash '$A' legacy '$ACCEPTED' | grep -q 'class=staged-candidate'"
ck "...carrying all $MATRIX_COUNT image definitions x 2 platforms" \
   "[ \"\$(jq '.children | length' '$ACCEPTED')\" -eq \"\$(( MATRIX_COUNT * 2 ))\" ]"

# --- the compatibility rule is EXPLICIT, never inferred ---------------------
ck "the compatibility grant pins the accepted evidence BY CONTENT DIGEST" \
   "[ \"\$(python3 -c 'import yaml;print([e[\"sha256\"] for e in yaml.safe_load(open(\"$POLICY\"))[\"legacy_records\"] if e[\"path\"]==\"$ACCEPTED\"][0])')\" \
     = \"\$(shasum -a 256 '$ACCEPTED' | cut -d\" \" -f1)\" ]"
ck "every legacy grant states a rationale and a declaring change" \
   "python3 -c 'import yaml,sys;rs=yaml.safe_load(open(\"$POLICY\"))[\"legacy_records\"];sys.exit(0 if all(str(r.get(\"rationale\",\"\")).strip() and str(r.get(\"declared_by\",\"\")).strip() for r in rs) else 1)'"
ck "every waived binding states WHY it is waived" \
   "python3 -c 'import yaml,sys;rs=yaml.safe_load(open(\"$POLICY\"))[\"legacy_records\"];sys.exit(0 if all(str(v).strip() for r in rs for v in (r.get(\"waived_bindings\") or {}).values()) else 1)'"

# SABOTAGE: mutate a pinned legacy record in a COPY and require refusal. The
# real file is never touched — this repository has already destroyed
# policies/required-release-checks.yaml with a self-test that mutated in place.
ISO="$TMP/iso"; mkdir -p "$ISO/$(dirname "$ACCEPTED")"
cp "$ACCEPTED" "$ISO/$ACCEPTED"
printf '\n' >> "$ISO/$ACCEPTED"
out="$(AEC_AUDIT_ROOT="$ISO" bash "$A" legacy "$ACCEPTED" 2>&1)"
ck "SABOTAGE: a legacy record whose BYTES changed is refused" \
   "! AEC_AUDIT_ROOT='$ISO' bash '$A' legacy '$ACCEPTED' >/dev/null 2>&1"
ck "...and the diagnostic says the pinned bytes changed" \
   "printf '%s' \"\$out\" | grep -q 'legacy record bytes changed'"
ck "...and the AMBIENT accepted evidence is byte-identical afterwards" \
   "[ \"\$(shasum -a 256 '$ACCEPTED' | cut -d' ' -f1)\" \
     = \"\$(python3 -c 'import yaml;print([e[\"sha256\"] for e in yaml.safe_load(open(\"$POLICY\"))[\"legacy_records\"] if e[\"path\"]==\"$ACCEPTED\"][0])')\" ]"

# --- reports must DISPLAY the class -----------------------------------------
ck "the policy requires reports to display the evidence class" \
   "[ \"\$(python3 -c 'import yaml;print(yaml.safe_load(open(\"$POLICY\"))[\"report_requirements\"][\"display_evidence_class\"])')\" = True ]"

# --- ONE identity derivation ------------------------------------------------
# child_key()/child_slug() in scripts/lib/common.sh are the only ones. A second
# derivation is how php-fpm/8.3 amd64 and arm64 collapsed onto one artifact name
# in cancelled run 32123758374.
# Asserted by BEHAVIOUR, not by a grep that would match its own explanation.
ck "the gate sources the one identity library" \
   "grep -q 'lib/common.sh' '$A'"
ck "child_key() is the derivation, and it is platform-bound" \
   "[ \"\$(child_key php-fpm 8.4 linux/amd64)\" = 'php-fpm/8.4/linux/amd64' ] &&
    [ \"\$(child_key php-fpm 8.4 linux/arm64)\" != \"\$(child_key php-fpm 8.4 linux/amd64)\" ]"
ck "...and the class gate contains no second identity assembler" \
   "[ \"\$(grep -cE 'printf .%s/%s/%s' '$A')\" = 0 ]"

echo "----"
[ "$fail" -eq 0 ] && echo "test_evidence_class: PASS" || echo "test_evidence_class: FAIL"
exit $fail
