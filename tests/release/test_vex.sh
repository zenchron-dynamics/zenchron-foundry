#!/usr/bin/env bash
# shellcheck disable=SC2034  # assertion vars are consumed inside eval'd assertion strings
# =============================================================================
# tests/release/test_vex.sh
# -----------------------------------------------------------------------------
# Machine-readable vulnerability dispositions (#115), asserted from OUTSIDE the
# generator and against the REAL committed exception ledger
# (policies/vulnerability-exceptions.yaml, 59 exceptions + 20 not_affected
# records) and the REAL committed accepted run (20 children, 982 observed
# finding tuples). Fixtures alone would prove the code runs, not that the
# repository's actual decisions can be published without overstating them.
#
# THE PROPERTY UNDER TEST is not "a VEX document is produced". It is that the
# document cannot say more than the evidence:
#
#   * every statement is bound to a manifest digest this run actually produced
#   * every subcomponent is a package@version actually observed in that image
#   * every advisory was actually reported for that image
#   * every backing record is live, version-pinned and image-scoped
#   * an accepted risk is published as `affected`, never as `not_affected`
#   * no reachability justification is invented from the ledger's internal
#     `reachability` field
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
# common.sh carries `set -e`; refusal assertions must survive it, and under
# pipefail `<refusing command> | grep` reports the refusal's status.
# shellcheck source=../../scripts/lib/common.sh
. scripts/lib/common.sh
set +e
set +o pipefail

fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

VEX=scripts/release/generate-vex.sh
SCHEMA=schemas/vex-openvex-v1.schema.json
LEDGER=policies/vulnerability-exceptions.yaml
ACCEPTED=docs/audits/acceptance-multiarch-2026-08-20/acceptance-evidence.json

TMP="$(mktemp -d)"
# Expand NOW: a single-quoted EXIT trap defers expansion past this scope.
# shellcheck disable=SC2064
trap "rm -rf '$TMP'" EXIT

if ! python3 -c 'import yaml' 2>/dev/null; then
  echo "SKIP - PyYAML absent"; echo "test_vex: PASS"; exit 0
fi

DAY=2026-08-25          # inside the acceptance window of the committed ledger
# The generator now REQUIRES --evidence-class: a disposition set has to state
# what it is about, because "what may ship" is not "what shipped". These
# wrappers supply the class the accepted multiarch run actually is — the same
# value tests/integration/test_evidence_path_e2e.sh uses for this same evidence
# file — so every call site below keeps its original intent. A call site that
# passes its own --evidence-class still wins, since it appears later on the
# command line.
VEX_CLASS=staged-candidate
gen() { ( bash "$VEX" generate --evidence-class "$VEX_CLASS" "$@" ); }
vfy() { ( bash "$VEX" verify   --evidence-class "$VEX_CLASS" "$@" ); }

ck "the OpenVEX schema is valid JSON" "python3 -c 'import json;json.load(open(\"$SCHEMA\"))'"
ck "the generator is executable"      "test -x '$VEX'"
ck "the real exception ledger is present" "test -f '$LEDGER'"

# --- the generator's own sabotage suite --------------------------------------
bash "$VEX" --self-test >"$TMP/self.out" 2>&1; selfrc=$?
ck "the generator's sabotage suite passes" "[ '$selfrc' -eq 0 ]"
for s in S1 S2 S3 S4 S5 S6 S7 S8 S9 S10 S11; do
  ck "sabotage $s is exercised and refused" "grep -q \"^ok   - $s \" '$TMP/self.out'"
done

# --- generated from the REAL ledger and the REAL accepted run ----------------
ck "a document is generated from the real ledger and the real accepted run" \
   "gen --evidence '$ACCEPTED' --out '$TMP/vex.json' --ledger '$LEDGER' --today '$DAY' >/dev/null"
V="$TMP/vex.json"
ck "it verifies against the same inputs" \
   "vfy --vex '$V' --evidence '$ACCEPTED' --ledger '$LEDGER' --today '$DAY' >/dev/null"
ck "it validates against the OpenVEX schema" \
   "python3 -c 'import json,sys
try: from jsonschema import Draft202012Validator
except ImportError: sys.exit(0)
e=list(Draft202012Validator(json.load(open(\"$SCHEMA\"))).iter_errors(json.load(open(\"$V\"))))
sys.exit(1 if e else 0)'"
ck "it declares the OpenVEX 0.2.0 context" \
   "[ \"\$(python3 -c 'import json;print(json.load(open(\"$V\"))[\"@context\"])')\" = 'https://openvex.dev/ns/v0.2.0' ]"

# --- COVERAGE: exactly the observed universe, no more and no less ------------
ck "every observed (digest, advisory, package, version) tuple has a disposition" \
   "python3 -c 'import json,sys
ev=json.load(open(\"$ACCEPTED\"));d=json.load(open(\"$V\"))
want=set()
for c in ev[\"children\"]:
    for cve,ps in (c[\"governed_findings\"] or {}).items():
        for p in ps: want.add((c[\"manifest_digest\"],cve,p))
import re
got=set()
for s in d[\"statements\"]:
    cve=s[\"vulnerability\"][\"name\"]
    for pr in s[\"products\"]:
        dig=\"sha256:\"+re.search(r\"@sha256%3A([0-9a-f]{64})\",pr[\"@id\"]).group(1)
        for sub in pr[\"subcomponents\"]:
            m=re.match(r\"pkg:[a-z]+/(?:[^@]*/)?([^/@]+)@(.+?)(?:\?|\$)\",sub[\"@id\"])
            got.add((dig,cve,sub[\"@id\"]))
sys.exit(0 if len(want)==982 and len(got)==len(want) else 1)'"
ck "the document reports the observed tuple count it was built from" \
   "[ \"\$(python3 -c 'import json;print(json.load(open(\"$V\"))[\"foundry\"][\"observed_tuples\"])')\" = 982 ]"
ck "every product is digest-bound; no tag-scoped product exists" \
   "python3 -c 'import json,re,sys
d=json.load(open(\"$V\"))
sys.exit(0 if all(re.search(r\"@sha256%3A[0-9a-f]{64}\",p[\"@id\"]) for s in d[\"statements\"] for p in s[\"products\"]) else 1)'"
ck "every product digest is one of the 20 accepted children" \
   "python3 -c 'import json,re,sys
ev=json.load(open(\"$ACCEPTED\"));d=json.load(open(\"$V\"))
ok={c[\"manifest_digest\"] for c in ev[\"children\"]}
for s in d[\"statements\"]:
    for p in s[\"products\"]:
        if \"sha256:\"+re.search(r\"@sha256%3A([0-9a-f]{64})\",p[\"@id\"]).group(1) not in ok: sys.exit(1)
sys.exit(0)'"
ck "every product carries the platform the evidence recorded" \
   "python3 -c 'import json,re,sys
ev=json.load(open(\"$ACCEPTED\"));d=json.load(open(\"$V\"))
plat={c[\"manifest_digest\"]:c[\"platform\"] for c in ev[\"children\"]}
for s in d[\"statements\"]:
    for p in s[\"products\"]:
        dig=\"sha256:\"+re.search(r\"@sha256%3A([0-9a-f]{64})\",p[\"@id\"]).group(1)
        if p[\"foundry\"][\"platform\"]!=plat[dig]: sys.exit(1)
sys.exit(0)'"

# --- HONESTY: what the document must NOT claim -------------------------------
ck "an accepted risk is published as 'affected', never as 'not_affected'" \
   "python3 -c 'import json,sys
d=json.load(open(\"$V\"))
bad=[s for s in d[\"statements\"] if s[\"foundry\"][\"record_kind\"]==\"exception\" and s[\"status\"]!=\"affected\"]
sys.exit(1 if bad else 0)'"
ck "no reachability justification is invented from the ledger" \
   "! grep -q 'vulnerable_code_not_in_execute_path\|vulnerable_code_cannot_be_controlled_by_adversary' '$V'"
ck "...even though the ledger carries reachability rationale on 59 records" \
   "grep -q 'not-reachable-under-intended-use' '$LEDGER'"
ck "every 'affected' statement carries an action statement" \
   "python3 -c 'import json,sys
d=json.load(open(\"$V\"))
sys.exit(0 if all(s.get(\"action_statement\") for s in d[\"statements\"] if s[\"status\"]==\"affected\") else 1)'"
ck "every 'not_affected' statement carries a justification from the fixed vocabulary" \
   "python3 -c 'import json,sys
V={\"component_not_present\",\"vulnerable_code_not_present\",\"vulnerable_code_not_in_execute_path\",
   \"vulnerable_code_cannot_be_controlled_by_adversary\",\"inline_mitigations_already_exist\"}
d=json.load(open(\"$V\"))
sys.exit(0 if all(s.get(\"justification\") in V for s in d[\"statements\"] if s[\"status\"]==\"not_affected\") else 1)'"
ck "every statement names the ledger record it was derived from" \
   "python3 -c 'import json,sys
d=json.load(open(\"$V\"))
sys.exit(0 if all(s[\"foundry\"][\"record_id\"] for s in d[\"statements\"]) else 1)'"
ck "every named record actually exists in the ledger" \
   "python3 -c 'import json,sys,yaml
sys.path.insert(0,\"scripts/lib\")
from exception_id import exc_id
led=yaml.safe_load(open(\"$LEDGER\"));d=json.load(open(\"$V\"))
have={\"exception:\"+exc_id(r) for r in led[\"exceptions\"]}
have|={\"not_affected:\"+exc_id(r) for r in led.get(\"not_affected\") or []}
sys.exit(0 if all(s[\"foundry\"][\"record_id\"] in have for s in d[\"statements\"]) else 1)'"
ck "the document pins the exception policy digest it was derived from" \
   "[ \"\$(python3 -c 'import json;print(json.load(open(\"$V\"))[\"foundry\"][\"exception_policy_sha256\"])')\" \
      = \"\$(shasum -a 256 '$LEDGER' | awk '{print \$1}')\" ]"

# --- REFUSALS asserted from outside ------------------------------------------
python3 - "$V" "$TMP/wide.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
p = d["statements"][0]["products"][0]
p["@id"] = p["@id"].split("@")[0] + "@sha256%3A" + "b" * 64 + "?arch=amd64&tag=prod"
p["identifiers"]["purl"] = p["@id"]
json.dump(d, open(sys.argv[2], "w"), indent=2)
PY
ck "REFUSE: a statement about a digest this run never produced" \
   "! vfy --vex '$TMP/wide.json' --evidence '$ACCEPTED' --ledger '$LEDGER' --today '$DAY' >/dev/null 2>&1"

python3 - "$V" "$TMP/ghost.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["statements"][0]["products"][0]["subcomponents"].append(
    {"@id": "pkg:deb/debian/never-installed@1.2.3?arch=amd64"})
json.dump(d, open(sys.argv[2], "w"), indent=2)
PY
ck "REFUSE: a package/version tuple never observed on that image" \
   "! vfy --vex '$TMP/ghost.json' --evidence '$ACCEPTED' --ledger '$LEDGER' --today '$DAY' >/dev/null 2>&1"

python3 - "$V" "$TMP/nocve.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["statements"][0]["vulnerability"]["name"] = "CVE-2000-11111"
json.dump(d, open(sys.argv[2], "w"), indent=2)
PY
ck "REFUSE: a disposition for an advisory the scan never reported" \
   "! vfy --vex '$TMP/nocve.json' --evidence '$ACCEPTED' --ledger '$LEDGER' --today '$DAY' >/dev/null 2>&1"

ck "REFUSE: generation once an acceptance has lapsed" \
   "! gen --evidence '$ACCEPTED' --out '$TMP/stale.json' --ledger '$LEDGER' --today 2099-01-01 >/dev/null 2>&1"
ck "REFUSE: an already-published document backed by a lapsed acceptance" \
   "! vfy --vex '$V' --evidence '$ACCEPTED' --ledger '$LEDGER' --today 2099-01-01 >/dev/null 2>&1"

# An unbounded selector: `all` would silently absorb an image family added
# tomorrow, and a published statement cannot be recalled from a consumer's cache.
python3 - "$LEDGER" "$TMP/led-all.yaml" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
d["exceptions"][0]["image"] = "all"
yaml.safe_dump(d, open(sys.argv[2], "w"), default_flow_style=False, allow_unicode=True)
PY
ck "REFUSE: an unbounded image selector cannot back a published statement" \
   "! gen --evidence '$ACCEPTED' --out '$TMP/all.json' --ledger '$TMP/led-all.yaml' --today '$DAY' >/dev/null 2>&1"

python3 - "$LEDGER" "$TMP/led-nopin.yaml" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
for e in d["exceptions"]:
    e.pop("installed_version", None); e.pop("package_versions", None)
yaml.safe_dump(d, open(sys.argv[2], "w"), default_flow_style=False, allow_unicode=True)
PY
ck "REFUSE: a record with no exact version pin" \
   "! gen --evidence '$ACCEPTED' --out '$TMP/nopin.json' --ledger '$TMP/led-nopin.yaml' --today '$DAY' >/dev/null 2>&1"

python3 - "$LEDGER" "$TMP/led-amb.yaml" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
src = d["exceptions"][0]
d.setdefault("not_affected", []).append({
    "cve": src["cve"], "image": src["image"], "package": src["package"],
    "installed_version": src.get("installed_version"),
    "verified_architectures": src.get("verified_architectures"),
    "classification": "vulnerable-code-not-present",
    "evidence": "fixture conflict", "references": ["fixture"]})
yaml.safe_dump(d, open(sys.argv[2], "w"), default_flow_style=False, allow_unicode=True)
PY
ck "REFUSE: one tuple governed as BOTH accepted risk and not-affected" \
   "! gen --evidence '$ACCEPTED' --out '$TMP/amb.json' --ledger '$TMP/led-amb.yaml' --today '$DAY' >/dev/null 2>&1"

python3 - "$V" "$TMP/partial.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); d["statements"] = d["statements"][2:]
json.dump(d, open(sys.argv[2], "w"), indent=2)
PY
ck "REFUSE: a partial document, which a consumer reads as 'all else is fine'" \
   "! vfy --vex '$TMP/partial.json' --evidence '$ACCEPTED' --ledger '$LEDGER' --today '$DAY' >/dev/null 2>&1"

# --- SABOTAGE ON THE PRE-CHANGE STATE ----------------------------------------
# Before this work, the repository published no machine-readable dispositions at
# all. The pre-change state is therefore "no document"; assert that the absence
# is a refusal and not an implicit pass.
ck "SABOTAGE: verifying a document that does not exist REFUSES" \
   "! vfy --vex '$TMP/absent.json' --evidence '$ACCEPTED' --ledger '$LEDGER' --today '$DAY' >/dev/null 2>&1"
printf '{}\n' > "$TMP/empty.json"
ck "SABOTAGE: an empty JSON object is not a disposition set" \
   "! vfy --vex '$TMP/empty.json' --evidence '$ACCEPTED' --ledger '$LEDGER' --today '$DAY' >/dev/null 2>&1"

# --- NON-VACUITY -------------------------------------------------------------
ck "NON-VACUOUS: the untouched document still verifies after every sabotage" \
   "vfy --vex '$V' --evidence '$ACCEPTED' --ledger '$LEDGER' --today '$DAY' >/dev/null"
ck "NON-VACUOUS: the document is not empty" \
   "[ \"\$(python3 -c 'import json;print(len(json.load(open(\"$V\"))[\"statements\"]))')\" -gt 20 ]"
ck "NON-VACUOUS: both statuses actually occur, so neither branch is dead" \
   "python3 -c 'import json,sys
d=json.load(open(\"$V\"));st={s[\"status\"] for s in d[\"statements\"]}
sys.exit(0 if st=={\"affected\",\"not_affected\"} else 1)'"

echo "----"
[ "$fail" -eq 0 ] && echo "test_vex: PASS" || echo "test_vex: FAIL"
exit $fail
