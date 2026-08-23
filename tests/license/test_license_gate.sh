#!/usr/bin/env bash
# =============================================================================
# tests/license/test_license_gate.sh — the licence/publication gate (#120, #98).
#
# Three things are being proved, and they are different things:
#
#   1. The pipeline WORKS end to end: SBOMs in, normalised inventory out, a
#      verdict, and a notice candidate.
#   2. The gate FAILS CLOSED. Unknown, conflicting, denied and unreviewed each
#      refuse, and the refusal names what is wrong. An unclassified licence
#      falls to review, never to allowed.
#   3. The verdict is NOT VACUOUS. The shipped policy really does refuse real
#      components, and the pass on a clean inventory is caused by the policy
#      rather than by the gate being unable to refuse anything.
#
# Everything runs against fixtures in a scratch directory. Nothing here writes
# to the checkout: a test that edits policies/ to prove a point has destroyed
# the artefact it was asserting about, which has happened in this repository
# before.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

TMP="$(mktemp -d)"
# shellcheck disable=SC2064
trap "rm -rf '$TMP'" EXIT

INV=scripts/license/license-inventory.sh
GATE=scripts/license/assert-license-policy.sh
NOTICE=scripts/license/generate-notice.sh
POLICY=policies/license-policy.yaml

# --- the components' own self-tests -----------------------------------------
ck "license-inventory self-test passes"     "bash $INV --self-test >/dev/null"
ck "assert-license-policy self-test passes" "bash $GATE --self-test >/dev/null"
ck "generate-notice self-test passes"       "bash $NOTICE --self-test >/dev/null"

# --- the shipped policy is well formed and honest ---------------------------
ck "the shipped policy is valid YAML" \
   "python3 -c \"import yaml;yaml.safe_load(open('$POLICY'))\""
ck "the shipped policy fails closed by default" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$POLICY'))
assert d['default_state']=='legal-review-required',d['default_state']\""
ck "the shipped policy declares exactly the three states" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$POLICY'))
assert sorted(d['states'])==['allowed','denied','legal-review-required'],d['states']\""
# #98 is a legal decision. This repository must not record one.
ck "the publication decision is left UNDETERMINED for the owner (#98)" \
   "python3 -c \"
import yaml;p=yaml.safe_load(open('$POLICY'))['publication']
assert p['decision']=='undetermined',p['decision']
assert p['decided_by'] is None and p['decided_on'] is None,p
assert p['notices_approved_for_distribution'] is False,p\""
ck "the policy records the live contradiction rather than resolving it" \
   "python3 -c \"
import yaml;o=yaml.safe_load(open('$POLICY'))['publication']['observed']
assert o['repository_visibility']=='public',o
assert o['package_visibility']=='private',o
assert 'proprietary' in o['license_file_grant'],o\""
# Denying a licence is a legal conclusion; engineering must not invent one.
ck "no licence was DENIED by engineering fiat" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$POLICY'))
assert d['denied']==[],d['denied']
assert not [e for e in d['licenses'] if e['state']=='denied'],d\""
ck "every copyleft/reciprocal licence carries a stated reason for review" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$POLICY'))
bad=[e['id'] for e in d['licenses']
     if e['state']=='legal-review-required' and not e.get('reason')]
assert not bad,bad\""
ck "every allowed licence records its obligations" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$POLICY'))
bad=[e['id'] for e in d['licenses'] if e['state']=='allowed' and 'obligations' not in e]
assert not bad,bad\""

# --- end to end over SBOM fixtures ------------------------------------------
mkdir -p "$TMP/sbom"
cat >"$TMP/sbom/clean.spdx.json" <<'JSON'
{"spdxVersion":"SPDX-2.3","packages":[
 {"name":"zlib","versionInfo":"1.3","licenseConcluded":"Zlib","licenseDeclared":"Zlib"},
 {"name":"libssl","versionInfo":"3.0","licenseConcluded":"Apache-2.0","licenseDeclared":"Apache-2.0"}
]}
JSON
ck "SBOMs normalise into an inventory" \
   "bash $INV --sbom-dir '$TMP/sbom' --out '$TMP/inv.json' >/dev/null"
ck "the inventory is a v1 document with both components" \
   "python3 -c \"
import json;d=json.load(open('$TMP/inv.json'))
assert d['schema']=='foundry.license-inventory/v1',d['schema']
assert d['component_count']==2,d['component_count']\""
ck "an all-permissive inventory PASSES the shipped policy" \
   "bash $GATE --inventory '$TMP/inv.json' >/dev/null 2>&1"
ck "...and the pass still refuses to imply a right to publish" \
   "bash $GATE --inventory '$TMP/inv.json' >'$TMP/o' 2>&1 || true; grep -q 'remains UNDETERMINED' '$TMP/o'"
ck "a notice CANDIDATE renders from the passing inventory" \
   "bash $NOTICE --inventory '$TMP/inv.json' --out '$TMP/NOTICE.txt' >/dev/null 2>&1"
ck "the notice is marked a draft, not an approved legal artefact" \
   "head -1 '$TMP/NOTICE.txt' | grep -q 'DRAFT, NOT APPROVED FOR DISTRIBUTION'"

# --- fail-closed, against the SHIPPED policy --------------------------------
mkdir -p "$TMP/sbom-unknown"
cat >"$TMP/sbom-unknown/x.spdx.json" <<'JSON'
{"spdxVersion":"SPDX-2.3","packages":[
 {"name":"mysterylib","versionInfo":"0.1","licenseConcluded":"NOASSERTION","licenseDeclared":"NOASSERTION"}
]}
JSON
ck "a component with NO established licence refuses" \
   "bash $INV --sbom-dir '$TMP/sbom-unknown' --out '$TMP/u.json' >/dev/null && ! bash $GATE --inventory '$TMP/u.json' >/dev/null 2>&1"
ck "...and the refusal names the component" \
   "bash $GATE --inventory '$TMP/u.json' >'$TMP/o' 2>&1 || true; grep -q 'mysterylib@0.1' '$TMP/o'"

mkdir -p "$TMP/sbom-conflict"
cat >"$TMP/sbom-conflict/x.spdx.json" <<'JSON'
{"spdxVersion":"SPDX-2.3","packages":[
 {"name":"splitlib","versionInfo":"1.0","licenseConcluded":"MIT","licenseDeclared":"GPL-2.0-only"}
]}
JSON
ck "sources disagreeing about a licence refuses" \
   "bash $INV --sbom-dir '$TMP/sbom-conflict' --out '$TMP/c.json' >/dev/null && ! bash $GATE --inventory '$TMP/c.json' >/dev/null 2>&1"
ck "...and shows both asserted values" \
   "bash $GATE --inventory '$TMP/c.json' >'$TMP/o' 2>&1 || true; grep -q 'GPL-2.0-only vs MIT' '$TMP/o'"

mkdir -p "$TMP/sbom-copyleft"
cat >"$TMP/sbom-copyleft/x.spdx.json" <<'JSON'
{"spdxVersion":"SPDX-2.3","packages":[
 {"name":"readline","versionInfo":"8.2","licenseConcluded":"GPL-3.0-or-later","licenseDeclared":"GPL-3.0-or-later"}
]}
JSON
ck "an UNREVIEWED copyleft component refuses under the shipped policy" \
   "bash $INV --sbom-dir '$TMP/sbom-copyleft' --out '$TMP/g.json' >/dev/null && ! bash $GATE --inventory '$TMP/g.json' >/dev/null 2>&1"
ck "...naming legal review as the missing act, not a technical fault" \
   "bash $GATE --inventory '$TMP/g.json' >'$TMP/o' 2>&1 || true; grep -q 'needs legal review and has not had it' '$TMP/o'"
ck "an unresolved inventory cannot produce a NOTICE at all" \
   "! bash $NOTICE --inventory '$TMP/u.json' --out '$TMP/bad-notice.txt' >/dev/null 2>&1 && test ! -f '$TMP/bad-notice.txt'"

# --- NON-VACUITY -------------------------------------------------------------
# The clean inventory passing is only meaningful if this gate can fail at all,
# and if the SHIPPED policy is what decides. Prove both.
ck "non-vacuity: the shipped policy refuses at least one real SPDX licence" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$POLICY'))
review=[e['id'] for e in d['licenses'] if e['state']=='legal-review-required']
assert len(review)>=10,len(review)\""
ck "non-vacuity: the gate distinguishes pass from fail on the same policy" \
   "bash $GATE --inventory '$TMP/inv.json' >/dev/null 2>&1 && ! bash $GATE --inventory '$TMP/g.json' >/dev/null 2>&1"

# --- SABOTAGE ----------------------------------------------------------------
# Each sabotage is applied to a COPY. If any of these stopped changing the
# verdict, the gate would have become decoration.
cp "$POLICY" "$TMP/sabotage.yaml"
ck "sabotage: flipping default_state to 'allowed' is REFUSED outright" \
   "sed 's/^default_state: legal-review-required$/default_state: allowed/' '$POLICY' >'$TMP/s1.yaml';
    ! bash $GATE --inventory '$TMP/inv.json' --policy '$TMP/s1.yaml' >/dev/null 2>&1"
ck "sabotage: deleting the states list is REFUSED" \
   "grep -v '^  - allowed$' '$POLICY' >'$TMP/s2.yaml';
    ! bash $GATE --inventory '$TMP/inv.json' --policy '$TMP/s2.yaml' >/dev/null 2>&1"
# The pre-change state of this repository had NO licence gate at all. This is
# the proof that the gate — not the fixture — is what refuses: reclassify the
# offending licence to `allowed` in a copy and the same inventory passes.
ck "sabotage: reclassifying GPL-3.0-or-later to allowed makes the SAME inventory pass" \
   "python3 - <<'PY' >'$TMP/s3.yaml'
import yaml
d=yaml.safe_load(open('$POLICY'))
for e in d['licenses']:
    if e['id']=='GPL-3.0-or-later':
        e['state']='allowed'; e['obligations']=[]
print(yaml.safe_dump(d))
PY
    bash $GATE --inventory '$TMP/g.json' --policy '$TMP/s3.yaml' >/dev/null 2>&1"
ck "sabotage: an exception with no expiry is REFUSED, not silently honoured" \
   "python3 - <<'PY' >'$TMP/s4.yaml'
import yaml
d=yaml.safe_load(open('$POLICY'))
d['exceptions']=[{'component':'readline','license':'GPL-3.0-or-later',
                  'granted_by':'nobody','tracked_issue':120}]
print(yaml.safe_dump(d))
PY
    ! bash $GATE --inventory '$TMP/g.json' --policy '$TMP/s4.yaml' >/dev/null 2>&1"
ck "sabotage: an EXPIRED exception is REFUSED" \
   "python3 - <<'PY' >'$TMP/s5.yaml'
import yaml
d=yaml.safe_load(open('$POLICY'))
d['exceptions']=[{'component':'readline','license':'GPL-3.0-or-later',
                  'granted_by':'nobody','tracked_issue':120,'expires':'2001-01-01'}]
print(yaml.safe_dump(d))
PY
    ! bash $GATE --inventory '$TMP/g.json' --policy '$TMP/s5.yaml' >/dev/null 2>&1"

# --- the checkout must be untouched -----------------------------------------
ck "the test mutated no tracked file" \
   "test -z \"\$(git -C '$ROOT' status --porcelain -- policies scripts/license 2>/dev/null | grep -v '^??' || true)\""

echo "----"
[ "$fail" -eq 0 ] && echo "test_license_gate: PASS" || echo "test_license_gate: FAIL"
exit "$fail"
