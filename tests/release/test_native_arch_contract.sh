#!/usr/bin/env bash
# shellcheck disable=SC2034
# =============================================================================
# tests/release/test_native_arch_contract.sh — the QEMU/native boundary (#111).
#
# The accepted run 32395890071 produced ten linux/arm64 children, ALL emulated.
# That is legitimate evidence for #139 and must never become a native-runtime
# claim. These assertions make the two impossible to confuse.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
G=scripts/release/assert-native-arch-evidence.sh
P=policies/native-arch-requirements.yaml
W=.github/workflows/native-arm64-smoke.yml
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

ck "the native-arch gate self-tests clean" "bash $G --self-test >/dev/null 2>&1"

# --- policy states the boundary in both directions -------------------------
ck "policy declares QEMU sufficient for #139" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$P'))
assert d['qemu_sufficient_for']['issue']==139\""
ck "policy declares native required for #111" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$P'))
assert all(111 in x['blocks'] for x in d['native_evidence_required_for'])\""
ck "policy records the exact runner label contract" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$P'))
assert d['required_runner']['labels']==['self-hosted','Linux','ARM64','zenchron']
assert d['required_runner']['minimum_free_disk_gb']>=60\""
ck "the release gate is OFF and says why" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$P'))
g=d['release_gate']
assert g['require_native_arm64'] is False
assert 'no native arm64 runner' in g['rationale'].lower()\""

# --- the smoke workflow routes to the label and refuses emulation ----------
ck "the native workflow requires the ARM64 runner label" \
   "grep -q 'runs-on: \\[self-hosted, Linux, ARM64, zenchron\\]' $W"
ck "it proves uname -m rather than trusting the label" \
   "grep -q 'uname -m' $W && grep -q 'aarch64|arm64' $W"
ck "it REFUSES on a non-aarch64 host instead of degrading" \
   "grep -q 'REFUSE: native arm64 smoke landed on a' $W"
ck "it is dispatch-only — it cannot be triggered by a push" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$W'))
on=d.get(True) or d.get('on')
assert set(on)=={'workflow_dispatch'}, on\""
ck "its evidence is checked by the same gate, not by prose" \
   "grep -q 'assert-native-arch-evidence.sh native-evidence --require-native linux/arm64' $W"

# --- SABOTAGE: QEMU must never satisfy native ------------------------------
mkq() { mkdir -p "$1"; jq -n --arg k "$2" '{child_key:$k, platform:"linux/arm64",
        execution_mode:"qemu", host_architecture:"amd64"}' > "$1/$2.json"; }
D="$T/q"; mkq "$D" c1; mkq "$D" c2
bash "$G" "$D" --require-native linux/arm64 > "$T/q.out" 2>&1; rcq=$?
ck "SABOTAGE: emulated arm64 evidence CANNOT satisfy a native requirement" "[ $rcq -ne 0 ]"
ck "...and the refusal names emulation, not an unrelated error" \
   "grep -q 'ran emulated' '$T/q.out'"

# A record that simply relabels itself native must still fail, because the host
# architecture disagrees. Renaming the field is not evidence.
D2="$T/lie"; mkdir -p "$D2"
jq -n '{child_key:"c", platform:"linux/arm64", execution_mode:"native", host_architecture:"amd64"}' > "$D2/c.json"
bash "$G" "$D2" > "$T/lie.out" 2>&1; rcl=$?
ck "SABOTAGE: relabelling an emulated child 'native' is REFUSED" "[ $rcl -ne 0 ]"
ck "...because host_architecture contradicts the platform" \
   "grep -q 'host_architecture' '$T/lie.out'"

# --- the real accepted evidence behaves as documented ----------------------
A=docs/audits/acceptance-multiarch-2026-08-20/acceptance-evidence.json
ck "the accepted run's arm64 children are all recorded as qemu" \
   "[ \"\$(jq -r '[.children[]|select(.platform==\"linux/arm64\" and .execution_mode==\"qemu\")]|length' $A)\" -eq 10 ]"
ck "...and its amd64 children are all native" \
   "[ \"\$(jq -r '[.children[]|select(.platform==\"linux/amd64\" and .execution_mode==\"native\")]|length' $A)\" -eq 10 ]"
ck "so that evidence closes #139 and explicitly does not close #111" \
   "jq -e '.issue_linkage.closes==[139] and (.issue_linkage.does_not_close[\"111\"]|length>0)' $A >/dev/null"

echo "----"; [ "$fail" -eq 0 ] && echo "test_native_arch_contract: PASS" || echo "test_native_arch_contract: FAIL"
exit $fail
