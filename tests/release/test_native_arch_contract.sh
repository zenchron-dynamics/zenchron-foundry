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
# --- the disk floor is a property of the RUNNER, not of the job -------------
# It used to be ONE global number, `required_runner.minimum_free_disk_gb: 60`,
# copied from a persistent self-hosted incident (_work/_update self-update
# staging on a volume that survives every job). A hosted ephemeral runner ships
# ~14 GB and starts clean, so the inherited 60 made an eligible runner look
# ineligible. These assertions fail against that previous state in three
# independent ways: the flat key is gone, the floors are per-kind, and they
# differ from each other.
ck "the policy no longer carries ONE global disk floor" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$P'))
assert 'required_runner' not in d, 'the flat required_runner block is back'\""
ck "the disk floor is scoped by runner KIND, with at least two kinds" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$P'))
rs=d['accepted_runners']
kinds=[r['kind'] for r in rs]
assert len(kinds)==len(set(kinds)), kinds
assert {'ephemeral-hosted','persistent-self-hosted'} <= set(kinds), kinds
assert all(isinstance(r['minimum_free_disk_gb'],int) for r in rs)\""
ck "...and the two kinds do NOT share the same floor" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$P'))
f={r['kind']:r['minimum_free_disk_gb'] for r in d['accepted_runners']}
assert f['ephemeral-hosted'] != f['persistent-self-hosted'], f\""
ck "the persistent self-hosted floor KEEPS the 60 GB incident figure" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$P'))
r=[x for x in d['accepted_runners'] if x['kind']=='persistent-self-hosted'][0]
assert r['minimum_free_disk_gb']>=60
assert r['disk_basis']=='incident'
assert r['labels']==['self-hosted','Linux','ARM64','zenchron']\""
ck "the hosted floor fits the runner it describes (<= 14 GB advertised SSD)" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$P'))
r=[x for x in d['accepted_runners'] if x['kind']=='ephemeral-hosted'][0]
assert 0 < r['minimum_free_disk_gb'] <= 14, r['minimum_free_disk_gb']\""
ck "every runner kind states WHY its floor is what it is" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$P'))
for r in d['accepted_runners']:
    assert len(r.get('disk_rationale','')) >= 80, r['id']\""

# --- the active runner is a REAL arm64 label the workflow actually targets ---
ck "the active runner is a known arm64 runner label, not a placeholder" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$P'))
a=[r for r in d['accepted_runners'] if r['id']==d['active_runner']]
assert len(a)==1, d['active_runner']
KNOWN_ARM64={'ubuntu-24.04-arm','ubuntu-22.04-arm','ubuntu-26.04-arm'}
lab=set(a[0]['labels'])
assert lab & KNOWN_ARM64 or {'self-hosted','ARM64'} <= lab, lab\""

ck "the release gate is ON and says why" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$P'))
g=d['release_gate']
assert g['require_native_arm64'] is True
assert 'public' in g['rationale'].lower()\""
# THE ASSERTION THAT FAILS ON THE PREVIOUS STATE. The policy used to carry a
# `known_gap` recording that no release-gating workflow invoked the gate, with
# `blocks_closure_of: 111`. Closing that gap means the key is gone AND the
# enforcement points it named are real — checked below, not merely declared.
ck "the policy no longer records the release-path gap as open" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$P'))
assert 'known_gap' not in d['release_gate'], 'the known_gap is back'\""
ck "...because the gate is enforced at named points on the release path" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$P'))
e=d['release_gate']['enforced_at']
assert len(e)>=2, e
assert all(x['refuses_without_native'] is True for x in e)
assert all(len(x['mechanism'])>=80 for x in e)\""
ck "...and every enforcement point names a file that EXISTS" \
   "python3 -c \"
import yaml,os;d=yaml.safe_load(open('$P'))
for x in d['release_gate']['enforced_at']:
    assert os.path.exists(x['component']), x['component']\""
ck "...and each of those components really invokes the gate, not just claims to" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$P'))
for x in d['release_gate']['enforced_at']:
    body=open(x['component']).read()
    assert ('assert-native-arch-evidence.sh' in body
            or 'require_native_arm64' in body), x['component']\""
ck "the policy still states where it is NOT enforced, rather than implying full coverage" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$P'))
n=d['release_gate']['not_enforced_at']
assert len(n)>=1 and all(isinstance(x,str) for x in n)\""

# --- the smoke workflow routes to the label and refuses emulation ----------
# THE ASSERTION THAT FAILS ON THE PREVIOUS STATE. The workflow used to target
# `[self-hosted, Linux, ARM64, zenchron]` — a label set no enrolled runner has
# carried, so the job could never start and the "gate" gated nothing. Whatever it
# targets must be a runner label that really resolves to arm64 hardware AND must
# match the runner the policy marks active.
ck "the native workflow targets the runner the policy marks ACTIVE" \
   "python3 -c \"
import yaml
p=yaml.safe_load(open('$P')); w=yaml.safe_load(open('$W'))
a=[r for r in p['accepted_runners'] if r['id']==p['active_runner']][0]
got=w['jobs']['native-smoke']['runs-on']
want=a.get('runs_on', a['labels'])
assert got==want, (got, want)\""
ck "...and that target is a real arm64 runner label, not an amd64 one" \
   "python3 -c \"
import yaml;w=yaml.safe_load(open('$W'))
got=w['jobs']['native-smoke']['runs-on']
got=[got] if isinstance(got,str) else list(got)
ARM64_HOSTED={'ubuntu-24.04-arm','ubuntu-22.04-arm','ubuntu-26.04-arm'}
assert (set(got) & ARM64_HOSTED) or ('ARM64' in got and 'self-hosted' in got), got\""
ck "the workflow reads the floor for ITS OWN runner kind from policy" \
   "grep -q 'runner-disk-floor.py' $W && grep -q 'RUNNER_KIND: ephemeral-hosted' $W"
ck "it refuses to start below that floor rather than dying on ENOSPC" \
   "grep -q 'is below the .* floor this' $W"
ck "it MEASURES and records what the smoke consumed" \
   "grep -q 'free_before_kb' $W && grep -q 'consumed_kb' $W"
ck "the disk-floor resolver self-tests clean" \
   "python3 scripts/release/runner-disk-floor.py --self-test >/dev/null 2>&1"
ck "it proves uname -m rather than trusting the label" \
   "grep -q 'uname -m' $W && grep -q 'aarch64|arm64' $W"
ck "it REFUSES on a non-aarch64 host instead of degrading" \
   "grep -q 'REFUSE: native arm64 smoke landed on a' $W"
ck "it is dispatch-only — it cannot be triggered by a push" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$W'))
on=d.get(True) or d.get('on')
assert set(on)=={'workflow_dispatch'}, on\""
ck "a non-master ref still needs an explicit opt-in, and is not authoritative" \
   "grep -q 'validation_run' $W && grep -q 'native smoke runs only on master' $W"
ck "evidence records its provenance instead of implying it" \
   "grep -q 'source_ref:' $W && grep -q 'authoritative:(' $W && grep -q 'runner_kind:' $W"
ck "its evidence is checked by the same gate, not by prose" \
   "grep -q 'assert-native-arch-evidence.sh native-evidence' $W && grep -q 'require-native linux/arm64' $W"
ck "the buildless mode checks evidence with the SAME release binding a release uses" \
   "grep -q -- '--gate-release' $W && grep -q -- '--expect-digests expect-digests.json' $W"
ck "it fails CLOSED if hosted arm64 availability changes, before queueing the arm64 job" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$W'))
g=d['jobs']['guard']
assert g['runs-on']=='ubuntu-latest', g['runs-on']
body=' '.join(s.get('run','') for s in g['steps'])
assert 'visibility' in body and 'ubuntu-24.04-arm' in body, body[:200]\""
ck "...and the availability refusal names what to do instead, not just that it failed" \
   "grep -q 'self-hosted-persistent-arm64' $W"

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

# --- NON-VACUITY: the new assertions must reject the state they replaced ----
# Each plants the PREVIOUS shape into a copy and requires a refusal. Nothing here
# touches the checkout.
S="$T/sab"; mkdir -p "$S"
python3 - "$P" "$S" <<'SAB'
import sys, yaml, os
src, out = sys.argv[1], sys.argv[2]
d = yaml.safe_load(open(src))
# 1. the old flat policy: one global 60 GB floor, no per-kind scoping
flat = dict(d); flat.pop("accepted_runners", None); flat.pop("active_runner", None)
flat["required_runner"] = {"labels": ["self-hosted", "Linux", "ARM64", "zenchron"],
                           "minimum_free_disk_gb": 60}
yaml.safe_dump(flat, open(os.path.join(out, "flat.yaml"), "w"))
# 2. per-kind scoping present but both floors the same number again
same = yaml.safe_load(open(src))
for r in same["accepted_runners"]:
    r["minimum_free_disk_gb"] = 60
yaml.safe_dump(same, open(os.path.join(out, "same.yaml"), "w"))
SAB
ck "SABOTAGE: the old flat single-floor policy is REJECTED by the scoping check" \
   "! python3 -c \"
import yaml;d=yaml.safe_load(open('$S/flat.yaml'))
assert 'required_runner' not in d\" 2>/dev/null"
ck "SABOTAGE: re-flattening both kinds to 60 GB is REJECTED" \
   "! python3 -c \"
import yaml;d=yaml.safe_load(open('$S/same.yaml'))
f={r['kind']:r['minimum_free_disk_gb'] for r in d['accepted_runners']}
assert f['ephemeral-hosted'] != f['persistent-self-hosted']\" 2>/dev/null"
ck "SABOTAGE: the resolver REFUSES the flat policy instead of reusing its 60" \
   "! POLICY='$S/flat.yaml' python3 scripts/release/runner-disk-floor.py ephemeral-hosted >/dev/null 2>&1"
# 3. an amd64 runs-on must fail the arm64-label check
ck "SABOTAGE: a runs-on of ubuntu-latest is NOT accepted as an arm64 target" \
   "! python3 -c \"
got=['ubuntu-latest']
ARM64_HOSTED={'ubuntu-24.04-arm','ubuntu-22.04-arm','ubuntu-26.04-arm'}
assert (set(got) & ARM64_HOSTED) or ('ARM64' in got and 'self-hosted' in got)\" 2>/dev/null"

echo "----"; [ "$fail" -eq 0 ] && echo "test_native_arch_contract: PASS" || echo "test_native_arch_contract: FAIL"
exit $fail
