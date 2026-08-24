#!/usr/bin/env bash
# shellcheck disable=SC2034  # assertion vars are consumed inside ck() eval strings
# =============================================================================
# tests/governance/test_workflow_input_wiring.sh
# -----------------------------------------------------------------------------
# A workflow input that is DECLARED and NEVER READ is a false interface. It
# appears in the "Run workflow" form, an operator fills it in, and it does
# nothing.
#
# THE INSTANCE THIS EXISTS FOR. native-arm64-smoke.yml declared an `images`
# input and never referenced it. The job proved `uname -m`, wrote an evidence
# record and smoked NO IMAGE — while the workflow described itself as "the
# executable half of #111". An operator selecting images would have got a green
# run that tested none of them, and an architecture assertion is not runtime
# evidence in any case.
#
# THE RULE. Every workflow_dispatch / workflow_call input must either
#
#   (a) be REFERENCED — `inputs.<name>` or `github.event.inputs.<name>` — or
#   (b) belong to a DISABLED entry point: an input whose description begins
#       "(disabled)" in a workflow whose jobs exist only to refuse.
#
# (b) is not a loophole and not an allowlist. promote-stable.yml, publish-rc.yml
# and release.yml keep their inputs on purpose so that an operator who
# dispatches them gets a loud, specific refusal instead of a missing-input
# error. The exemption is derived from what the workflow DOES — it must actually
# refuse — so it cannot be claimed by a workflow that merely says so.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

TMP="$(mktemp -d)"
# Expand NOW: a single-quoted EXIT trap defers expansion past this scope.
# shellcheck disable=SC2064
trap "rm -rf '$TMP'" EXIT

if ! python3 -c 'import yaml' 2>/dev/null; then
  echo "SKIP - pyyaml absent"; echo "test_workflow_input_wiring: PASS"; exit 0
fi

# The scanner is a file so the sabotage below can run the SAME code over a
# planted workflow. A second copy of the rule would let proof and rule diverge.
cat > "$TMP/scan.py" <<'PY'
import sys, glob, os, yaml

def scan(paths):
    findings = []
    for f in sorted(paths):
        raw = open(f, encoding="utf-8", errors="replace").read()
        try:
            doc = yaml.safe_load(raw) or {}
        except yaml.YAMLError as exc:
            findings.append((f, "<unparseable>", "YAML error: %s" % exc))
            continue
        # PyYAML resolves the bare key `on:` to boolean True.
        on = doc.get("on", doc.get(True)) or {}
        if not isinstance(on, dict):
            continue
        # A workflow whose every job only refuses may keep declared-dead inputs.
        jobs = doc.get("jobs") or {}
        steps = [s for j in jobs.values() if isinstance(j, dict)
                 for s in (j.get("steps") or []) if isinstance(s, dict)]
        runs = "\n".join(str(s.get("run") or "") for s in steps)
        refuses = bool(jobs) and "REFUSE" in runs and "exit 1" in runs
        for ev in ("workflow_dispatch", "workflow_call"):
            blk = on.get(ev) or {}
            if not isinstance(blk, dict):
                continue
            for name, spec in (blk.get("inputs") or {}).items():
                refs = ["inputs.%s" % name,
                        "inputs['%s']" % name, 'inputs["%s"]' % name]
                if any(r in raw for r in refs):
                    continue
                desc = str((spec or {}).get("description") or "")
                if desc.lstrip().startswith("(disabled)") and refuses:
                    continue
                findings.append((f, name, "declared in %s and never referenced" % ev))
    return findings

if __name__ == "__main__":
    hits = scan(sys.argv[1:] or glob.glob(".github/workflows/*.yml"))
    for f, n, why in hits:
        print("%s: input '%s' %s" % (f, n, why))
    sys.exit(1 if hits else 0)
PY

# --- the repository is clean -------------------------------------------------
out="$(python3 "$TMP/scan.py" .github/workflows/*.yml 2>&1)"; rc=$?
ck "no workflow declares an input it never references" \
   "[ '$rc' -eq 0 ] || { printf '%s\n' \"\$out\"; false; }"

# --- NON-VACUITY: the scanner must be able to find one ----------------------
mkdir -p "$TMP/wf"
cat > "$TMP/wf/planted.yml" <<'PLANT'
name: planted
on:
  workflow_dispatch:
    inputs:
      never_read:
        description: "an input nothing consumes"
        required: false
jobs:
  work:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
PLANT
ck "NON-VACUOUS: the scanner catches a planted unreferenced input" \
   "! python3 '$TMP/scan.py' '$TMP/wf/planted.yml' >/dev/null 2>&1"
# Captured, not piped: the scanner exits 1 by design and `set -o pipefail`
# makes a pipeline inherit that, so `scanner | grep -q` fails even when grep
# matches. That cost a debugging cycle here and is worth naming.
python3 "$TMP/scan.py" "$TMP/wf/planted.yml" > "$TMP/planted.out" 2>&1 || true
ck "...and names the input, not just the file" \
   "grep -q never_read '$TMP/planted.out'"

# A referenced input must NOT be reported — a scanner that flags everything
# would satisfy the assertion above while being useless.
sed 's|      - run: echo hello|      - run: echo "${{ inputs.never_read }}"|' \
    "$TMP/wf/planted.yml" > "$TMP/wf/wired.yml"
ck "...and a WIRED input is not reported" \
   "python3 '$TMP/scan.py' '$TMP/wf/wired.yml' >/dev/null 2>&1"

# --- the disabled-entry-point exemption is EARNED, not claimed --------------
cat > "$TMP/wf/fake-disabled.yml" <<'FAKE'
name: fake-disabled
on:
  workflow_dispatch:
    inputs:
      version:
        description: "(disabled) looks exempt but the job does real work"
        required: false
jobs:
  work:
    runs-on: ubuntu-latest
    steps:
      - run: echo "this job does not refuse"
FAKE
ck "SABOTAGE: '(disabled)' does NOT exempt a workflow that fails to refuse" \
   "! python3 '$TMP/scan.py' '$TMP/wf/fake-disabled.yml' >/dev/null 2>&1"

# --- the specific instance, asserted by name --------------------------------
NAS=.github/workflows/native-arm64-smoke.yml
ck "native-arm64-smoke reads the families input it declares" \
   "grep -q 'inputs.families' '$NAS'"
ck "...and actually runs the runtime smoke, not just an arch assertion" \
   "grep -q 'scripts/smoke-all.sh' '$NAS' && grep -q 'SMOKE_FAMILIES' '$NAS'"
ck "...and an unknown family REFUSES instead of smoking nothing" \
   "grep -q 'is not an image family' '$NAS'"
ck "...and it no longer claims to be the executable half of #111" \
   "! grep -q 'executable half of #111' '$NAS'"
ck "...while still refusing to run emulated" \
   "grep -q 'must' '$NAS' && grep -q 'never run emulated' '$NAS'"

echo "----"
[ "$fail" -eq 0 ] && echo "test_workflow_input_wiring: PASS" || echo "test_workflow_input_wiring: FAIL"
exit $fail
