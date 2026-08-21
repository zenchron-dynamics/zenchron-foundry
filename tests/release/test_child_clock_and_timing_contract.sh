#!/usr/bin/env bash
# =============================================================================
# tests/release/test_child_clock_and_timing_contract.sh
# -----------------------------------------------------------------------------
# D2. The stage job's FIRST step writes the child wall clock to $GITHUB_ENV:
#
#     echo "CHILD_STARTED_AT=$(date -u +%s)" >> "$GITHUB_ENV"
#
# The evidence step then rebound it as a STEP OUTPUT of a step that never emits
# one:
#
#     CHILD_STARTED_AT: ${{ steps.id.outputs.child_started_at }}
#
# A step-level `env:` SHADOWS the job environment, so the good value was replaced
# by the empty string. child_wall_seconds became 0 for all twenty children in run
# 32150666171, the phase totals then exceeded a zero wall time, the timer refused
# exactly as designed — and `2>/dev/null` at the call site threw the diagnostic
# away, leaving only `timing_available: false`.
#
# Two different mistakes with one signature: the writer moved, the reader did not.
# =============================================================================
# shellcheck disable=SC2034
# ^ Assertions run through ck(), which evals its second argument, so shellcheck
#   cannot see that $OUT/$O/$OUTT are referenced inside those quoted strings.
#   CI lints ./scripts, not tests/; this keeps the file clean if that ever widens.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
WF=.github/workflows/stage-and-authorize.yml
TIMER=scripts/ci/phase-timer.sh
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

# --- wiring: the clock is a JOB env var, set first, never rebound -----------
ck "no stale steps.id.outputs.child_started_at reference remains anywhere" \
   "! grep -q 'steps\.id\.outputs\.child_started_at' $WF"

ck "no step-level env: mapping rebinds CHILD_STARTED_AT" \
   "! grep -nE '^\s+CHILD_STARTED_AT:' $WF"

ck "the clock is written to \$GITHUB_ENV" \
   "grep -q 'CHILD_STARTED_AT=\$(date -u +%s)\" >> \"\\\$GITHUB_ENV\"' $WF"

# Order matters: the clock must start before ANY measured phase, or the wall
# time is shorter than the phases it is supposed to contain.
python3 - "$WF" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
steps = d['jobs']['stage']['steps']
def idx(pred):
    for i, s in enumerate(steps):
        if pred(s): return i
    return -1
clock = idx(lambda s: 'CHILD_STARTED_AT=' in (s.get('run') or ''))
first_phase = idx(lambda s: 'phase-timer.sh start' in (s.get('run') or ''))
db = idx(lambda s: 'phase-timer.sh start db_acquire' in (s.get('run') or ''))
assert clock >= 0, "no step starts the child wall clock"
assert db >= 0, "db_acquire phase not found"
print("ok   - the wall clock starts at step %d, db_acquire at step %d" % (clock, db))
assert clock < db, "clock (%d) must precede db_acquire (%d)" % (clock, db)
print("ok   - CHILD_STARTED_AT is initialized BEFORE db_acquire")
assert clock < first_phase, "clock must precede the first measured phase"
print("ok   - ...and before every measured phase (first at step %d)" % first_phase)
# Exactly one clock: a second one would silently redefine the baseline.
clocks = [i for i, s in enumerate(steps) if 'CHILD_STARTED_AT=' in (s.get('run') or '')]
assert len(clocks) == 1, "expected exactly one clock start, found %r" % clocks
print("ok   - exactly one child clock exists (no second, later baseline)")
PY
[ $? -eq 0 ] || fail=1

# --- the call site must not swallow the timer's diagnostic ------------------
ck "the phase-timer call site does not redirect stderr to /dev/null" \
   "! grep -nE 'phase-timer\.sh emit.*2>/dev/null' $WF"
ck "the timer's stderr is captured and surfaced instead" \
   "grep -q 'phase-timer.sh emit .* 2>\"\\\$timer_err\"' $WF"
ck "an unavailable timing emits a visible ::warning:: carrying the diagnostic" \
   "grep -q '::warning::phase timing unavailable' $WF"
ck "an empty clock at the evidence step emits a visible ::error::" \
   "grep -q '::error::CHILD_STARTED_AT is empty' $WF"

# --- timer behaviour, on deterministic fixtures (no sleeps) -----------------
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

emit() { PHASE_LOG="$1" bash "$TIMER" emit "$2" 2>"$T/err"; }

# A realistic child: phases inside a longer wall time.
printf 'db_acquire\tstart\t1000\ndb_acquire\tend\t1030\nbuild_and_push\tstart\t1030\nbuild_and_push\tend\t1200\n' > "$T/good.tsv"
OUT="$(emit "$T/good.tsv" 300)"; rc=$?
ck "a realistic phase log emits successfully" "[ $rc -eq 0 ]"
ck "...total phase seconds are computed (30 + 170 = 200)" \
   "[ \"\$(jq -r '[.phases[]]|add' <<<\"\$OUT\")\" -eq 200 ]"
ck "...uninstrumented overhead is nonnegative (300 - 200 = 100)" \
   "[ \"\$(jq -r .uninstrumented_overhead_seconds <<<\"\$OUT\")\" -eq 100 ]"
ck "...queue time is null, never fabricated as zero" \
   "[ \"\$(jq -r .queue_seconds <<<\"\$OUT\")\" = null ]"

# The exact D2 shape: a zero wall clock with real phases must REFUSE.
OUT0="$(emit "$T/good.tsv" 0)"; rc0=$?
ck "phase totals exceeding wall time REFUSE (the run-32150666171 shape)" "[ $rc0 -ne 0 ]"
ck "...and the refusal diagnostic is non-empty and reaches stderr" "[ -s '$T/err' ]"
ck "...naming the invariant it enforces" \
   "grep -qiE 'exceed|wall' '$T/err'"

# A phase left open is REPORTED as incomplete, not refused and not silently
# dropped — that is the timer's documented contract, and it is deliberate: a
# child that died mid-phase should still surrender the phases it did finish.
# The refusal cases are the one-directional invariant, an end before its start,
# and a missing log; all three are asserted here.
printf 'build\tstart\t1000\nbuild\tend\t1060\nscan\tstart\t1060\n' > "$T/trunc.tsv"
OUTT="$(emit "$T/trunc.tsv" 300)"; rct=$?
ck "an unclosed phase is reported, not refused" "[ $rct -eq 0 ]"
ck "...marked timing_complete=false" \
   "[ \"\$(jq -r .timing_complete <<<\"\$OUTT\")\" = false ]"
ck "...and named in incomplete_phases rather than dropped" \
   "[ \"\$(jq -r '.incomplete_phases[0]' <<<\"\$OUTT\")\" = scan ]"

# An end BEFORE its start is a broken clock and must refuse.
printf 'build\tstart\t1100\nbuild\tend\t1000\n' > "$T/rev.tsv"
emit "$T/rev.tsv" 300 >/dev/null; rcr=$?
ck "a phase ending before it started REFUSES" "[ $rcr -ne 0 ]"
ck "...naming that invariant" "grep -qi 'ended before it started' '$T/err'"

# A missing log refuses loudly rather than reporting zero-duration work.
emit "$T/does-not-exist.tsv" 300 >/dev/null; rcm=$?
ck "a MISSING phase log refuses rather than reporting zero work" "[ $rcm -ne 0 ]"

# --- producer fixture: a real child record carries a positive wall time -----
# Deterministic: the clock is injected, not slept for.
python3 - "$WF" "$T" <<'PY'
import sys, yaml, re
wf, t = sys.argv[1], sys.argv[2]
d = yaml.safe_load(open(wf))
step = [s for s in d['jobs']['stage']['steps'] if s.get('name') == 'Emit child evidence']
assert len(step) == 1
body = step[0]['run']
# The evidence step must compute the difference from CHILD_STARTED_AT itself.
assert 'CHILD_STARTED_AT' in body, "the emit step no longer reads the clock"
assert re.search(r'child_seconds=\$\(\(\s*\$\(date -u \+%s\)\s*-\s*CHILD_STARTED_AT\s*\)\)', body), \
    "the emit step does not derive child_seconds from CHILD_STARTED_AT"
print("ok   - the evidence step derives child_wall_seconds from the job-env clock")
open(t + '/emit.sh', 'w').write(body)
PY
[ $? -eq 0 ] || fail=1

# Run the real emit body with an injected clock 42 seconds in the past.
W="$T/w"; mkdir -p "$W/evidence/child"
printf 'smoke\n' > "$W/evidence/child/smoke.log"
printf '{"a":1}\n' > "$W/evidence/child/oci-labels.json"
printf 'db_acquire\tstart\t1000\ndb_acquire\tend\t1010\n' > "$W/phases.tsv"
DIG="sha256:$(printf 'b%.0s' {1..64})"
( cd "$W" || exit 1
  ln -sfn "$ROOT/scripts" scripts
  PHASE_LOG="$W/phases.tsv" \
  CHILD_STARTED_AT="$(( $(date -u +%s) - 42 ))" \
  LABEL="php-fpm/8.3" PLATFORM="linux/amd64" TAG="php-fpm-8.3-r7-a1-sabc1234-amd64" \
  DIGEST_REF="ghcr.io/zenchron-dynamics/foundry-staging@${DIG}" \
  DIGEST="$DIG" RESOLVED="$DIG" MTYPE="application/vnd.oci.image.manifest.v1+json" \
  VIS="private" CARCH="amd64" DB="db@2026-08-06" \
  SMOKE="PASS" SCAN="PASS" RECON="PASS" META="PASS" \
  EXEC_MODE="native" HOST_ARCH="amd64" RUNNER_NAME_OBSERVED="test-runner" \
  CHILD_SLUG="php-fpm-8.3-linux-amd64" CHILD_KEY="php-fpm/8.3/linux/amd64" \
  GITHUB_SHA="$(printf 'a%.0s' {1..40})" \
  GITHUB_REPOSITORY="zenchron-dynamics/zenchron-foundry" \
  GITHUB_RUN_ID=7 GITHUB_RUN_ATTEMPT=1 \
  bash -e "$T/emit.sh" > "$W/emit.log" 2>&1 )
J="$W/evidence/out/php-fpm-8.3-linux-amd64.json"
ck "the producer emits a child record with an injected clock" "test -s '$J'"
ck "child_wall_seconds is POSITIVE, not zero (the D2 regression)" \
   "[ \"\$(jq -r .child_wall_seconds '$J')\" -ge 42 ]"
ck "...and phase timing is available for a consistent log" \
   "[ \"\$(jq -r .phase_timing.timing_available '$J')\" = true ]"

# Now the D2 failure mode itself: no clock at all.
W2="$T/w2"; mkdir -p "$W2/evidence/child"
printf 'smoke\n' > "$W2/evidence/child/smoke.log"
printf '{"a":1}\n' > "$W2/evidence/child/oci-labels.json"
printf 'db_acquire\tstart\t1000\ndb_acquire\tend\t1010\n' > "$W2/phases.tsv"
( cd "$W2" || exit 1
  ln -sfn "$ROOT/scripts" scripts
  PHASE_LOG="$W2/phases.tsv" CHILD_STARTED_AT="" \
  LABEL="php-fpm/8.3" PLATFORM="linux/amd64" TAG="t-amd64" \
  DIGEST_REF="ghcr.io/zenchron-dynamics/foundry-staging@${DIG}" \
  DIGEST="$DIG" RESOLVED="$DIG" MTYPE="application/vnd.oci.image.manifest.v1+json" \
  VIS="private" CARCH="amd64" DB="db@2026-08-06" \
  SMOKE="PASS" SCAN="PASS" RECON="PASS" META="PASS" \
  EXEC_MODE="native" HOST_ARCH="amd64" RUNNER_NAME_OBSERVED="test-runner" \
  CHILD_SLUG="php-fpm-8.3-linux-amd64" CHILD_KEY="php-fpm/8.3/linux/amd64" \
  GITHUB_SHA="$(printf 'a%.0s' {1..40})" \
  GITHUB_REPOSITORY="zenchron-dynamics/zenchron-foundry" \
  GITHUB_RUN_ID=7 GITHUB_RUN_ATTEMPT=1 \
  bash -e "$T/emit.sh" > "$W2/emit.log" 2>&1 )
J2="$W2/evidence/out/php-fpm-8.3-linux-amd64.json"
ck "an empty clock still produces a record (timing is non-fatal)" "test -s '$J2'"
ck "...with timing marked UNAVAILABLE, not fabricated" \
   "[ \"\$(jq -r .phase_timing.timing_available '$J2')\" = false ]"
ck "...and the missing-clock error IS visible in the job log" \
   "grep -q '::error::CHILD_STARTED_AT is empty' '$W2/emit.log'"
ck "...and the timer's own refusal diagnostic reaches the log too" \
   "grep -qiE 'exceed|wall|REFUSE' '$W2/emit.log'"

# =============================================================================
# evidence_emit: the unreachable-end phase (fixed 2026-08-21)
# -----------------------------------------------------------------------------
# `phase start evidence_emit` ran before the emit step and `phase end
# evidence_emit` ran after it — but the emit step is what SERIALIZES phases.json,
# so at serialization time the phase always had a start and no end. All twenty
# children in run 32395890071 reported timing_complete:false: a metric that could
# not succeed. The end existed; it was simply always too late.
#
# Closing it early was rejected — that closes a phase before its work happens.
# The instrumentation is removed and its cost lands in
# uninstrumented_overhead_seconds.
# =============================================================================
ck "evidence_emit is no longer an instrumented phase" \
   "! grep -qE 'phase-timer\.sh (start|end) evidence_emit' $WF"
ck "...and the reason is recorded beside the emit step" \
   "grep -q 'evidence_emit is deliberately NOT an instrumented phase' $WF"

# EVERY instrumented phase must have a start AND an end that happens BEFORE the
# record is serialized. This is the general form of the defect, not a spot fix.
python3 - "$WF" <<'PY2'
import re, sys
s = open(sys.argv[1]).read()
emit_at = s.index('phase-timer.sh emit')
starts = {m.group(1): m.start() for m in re.finditer(r'phase-timer\.sh start (\w+)', s)}
ends   = {m.group(1): m.start() for m in re.finditer(r'phase-timer\.sh end (\w+)', s)}
assert starts, "no instrumented phases found — the search is vacuous"
bad = [n for n, p in starts.items() if n not in ends or ends[n] > emit_at]
assert not bad, "phases whose end is unreachable before serialization: %r" % bad
print("ok   - all %d instrumented phases close before the record is serialized" % len(starts))
orphan = [n for n in ends if n not in starts]
assert not orphan, "phase ends with no start: %r" % orphan
print("ok   - no phase end exists without a matching start")
PY2
[ $? -eq 0 ] || fail=1

# --- timing_complete must now be ACHIEVABLE (it never was before) ----------
printf 'db_acquire\tstart\t1000\ndb_acquire\tend\t1030\nsmoke\tstart\t1030\nsmoke\tend\t1040\n' > "$T/complete.tsv"
OUTC="$(emit "$T/complete.tsv" 300)"; rcc=$?
ck "a fully-closed phase log emits successfully" "[ $rcc -eq 0 ]"
ck "...and reports timing_complete=TRUE (impossible before this fix)" \
   "[ \"\$(jq -r .timing_complete <<<\"\$OUTC\")\" = true ]"
ck "...with no incomplete phases" \
   "[ \"\$(jq -r '.incomplete_phases|length' <<<\"\$OUTC\")\" -eq 0 ]"
ck "...and overhead stays nonnegative and explicit (300 - 40 = 260)" \
   "[ \"\$(jq -r .uninstrumented_overhead_seconds <<<\"\$OUTC\")\" -eq 260 ]"

# --- SABOTAGE: reintroduce the recursive phase ------------------------------
SABWF="$T/sabotaged-workflow.yml"
sed 's|      # evidence_emit is deliberately NOT an instrumented phase.|      - name: phase start evidence_emit\n        run: bash scripts/ci/phase-timer.sh start evidence_emit\n      # evidence_emit is deliberately NOT an instrumented phase.|' \
    "$WF" > "$SABWF"
ck "SABOTAGE fixture really reintroduced the start" \
   "grep -q 'phase-timer.sh start evidence_emit' '$SABWF'"
python3 - "$SABWF" > "$T/sab.out" 2>&1 <<'PY2'
import re, sys
s = open(sys.argv[1]).read()
emit_at = s.index('phase-timer.sh emit')
starts = {m.group(1): m.start() for m in re.finditer(r'phase-timer\.sh start (\w+)', s)}
ends   = {m.group(1): m.start() for m in re.finditer(r'phase-timer\.sh end (\w+)', s)}
bad = [n for n, p in starts.items() if n not in ends or ends[n] > emit_at]
assert not bad, "unreachable-end phases: %r" % bad
PY2
ck "SABOTAGE: the audit REJECTS a reintroduced evidence_emit phase" \
   "grep -q 'unreachable-end phases' '$T/sab.out'"
ck "...naming evidence_emit specifically, not a generic failure" \
   "grep -q 'evidence_emit' '$T/sab.out'"

# --- historical compatibility ----------------------------------------------
# Records from run 32395890071 carry timing_complete:false and incomplete_phases:
# ["evidence_emit"]. They must still validate against the schema.
ck "historical records with incomplete_phases remain schema-compatible" \
   "python3 -c \"
import json,glob,jsonschema
s=json.load(open('schemas/post-build-authorization-v1.schema.json'))
c=s['\\\$defs']['child']; c['\\\$schema']='https://json-schema.org/draft/2020-12/schema'
fs=glob.glob('docs/audits/acceptance-multiarch-2026-08-20/acceptance-evidence.json')
assert fs, 'no historical record found — check is vacuous'
d=json.load(open(fs[0]))
n=sum(1 for ch in d['children'] if ch['phase_timing'].get('timing_complete') is False)
assert n==20, n
print('  (20 historical records carry timing_complete:false and remain readable)')
\""

echo "----"; [ "$fail" -eq 0 ] && echo "test_child_clock_and_timing_contract: PASS" || echo "test_child_clock_and_timing_contract: FAIL"
exit $fail
