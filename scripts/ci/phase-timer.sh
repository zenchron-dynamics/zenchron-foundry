#!/usr/bin/env bash
# =============================================================================
# scripts/ci/phase-timer.sh — per-phase wall time for one acceptance child.
# -----------------------------------------------------------------------------
# WHY. `child_wall_seconds` says an emulated child costs ~53 minutes against ~5
# native. It does not say WHERE those minutes go. Emulation could dominate in
# foreign-architecture build execution, in runtime smoke, in scanning, in
# transfer, or in several at once — and the optimisation ranking is guesswork
# until that is measured. This makes the next acceptance run answer it.
#
# HONESTY RULES BUILT IN:
#
#   * Queue and runner-acquisition time is NOT measured. An in-job clock starts
#     after the job is already running, so it cannot see waiting. It is emitted
#     as `unavailable`, never as zero.
#   * Phases are NOT required to sum to wall time. Steps have gaps (action
#     setup, uses: steps, runner bookkeeping). The remainder is emitted
#     explicitly as `uninstrumented_overhead_seconds`, never silently absorbed.
#   * The invariant is one-directional: total wall >= sum of measured phases.
#     A sum EXCEEDING wall time means phases overlapped or a timer is wrong, and
#     is a hard error rather than a negative overhead.
#
# Usage:
#   PHASE_LOG=/path/to/log phase-timer.sh start <phase>
#   PHASE_LOG=/path/to/log phase-timer.sh end   <phase>
#   PHASE_LOG=/path/to/log phase-timer.sh emit  <child_wall_seconds>
#   phase-timer.sh --self-test
# =============================================================================
set -uo pipefail

_log() { printf '%s' "${PHASE_LOG:-}"; }

start_phase() {
  local p="${1:?phase name required}" f; f="$(_log)"
  [ -n "$f" ] || { echo "REFUSE: PHASE_LOG is not set" >&2; return 1; }
  printf '%s\tstart\t%s\n' "$p" "$(date -u +%s)" >> "$f"
}

end_phase() {
  local p="${1:?phase name required}" f; f="$(_log)"
  [ -n "$f" ] || { echo "REFUSE: PHASE_LOG is not set" >&2; return 1; }
  printf '%s\tend\t%s\n' "$p" "$(date -u +%s)" >> "$f"
}

emit() {
  local wall="${1:?child wall seconds required}" f; f="$(_log)"
  [ -n "$f" ] || { echo "REFUSE: PHASE_LOG is not set" >&2; return 1; }
  [ -s "$f" ] || { echo "REFUSE: no phase records at $f" >&2; return 1; }
  PHASE_LOG="$f" WALL="$wall" python3 <<'PY'
import os, sys, json, collections
log, wall = os.environ["PHASE_LOG"], int(os.environ["WALL"])
starts, ends = {}, {}
order = []
for line in open(log):
    parts = line.rstrip("\n").split("\t")
    if len(parts) != 3:
        continue
    name, kind, ts = parts[0], parts[1], int(parts[2])
    if kind == "start":
        if name not in order:
            order.append(name)
        starts[name] = ts
    elif kind == "end":
        ends[name] = ts

phases, incomplete = {}, []
for name in order:
    if name not in ends:
        incomplete.append(name)
        continue
    d = ends[name] - starts[name]
    if d < 0:
        print("REFUSE: phase %r ended before it started" % name, file=sys.stderr)
        sys.exit(1)
    phases[name] = d

total = sum(phases.values())
# One-directional invariant. A sum over wall time means overlap or a broken
# timer; it must not be papered over with a negative overhead.
if total > wall:
    print("REFUSE: measured phases (%ds) exceed child wall time (%ds)" % (total, wall),
          file=sys.stderr)
    sys.exit(1)

slowest = max(phases, key=phases.get) if phases else None
json.dump({
    "phases": phases,
    "measured_phase_seconds": total,
    "child_wall_seconds": wall,
    "uninstrumented_overhead_seconds": wall - total,
    "slowest_phase": slowest,
    "slowest_phase_seconds": phases.get(slowest, 0) if slowest else 0,
    "incomplete_phases": incomplete,
    "timing_complete": not incomplete,
    # An in-job clock cannot observe time spent before the job started.
    "queue_seconds": None,
    "queue_seconds_note": "unavailable: not observable from inside the job",
}, sys.stdout, indent=2, sort_keys=True)
PY
}

# shellcheck disable=SC2034  # `out` is consumed inside the eval'd ck assertions
self_test() {
  local pass=0 fail=0 t
  ck() { if eval "$2"; then pass=$((pass+1)); echo "ok   - $1"; else fail=$((fail+1)); echo "FAIL - $1"; fi; }
  t="$(mktemp -d)"; export PHASE_LOG="$t/p.tsv"

  printf 'build\tstart\t1000\nbuild\tend\t1060\nscan\tstart\t1060\nscan\tend\t1075\n' > "$PHASE_LOG"
  local out
  out="$(emit 100)"
  ck "phases are computed from start/end pairs" \
     '[ "$(jq -r .phases.build <<<"$out")" = 60 ] && [ "$(jq -r .phases.scan <<<"$out")" = 15 ]'
  ck "the measured sum is reported"        '[ "$(jq -r .measured_phase_seconds <<<"$out")" = 75 ]'
  ck "overhead is the explicit remainder"  '[ "$(jq -r .uninstrumented_overhead_seconds <<<"$out")" = 25 ]'
  ck "the slowest phase is identified"     '[ "$(jq -r .slowest_phase <<<"$out")" = build ]'
  ck "queue time is unavailable, NOT zero" \
     '[ "$(jq -r .queue_seconds <<<"$out")" = null ] && jq -e ".queue_seconds_note" <<<"$out" >/dev/null'
  ck "complete timing is flagged complete" '[ "$(jq -r .timing_complete <<<"$out")" = true ]'

  # a phase left open is reported, not silently dropped
  printf 'build\tstart\t1000\nbuild\tend\t1060\nscan\tstart\t1060\n' > "$PHASE_LOG"
  out="$(emit 100)"
  ck "an unfinished phase marks timing INCOMPLETE" \
     '[ "$(jq -r .timing_complete <<<"$out")" = false ] &&
      [ "$(jq -r ".incomplete_phases[0]" <<<"$out")" = scan ]'

  # the one-directional invariant
  printf 'a\tstart\t1000\na\tend\t1100\nb\tstart\t1000\nb\tend\t1100\n' > "$PHASE_LOG"
  ck "a phase sum EXCEEDING wall time is REFUSED (overlap or broken timer)" \
     '! emit 100 >/dev/null 2>&1'
  # Captured first: `emit | grep` under pipefail reports emit's status, and emit
  # fails here ON PURPOSE. Documented in AGENTS.md; this is the fifth time.
  ck "...and says so" 'msg="$(emit 100 2>&1 || true)"; grep -q "exceed child wall time" <<<"$msg"'

  printf 'a\tstart\t1100\na\tend\t1000\n' > "$PHASE_LOG"
  ck "an end before its start is REFUSED" '! emit 500 >/dev/null 2>&1'
  ck "...and names the phase"  'msg="$(emit 500 2>&1 || true)"; grep -q "ended before it started" <<<"$msg"'

  : > "$PHASE_LOG"
  ck "an empty phase log is REFUSED, not reported as zero work" '! emit 10 >/dev/null 2>&1'
  unset PHASE_LOG
  ck "a missing PHASE_LOG is REFUSED" '! start_phase build >/dev/null 2>&1'

  rm -rf "$t"
  echo "----"; printf 'self-test: %d ok, %d failed\n' "$pass" "$fail"
  [ "$fail" -eq 0 ]
}

case "${1:-}" in
  start)       shift; start_phase "${1-}" ;;
  end)         shift; end_phase "${1-}" ;;
  emit)        shift; emit "${1-}" ;;
  --self-test) self_test ;;
  *) echo "usage: $(basename "$0") start|end <phase> | emit <wall> | --self-test" >&2; exit 64 ;;
esac
