#!/usr/bin/env bash
# =============================================================================
# Phase-level cost telemetry, proven without running a builder.
#
# `child_wall_seconds` says an emulated child costs ~53 minutes against ~5
# native. It does not say WHERE. Until that is known, every optimisation
# ranking is argued rather than measured — which is why the previous
# "~9 hours saved by child reuse" claim was arithmetic on a total, not a
# measurement of a mechanism.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

W=.github/workflows/stage-and-authorize.yml
T=scripts/ci/phase-timer.sh
HIST=docs/audits/acceptance-amd64-2026-08-14/post-build-authorization.json

ck "the phase timer self-tests clean" "bash $T --self-test >/dev/null 2>&1"

# --- every required phase is instrumented ----------------------------------
for ph in db_acquire build_and_push digest_resolve pull_by_digest smoke \
          metadata_contract vulnerability_scan package_inventory \
          reconciliation evidence_emit; do
  ck "phase '$ph' is instrumented" \
     "grep -q 'phase-timer.sh start $ph' $W && grep -q 'phase-timer.sh end $ph' $W"
done

ck "every started phase is also ended" \
   'python3 -c "
import re
s=open(\"'"$W"'\").read()
st=set(re.findall(r\"phase-timer\.sh start (\w+)\", s))
en=set(re.findall(r\"phase-timer\.sh end (\w+)\", s))
assert st==en, (sorted(st-en), sorted(en-st))"'

# --- timing reaches child evidence, and is COVERED BY THE CHECKSUM ----------
ck "timing is written into the child evidence directory" \
   "grep -q 'evidence/child/phases.json' $W"
ck "timing reaches the child record" "grep -q 'phase_timing:\$tm' $W"
# The ordering matters: phases.json must exist BEFORE the directory is hashed,
# or the cost claim sits outside the binding that is supposed to cover it.
ck "phases.json is written BEFORE the evidence checksum is computed" \
   'python3 -c "
s=open(\"'"$W"'\").read()
a=s.index(\"phase-timer.sh emit\")
b=s.index(\"evidence-checksum.sh evidence/child\")
c=s.index(\"jq -n --arg l\")
assert a < b < c, (a,b,c)"'

# --- the summary consumes CHILD EVIDENCE, not API timestamps ---------------
ck "the run summary derives phases from the authorization record" \
   'grep -q "phase_timing.timing_available" '"$W"
ck "the summary does not scrape API timestamps for cost" \
   '! grep -qE "gh (api|run view).*(started_at|completed_at)" '"$W"

# --- native and emulated stay separated ------------------------------------
ck "the summary splits native from emulated children" \
   'grep -q "execution_mode==\"native\"" '"$W"' && grep -q "execution_mode==\"qemu\"" '"$W"

# --- honesty about what cannot be measured ---------------------------------
ck "queue time is reported as unavailable, never as zero" \
   'out="$(PHASE_LOG=$(mktemp) bash -c "
        printf \"a\tstart\t100\na\tend\t150\n\" > \$PHASE_LOG
        PHASE_LOG=\$PHASE_LOG bash '"$T"' emit 200")";
    [ "$(jq -r .queue_seconds <<<"$out")" = null ] &&
    jq -e ".queue_seconds_note" <<<"$out" >/dev/null'
ck "uninstrumented overhead is named, not absorbed" \
   'out="$(PHASE_LOG=$(mktemp) bash -c "
        printf \"a\tstart\t100\na\tend\t150\n\" > \$PHASE_LOG
        PHASE_LOG=\$PHASE_LOG bash '"$T"' emit 200")";
    [ "$(jq -r .uninstrumented_overhead_seconds <<<"$out")" = 150 ]'
ck "the slowest phase is identified correctly" \
   'out="$(PHASE_LOG=$(mktemp) bash -c "
        printf \"fast\tstart\t0\nfast\tend\t5\nslow\tstart\t5\nslow\tend\t95\n\" > \$PHASE_LOG
        PHASE_LOG=\$PHASE_LOG bash '"$T"' emit 200")";
    [ "$(jq -r .slowest_phase <<<"$out")" = slow ] &&
    [ "$(jq -r .slowest_phase_seconds <<<"$out")" = 90 ]'

# --- schema: new records constrained, historical records unharmed ----------
ck "the schema accepts phase_timing" \
   'python3 -c "
import json
d=json.load(open(\"schemas/post-build-authorization-v1.schema.json\"))
p=d[\"\$defs\"][\"child\"][\"properties\"][\"phase_timing\"]
assert p[\"required\"]==[\"timing_available\"]
assert p[\"properties\"][\"queue_seconds\"][\"type\"]==\"null\"
assert p[\"properties\"][\"uninstrumented_overhead_seconds\"][\"minimum\"]==0"'
ck "phase_timing is NOT required, so historical records stay valid" \
   'python3 -c "
import json
d=json.load(open(\"schemas/post-build-authorization-v1.schema.json\"))
assert \"phase_timing\" not in (d[\"\$defs\"][\"child\"].get(\"required\") or [])"'
ck "the committed 2026-08-14 record still validates" \
   "bash scripts/release/validate-authorization-record.sh $HIST >/dev/null 2>&1"
ck "a record with no timing reports 'no timing', not zero-duration work" \
   'out="$(jq -r "[.children[]|select(.phase_timing.timing_available==true)]|length" '"$HIST"')";
    [ "$out" = 0 ]'

# --- refusals ---------------------------------------------------------------
emit_with() { local f; f="$(mktemp)"; printf '%b' "$1" > "$f"; PHASE_LOG="$f" bash "$T" emit "$2" 2>&1 || true; }
ck "a negative phase duration is REFUSED" \
   '! PHASE_LOG=$(mktemp) bash -c "printf \"a\tstart\t200\na\tend\t100\n\" > \$PHASE_LOG; PHASE_LOG=\$PHASE_LOG bash '"$T"' emit 500" >/dev/null 2>&1'
ck "...for the intended reason" \
   'grep -q "ended before it started" <<<"$(emit_with "a\tstart\t200\na\tend\t100\n" 500)"'
ck "a phase sum EXCEEDING wall time is REFUSED (manipulated totals)" \
   '! PHASE_LOG=$(mktemp) bash -c "printf \"a\tstart\t0\na\tend\t900\n\" > \$PHASE_LOG; PHASE_LOG=\$PHASE_LOG bash '"$T"' emit 10" >/dev/null 2>&1'
ck "...for the intended reason" \
   'grep -q "exceed child wall time" <<<"$(emit_with "a\tstart\t0\na\tend\t900\n" 10)"'
ck "an incomplete child is flagged incomplete, not complete" \
   'out="$(emit_with "a\tstart\t0\na\tend\t5\nb\tstart\t5\n" 100)";
    [ "$(jq -r .timing_complete <<<"$out")" = false ]'
ck "an empty phase log is REFUSED rather than reported as no work" \
   '! PHASE_LOG=$(mktemp) bash '"$T"' emit 10 >/dev/null 2>&1'

# --- sabotage ---------------------------------------------------------------
sab() { # sab <sed-expr> <grep-pattern-that-must-then-be-absent>
  local tmp; tmp="$(mktemp -d)"; local rc=1
  sed "$1" "$W" > "$tmp/w.yml"
  grep -q "$2" "$tmp/w.yml" || rc=0     # 0 == sabotage detectable
  rm -rf "$tmp"; return $rc
}
ck "SABOTAGE: removing one timer is detectable" \
   'sab "/phase-timer.sh start vulnerability_scan/d" "phase-timer.sh start vulnerability_scan"'
ck "SABOTAGE: disconnecting timing from evidence is detectable" \
   'sab "s|phase_timing:\$tm,||" "phase_timing:\$tm"'
ck "SABOTAGE: disconnecting evidence from the summary is detectable" \
   'sab "s|phase_timing.timing_available|removed|g" "phase_timing.timing_available"'

# --- THE CLOCK BOUNDARY (root cause of the 32123758374 telemetry failure) ---
# child_started_at used to be set in the "Staging identity" step, which runs
# AFTER db_acquire. Correct phase measurements then summed to more than the wall
# time they were nested in, the one-directional invariant refused, and every
# child recorded timing_available:false. The invariant was right; the clock was
# started too late.
clock_before_first_phase() {
  python3 - "${1:-$W}" <<'CLKPY'
import sys
s = open(sys.argv[1]).read()
i_clock = s.index("CHILD_STARTED_AT=$(date -u +%s)")
i_phase = s.index("phase-timer.sh start db_acquire")
assert i_clock < i_phase, ("child clock starts after the first measured phase", i_clock, i_phase)
CLKPY
}
ck "the child wall clock starts BEFORE db_acquire" 'clock_before_first_phase'
ck "the clock is set in the job's FIRST executable step"    'python3 -c "
import yaml
d=yaml.safe_load(open(\"$W\"))
first=[x for x in d[\"jobs\"][\"stage\"][\"steps\"] if \"run\" in x][0]
assert \"CHILD_STARTED_AT\" in first[\"run\"], first.get(\"name\")"'
ck "the identity step no longer redefines the clock (it would overwrite it)"    '! grep -q "child_started_at=\"\$(date -u" '"$W"
ck "SABOTAGE: moving the clock after db_acquire is DETECTED"    'tmp="$(mktemp -d)";
    python3 -c "
import sys
s=open(\"$W\").read()
s=s.replace(\"echo \\\"CHILD_STARTED_AT=\$(date -u +%s)\\\" >> \\\"\$GITHUB_ENV\\\"\n\",\"\",1)
open(\"$tmp/w.yml\",\"w\").write(s)";
    ! clock_before_first_phase "$tmp/w.yml" >/dev/null 2>&1; rc=$?; rm -rf "$tmp"; [ $rc -eq 0 ]'

# A cancelled child must never look like a complete cost record.
ck "a cancelled child cannot report complete timing"    'out="$(emit_with "a\tstart\t0\na\tend\t5\nb\tstart\t5\n" 100)";
    [ "$(jq -r .timing_complete <<<"$out")" = false ] &&
    [ "$(jq -r ".incomplete_phases|length" <<<"$out")" -ge 1 ]'

echo "----"
[ "$fail" -eq 0 ] && echo "test_phase_telemetry: PASS" || echo "test_phase_telemetry: FAIL"
exit $fail
