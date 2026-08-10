#!/usr/bin/env bash
# =============================================================================
# tests/runtime/test_worker_heartbeat.sh — worker heartbeat contract (#117).
#
# Drives the REAL images/php-worker/*/worker-entrypoint and worker-healthcheck
# with /bin/sh, the interpreter they run under in the image. Nothing here
# re-implements the age arithmetic or the validation: every case executes the
# shipped script and reads its exit status, so a mutation to the bounds check,
# the future-timestamp guard or the atomic write breaks a case here.
#
# The defect these exist for: a heartbeat timestamp in the FUTURE produced a
# negative age, `age <= MAX` was true, and a dead worker was reported HEALTHY.
# Alongside it, an unvalidated WORKER_HEARTBEAT_INTERVAL of 0 turned the ticker
# into a busy loop and a non-numeric one made every `sleep` fail, in both cases
# silently ending the heartbeat while the container still looked normal.
#
# Runs offline. No docker, no network.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

for V in 8.3 8.4; do
  HC="images/php-worker/$V/worker-healthcheck"
  EP="images/php-worker/$V/worker-entrypoint"

  ck "[$V] healthcheck is executable shell"  "test -r '$HC'"
  ck "[$V] entrypoint is executable shell"   "test -r '$EP'"

  # --- healthcheck ---------------------------------------------------------
  # hc <file-contents-or-MISSING> <max-age> <now-offset> -> exit status
  hc() {
    local hb="$TMP/hb.$$"
    rm -f "$hb"
    if [ "$1" != MISSING ]; then printf '%s\n' "$1" > "$hb"; fi
    WORKER_HEARTBEAT_FILE="$hb" WORKER_HEARTBEAT_MAX_AGE="$2" sh "$HC" >/dev/null 2>&1
  }
  now() { date +%s; }

  ck "[$V] a fresh heartbeat is HEALTHY"          "hc \"\$(now)\" 90"
  ck "[$V] a heartbeat older than MAX is UNHEALTHY" "! hc \"\$((\$(now) - 500))\" 90"
  ck "[$V] a missing heartbeat file is UNHEALTHY"   "! hc MISSING 90"
  ck "[$V] an empty heartbeat file is UNHEALTHY"    "! hc '' 90"
  ck "[$V] a non-numeric heartbeat is UNHEALTHY"    "! hc 'not-a-timestamp' 90"

  # THE regression. On the previous implementation this returned 0: age went
  # negative and sailed through `age <= MAX`.
  ck "[$V] a heartbeat 1 hour in the FUTURE is UNHEALTHY" \
     "! hc \"\$((\$(now) + 3600))\" 90"
  ck "[$V] a heartbeat 10 years in the future is UNHEALTHY" \
     "! hc \"\$((\$(now) + 315360000))\" 90"
  # ...but a stamp written in the same second the probe reads it must not flap.
  ck "[$V] a heartbeat 1s ahead (write/read race) is still HEALTHY" \
     "hc \"\$((\$(now) + 1))\" 90"

  # Invalid MAX used to be interpolated into `[ age -le MAX ]`, letting the
  # shell's own error decide the verdict.
  ck "[$V] a non-numeric MAX_AGE is UNHEALTHY"  "! hc \"\$(now)\" 'abc'"
  ck "[$V] MAX_AGE=0 is UNHEALTHY"              "! hc \"\$(now)\" 0"
  ck "[$V] a negative MAX_AGE is UNHEALTHY"     "! hc \"\$(now)\" -5"
  ck "[$V] an empty MAX_AGE is UNHEALTHY"       "! hc \"\$(now)\" ''"
  ck "[$V] an absurd MAX_AGE (>1 day) is UNHEALTHY" "! hc \"\$(now)\" 999999"
  ck "[$V] MAX_AGE at the 86400 boundary is accepted" "hc \"\$(now)\" 86400"

  # --- entrypoint ----------------------------------------------------------
  # ep <interval> <auto> <hb-dir> <cmd...> -> exit status
  ep() {
    local iv="$1" auto="$2" dir="$3"; shift 3
    WORKER_HEARTBEAT_INTERVAL="$iv" WORKER_HEARTBEAT_AUTO="$auto" \
      WORKER_HEARTBEAT_FILE="$dir/hb" sh "$EP" "$@" >/dev/null 2>&1
  }

  ck "[$V] no worker command exits 64 (EX_USAGE)" \
     "ep 15 1 '$TMP'; [ \$? -eq 64 ]"
  # Each of these used to be accepted and to break the heartbeat at runtime.
  ck "[$V] INTERVAL=0 is refused at startup (was a busy loop)" \
     "ep 0 1 '$TMP' true; [ \$? -eq 78 ]"
  ck "[$V] a non-numeric INTERVAL is refused (was a failing sleep)" \
     "ep 'soon' 1 '$TMP' true; [ \$? -eq 78 ]"
  ck "[$V] a negative INTERVAL is refused" \
     "ep -1 1 '$TMP' true; [ \$? -eq 78 ]"
  ck "[$V] an INTERVAL longer than any MAX_AGE is refused" \
     "ep 99999 1 '$TMP' true; [ \$? -eq 78 ]"
  ck "[$V] a non-boolean AUTO is refused" \
     "ep 15 maybe '$TMP' true; [ \$? -eq 78 ]"
  ck "[$V] AUTO=0 (application-driven heartbeat) is accepted" \
     "ep 15 0 '$TMP' true"

  # An unwritable heartbeat directory used to be swallowed by `|| true`: the
  # worker ran with no heartbeat at all and the healthcheck blamed the worker.
  mkdir -p "$TMP/ro" && chmod 0555 "$TMP/ro"
  ck "[$V] an unwritable heartbeat path is refused at startup" \
     "ep 15 1 '$TMP/ro' true; [ \$? -eq 78 ]"
  chmod 0755 "$TMP/ro"

  # Happy path, end to end: the entrypoint's heartbeat must satisfy the
  # healthcheck, and the worker's exit status must survive.
  D="$TMP/live"; mkdir -p "$D"
  ck "[$V] the entrypoint writes a heartbeat the healthcheck accepts" \
     "ep 15 0 '$D' true && WORKER_HEARTBEAT_FILE='$D/hb' WORKER_HEARTBEAT_MAX_AGE=90 sh '$HC' >/dev/null 2>&1"
  ck "[$V] the worker's exit status is propagated" \
     "ep 15 0 '$D' sh -c 'exit 7'; [ \$? -eq 7 ]"
  # The atomic write must not leave its temp file behind for a reader to find.
  ck "[$V] no heartbeat temp file is left behind" "! test -e '$D/hb.tmp'"

  # The two PHP lines must not drift apart: a fix applied to one only is how
  # 8.4 would keep the bug after 8.3 was patched.
  if [ "$V" = 8.4 ]; then
    ck "8.3 and 8.4 worker-healthcheck are identical" \
       "diff -q images/php-worker/8.3/worker-healthcheck images/php-worker/8.4/worker-healthcheck >/dev/null"
    ck "8.3 and 8.4 worker-entrypoint are identical" \
       "diff -q images/php-worker/8.3/worker-entrypoint images/php-worker/8.4/worker-entrypoint >/dev/null"
  fi
done

echo "----"; [ "$fail" -eq 0 ] && echo "test_worker_heartbeat: PASS" || echo "test_worker_heartbeat: FAIL"
exit $fail
