#!/usr/bin/env bash
# =============================================================================
# tests/tools/stress-stale-exception-selftest.sh
# -----------------------------------------------------------------------------
# The repro harness for the intermittent failure of
# `scripts/ci/assert-no-stale-exceptions.sh --self-test` on GitHub-hosted
# runners (CI runs 32814974957, 32815714210, 32817501744 — 2026-08-24/25).
#
# NOT a test. `tests/run-all.sh` only discovers `test_*.sh`, so this is never
# run by CI; it is the instrument that found the cause and the instrument that
# reproduces it on demand. The permanent guard is
# tests/lib/test_pipefail_sigpipe.sh.
#
# It varies, per trial:
#   * locale        LC_ALL/LANG   (C, C.UTF-8, en_US.UTF-8, tr_TR.UTF-8*)
#   * timezone      TZ            (UTC, Pacific/Kiritimati, Pacific/Niue)
#         *tr_TR is deliberate: dotless-i collation breaks naive [a-z] ranges.
#          The two extreme TZs sit on opposite sides of the date line, so
#          `date -u +%F` and local date disagree — the ledger has 55 entries
#          expiring 2026-08-31 and 4 expiring 2026-09-01, and the reconciler
#          refuses at `expires_at <= today`.
#   * tracing       bash vs bash -T (functrace)
#   * TMPDIR        clean | noisy | spaced
#         noisy  = pre-existing *.json, *.log, a stale dir and a chmod-000 file
#                  seeded into TMPDIR, to catch glob/`sorted(glob(...))` bleed
#         spaced = a TMPDIR path containing a space
#   * scheduling    serial vs N-way parallel (the race needs CPU contention)
#   * order         the trial list is shuffled by $SEED
#
# It does NOT randomise the ORDER OF SUBTESTS inside the self-test: that order
# is hardcoded in self_test() and is not injectable from outside. Trial order
# and concurrency are randomised instead, which is what actually perturbs the
# producer/consumer race that turned out to be the cause.
#
# Every trial writes env, seed, fixture path, exact command, exit status and
# FULL stdout+stderr to $OUTDIR/trial-NNN.log. Nothing is discarded.
#
# Usage:
#   tests/tools/stress-stale-exception-selftest.sh [--trials N] [--seed S]
#                                                  [--jobs N] [--today YYYY-MM-DD]
#                                                  [--outdir DIR] [--linux]
#   --linux  re-execs the whole harness inside ubuntu:24.04 (docker). The flake
#            is Linux-only in the wild: bash 5.2 loses the race, macOS bash 3.2
#            never does. Prefer this.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

TRIALS=40 SEED="${SEED:-$RANDOM}" JOBS=4 TODAY="" OUTDIR="" LINUX=0
while [ $# -gt 0 ]; do
  case "$1" in
    --trials) TRIALS="$2"; shift 2 ;;
    --seed)   SEED="$2";   shift 2 ;;
    --jobs)   JOBS="$2";   shift 2 ;;
    --today)  TODAY="$2";  shift 2 ;;
    --outdir) OUTDIR="$2"; shift 2 ;;
    --linux)  LINUX=1;     shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [ "$LINUX" = 1 ]; then
  command -v docker >/dev/null || { echo "--linux needs docker" >&2; exit 2; }
  # /repo is mounted read-write only because the harness writes its logs under
  # --outdir; it never writes into the checkout itself.
  exec docker run --rm -v "$ROOT:/repo" -w /repo ubuntu:24.04 bash -c '
    apt-get update -qq >/dev/null 2>&1
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 python3-yaml locales tzdata >/dev/null 2>&1
    exec bash tests/tools/stress-stale-exception-selftest.sh "$@"
  ' _ --trials "$TRIALS" --seed "$SEED" --jobs "$JOBS" ${TODAY:+--today "$TODAY"} \
       ${OUTDIR:+--outdir "$OUTDIR"}
fi

[ -n "$OUTDIR" ] || OUTDIR="$(mktemp -d)/stress"
mkdir -p "$OUTDIR"

echo "== stress-stale-exception-selftest =="
echo "root      : $ROOT"
echo "outdir    : $OUTDIR"
echo "seed      : $SEED"
echo "trials    : $TRIALS   jobs: $JOBS"
echo "uname     : $(uname -srm)"
echo "bash      : $BASH_VERSION"
echo "python3   : $(python3 -V 2>&1)"
echo "date -u   : $(date -u +%FT%TZ)"
echo

LOCALES=(C C.UTF-8 en_US.UTF-8 tr_TR.UTF-8)
ZONES=(UTC Pacific/Kiritimati Pacific/Niue)
TRACE=(plain functrace)
DIRTY=(clean noisy spaced)

# Deterministic per-trial parameter choice from $SEED, so a failing trial is
# replayable: same --seed + same trial number == same environment.
pick() { # pick <trial> <salt> <n>
  python3 -c 'import sys;print((hash((int(sys.argv[1]),int(sys.argv[2]),sys.argv[3]))%int(sys.argv[4]))if 0 else ((int(sys.argv[1])*2654435761+int(sys.argv[2])*40503+sum(map(ord,sys.argv[3])))%int(sys.argv[4])))' \
    "$1" "$SEED" "$2" "$3"
}

seed_tmpdir() { # seed_tmpdir <dir> <mode>
  local d="$1"
  mkdir -p "$d"
  case "$2" in
    noisy)
      printf '{"image":"nginx/prod","verdict":"PASS","matched_exception_ids":[],"shadowed_exception_ids":[]}' > "$d/stray-recon.json"
      printf '{"image":"caddy/prod"}' > "$d/aaa-first-by-sort.json"
      printf 'stale reconcile output\n' > "$d/reconcile-99.log"
      mkdir -p "$d/leftover.d"; : > "$d/leftover.d/img1.json"
      : > "$d/unreadable.json"; chmod 000 "$d/unreadable.json" 2>/dev/null || true
      ;;
  esac
}

run_trial() { # run_trial <n>
  local n="$1"
  local log loc zone tr dirty base tmp cmd rc
  log="$OUTDIR/trial-$(printf '%03d' "$n").log"
  loc="${LOCALES[$(pick "$n" locale   "${#LOCALES[@]}")]}"
  zone="${ZONES[$(pick "$n" tz        "${#ZONES[@]}")]}"
  tr="${TRACE[$(pick "$n" trace       "${#TRACE[@]}")]}"
  dirty="${DIRTY[$(pick "$n" dirty    "${#DIRTY[@]}")]}"

  base="$OUTDIR/fixtures"
  case "$dirty" in
    spaced) tmp="$base/trial $n with space" ;;
    *)      tmp="$base/trial-$n" ;;
  esac
  seed_tmpdir "$tmp" "$dirty"

  case "$tr" in
    plain)     cmd=(bash    "$ROOT/scripts/ci/assert-no-stale-exceptions.sh" --self-test) ;;
    functrace) cmd=(bash -T "$ROOT/scripts/ci/assert-no-stale-exceptions.sh" --self-test) ;;
  esac

  {
    echo "trial      : $n"
    echo "seed       : $SEED"
    echo "LC_ALL/LANG: $loc"
    echo "TZ         : $zone"
    echo "tracing    : $tr"
    echo "tmpdir mode: $dirty"
    echo "TMPDIR     : $tmp"
    echo "TODAY      : ${TODAY:-<unset, script uses date -u +%F>}"
    echo "command    : LC_ALL=$loc LANG=$loc TZ=$zone TMPDIR='$tmp' ${TODAY:+TODAY=$TODAY }${cmd[*]}"
    echo "--- stdout+stderr ---"
  } > "$log"

  LC_ALL="$loc" LANG="$loc" TZ="$zone" TMPDIR="$tmp" ${TODAY:+TODAY="$TODAY"} \
    "${cmd[@]}" >>"$log" 2>&1
  rc=$?
  echo "--- exit status: $rc ---" >> "$log"
  # chmod back so the caller can clean up
  chmod -R u+rwX "$tmp" 2>/dev/null || true
  printf '%s %s\n' "$n" "$rc" >> "$OUTDIR/results.tsv"
  if [ "$rc" -ne 0 ]; then
    printf 'TRIAL %3d FAIL rc=%-4s loc=%-12s tz=%-18s %-9s tmp=%-6s -> %s\n' \
      "$n" "$rc" "$loc" "$zone" "$tr" "$dirty" "$log"
  else
    printf 'TRIAL %3d ok        loc=%-12s tz=%-18s %-9s tmp=%s\n' \
      "$n" "$loc" "$zone" "$tr" "$dirty"
  fi
}

: > "$OUTDIR/results.tsv"

# Shuffle trial order by $SEED, then run either serially or $JOBS at a time.
# Concurrency is not decoration: the defect this harness found is a race
# between a shell producer and a short-circuiting reader, and CPU contention is
# what decides it.
# `mapfile` would be shorter but does not exist in bash 3.2, which is what
# macOS ships and half of this investigation ran on.
ORDER=()
while IFS= read -r _n; do ORDER+=("$_n"); done < <(python3 -c '
import sys, random
n, seed = int(sys.argv[1]), int(sys.argv[2])
xs = list(range(1, n + 1)); random.Random(seed).shuffle(xs)
sys.stdout.write("\n".join(map(str, xs)) + "\n")' "$TRIALS" "$SEED")

running=0
for n in "${ORDER[@]}"; do
  if [ "$JOBS" -le 1 ]; then
    run_trial "$n"
  else
    run_trial "$n" &
    running=$((running + 1))
    [ "$running" -lt "$JOBS" ] || { wait -n 2>/dev/null || wait; running=$((running - 1)); }
  fi
done
wait

echo
fails=$(awk '$2 != 0' "$OUTDIR/results.tsv" | wc -l | tr -d ' ')
total=$(wc -l < "$OUTDIR/results.tsv" | tr -d ' ')
echo "================================================================"
echo "seed $SEED: $((total - fails))/$total passed, $fails failed"
echo "per-trial evidence (env, seed, fixture, command, exit, full output): $OUTDIR/trial-*.log"
if [ "$fails" -gt 0 ]; then
  echo "exit statuses observed on failure:"
  awk '$2 != 0 {print "  rc=" $2 "  " "trial " $1}' "$OUTDIR/results.tsv" | sort -u
  echo "  (rc=141 is SIGPIPE — a producer killed by a short-circuiting reader"
  echo "   under set -o pipefail, NOT a policy refusal)"
fi
[ "$fails" -eq 0 ]
