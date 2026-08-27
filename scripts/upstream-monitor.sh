#!/usr/bin/env bash
# self-test: waived (thin wrapper; the logic and its self-test live in
# scripts/upstream-monitor.py --self-test, exercised by
# tests/vulnerability-policy/test_upstream_monitor.sh)
# =============================================================================
# scripts/upstream-monitor.sh — buildless upstream monitor, entry point.
#
# OBSERVES AND REPORTS. NOTHING ELSE. It does not rebuild an image, move a base
# pin, dispatch acceptance, publish, promote, sign, tag, renew an exception or
# remove one. It has no write path into policies/ at all; the only file it
# writes is the observation/verdict JSON under --out-dir.
#
#   scripts/upstream-monitor.sh                     observe, evaluate, report
#   scripts/upstream-monitor.sh --manifests-only    skip inventory + feeds
#   scripts/upstream-monitor.sh --fail-on-alert     exit 3 if an alert fires
#   scripts/upstream-monitor.sh --checkpoints-only  expiry checkpoints only
#   scripts/upstream-monitor.sh --today 2026-09-15  pin the checkpoint date
#   scripts/upstream-monitor.sh --out-dir DIR       keep the observation JSON
#
# Exit codes: 0 quiet, 2 usage/observation failure, 3 alert (with
# --fail-on-alert), 4 a checkpoint is due (with --fail-on-checkpoint).
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MON="$ROOT/scripts/upstream-monitor.py"
# NOT rooted at the checkout. A tool that writes into $ROOT by default is one
# crash away from leaving debris in a working tree, which is a class this
# repository has already been bitten by (tests/lib/test_no_ambient_mutation.sh).
OUT_DIR=""
MANIFESTS_ONLY=""
FAIL_ON_ALERT=""
FAIL_ON_CHECKPOINT=""
CHECKPOINTS_ONLY=""
TODAY=""
OBSERVATION=""

usage() { sed -n '5,22p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

while [ "$#" -gt 0 ]; do
    case "$1" in
        --manifests-only)     MANIFESTS_ONLY=1 ;;
        --fail-on-alert)      FAIL_ON_ALERT=1 ;;
        --fail-on-checkpoint) FAIL_ON_CHECKPOINT=1 ;;
        --checkpoints-only)   CHECKPOINTS_ONLY=1 ;;
        --observation)        shift; OBSERVATION="${1:-}" ;;
        --out-dir)            shift; OUT_DIR="${1:-}" ;;
        --today)              shift; TODAY="${1:-}" ;;
        -h|--help)            usage; exit 0 ;;
        *) printf 'REFUSE: unknown argument %s\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

command -v python3 >/dev/null 2>&1 || { echo "REFUSE: python3 is required" >&2; exit 2; }

# --- part 2: expiry operating checkpoints ------------------------------------
# Printed FIRST and on every run, because the checkpoint is the thing with a
# deadline. Silent outside the reporting window.
cp_args=(checkpoints)
[ -n "$TODAY" ] && cp_args+=(--today "$TODAY")
[ -n "$FAIL_ON_CHECKPOINT" ] && cp_args+=(--fail-on-checkpoint)
cp_rc=0
python3 "$MON" "${cp_args[@]}" || cp_rc=$?
if [ "$cp_rc" = 5 ]; then
    echo "REFUSE: the watch config no longer binds to the exception ledger." >&2
    exit 2
fi

if [ -n "$CHECKPOINTS_ONLY" ]; then
    exit "$cp_rc"
fi

echo
echo "=============================================================="

# --- part 1: buildless upstream observation ----------------------------------
if [ -z "$OBSERVATION" ]; then
    [ -n "$OUT_DIR" ] || OUT_DIR="$(mktemp -d)"
    mkdir -p "$OUT_DIR"
    OBSERVATION="$OUT_DIR/observation.json"
    obs_args=(observe --out "$OBSERVATION")
    [ -n "$MANIFESTS_ONLY" ] && obs_args+=(--manifests-only)
    python3 "$MON" "${obs_args[@]}" || {
        echo "REFUSE: observation failed; no verdict is produced from a failed read." >&2
        exit 2
    }
fi

ev_args=(evaluate --observation "$OBSERVATION")
[ -n "$FAIL_ON_ALERT" ] && ev_args+=(--fail-on-alert)
ev_rc=0
python3 "$MON" "${ev_args[@]}" || ev_rc=$?

# A due checkpoint and a fired alert are different signals; the alert wins the
# exit code because it is the one that can change what the maintainer does.
if [ "$ev_rc" != 0 ]; then
    exit "$ev_rc"
fi
exit "$cp_rc"
