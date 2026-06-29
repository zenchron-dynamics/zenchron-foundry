#!/usr/bin/env bash
# =============================================================================
# Zenchron Dynamics — php-worker runtime smoke test.
# Usage: smoke-php-worker.sh <image-ref>   (image must already be built)
#
# Ground truth (images/php-worker/8.{3,4}/Dockerfile + worker-entrypoint + healthcheck):
#   ENTRYPOINT ["tini","--","/usr/local/bin/worker-entrypoint"]; CMD ["php","-v"].
#   USER 10001:10001; tini is PID 1; heartbeat file /tmp/worker-heartbeat (tmpfs,
#   so read-only-rootfs friendly); HEALTHCHECK /usr/local/bin/worker-healthcheck.
#   The app supplies the worker command; signals are forwarded for graceful stop.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" >/dev/null 2>&1 && pwd)"
# shellcheck source=lib.sh
. "$SCRIPT_DIR/lib.sh"

require_image "${1:-}"
IMG="$1"

printf '== smoke: php-worker (%s) ==\n' "$IMG"

# Non-root identity (entrypoint is tini; override to read the uid).
check "runs as non-root (uid != 0)" assert_nonroot "$IMG"
check "runs as the pinned uid 10001" assert_uid "$IMG" "10001"

# PID 1 is tini (init that reaps zombies and forwards signals). The supplied
# command runs under worker-entrypoint, so reading /proc/1/comm reports tini.
check "PID 1 is tini" \
    sh -c "docker run --rm '$IMG' cat /proc/1/comm | grep -qx tini"

# Long-lived worker container used for the heartbeat / healthcheck / SIGTERM checks.
NAME="smoke-worker-$$-$RANDOM"
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

start_worker() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    # Read-only rootfs + tmpfs /tmp: the heartbeat must land on the tmpfs path.
    docker run -d --name "$NAME" --read-only --tmpfs /tmp "$IMG" \
        sh -c 'while true; do sleep 1; done' >/dev/null || return 1
    sleep 3
    [ "$(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null)" = "true" ]
}

check "worker entrypoint starts under read-only rootfs" start_worker

# Heartbeat file is created by the entrypoint at the tmpfs path.
check "heartbeat file created at /tmp/worker-heartbeat" \
    docker exec "$NAME" test -f /tmp/worker-heartbeat

# The image's healthcheck command reports healthy.
check "worker-healthcheck exits 0 (fresh heartbeat)" \
    docker exec "$NAME" /usr/local/bin/worker-healthcheck

# Graceful SIGTERM: `docker stop` must return well within the grace period
# (a clean shutdown), not be SIGKILLed at the end of it.
graceful_stop() {
    _start="$(date +%s)"
    docker stop --time 10 "$NAME" >/dev/null || return 1
    _elapsed=$(( $(date +%s) - _start ))
    [ "$_elapsed" -lt 9 ]
}

check "clean SIGTERM (stops within grace period)" graceful_stop

finish
