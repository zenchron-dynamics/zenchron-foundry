#!/usr/bin/env bash
# =============================================================================
# Zenchron Dynamics — nginx runtime smoke test.
# Usage: smoke-nginx.sh <image-ref>   (image must already be built)
#
# Ground truth (images/nginx/Dockerfile + nginx.conf):
#   Base nginxinc/nginx-unprivileged; USER 101:101; EXPOSE 8080.
#   ENTRYPOINT ["nginx","-g","daemon off;"]; EXPOSE 8081 for the readiness site.
#   HEALTHCHECK ["/usr/local/bin/nginx-healthcheck"] — a real HTTP request to
#   :8081/healthz, NOT `nginx -t -q` (#127): a config parse reported a hung or
#   unforked nginx as healthy. conf.d/00-readiness.conf ships that listener, so
#   the probe no longer depends on a consumer-supplied site config.
#   pid /tmp/nginx.pid and all *_temp_path live under /tmp, so a read-only rootfs
#   needs a tmpfs /tmp.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" >/dev/null 2>&1 && pwd)"
# shellcheck source=lib.sh
. "$SCRIPT_DIR/lib.sh"

require_image "${1:-}"
IMG="$1"

printf '== smoke: nginx (%s) ==\n' "$IMG"

# Config syntax test (the image's own healthcheck command).
check "nginx -t config test passes" \
    docker run --rm --entrypoint nginx "$IMG" -t -q

# Non-root identity (upstream unprivileged image runs as uid 101).
check "runs as non-root (uid != 0)" assert_nonroot "$IMG"
check "runs as the unprivileged uid 101" assert_uid "$IMG" "101"

# Listeners on the expected unprivileged ports.
check "exposes port 8080" exposes_port "$IMG" "8080"
check "exposes the readiness port 8081" exposes_port "$IMG" "8081"

# Read-only rootfs with tmpfs for /tmp (pid + temp paths): master stays up.
check "read-only rootfs + tmpfs /tmp: nginx stays up" \
    container_stays_up 2 --read-only --tmpfs /tmp "$IMG"

# Health endpoint is defined in the shipped site template (best-effort static check).
check "healthz endpoint defined in site template" \
    sh -c "docker run --rm --entrypoint sh '$IMG' -c 'cat /etc/nginx/conf.d/app.conf.example 2>/dev/null' | grep -q '/healthz'"

# --- #127: the healthcheck must observe a SERVING nginx, not a parsable config -
# Run under the full production posture and make a real request to the readiness
# listener the IMAGE ships, so this passes only if a worker forked, bound the
# socket and completed a request cycle.
NAME="smoke-nginx-$$-$RANDOM"
cleanup_ready() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup_ready EXIT

if docker run -d --name "$NAME" \
        --read-only --tmpfs /tmp \
        --cap-drop ALL --security-opt no-new-privileges \
        -p 127.0.0.1::8081 "$IMG" >/dev/null 2>&1; then
    READY_PORT="$(docker port "$NAME" 8081/tcp 2>/dev/null | head -n1 | sed 's/.*://')"
else
    READY_PORT=""
fi

check "read-only rootfs + cap_drop ALL: readiness /healthz returns ok on :8081" \
    poll_http_body "http://127.0.0.1:${READY_PORT:-0}/healthz" "ok" 20

# The shipped healthcheck binary, executed inside the container, against the
# live server. This is the exact command Docker runs every interval.
check "the shipped healthcheck reports a serving nginx as healthy" \
    docker exec "$NAME" /usr/local/bin/nginx-healthcheck

# ...and it must NOT accept a wedged server. SIGSTOP every nginx process: the
# config still parses, but nothing answers.
#
# Match on /proc/<pid>/comm — the executable name, exactly "nginx" for the
# master AND every worker, and "sh" for the shell running this probe. The
# previous version matched "daemon off" within the first 40 bytes of cmdline
# and stopped NOTHING: the master's cmdline is
#
#     nginx: master process nginx -g daemon off;
#
# which head -c40 truncates to "...daemon of", and the workers are
# "nginx: worker process", which never contained the string at all. The workers
# kept serving, so the healthcheck correctly reported healthy and this
# assertion failed in run 31701249058 — the first time the image had been built
# since the check was written. It had never wedged anything, so it had never
# tested what it claims to test.
#
# The WORKERS are the whole point: they answer requests, and the master does
# not. PID 1 is deliberately skipped — the master runs as PID 1 and the kernel
# ignores SIGSTOP sent to PID 1 from inside its own PID namespace, so trying to
# stop it silently does nothing. Stopping every worker leaves connections
# sitting in the listen backlog unanswered, which is precisely a wedged server:
# nginx -t still parses the config, nothing serves.
#
# The precondition asserts at least two workers were found AND that every one
# of them is really in state T, so this can never go back to proving nothing.
check "a WEDGED nginx is reported UNHEALTHY (nginx -t said healthy)" \
    sh -c "
      docker exec '$NAME' sh -c 'for d in /proc/[0-9]*; do p=\${d#/proc/}; [ \"\$p\" = 1 ] && continue; [ \"\$(cat \$d/comm 2>/dev/null)\" = nginx ] && kill -STOP \"\$p\" 2>/dev/null; done; exit 0' >/dev/null 2>&1
      docker exec '$NAME' sh -c 'n=0; for d in /proc/[0-9]*; do p=\${d#/proc/}; [ \"\$p\" = 1 ] && continue; [ \"\$(cat \$d/comm 2>/dev/null)\" = nginx ] || continue; n=\$((n+1)); grep -q \"^State:[[:space:]]*T\" \$d/status 2>/dev/null || exit 1; done; [ \"\$n\" -ge 2 ]' \
        || { echo 'precondition failed: expected >=2 nginx workers, all in state T' >&2; exit 1; }
      docker exec '$NAME' nginx -t -q >/dev/null 2>&1 || { echo 'precondition failed: nginx -t did not pass on the wedged server' >&2; exit 1; }
      ! docker exec '$NAME' /usr/local/bin/nginx-healthcheck >/dev/null 2>&1
    "

cleanup_ready
trap - EXIT

finish
