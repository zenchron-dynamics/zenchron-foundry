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
# config still parses (the old check returned 0 here), but nothing answers.
# `head -c40` on cmdline keeps this from matching the probing shell itself.
check "a WEDGED nginx is reported UNHEALTHY (nginx -t said healthy)" \
    sh -c "
      docker exec '$NAME' sh -c 'me=\$\$; for d in /proc/[0-9]*; do p=\${d#/proc/}; [ \"\$p\" = \"\$me\" ] && continue; c=\$(head -c40 \$d/cmdline 2>/dev/null | tr \"\\0\" \" \"); case \"\$c\" in *\"daemon off\"*) kill -STOP \"\$p\" 2>/dev/null;; esac; done' >/dev/null 2>&1
      docker exec '$NAME' nginx -t -q >/dev/null 2>&1 || { echo 'precondition failed: nginx -t did not pass on the wedged server' >&2; exit 1; }
      ! docker exec '$NAME' /usr/local/bin/nginx-healthcheck >/dev/null 2>&1
    "

cleanup_ready
trap - EXIT

finish
