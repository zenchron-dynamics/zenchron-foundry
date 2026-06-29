#!/usr/bin/env bash
# =============================================================================
# Zenchron Dynamics — nginx runtime smoke test.
# Usage: smoke-nginx.sh <image-ref>   (image must already be built)
#
# Ground truth (images/nginx/Dockerfile + nginx.conf):
#   Base nginxinc/nginx-unprivileged; USER 101:101; EXPOSE 8080.
#   ENTRYPOINT ["nginx","-g","daemon off;"]; HEALTHCHECK ["nginx","-t","-q"].
#   pid /tmp/nginx.pid and all *_temp_path live under /tmp, so a read-only rootfs
#   needs a tmpfs /tmp. Only app.conf.example ships (no active server by default),
#   so the listener is asserted via EXPOSE / config rather than a live HTTP probe.
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

# Listener on the expected unprivileged port.
check "exposes port 8080" exposes_port "$IMG" "8080"

# Read-only rootfs with tmpfs for /tmp (pid + temp paths): master stays up.
check "read-only rootfs + tmpfs /tmp: nginx stays up" \
    container_stays_up 2 --read-only --tmpfs /tmp "$IMG"

# Health endpoint is defined in the shipped site template (best-effort static check).
check "healthz endpoint defined in site template" \
    sh -c "docker run --rm --entrypoint sh '$IMG' -c 'cat /etc/nginx/conf.d/app.conf.example 2>/dev/null' | grep -q '/healthz'"

finish
