#!/usr/bin/env bash
# =============================================================================
# Zenchron Dynamics — php-fpm runtime smoke test.
# Usage: smoke-php-fpm.sh <image-ref>   (image must already be built)
#
# Ground truth (images/php-fpm/8.{3,4}/Dockerfile + www.conf + php-fpm.conf):
#   ENTRYPOINT ["php-fpm","--nodaemonize","--fpm-config","/usr/local/etc/php-fpm.conf"]
#   USER 10001:10001; EXPOSE 9000; pool listen 0.0.0.0:9000; daemonize=no, no pidfile.
#   HEALTHCHECK /usr/local/bin/docker-healthcheck probes the 9000 TCP listener.
#   FPM intentionally OMITS pcntl (so it is excluded from the required set).
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" >/dev/null 2>&1 && pwd)"
# shellcheck source=lib.sh
. "$SCRIPT_DIR/lib.sh"

require_image "${1:-}"
IMG="$1"

# Required extensions for FPM — same as CLI but WITHOUT pcntl (omitted by design).
REQUIRED_EXTS="bcmath ctype curl dom fileinfo gd intl mbstring opcache openssl \
pdo pdo_mysql pdo_pgsql pgsql redis simplexml sockets sodium sqlite3 \
tokenizer xml zip"

printf '== smoke: php-fpm (%s) ==\n' "$IMG"

# Config test passes.
check "php-fpm -t config test passes" \
    docker run --rm --entrypoint php-fpm "$IMG" \
        -t --fpm-config /usr/local/etc/php-fpm.conf

# Required extensions present (pcntl excluded).
check "required extensions present (no pcntl)" \
    php_extensions_present "$IMG" "$REQUIRED_EXTS"

# pcntl is intentionally absent in FPM.
check "pcntl intentionally absent" \
    sh -c "! docker run --rm --entrypoint php '$IMG' -r 'exit(extension_loaded(\"pcntl\")?0:1);'"

# Non-root identity.
check "runs as non-root (uid != 0)" assert_nonroot "$IMG"
check "runs as the pinned uid 10001" assert_uid "$IMG" "10001"

# Port 9000 is exposed.
check "exposes port 9000" exposes_port "$IMG" "9000"

# Boots under a read-only rootfs and the master stays up, then the listener on
# the configured port answers (probed with the image's own healthcheck).
NAME="smoke-fpm-$$-$RANDOM"
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

fpm_up_and_listening() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker run -d --name "$NAME" --read-only --tmpfs /tmp "$IMG" >/dev/null || return 1
    sleep 2
    [ "$(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null)" = "true" ] || return 1
    # The bundled healthcheck connects to 127.0.0.1:9000 — proves it is listening.
    docker exec "$NAME" /usr/local/bin/docker-healthcheck
}

check "read-only rootfs: master starts and listens on 9000" fpm_up_and_listening

finish
