#!/usr/bin/env bash
# =============================================================================
# Zenchron Dynamics — php-frankenphp runtime smoke test.
# Usage: smoke-frankenphp.sh <image-ref>   (image must already be built)
#
# Ground truth (images/php-frankenphp/8.{3,4}/Dockerfile + Caddyfile):
#   ENTRYPOINT ["frankenphp"]; CMD ["run","--config","/etc/frankenphp/Caddyfile"].
#   USER 10001:10001; SERVER_NAME=":8080"; root * /app/public; EXPOSE 8080 8081.
#   (8443 went with TLS termination; this image terminates no TLS.)
#   Readiness site :8081 responds /healthz "ok" 200. XDG_*HOME under /tmp/caddy-*,
#   so a single tmpfs /tmp satisfies a read-only rootfs.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" >/dev/null 2>&1 && pwd)"
# shellcheck source=lib.sh
. "$SCRIPT_DIR/lib.sh"

require_image "${1:-}"
IMG="$1"

printf '== smoke: php-frankenphp (%s) ==\n' "$IMG"

# Non-root identity.
check "runs as non-root (uid != 0)" assert_nonroot "$IMG"
check "runs as the pinned uid 10001" assert_uid "$IMG" "10001"

# Ports exposed.
check "exposes HTTP port 8080" exposes_port "$IMG" "8080"
check "exposes readiness port 8081" exposes_port "$IMG" "8081"

# Document root is /app/public (per the baked-in Caddyfile).
check "document root is /app/public" \
    sh -c "docker run --rm --entrypoint sh '$IMG' -c 'cat /etc/frankenphp/Caddyfile' | grep -q 'root \\* /app/public'"

# Boot the server under a read-only rootfs (tmpfs /tmp for Caddy state) and probe
# both the HTTP listener and the readiness endpoint over the network.
NAME="smoke-franken-$$-$RANDOM"
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker rm -f "$NAME" >/dev/null 2>&1 || true
# Run under the FULL production profile, not read-only rootfs alone:
# `cap_drop: ALL` + `no-new-privileges` is where a leftover file capability
# actually bites — with no-new-privileges the kernel refuses to exec a file
# carrying capabilities, so this container failing to serve IS the capability
# regression (#100), observed behaviourally rather than inferred.
if docker run -d --name "$NAME" --read-only --tmpfs /tmp \
        --cap-drop ALL --security-opt no-new-privileges \
        -p 127.0.0.1::8080 -p 127.0.0.1::8081 "$IMG" >/dev/null; then
    HTTP_PORT="$(docker port "$NAME" 8080/tcp 2>/dev/null | head -n1 | sed 's/.*://')"
    READY_PORT="$(docker port "$NAME" 8081/tcp 2>/dev/null | head -n1 | sed 's/.*://')"
else
    HTTP_PORT=""
    READY_PORT=""
fi

check "read-only rootfs: HTTP listener answers on :8080" \
    poll_http_up "http://127.0.0.1:${HTTP_PORT:-0}/" 20

check "readiness endpoint /healthz returns ok on :8081" \
    poll_http_body "http://127.0.0.1:${READY_PORT:-0}/healthz" "ok" 20

# --- the PHP runtime must actually LOAD what it ships -----------------------
# Every assertion above passes on an image whose `gd` extension cannot load:
# the checks are about identity, ports, the document root and two HTTP
# endpoints, and not one of them starts PHP with its extensions. Measured on a
# deliberately broken build (libaom3 purged, taking libavif15 with it): this
# smoke returned 8 passed / 0 failed while `extension_loaded("gd")` was false
# and `imagecreatetruecolor()` was an undefined function.
#
# So a "remediation" that deletes a shipped capability reaches production
# green. That is the vacuous-gate class: the suite answers "does it serve
# HTTP", never "does the runtime work".
#
# PHP reports a failed dynamic load on stderr at startup and still exits 0,
# so the exit status cannot be trusted here — the diagnostic is the signal.
php_starts_clean() {
    local out
    out="$(docker run --rm --entrypoint php "$IMG" -m 2>&1 >/dev/null || true)"
    if grep -q 'Unable to load dynamic library' <<<"$out"; then
        printf '    %s\n' "$(grep -m1 'Unable to load dynamic library' <<<"$out" | cut -c1-200)" >&2
        return 1
    fi
    return 0
}

check "every shipped PHP extension loads (no startup load failure)" \
    php_starts_clean

finish
