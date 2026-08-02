#!/usr/bin/env bash
# =============================================================================
# Zenchron Dynamics — caddy runtime smoke test.
# Usage: smoke-caddy.sh <image-ref>   (image must already be built)
#
# Ground truth (images/caddy/Dockerfile + Caddyfile):
#   Base caddy:2-alpine; USER 10001:10001; EXPOSE 8080 8081 — 8443 was REMOVED
#   with TLS termination (CVE-2026-56852); the checks below prove it is gone.
#   ENTRYPOINT ["caddy"]; CMD ["run","--config","/etc/caddy/Caddyfile","--adapter","caddyfile"].
#   Always-on readiness site :8081 responds /healthz "ok" 200. XDG_DATA_HOME=/data,
#   XDG_CONFIG_HOME=/config, storage /data/caddy -> needs writable /data and /config.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" >/dev/null 2>&1 && pwd)"
# shellcheck source=lib.sh
. "$SCRIPT_DIR/lib.sh"

require_image "${1:-}"
IMG="$1"

printf '== smoke: caddy (%s) ==\n' "$IMG"

# Caddyfile config validation (entrypoint is caddy; pass the subcommand).
check "caddy validate accepts the baked Caddyfile" \
    docker run --rm "$IMG" validate --config /etc/caddy/Caddyfile --adapter caddyfile

# Non-root identity.
check "runs as non-root (uid != 0)" assert_nonroot "$IMG"
check "runs as the pinned uid 10001" assert_uid "$IMG" "10001"

# Expected ports exposed.
check "exposes HTTP port 8080" exposes_port "$IMG" "8080"
check "exposes readiness port 8081" exposes_port "$IMG" "8081"

# Boot under a read-only rootfs (tmpfs for the writable state dirs) and probe the
# always-on readiness endpoint over the network.
NAME="smoke-caddy-$$-$RANDOM"
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker rm -f "$NAME" >/dev/null 2>&1 || true
# Run under the FULL production profile, not read-only rootfs alone:
# `cap_drop: ALL` + `no-new-privileges` is where a leftover file capability
# actually bites — with no-new-privileges the kernel refuses to exec a file
# carrying capabilities, and the upstream caddy binary ships
# cap_net_bind_service. This container failing to serve IS the capability
# regression (#100), observed behaviourally rather than inferred.
if docker run -d --name "$NAME" \
        --read-only --tmpfs /data --tmpfs /config --tmpfs /tmp \
        --cap-drop ALL --security-opt no-new-privileges \
        -p 127.0.0.1::8081 "$IMG" >/dev/null; then
    READY_PORT="$(docker port "$NAME" 8081/tcp 2>/dev/null | head -n1 | sed 's/.*://')"
else
    READY_PORT=""
fi

check "read-only rootfs: readiness /healthz returns ok on :8081" \
    poll_http_body "http://127.0.0.1:${READY_PORT:-0}/healthz" "ok" 20

# --- certified topology: NO TLS termination (CVE-2026-56852) ----------------
# The vendored golang.org/x/text v0.37.0 has an infinite loop in norm.Iter on
# invalid UTF-8. Caddy reaches it from attacker-controlled TLS SNI:
#   ClientHelloInfo.ServerName -> certmagic getNameFromClientHello
#   -> idna.Lookup.ToASCII -> norm.NFC.String/QuickSpan/Bytes
# The certified configuration therefore terminates NO TLS. Prove it from the
# adapted config rather than trusting the Caddyfile text.
check "shipped config creates no TLS app (no TLS termination)" \
    sh -c 'docker run --rm --entrypoint caddy "$0" adapt --config /etc/caddy/Caddyfile --adapter caddyfile 2>/dev/null \
           | grep -q "\"tls\"" && exit 1 || exit 0' "$IMG"
check "shipped config disables automatic HTTPS" \
    sh -c 'docker run --rm --entrypoint caddy "$0" adapt --config /etc/caddy/Caddyfile --adapter caddyfile 2>/dev/null \
           | grep -q "\"disable\":true" ' "$IMG"
check "no listener on a TLS port (443/8443)" \
    sh -c 'docker run --rm --entrypoint caddy "$0" adapt --config /etc/caddy/Caddyfile --adapter caddyfile 2>/dev/null \
           | grep -qE "\":(443|8443)\"" && exit 1 || exit 0' "$IMG"
check "image does not advertise a TLS port" \
    sh -c '! docker image inspect --format "{{json .Config.ExposedPorts}}" "$0" | grep -q "8443"' "$IMG"

finish
