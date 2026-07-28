# syntax=docker/dockerfile:1.7
# =============================================================================
# Zenchron Dynamics — caddy (production reverse proxy / static server)
# Non-root, listens on :8080 / :8443. Bind :80/:443 only via NET_BIND_SERVICE
# or upstream LB. Read-only-rootfs compatible (writable /data, /config tmpfs).
#
# BASE EXCEPTION (Debian-first migration): the official Caddy image publishes
# ONLY Alpine and Windows variants — there is no upstream Debian Caddy image, and
# rebuilding Caddy on Debian (xcaddy) would be an UNOFFICIAL rebuild (forbidden
# without an ADR). Per docs/base-image-strategy.md this image stays on the
# OFFICIAL Alpine base: it is a durable official upstream, digest-pinned, runs no
# `apk` commands, and clears every security gate. See ADR-0001.
# =============================================================================
ARG CADDY_BASE="caddy:2-alpine@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648"

FROM ${CADDY_BASE} AS runtime

ARG BUILD_DATE
ARG VCS_REF

LABEL org.opencontainers.image.title="zenchron-caddy" \
      org.opencontainers.image.description="Hardened Caddy reverse proxy / static file server" \
      org.opencontainers.image.vendor="Zenchron Dynamics" \
      org.opencontainers.image.source="https://github.com/zenchron-dynamics/zenchron-foundry" \
      org.opencontainers.image.version="prod" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.licenses="LicenseRef-Zenchron-Internal" \
      com.zenchron.runtime="caddy" \
      com.zenchron.support="supported"

COPY Caddyfile   /etc/caddy/Caddyfile
COPY conf.d/     /etc/caddy/conf.d/

# Deterministic non-root identity + writable state dirs.
# Strip the cap_net_bind_service file capability from the caddy binary: with it,
# the binary cannot be exec'd under `cap_drop: ALL` + no-new-privileges
# ("operation not permitted"). We listen on high ports (8080/8443/8081) and
# terminate TLS upstream, so the capability is unnecessary; removing it lets the
# image run with ZERO Linux capabilities. (To bind :80/:443 directly, front it
# with an LB or use the upstream caddy image instead.)
#
# Capability removal is FAIL-CLOSED (#100). This used to read
# `setcap -r ... 2>/dev/null || true`, which turns a missing binary, an absent
# setcap, or a failed removal into a green build shipping a capability the
# runtime contract says cannot exist. Every step below is load-bearing, and the
# removal is proven afterwards instead of assumed:
#   1. the binary must exist and be executable;
#   2. setcap/getcap must be present — this Alpine base ships libcap, and per
#      ADR-0001 this image runs NO apk commands, so they cannot be installed
#      here: their absence must fail the build, not be papered over;
#   3. the removal itself must succeed;
#   4. the binary must afterwards carry NO capability;
#   5. NO file anywhere in the image may carry one.
# Step 5 is the real guarantee: it catches a capability arriving by some other
# path in a future base image, which a check scoped to /usr/bin/caddy would miss.
# The identity/dir commands lose their `|| true` for the same reason — a failed
# adduser must not yield an image whose USER does not exist.
RUN set -eux; \
    test -x /usr/bin/caddy; \
    command -v setcap >/dev/null || { echo "REFUSE: setcap absent; cannot remove capabilities" >&2; exit 1; }; \
    command -v getcap >/dev/null || { echo "REFUSE: getcap absent; cannot verify removal" >&2; exit 1; }; \
    setcap -r /usr/bin/caddy; \
    if [ -n "$(getcap /usr/bin/caddy)" ]; then \
        echo "REFUSE: /usr/bin/caddy still carries: $(getcap /usr/bin/caddy)" >&2; \
        exit 1; \
    fi; \
    remaining="$(getcap -r / 2>/dev/null)"; \
    if [ -n "${remaining}" ]; then \
        echo "REFUSE: file capabilities remain in the final image:" >&2; \
        echo "${remaining}" >&2; \
        exit 1; \
    fi; \
    addgroup -g 10001 app; \
    adduser -u 10001 -G app -h /app -s /sbin/nologin -D app; \
    mkdir -p /app /data/caddy /config/caddy; \
    chown -R 10001:10001 /app /data /config /etc/caddy

ENV XDG_DATA_HOME=/data XDG_CONFIG_HOME=/config

USER 10001:10001
WORKDIR /app
# 8443 is deliberately NOT exposed: the certified configuration sets
# `auto_https off` and terminates no TLS (CVE-2026-56852). Advertising a TLS
# port would invite a topology this image is not certified for.
EXPOSE 8080 8081

# Readiness probe: hit the always-on /healthz site (proves Caddy is serving HTTP,
# not just that the binary exists). wget ships in the alpine base; no curl needed.
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD ["wget", "-q", "-O", "-", "http://127.0.0.1:8081/healthz"]

ENTRYPOINT ["caddy"]
CMD ["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
