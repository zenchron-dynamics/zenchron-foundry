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
RUN setcap -r /usr/bin/caddy 2>/dev/null || true \
    && addgroup -g 10001 app 2>/dev/null || true \
    && adduser -u 10001 -G app -h /app -s /sbin/nologin -D app 2>/dev/null || true \
    && mkdir -p /app /data/caddy /config/caddy \
    && chown -R 10001:10001 /app /data /config /etc/caddy

ENV XDG_DATA_HOME=/data XDG_CONFIG_HOME=/config

USER 10001:10001
WORKDIR /app
EXPOSE 8080 8443 8081

# Readiness probe: hit the always-on /healthz site (proves Caddy is serving HTTP,
# not just that the binary exists). wget ships in the alpine base; no curl needed.
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD ["wget", "-q", "-O", "-", "http://127.0.0.1:8081/healthz"]

ENTRYPOINT ["caddy"]
CMD ["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
