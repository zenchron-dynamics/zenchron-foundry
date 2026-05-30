# syntax=docker/dockerfile:1.7
# =============================================================================
# Zenchron Dynamics — caddy (production reverse proxy / static server)
# Non-root, listens on :8080 / :8443. Bind :80/:443 only via NET_BIND_SERVICE
# or upstream LB. Read-only-rootfs compatible (writable /data, /config tmpfs).
# =============================================================================
ARG CADDY_BASE="caddy:2-alpine"

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
RUN addgroup -g 10001 app 2>/dev/null || true \
    && adduser -u 10001 -G app -h /app -s /sbin/nologin -D app 2>/dev/null || true \
    && mkdir -p /app /data/caddy /config/caddy \
    && chown -R 10001:10001 /app /data /config /etc/caddy

ENV XDG_DATA_HOME=/data XDG_CONFIG_HOME=/config

USER 10001:10001
WORKDIR /app
EXPOSE 8080 8443

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD ["caddy", "version"]

ENTRYPOINT ["caddy"]
CMD ["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
