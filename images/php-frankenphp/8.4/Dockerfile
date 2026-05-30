# syntax=docker/dockerfile:1.7
# =============================================================================
# Zenchron Dynamics — php-frankenphp 8.4 (production)
# Modern PHP app server with embedded Caddy. Single binary replaces
# php-fpm + nginx/caddy. FrankenPHP requires PHP >= 8.2, so 7.4/8.0 do NOT and
# CANNOT exist for this family — by design.
# Non-root, listens on high ports (8080/8443); bind :80/:443 only via
# cap_add NET_BIND_SERVICE or an upstream LB. See docs/runtime-hardening.md.
# Upstream FrankenPHP images are Debian/Alpine based; we use the Alpine variant
# and harden it (no true distroless build exists upstream yet).
# =============================================================================
ARG FRANKENPHP_BASE="dunglas/frankenphp:1-php8.4-alpine"

FROM ${FRANKENPHP_BASE} AS runtime

ARG BUILD_DATE
ARG VCS_REF

LABEL org.opencontainers.image.title="zenchron-php-frankenphp" \
      org.opencontainers.image.description="Hardened FrankenPHP 8.3 app server (embedded Caddy)" \
      org.opencontainers.image.vendor="Zenchron Dynamics" \
      org.opencontainers.image.source="https://github.com/zenchron-dynamics/zenchron-foundry" \
      org.opencontainers.image.version="8.4-prod" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.licenses="LicenseRef-Zenchron-Internal" \
      com.zenchron.runtime="php-frankenphp" \
      com.zenchron.php="8.4" \
      com.zenchron.support="supported"

# Install common production PHP extensions via the helper shipped in the image,
# then strip build tooling. Adjust the extension set per docs/php-extension-policy.md.
# hadolint ignore=DL3018
RUN install-php-extensions \
        opcache \
        intl \
        pdo_mysql \
        pdo_pgsql \
        zip \
        gd \
        bcmath \
        redis \
    && apk del --no-network .build-deps 2>/dev/null || true \
    && rm -rf /var/cache/apk/* /tmp/*

# Hardened production config.
COPY Caddyfile        /etc/frankenphp/Caddyfile
COPY php.ini          /usr/local/etc/php/conf.d/zz-zenchron.ini

# Deterministic non-root identity + writable runtime dirs (read-only rootfs:
# mount tmpfs for /data and /config, or use named volumes).
RUN addgroup -g 10001 app 2>/dev/null || true \
    && adduser -u 10001 -G app -h /app -s /sbin/nologin -D app 2>/dev/null || true \
    && mkdir -p /app /data/caddy /config/caddy \
    && chown -R 10001:10001 /app /data /config

ENV SERVER_NAME=":8080" \
    FRANKENPHP_CONFIG="" \
    XDG_DATA_HOME=/data \
    XDG_CONFIG_HOME=/config

USER 10001:10001
WORKDIR /app
EXPOSE 8080 8443

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["frankenphp", "version"]

ENTRYPOINT ["frankenphp"]
CMD ["run", "--config", "/etc/frankenphp/Caddyfile"]
