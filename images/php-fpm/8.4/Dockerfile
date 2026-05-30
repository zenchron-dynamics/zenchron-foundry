# syntax=docker/dockerfile:1.7
# =============================================================================
# Zenchron Dynamics — php-fpm 8.4 (production)
# Base: Chainguard Wolfi (hardened-minimal, apk-based, low-CVE). PHP extensions
# ship as prebuilt apk packages, so NO compiler/builder stage is required — the
# image stays minimal with runtime packages only. See docs/distroless-strategy.md.
# Final image: non-root (10001:10001), read-only-rootfs compatible.
# Pin WOLFI_BASE by digest in CI (Dependabot updates it).
# =============================================================================
ARG WOLFI_BASE="cgr.dev/chainguard/wolfi-base:latest"

FROM ${WOLFI_BASE} AS runtime

ARG BUILD_DATE
ARG VCS_REF

LABEL org.opencontainers.image.title="zenchron-php-fpm" \
      org.opencontainers.image.description="Hardened PHP-FPM 8.4 runtime (web app backend)" \
      org.opencontainers.image.vendor="Zenchron Dynamics" \
      org.opencontainers.image.source="https://github.com/zenchron-dynamics/zenchron-foundry" \
      org.opencontainers.image.version="8.4-prod" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.licenses="LicenseRef-Zenchron-Internal" \
      com.zenchron.runtime="php-fpm" \
      com.zenchron.php="8.4" \
      com.zenchron.support="supported"

# Runtime packages only. session/tokenizer are compiled into the core php-8.4
# package in Wolfi, so they are NOT separate apk packages.
# hadolint ignore=DL3018
RUN apk add --no-cache \
        php-8.4 \
        php-8.4-fpm \
        php-8.4-opcache \
        php-8.4-bcmath \
        php-8.4-ctype \
        php-8.4-curl \
        php-8.4-dom \
        php-8.4-fileinfo \
        php-8.4-gd \
        php-8.4-iconv \
        php-8.4-intl \
        php-8.4-mbstring \
        php-8.4-openssl \
        php-8.4-pdo \
        php-8.4-mysqlnd \
        php-8.4-pdo_mysql \
        php-8.4-pdo_pgsql \
        php-8.4-phar \
        php-8.4-simplexml \
        php-8.4-sodium \
        php-8.4-xml \
        php-8.4-zip \
        php-8.4-redis \
        tzdata \
        ca-certificates-bundle \
    && rm -rf /var/cache/apk/* \
    && addgroup -g 10001 app \
    && adduser -u 10001 -G app -h /app -s /sbin/nologin -D app \
    && mkdir -p /app /var/run/php \
    && chown -R 10001:10001 /app /var/run/php

# Production configuration (no app code, no secrets). Wolfi paths: /etc/php/*.
COPY php.ini        /etc/php/conf.d/zz-zenchron.ini
COPY php-fpm.conf   /etc/php/php-fpm.conf
COPY www.conf       /etc/php/php-fpm.d/www.conf
COPY docker-healthcheck.sh /usr/local/bin/docker-healthcheck

# Drop the base apko pool override so there is exactly one [www] pool, and make
# the healthcheck executable.
RUN rm -f /etc/php/php-fpm.d/zz-apko.conf \
    && chmod 0555 /usr/local/bin/docker-healthcheck

USER 10001:10001
WORKDIR /app
EXPOSE 9000

# No curl/wget/cgi-fcgi in a hardened image: probe the FPM TCP listener with the
# bundled php binary. A successful connect means FPM is accepting work.
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/docker-healthcheck"]

# --nodaemonize keeps php-fpm as PID 1 for correct SIGTERM/SIGQUIT handling.
ENTRYPOINT ["php-fpm", "--nodaemonize", "--fpm-config", "/etc/php/php-fpm.conf"]
