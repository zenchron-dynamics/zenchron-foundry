# syntax=docker/dockerfile:1.7
# =============================================================================
# Zenchron Dynamics — php-fpm 8.4 (production)
# Base strategy: Chainguard Wolfi (hardened-minimal, apk-based, low-CVE).
# Multi-stage: build tools never reach the final image.
# Final image: non-root (10001:10001), read-only-rootfs compatible.
# True Google distroless is not used — PHP-FPM needs shared libs + a healthcheck
# client. See docs/distroless-strategy.md for the full rationale.
# Pin BASE_DIGEST in CI (Dependabot updates it). Tag here for local dev.
# =============================================================================
ARG WOLFI_BASE="cgr.dev/chainguard/wolfi-base:latest"

# ---- builder ----------------------------------------------------------------
FROM ${WOLFI_BASE} AS builder
# Builder may have apk/build tooling; it is discarded.
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
        php-8.4-pdo_mysql \
        php-8.4-pdo_pgsql \
        php-8.4-phar \
        php-8.4-session \
        php-8.4-simplexml \
        php-8.4-sodium \
        php-8.4-tokenizer \
        php-8.4-xml \
        php-8.4-zip \
        php-8.4-redis \
        fcgi

# ---- runtime ----------------------------------------------------------------
FROM ${WOLFI_BASE} AS runtime

ARG PHP_VERSION="8.4"
ARG BUILD_DATE
ARG VCS_REF

LABEL org.opencontainers.image.title="zenchron-php-fpm" \
      org.opencontainers.image.description="Hardened PHP-FPM 8.3 runtime (web app backend)" \
      org.opencontainers.image.vendor="Zenchron Dynamics" \
      org.opencontainers.image.source="https://github.com/zenchron-dynamics/docker-platform" \
      org.opencontainers.image.version="8.4-prod" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.licenses="LicenseRef-Zenchron-Internal" \
      com.zenchron.runtime="php-fpm" \
      com.zenchron.php="8.4" \
      com.zenchron.support="supported"

# Install only runtime packages (no -dev, no compilers, no composer).
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
        php-8.4-pdo_mysql \
        php-8.4-pdo_pgsql \
        php-8.4-phar \
        php-8.4-session \
        php-8.4-simplexml \
        php-8.4-sodium \
        php-8.4-tokenizer \
        php-8.4-xml \
        php-8.4-zip \
        php-8.4-redis \
        fcgi \
        tzdata \
        ca-certificates-bundle \
    && rm -rf /var/cache/apk/* \
    # Deterministic non-root identity.
    && addgroup -g 10001 app \
    && adduser -u 10001 -G app -h /app -s /sbin/nologin -D app \
    && mkdir -p /app /var/run/php /var/log/php \
    && chown -R 10001:10001 /app /var/run/php /var/log/php

# Production configuration (no app code, no secrets).
COPY php.ini        /etc/php/8.4/php-fpm.d/zz-zenchron-php.ini
COPY php-fpm.conf   /etc/php/8.4/php-fpm.conf
COPY www.conf       /etc/php/8.4/php-fpm.d/www.conf
COPY docker-healthcheck.sh /usr/local/bin/docker-healthcheck

RUN chmod 0555 /usr/local/bin/docker-healthcheck

USER 10001:10001
WORKDIR /app
EXPOSE 9000

# FPM exposes a ping endpoint (see www.conf); cgi-fcgi queries it.
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/docker-healthcheck"]

# php-fpm.conf sets `daemonize = no` for proper PID1 signal handling.
ENTRYPOINT ["php-fpm8.4", "--nodaemonize", "--fpm-config", "/etc/php/8.4/php-fpm.conf"]
