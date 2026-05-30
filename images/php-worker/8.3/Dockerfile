# syntax=docker/dockerfile:1.7
# =============================================================================
# Zenchron Dynamics — php-worker 8.3 (production)
# Long-running queue/messenger workers. One process per container (NO supervisor
# unless strictly justified). PID 1 must receive signals for graceful shutdown.
# Requires pcntl/posix for signal handling. Non-root, read-only-rootfs friendly.
# Graceful-stop & restart guidance: docs/runtime-hardening.md.
# =============================================================================
ARG WOLFI_BASE="cgr.dev/chainguard/wolfi-base:latest"

FROM ${WOLFI_BASE} AS runtime

ARG BUILD_DATE
ARG VCS_REF

LABEL org.opencontainers.image.title="zenchron-php-worker" \
      org.opencontainers.image.description="Hardened PHP 8.3 worker runtime (queue/messenger)" \
      org.opencontainers.image.vendor="Zenchron Dynamics" \
      org.opencontainers.image.source="https://github.com/zenchron-dynamics/zenchron-foundry" \
      org.opencontainers.image.version="8.3-prod" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.licenses="LicenseRef-Zenchron-Internal" \
      com.zenchron.runtime="php-worker" \
      com.zenchron.php="8.3" \
      com.zenchron.support="supported"

RUN apk add --no-cache \
        php-8.3 \
        php-8.3-opcache \
        php-8.3-bcmath \
        php-8.3-ctype \
        php-8.3-curl \
        php-8.3-dom \
        php-8.3-fileinfo \
        php-8.3-iconv \
        php-8.3-intl \
        php-8.3-mbstring \
        php-8.3-openssl \
        php-8.3-pcntl \
        php-8.3-pdo \
        php-8.3-mysqlnd \
        php-8.3-pdo_mysql \
        php-8.3-pdo_pgsql \
        php-8.3-phar \
        php-8.3-posix \
        php-8.3-redis \
        php-8.3-simplexml \
        php-8.3-sodium \
        php-8.3-xml \
        php-8.3-zip \
        tini \
        tzdata \
        ca-certificates-bundle \
    && rm -rf /var/cache/apk/* \
    && addgroup -g 10001 app \
    && adduser -u 10001 -G app -h /app -s /sbin/nologin -D app \
    && mkdir -p /app && chown -R 10001:10001 /app

COPY php-worker.ini /etc/php/conf.d/zz-zenchron-worker.ini

USER 10001:10001
WORKDIR /app

# tini as PID 1 reaps zombies and forwards SIGTERM to the worker for graceful
# stop. The app supplies the worker command, e.g.:
#   Laravel:  php artisan queue:work --max-time=3600 --max-jobs=1000 --stop-when-empty
#   Symfony:  php bin/console messenger:consume async --time-limit=3600 --memory-limit=256M
ENTRYPOINT ["tini", "--"]
CMD ["php", "-v"]
