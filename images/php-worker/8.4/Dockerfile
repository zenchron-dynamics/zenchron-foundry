# syntax=docker/dockerfile:1.7
# =============================================================================
# Zenchron Dynamics — php-worker 8.3 (production)
# Long-running queue/messenger workers. One process per container (NO supervisor
# unless strictly justified). PID 1 must receive signals for graceful shutdown.
# Requires pcntl/posix for signal handling. Non-root, read-only-rootfs friendly.
# Graceful-stop & restart guidance: docs/runtime-hardening.md.
# =============================================================================
ARG WOLFI_BASE="cgr.dev/chainguard/wolfi-base:latest@sha256:441d6709305552a3411e585ad98aacb9dadda00c80f3267483c38ac6f86f49d4"

FROM ${WOLFI_BASE} AS runtime

ARG BUILD_DATE
ARG VCS_REF

LABEL org.opencontainers.image.title="zenchron-php-worker" \
      org.opencontainers.image.description="Hardened PHP 8.4 worker runtime (queue/messenger)" \
      org.opencontainers.image.vendor="Zenchron Dynamics" \
      org.opencontainers.image.source="https://github.com/zenchron-dynamics/zenchron-foundry" \
      org.opencontainers.image.version="8.4-prod" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.licenses="LicenseRef-Zenchron-Internal" \
      com.zenchron.runtime="php-worker" \
      com.zenchron.php="8.4" \
      com.zenchron.support="supported"

RUN apk add --no-cache \
        php-8.4 \
        php-8.4-opcache \
        php-8.4-bcmath \
        php-8.4-ctype \
        php-8.4-curl \
        php-8.4-dom \
        php-8.4-fileinfo \
        php-8.4-iconv \
        php-8.4-intl \
        php-8.4-mbstring \
        php-8.4-openssl \
        php-8.4-pcntl \
        php-8.4-pdo \
        php-8.4-mysqlnd \
        php-8.4-pdo_mysql \
        php-8.4-pdo_pgsql \
        php-8.4-phar \
        php-8.4-posix \
        php-8.4-redis \
        php-8.4-simplexml \
        php-8.4-sodium \
        php-8.4-xml \
        php-8.4-zip \
        tini \
        tzdata \
        ca-certificates-bundle \
    && rm -rf /var/cache/apk/* \
    && addgroup -g 10001 app \
    && adduser -u 10001 -G app -h /app -s /sbin/nologin -D app \
    && mkdir -p /app && chown -R 10001:10001 /app

COPY php-worker.ini /etc/php/conf.d/zz-zenchron-worker.ini
COPY worker-entrypoint  /usr/local/bin/worker-entrypoint
COPY worker-healthcheck /usr/local/bin/worker-healthcheck
RUN chmod 0555 /usr/local/bin/worker-entrypoint /usr/local/bin/worker-healthcheck

USER 10001:10001
WORKDIR /app

# Liveness via heartbeat (see worker-entrypoint / docs/worker-runtime.md). The
# heartbeat lives in tmpfs /tmp, so this works under a read-only rootfs.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["/usr/local/bin/worker-healthcheck"]

# tini (PID 1) reaps zombies and forwards SIGTERM; worker-entrypoint maintains
# the heartbeat and forwards signals to the worker for graceful stop. The app
# supplies the worker command, e.g.:
#   Laravel:  php artisan queue:work --max-time=3600 --max-jobs=1000 --stop-when-empty
#   Symfony:  php bin/console messenger:consume async --time-limit=3600 --memory-limit=256M
ENTRYPOINT ["tini", "--", "/usr/local/bin/worker-entrypoint"]
CMD ["php", "-v"]
