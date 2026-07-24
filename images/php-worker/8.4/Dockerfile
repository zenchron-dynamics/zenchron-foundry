# syntax=docker/dockerfile:1.7
# =============================================================================
# Zenchron Dynamics — php-worker 8.4 (production, Debian-first)
# Long-running queue/messenger workers. One process per container (NO supervisor
# unless strictly justified). PID 1 must receive signals for graceful shutdown.
# Requires pcntl/posix for signal handling. Non-root, read-only-rootfs friendly.
# Base: official php:8.4-cli-bookworm (SAME base as php-cli) + tini + worker
# entrypoint/heartbeat. Extensions compiled with the official toolchain; the
# compiler toolchain is stripped from the final image.
# Graceful-stop & restart guidance: docs/worker-runtime.md.
# =============================================================================
ARG PHP_CLI_BASE="php:8.4-cli-bookworm@sha256:138a210978c7767ef2a26f499c413fe6de1c13233c9a5068139565c81191b1ac"

# --- build stage: compile extensions with the official toolchain -------------
FROM ${PHP_CLI_BASE} AS build

ARG PHPREDIS_VERSION="6.1.0"

# hadolint ignore=DL3008
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ${PHPIZE_DEPS} \
        libicu-dev \
        libpq-dev \
        libzip-dev \
        libpng-dev \
        libjpeg62-turbo-dev \
        libfreetype6-dev; \
    docker-php-ext-configure gd --with-jpeg --with-freetype; \
    docker-php-ext-install -j"$(nproc)" \
        bcmath \
        intl \
        opcache \
        pcntl \
        pdo_pgsql \
        pgsql \
        pdo_mysql \
        sockets \
        zip \
        gd; \
    pecl install "redis-${PHPREDIS_VERSION}"; \
    docker-php-ext-enable redis; \
    rm -rf /tmp/pear /var/lib/apt/lists/*

# --- runtime stage -----------------------------------------------------------
FROM ${PHP_CLI_BASE} AS runtime

ARG BUILD_DATE
ARG VCS_REF

LABEL org.opencontainers.image.title="zenchron-php-worker" \
      org.opencontainers.image.description="Hardened PHP 8.4 worker runtime (queue/messenger), Debian-based" \
      org.opencontainers.image.vendor="Zenchron Dynamics" \
      org.opencontainers.image.source="https://github.com/zenchron-dynamics/zenchron-foundry" \
      org.opencontainers.image.base.name="docker.io/library/php:8.4-cli-bookworm" \
      org.opencontainers.image.version="8.4-prod" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.licenses="LicenseRef-Zenchron-Internal" \
      com.zenchron.runtime="php-worker" \
      com.zenchron.php="8.4" \
      com.zenchron.base="debian-bookworm" \
      com.zenchron.support="supported"

# Runtime shared libraries + tini (PID 1 init), then strip the compiler toolchain.
# hadolint ignore=DL3008
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        libicu72 \
        libpq5 \
        libzip4 \
        libpng16-16 \
        libjpeg62-turbo \
        libfreetype6 \
        tini \
        tzdata \
        ca-certificates; \
    apt-get purge -y --auto-remove \
        gcc g++ cpp make autoconf binutils dpkg-dev libc6-dev m4 patch re2c; \
    rm -f /usr/local/bin/phpize /usr/local/bin/docker-php-source; \
    rm -rf /usr/src/*; \
    rm -rf /var/lib/apt/lists/*; \
    groupadd -g 10001 app; \
    useradd  -u 10001 -g app -d /app -s /usr/sbin/nologin -M app; \
    mkdir -p /app; chown -R 10001:10001 /app

COPY --from=build /usr/local/lib/php/extensions/ /usr/local/lib/php/extensions/
COPY --from=build /usr/local/etc/php/conf.d/ /usr/local/etc/php/conf.d/

COPY php-worker.ini /usr/local/etc/php/conf.d/zz-zenchron-worker.ini
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
