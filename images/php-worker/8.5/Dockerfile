# syntax=docker/dockerfile:1.7
# =============================================================================
# Zenchron Dynamics — php-worker 8.5 (production, Debian-first)
# Long-running queue/messenger workers. One process per container (NO supervisor
# unless strictly justified). PID 1 must receive signals for graceful shutdown.
# Requires pcntl/posix for signal handling. Non-root, read-only-rootfs friendly.
# Base: official php:8.5-cli-bookworm (SAME base as php-cli) + tini + worker
# entrypoint/heartbeat. Extensions compiled with the official toolchain; the
# compiler toolchain is stripped from the final image.
# Graceful-stop & restart guidance: docs/worker-runtime.md.
# =============================================================================
ARG PHP_CLI_BASE="php:8.5-cli-bookworm@sha256:b3154b925899c55cca2885581c74cd9966484dc7469a36584353a6c8c26bbde0"

# --- build stage: compile extensions with the official toolchain -------------
FROM ${PHP_CLI_BASE} AS build

ARG PHPREDIS_VERSION="6.3.0"
# Integrity binding for the tarball above. Declared in
# policies/supply-chain-inputs.yaml; a mismatch fails the build.
ARG PHPREDIS_SHA256="0d5141f634bd1db6c1ddcda053d25ecf2c4fc1c395430d534fd3f8d51dd7f0b5"

# hadolint ignore=DL3008
# OPCACHE IS NOT COMPILED ON PHP 8.5.
# The official PHP 8.5 base already ships Zend OPcache built INTO the binary
# (`php -v` reports "with Zend OPcache v8.5.9"; `php -m` lists it). Asking
# docker-php-ext-install to build it produces no SHARED module and the build dies
# at `cp: cannot stat 'modules/*'`. Isolated by bisection 2026-08-23: opcache
# alone reproduces in 53 s; the full set minus opcache passes.
# OPcache is still REQUIRED at runtime and is verified present — it comes from the
# base instead of being compiled. PHP 8.3/8.4 keep compiling it and are unchanged.
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
        pcntl \
        pdo_pgsql \
        pgsql \
        pdo_mysql \
        sockets \
        zip \
        gd; \
    # #101: fetch and VERIFY, then install from the verified file. `pecl install
    # redis-X.Y.Z` pins the version but resolves and downloads the tarball
    # itself, so the build trusted whatever pecl.php.net served at that instant —
    # a version pin without an integrity binding. The checksum is declared in
    # policies/supply-chain-inputs.yaml and asserted against this line by
    # scripts/assert-supply-chain-inputs.sh, so the two cannot drift apart.
    curl -fsSL -o /tmp/redis.tgz \
        "https://pecl.php.net/get/redis-${PHPREDIS_VERSION}.tgz"; \
    # Written to a file rather than piped into `sha256sum -c -`: a pipe in a RUN
    # trips hadolint DL4006, and without `pipefail` a pipeline reports only its
    # LAST command — which happens to be correct here, but "happens to be" is not
    # how an integrity check should be written.
    printf '%s  /tmp/redis.tgz\n' "${PHPREDIS_SHA256}" > /tmp/redis.sha256; \
    sha256sum -c /tmp/redis.sha256; \
    rm -f /tmp/redis.sha256; \
    pecl install /tmp/redis.tgz; \
    rm -f /tmp/redis.tgz; \
    docker-php-ext-enable redis; \
    rm -rf /tmp/pear /var/lib/apt/lists/*

# --- runtime stage -----------------------------------------------------------
FROM ${PHP_CLI_BASE} AS runtime

ARG BUILD_DATE
ARG VCS_REF

LABEL org.opencontainers.image.title="zenchron-php-worker" \
      org.opencontainers.image.description="Hardened PHP 8.5 worker runtime (queue/messenger), Debian-based" \
      org.opencontainers.image.vendor="Zenchron Dynamics" \
      org.opencontainers.image.source="https://github.com/zenchron-dynamics/zenchron-foundry" \
      org.opencontainers.image.base.name="docker.io/library/php:8.5-cli-bookworm" \
      org.opencontainers.image.version="8.5-prod" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.licenses="LicenseRef-Zenchron-Internal" \
      com.zenchron.runtime="php-worker" \
      com.zenchron.php="8.5" \
      com.zenchron.base="debian-bookworm" \
      com.zenchron.support="supported" \
      com.zenchron.support_state="active"

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
    # #101: build RESIDUE, not image content. apt/dpkg logs record WHEN the
    # build ran and ldconfig's aux-cache embeds timestamps, so two builds of the
    # same commit differed in exactly these 8 files out of 3505 — enough to
    # change a layer digest while the served content was identical. Removing
    # them makes the layer reproducible, and also stops shipping a record of the
    # build host's clock to consumers.
    rm -rf /var/log/apt /var/log/dpkg.log /var/log/alternatives.log \
           /var/cache/ldconfig/aux-cache; \
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
