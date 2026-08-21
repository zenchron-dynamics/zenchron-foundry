# syntax=docker/dockerfile:1.7
# =============================================================================
# Zenchron Dynamics — php-fpm 8.5 (production, Debian-first)
# Base: official php:8.5-fpm-bookworm (Debian 12), pinned by digest. Extensions
# are compiled with the official toolchain in a throwaway build stage; the
# runtime stage carries only the compiled .so + their shared libraries and the
# compiler toolchain is stripped (no build tools in the final image).
# Final image: non-root (10001:10001), read-only-rootfs compatible.
# Patch model: bump the pinned base digest to absorb CVEs — do NOT apt-get
# upgrade inside the image (see docs/security/base-image-patching.md).
# =============================================================================
ARG PHP_FPM_BASE="php:8.5-fpm-bookworm@sha256:7b1deadd1d73c72d2eb952ebb494cd3e902d7b6ae4e4b3cd1113a1041b530c2c"

# --- build stage: compile extensions with the official toolchain -------------
FROM ${PHP_FPM_BASE} AS build

ARG PHPREDIS_VERSION="6.1.0"
# Integrity binding for the tarball above. Declared in
# policies/supply-chain-inputs.yaml; a mismatch fails the build.
ARG PHPREDIS_SHA256="f10405f639fe415e9ed4ec99538e72c90694d8dbd62868edcfcd6a453466b48c"

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
FROM ${PHP_FPM_BASE} AS runtime

ARG BUILD_DATE
ARG VCS_REF

LABEL org.opencontainers.image.title="zenchron-php-fpm" \
      org.opencontainers.image.description="Hardened PHP-FPM 8.5 runtime (web app backend), Debian-based" \
      org.opencontainers.image.vendor="Zenchron Dynamics" \
      org.opencontainers.image.source="https://github.com/zenchron-dynamics/zenchron-foundry" \
      org.opencontainers.image.base.name="docker.io/library/php:8.5-fpm-bookworm" \
      org.opencontainers.image.version="8.5-prod" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.licenses="LicenseRef-Zenchron-Internal" \
      com.zenchron.runtime="php-fpm" \
      com.zenchron.php="8.5" \
      com.zenchron.base="debian-bookworm" \
      com.zenchron.support="supported" \
      com.zenchron.support_state="active"

# Runtime shared libraries only, then strip the inherited compiler toolchain.
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

# Production configuration (no app code, no secrets). Official php paths: /usr/local/etc.
COPY php.ini        /usr/local/etc/php/conf.d/zz-zenchron.ini
COPY php-fpm.conf   /usr/local/etc/php-fpm.conf
COPY www.conf       /usr/local/etc/php-fpm.d/www.conf
COPY docker-healthcheck.sh /usr/local/bin/docker-healthcheck

# Drop the base image's zz-docker.conf pool override so there is exactly one
# [www] pool, and make the healthcheck executable.
RUN set -eux; \
    rm -f /usr/local/etc/php-fpm.d/zz-docker.conf /usr/local/etc/php-fpm.d/www.conf.default; \
    chmod 0555 /usr/local/bin/docker-healthcheck

USER 10001:10001
WORKDIR /app
EXPOSE 9000

# No curl/wget/cgi-fcgi in a hardened image: probe the FPM TCP listener with the
# bundled php binary. A successful connect means FPM is accepting work.
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/docker-healthcheck"]

# --nodaemonize keeps php-fpm as PID 1 for correct SIGTERM/SIGQUIT handling.
ENTRYPOINT ["php-fpm", "--nodaemonize", "--fpm-config", "/usr/local/etc/php-fpm.conf"]
