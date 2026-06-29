# syntax=docker/dockerfile:1.7
# =============================================================================
# Zenchron Dynamics — php-fpm 8.3 (production, Debian-first)
# Base: official php:8.3-fpm-bookworm (Debian 12), pinned by digest. Extensions
# are compiled with the official toolchain in a throwaway build stage; the
# runtime stage carries only the compiled .so + their shared libraries and the
# compiler toolchain is stripped (no build tools in the final image).
# Final image: non-root (10001:10001), read-only-rootfs compatible.
# Patch model: bump the pinned base digest to absorb CVEs — do NOT apt-get
# upgrade inside the image (see docs/security/base-image-patching.md).
# =============================================================================
ARG PHP_FPM_BASE="php:8.3-fpm-bookworm@sha256:36823ca48d6798ecef231042028a092e8e4b19146f126ba59cc56aa18e35dd7d"

# --- build stage: compile extensions with the official toolchain -------------
FROM ${PHP_FPM_BASE} AS build

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
FROM ${PHP_FPM_BASE} AS runtime

ARG BUILD_DATE
ARG VCS_REF

LABEL org.opencontainers.image.title="zenchron-php-fpm" \
      org.opencontainers.image.description="Hardened PHP-FPM 8.3 runtime (web app backend), Debian-based" \
      org.opencontainers.image.vendor="Zenchron Dynamics" \
      org.opencontainers.image.source="https://github.com/zenchron-dynamics/zenchron-foundry" \
      org.opencontainers.image.base.name="docker.io/library/php:8.3-fpm-bookworm" \
      org.opencontainers.image.version="8.3-prod" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.licenses="LicenseRef-Zenchron-Internal" \
      com.zenchron.runtime="php-fpm" \
      com.zenchron.php="8.3" \
      com.zenchron.base="debian-bookworm" \
      com.zenchron.support="supported"

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
