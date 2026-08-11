# syntax=docker/dockerfile:1.7
# =============================================================================
# Zenchron Dynamics — php-cli 8.4 (production, Debian-first)
# For artisan/console commands, migrations, one-off jobs. No web server, no
# Composer in the final image (Composer belongs in the app's OWN builder stage —
# see examples/ and docs/php-extension-policy.md).
# Base: official php:8.4-cli-bookworm (Debian 12), pinned by digest.
# Extensions are COMPILED with the official toolchain in a throwaway build stage;
# the runtime stage carries only the compiled .so files + their shared libraries,
# so NO compiler/autoconf/make reaches the final image.
# Final image: non-root (10001:10001), read-only-rootfs compatible.
# =============================================================================
ARG PHP_CLI_BASE="php:8.4-cli-bookworm@sha256:138a210978c7767ef2a26f499c413fe6de1c13233c9a5068139565c81191b1ac"

# --- build stage: compile extensions with the official toolchain -------------
FROM ${PHP_CLI_BASE} AS build

# pecl extension versions are pinned for reproducibility (see php-extension-matrix).
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

# --- runtime stage: official base + runtime libs + compiled extensions -------
FROM ${PHP_CLI_BASE} AS runtime

ARG BUILD_DATE
ARG VCS_REF

LABEL org.opencontainers.image.title="zenchron-php-cli" \
      org.opencontainers.image.description="Hardened PHP 8.4 CLI runtime (console/maintenance jobs), Debian-based" \
      org.opencontainers.image.vendor="Zenchron Dynamics" \
      org.opencontainers.image.source="https://github.com/zenchron-dynamics/zenchron-foundry" \
      org.opencontainers.image.base.name="docker.io/library/php:8.4-cli-bookworm" \
      org.opencontainers.image.version="8.4-prod" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.licenses="LicenseRef-Zenchron-Internal" \
      com.zenchron.runtime="php-cli" \
      com.zenchron.php="8.4" \
      com.zenchron.base="debian-bookworm" \
      com.zenchron.support="supported" \
      com.zenchron.support_state="active"

# Runtime shared libraries for the compiled extensions ONLY (no -dev), then strip
# the compiler toolchain the official php base inherits from buildpack-deps so no
# build tools reach the final image (validation gate: "no build tools in final").
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

# Compiled extensions + their generated enable-conf, from the build stage.
COPY --from=build /usr/local/lib/php/extensions/ /usr/local/lib/php/extensions/
COPY --from=build /usr/local/etc/php/conf.d/ /usr/local/etc/php/conf.d/

COPY php-cli.ini /usr/local/etc/php/conf.d/zz-zenchron-cli.ini

USER 10001:10001
WORKDIR /app

# Default to the PHP CLI; the app supplies the script/command at deploy time,
# e.g.  docker run ... php artisan migrate --force
ENTRYPOINT ["php"]
CMD ["-v"]
