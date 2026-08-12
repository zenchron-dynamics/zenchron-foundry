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
