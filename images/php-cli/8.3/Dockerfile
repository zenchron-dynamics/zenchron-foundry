# syntax=docker/dockerfile:1.7
# =============================================================================
# Zenchron Dynamics — php-cli 8.3 (production)
# For artisan/console commands, migrations, one-off jobs.
# No web server, no Composer in the final image (Composer belongs in the app's
# OWN builder stage — see examples/ and docs/php-extension-policy.md).
# Non-root, read-only-rootfs compatible.
# =============================================================================
ARG WOLFI_BASE="cgr.dev/chainguard/wolfi-base:latest"

FROM ${WOLFI_BASE} AS runtime

ARG BUILD_DATE
ARG VCS_REF

LABEL org.opencontainers.image.title="zenchron-php-cli" \
      org.opencontainers.image.description="Hardened PHP 8.3 CLI runtime (console/maintenance jobs)" \
      org.opencontainers.image.vendor="Zenchron Dynamics" \
      org.opencontainers.image.source="https://github.com/zenchron-dynamics/docker-platform" \
      org.opencontainers.image.version="8.3-prod" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.licenses="LicenseRef-Zenchron-Internal" \
      com.zenchron.runtime="php-cli" \
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
        php-8.3-gd \
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
        tzdata \
        ca-certificates-bundle \
    && rm -rf /var/cache/apk/* \
    && addgroup -g 10001 app \
    && adduser -u 10001 -G app -h /app -s /sbin/nologin -D app \
    && mkdir -p /app && chown -R 10001:10001 /app

COPY php-cli.ini /etc/php/conf.d/zz-zenchron-cli.ini

USER 10001:10001
WORKDIR /app

# Default to the PHP CLI; the app supplies the script/command at deploy time,
# e.g.  docker run ... php artisan migrate --force
ENTRYPOINT ["php"]
CMD ["-v"]
