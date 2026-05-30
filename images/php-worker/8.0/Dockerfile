# syntax=docker/dockerfile:1.7
# ██ LEGACY / EOL — PHP 8.0 worker. Compatibility only, unsupported, high risk. ██
# See docs/legacy-php-policy.md. One process per container; tini as PID 1.
ARG PHP_BASE="php:8.0-cli-alpine3.16@sha256:d3cd7dd3d043b0de163d36e9e8837f8a76770b970ad4df4e737a215793e9070b"
FROM ${PHP_BASE} AS runtime
ARG BUILD_DATE
ARG VCS_REF
LABEL org.opencontainers.image.title="zenchron-php-worker" \
      org.opencontainers.image.description="LEGACY EOL PHP 8.0 worker — compatibility only" \
      org.opencontainers.image.vendor="Zenchron Dynamics" \
      org.opencontainers.image.source="https://github.com/zenchron-dynamics/zenchron-foundry" \
      org.opencontainers.image.version="8.0-prod" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.licenses="LicenseRef-Zenchron-Internal" \
      com.zenchron.runtime="php-worker" com.zenchron.php="8.0" \
      com.zenchron.support="legacy-eol" com.zenchron.risk="high"
# hadolint ignore=DL3018,DL3019
RUN set -eux; \
    apk add --no-cache --virtual .build-deps $PHPIZE_DEPS icu-dev libzip-dev oniguruma-dev postgresql-dev; \
    docker-php-ext-install -j"$(nproc)" bcmath intl mbstring pdo pdo_mysql pdo_pgsql opcache zip pcntl posix; \
    pecl install redis && docker-php-ext-enable redis; \
    apk add --no-cache tini icu-libs libzip postgresql-libs; \
    apk del --no-network .build-deps; rm -rf /var/cache/apk/* /tmp/*; \
    addgroup -g 10001 app && adduser -u 10001 -G app -h /app -s /sbin/nologin -D app; \
    mkdir -p /app && chown -R 10001:10001 /app
USER 10001:10001
WORKDIR /app
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["php", "-v"]
