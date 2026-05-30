# syntax=docker/dockerfile:1.7
# =============================================================================
#  ██  LEGACY / END-OF-LIFE RUNTIME — HIGH RISK  ██
#  PHP 7.4 reached end-of-life on 2022-11-28. It receives NO upstream security
#  patches. This image exists ONLY for legacy application compatibility and
#  carries accepted, documented risk. DO NOT use for new systems.
#  See docs/legacy-php-policy.md.
#
#  Distroless/Wolfi is NOT available for EOL PHP, so this image is built on the
#  official php:7.4-fpm-alpine base (minimal, but not hardened-minimal Wolfi).
#  Still hardened to platform standards: non-root, read-only-rootfs friendly.
# =============================================================================
ARG PHP_BASE="php:7.4-fpm-alpine3.16"

FROM ${PHP_BASE} AS runtime

ARG BUILD_DATE
ARG VCS_REF

LABEL org.opencontainers.image.title="zenchron-php-fpm" \
      org.opencontainers.image.description="LEGACY EOL PHP-FPM 7.4 — compatibility only, unsupported" \
      org.opencontainers.image.vendor="Zenchron Dynamics" \
      org.opencontainers.image.source="https://github.com/zenchron-dynamics/zenchron-foundry" \
      org.opencontainers.image.version="7.4-prod" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.licenses="LicenseRef-Zenchron-Internal" \
      com.zenchron.runtime="php-fpm" \
      com.zenchron.php="7.4" \
      com.zenchron.support="legacy-eol" \
      com.zenchron.risk="high"

# Common extensions via the official helper; build deps removed afterwards.
# hadolint ignore=DL3018,DL3019,DL4006,SC2086
RUN set -eux; \
    apk add --no-cache --virtual .build-deps \
        $PHPIZE_DEPS icu-dev libzip-dev oniguruma-dev libpng-dev postgresql-dev; \
    docker-php-ext-install -j"$(nproc)" \
        bcmath intl mbstring pdo pdo_mysql pdo_pgsql opcache gd zip; \
    pecl install redis && docker-php-ext-enable redis; \
    runDeps="$( \
        scanelf --needed --nobanner --format '%n#p' --recursive /usr/local/lib/php/extensions \
        | tr ',' '\n' | sort -u | awk 'system("[ -e /usr/local/lib/"$1" ]") == 0 {next} {print "so:"$1}' \
    )"; \
    apk add --no-cache --virtual .phpext-runtime $runDeps icu-libs libzip libpng postgresql-libs; \
    apk del --no-network .build-deps; \
    rm -rf /var/cache/apk/* /tmp/* /usr/local/lib/php/.registry

# Deterministic non-root identity.
RUN addgroup -g 10001 app \
    && adduser -u 10001 -G app -h /app -s /sbin/nologin -D app \
    && mkdir -p /app /var/run/php && chown -R 10001:10001 /app /var/run/php

COPY php.ini      /usr/local/etc/php/conf.d/zz-zenchron.ini
COPY www.conf     /usr/local/etc/php-fpm.d/zz-www.conf

USER 10001:10001
WORKDIR /app
EXPOSE 9000

# Minimal TCP healthcheck — the official base lacks cgi-fcgi; rely on an
# orchestrator TCP probe or add fcgi explicitly. See legacy-php-policy.md.
ENTRYPOINT ["php-fpm", "--nodaemonize"]
