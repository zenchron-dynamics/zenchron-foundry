# syntax=docker/dockerfile:1.7
# =============================================================================
# Example Symfony application image on Zenchron platform bases.
#
# Every external reference below is DIGEST-PINNED (#109). Refresh with:
#
#     ../refresh-digests.sh
#
# There is deliberately NO `composer dump-env prod` in this build (#108/#109):
# it resolves the build environment into a checked-in .env.local.php, which bakes
# whatever secrets were present into an image layer. See the note below.
# =============================================================================

ARG PHP_CLI_BASE="ghcr.io/zenchron-dynamics/php-cli:8.3-prod@sha256:1c75cf2f712f6fda66c9c624723032ff812eae2af9c9e43fa2724e91cc71cf35"
ARG PHP_FPM_BASE="ghcr.io/zenchron-dynamics/php-fpm:8.3-prod@sha256:2044d7b3aad61f234d949d8e406c14cdb6386e4735dbd87148a895304aaef038"
ARG COMPOSER_BASE="composer:2@sha256:4d71c3c2109c61d5415544264b59ad4087e4c5b7244481723664138fd36d5040"

# --- builder: composer install + cache warmup (NOT shipped) -----------------
FROM ${COMPOSER_BASE} AS composer
FROM ${PHP_CLI_BASE} AS vendor
# hadolint ignore=DL3002
USER root
WORKDIR /app
COPY --from=composer /usr/bin/composer /usr/bin/composer
ENV APP_ENV=prod APP_DEBUG=0
COPY composer.json composer.lock symfony.lock ./
RUN composer install --no-dev --no-scripts --prefer-dist --no-interaction --optimize-autoloader
COPY . .
# `cache:warmup` compiles the service container. Symfony resolves %env()%
# placeholders at RUNTIME, not at compile time, so the warmed cache holds
# references rather than values and is safe to ship — unlike Laravel's
# config:cache, and unlike `composer dump-env prod`, which writes the resolved
# environment to disk. Neither of those appears in these examples.
#
# No `|| true` on any step here. A failed autoload dump or a failed warmup means
# the image is broken; suppressing the exit status ships it anyway and turns a
# build error into a runtime mystery.
RUN composer dump-autoload --optimize --classmap-authoritative \
 && php bin/console cache:warmup --env=prod

# --- runtime: php-fpm (ships) -----------------------------------------------
FROM ${PHP_FPM_BASE} AS app
WORKDIR /app
COPY --from=vendor --chown=10001:10001 /app /app
# var/ (cache, log, sessions) is a writable volume at runtime.
USER 10001:10001
EXPOSE 9000
