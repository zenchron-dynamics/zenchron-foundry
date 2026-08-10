# syntax=docker/dockerfile:1.7
# =============================================================================
# Example Laravel application image built on the Zenchron platform bases.
#
# Every external reference below is DIGEST-PINNED (#109). Reference code that
# says "pin your digests" while itself using a moving tag teaches the opposite of
# what it claims. Refresh the digests with:
#
#     ./refresh-digests.sh          (in this directory)
#
# There is deliberately NO `php artisan config:cache` in this build (#108). See
# the note above the runtime stage.
# =============================================================================

ARG PHP_CLI_BASE="ghcr.io/zenchron-dynamics/php-cli:8.3-prod@sha256:1c75cf2f712f6fda66c9c624723032ff812eae2af9c9e43fa2724e91cc71cf35"
ARG PHP_FPM_BASE="ghcr.io/zenchron-dynamics/php-fpm:8.3-prod@sha256:2044d7b3aad61f234d949d8e406c14cdb6386e4735dbd87148a895304aaef038"
ARG COMPOSER_BASE="composer:2@sha256:4d71c3c2109c61d5415544264b59ad4087e4c5b7244481723664138fd36d5040"

# --- builder: composer install (NOT shipped) --------------------------------
FROM ${COMPOSER_BASE} AS composer
FROM ${PHP_CLI_BASE} AS vendor
# hadolint ignore=DL3002
USER root
WORKDIR /app
COPY --from=composer /usr/bin/composer /usr/bin/composer
COPY composer.json composer.lock ./
RUN composer install --no-dev --no-scripts --prefer-dist --no-interaction --optimize-autoloader
COPY . .
# `route:cache` serialises the route table only. It resolves no configuration and
# reads no environment, so it is safe to bake into a layer.
#
# `config:cache` is NOT here, on purpose. Laravel resolves env() calls while
# WRITING the config cache, so whatever DB password, API key or endpoint is in
# the build environment gets frozen into bootstrap/cache/config.php — a layer
# that then travels through the registry, the SBOM and every provenance
# attestation. Cache configuration at DEPLOY time, after secrets are mounted:
#
#     command: sh -c 'php artisan config:cache && php-fpm'
#
# writing into the writable bootstrap/cache volume declared below. The trade-off
# is one extra second at container start in exchange for not shipping secrets.
RUN composer dump-autoload --optimize --classmap-authoritative \
 && php artisan route:cache

# --- runtime: php-fpm (ships) -----------------------------------------------
FROM ${PHP_FPM_BASE} AS app
WORKDIR /app
COPY --from=vendor --chown=10001:10001 /app /app
# storage/ and bootstrap/cache are writable volumes at runtime — bootstrap/cache
# is where a deploy-time `config:cache` writes.
USER 10001:10001
EXPOSE 9000
