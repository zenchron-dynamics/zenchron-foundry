# syntax=docker/dockerfile:1.7
# =============================================================================
# Example FrankenPHP app image.
# Every external reference is DIGEST-PINNED (#109); refresh with
# ../refresh-digests.sh.
# =============================================================================

ARG PHP_CLI_BASE="ghcr.io/zenchron-dynamics/php-cli:8.3-prod@sha256:1c75cf2f712f6fda66c9c624723032ff812eae2af9c9e43fa2724e91cc71cf35"
ARG FRANKENPHP_BASE="ghcr.io/zenchron-dynamics/php-frankenphp:8.3-prod@sha256:e12c84ed1349492240bec14ef7eb9748eecf5288867569c1ac93ebcbe2a77b58"
ARG COMPOSER_BASE="composer:2@sha256:4d71c3c2109c61d5415544264b59ad4087e4c5b7244481723664138fd36d5040"

FROM ${COMPOSER_BASE} AS composer
FROM ${PHP_CLI_BASE} AS vendor
# hadolint ignore=DL3002
USER root
WORKDIR /app
COPY --from=composer /usr/bin/composer /usr/bin/composer
COPY composer.json composer.lock ./
RUN composer install --no-dev --no-scripts --prefer-dist --no-interaction --optimize-autoloader
COPY . .
RUN composer dump-autoload --optimize --classmap-authoritative

FROM ${FRANKENPHP_BASE} AS app
WORKDIR /app
COPY --from=vendor --chown=10001:10001 /app /app
USER 10001:10001
EXPOSE 8080 8443
# Base image's ENTRYPOINT runs FrankenPHP with the hardened Caddyfile.
