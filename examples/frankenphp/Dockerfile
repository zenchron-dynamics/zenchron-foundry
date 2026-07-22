# syntax=docker/dockerfile:1.7
# Example FrankenPHP app image. Pin bases by digest in real projects.
FROM ghcr.io/zenchron-dynamics/php-cli:8.3-prod AS vendor
# hadolint ignore=DL3002
USER root
WORKDIR /app
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
COPY composer.json composer.lock ./
RUN composer install --no-dev --no-scripts --prefer-dist --no-interaction --optimize-autoloader
COPY . .
RUN composer dump-autoload --optimize --classmap-authoritative

FROM ghcr.io/zenchron-dynamics/php-frankenphp:8.3-prod AS app
WORKDIR /app
COPY --from=vendor --chown=10001:10001 /app /app
USER 10001:10001
EXPOSE 8080 8443
# Base image's ENTRYPOINT runs FrankenPHP with the hardened Caddyfile.
