# syntax=docker/dockerfile:1.7
# Example Laravel application image built on the Zenchron platform bases.
# Pin bases by digest in real projects.

# --- builder: composer install (NOT shipped) --------------------------------
FROM ghcr.io/zenchron-dynamics/php-cli:8.3-prod AS vendor
# hadolint ignore=DL3002
USER root
WORKDIR /app
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
COPY composer.json composer.lock ./
RUN composer install --no-dev --no-scripts --prefer-dist --no-interaction --optimize-autoloader
COPY . .
RUN composer dump-autoload --optimize --classmap-authoritative \
 && php artisan config:cache \
 && php artisan route:cache

# --- runtime: php-fpm (ships) -----------------------------------------------
FROM ghcr.io/zenchron-dynamics/php-fpm:8.3-prod AS app
WORKDIR /app
COPY --from=vendor --chown=10001:10001 /app /app
# storage/ and bootstrap/cache are writable volumes at runtime.
USER 10001:10001
EXPOSE 9000
