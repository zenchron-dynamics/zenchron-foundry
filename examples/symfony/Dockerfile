# syntax=docker/dockerfile:1.7
# Example Symfony application image on Zenchron platform bases. Pin by digest.

# --- builder: composer install + cache warmup (NOT shipped) -----------------
FROM ghcr.io/zenchron-dynamics/php-cli:8.3-prod AS vendor
USER root
WORKDIR /app
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
ENV APP_ENV=prod APP_DEBUG=0
COPY composer.json composer.lock symfony.lock ./
RUN composer install --no-dev --no-scripts --prefer-dist --no-interaction --optimize-autoloader
COPY . .
RUN composer dump-autoload --optimize --classmap-authoritative \
 && php bin/console cache:warmup --env=prod || true

# --- runtime: php-fpm (ships) -----------------------------------------------
FROM ghcr.io/zenchron-dynamics/php-fpm:8.3-prod AS app
WORKDIR /app
COPY --from=vendor --chown=10001:10001 /app /app
# var/ (cache, log, sessions) is a writable volume at runtime.
USER 10001:10001
EXPOSE 9000
