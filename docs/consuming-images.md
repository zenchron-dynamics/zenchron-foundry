# Consuming Platform Images

How an application repo builds on these base images. The pattern is always:
**multi-stage** — vendor/build in a builder stage, copy only artifacts into a
platform runtime base. No Composer in the final app image.

> Pin bases by digest in production. Tags shown for readability.

## 1. Laravel — php-fpm + nginx

```dockerfile
# syntax=docker/dockerfile:1.7
# --- builder: composer + assets (NOT shipped) ---
FROM ghcr.io/zenchron-dynamics/php-cli:8.3-prod AS vendor
USER root
WORKDIR /app
# Composer provided here only (copy the binary from the official image).
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
COPY composer.json composer.lock ./
RUN composer install --no-dev --no-scripts --prefer-dist --no-interaction --optimize-autoloader
COPY . .
RUN composer dump-autoload --optimize --classmap-authoritative

# --- runtime: php-fpm (ships) ---
FROM ghcr.io/zenchron-dynamics/php-fpm:8.3-prod AS app
WORKDIR /app
COPY --from=vendor --chown=10001:10001 /app /app
# storage/ & bootstrap/cache are mounted writable at runtime (see compose).
USER 10001:10001
```

`nginx` serves `/app/public` and proxies `*.php` to `php-fpm:9000`. Compose:

```bash
docker compose \
  -f compose.yml \
  -f profiles/compose.security.yml \
  -f profiles/compose.readonly.yml \
  -f profiles/compose.laravel.yml up -d
```

See [examples/laravel](../examples/laravel).

## 2. Laravel — php-fpm + Caddy

Same app image; swap the edge. Use `profiles/compose.caddy.yml` and mount a
site config copied from `images/caddy/conf.d/app.caddy.example`. Caddy's
`php_fastcgi php-fpm:9000` replaces the nginx FastCGI block.

## 3. Symfony — php-fpm + nginx

```dockerfile
FROM ghcr.io/zenchron-dynamics/php-cli:8.3-prod AS vendor
USER root
WORKDIR /app
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
COPY composer.json composer.lock symfony.lock ./
RUN composer install --no-dev --no-scripts --prefer-dist --no-interaction --optimize-autoloader
COPY . .
ENV APP_ENV=prod
RUN composer dump-env prod || true \
 && php bin/console cache:warmup --env=prod

FROM ghcr.io/zenchron-dynamics/php-fpm:8.3-prod AS app
WORKDIR /app
COPY --from=vendor --chown=10001:10001 /app /app
USER 10001:10001
```

Writable `var/` is externalized (`profiles/compose.symfony.yml` → `/app/var`).
See [examples/symfony](../examples/symfony).

## 4. FrankenPHP app

```dockerfile
FROM ghcr.io/zenchron-dynamics/php-cli:8.3-prod AS vendor
USER root
WORKDIR /app
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
COPY composer.json composer.lock ./
RUN composer install --no-dev --prefer-dist --no-interaction --optimize-autoloader
COPY . .

FROM ghcr.io/zenchron-dynamics/php-frankenphp:8.3-prod AS app
WORKDIR /app
COPY --from=vendor --chown=10001:10001 /app /app
USER 10001:10001
# Caddyfile from the base serves /app/public; enable worker mode for throughput.
```

No separate nginx/fpm — FrankenPHP is the server. See
[examples/frankenphp](../examples/frankenphp).

## 5. Queue worker

Reuse the **app image** (it already has the code) but override the command, or
build from `php-worker`:

```bash
docker compose run --rm worker \
  php artisan queue:work --max-time=3600 --max-jobs=1000 --memory=200
```

`profiles/compose.php-worker.yml` / `compose.laravel.yml` wire this with
`stop_grace_period` for graceful shutdown.

## 6. CLI / migration job

```bash
docker compose -f compose.yml -f profiles/compose.laravel.yml \
  --profile cli run --rm migrate            # runs: php artisan migrate --force
# or ad-hoc:
docker compose run --rm php-cli php artisan about
```

## Golden rules for consumers

- `FROM` a platform base; never re-derive a runtime from scratch.
- Composer/build tools live in the **builder** stage only.
- `COPY --chown=10001:10001`; keep the runtime non-root.
- Externalize writable paths (storage/var); don't disable read-only rootfs.
- Pin the base **by digest** and **verify its signature** in your CI.
