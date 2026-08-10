# Consuming Platform Images

How an application repo builds on these base images. The pattern is always:
**multi-stage** — vendor/build in a builder stage, copy only artifacts into a
platform runtime base. No Composer in the final app image.

> **Every reference below is digest-pinned, including in the snippets.** This
> document used to say "pin by digest in production. Tags shown for readability"
> and then show tag-only `FROM` lines — reference code that teaches the opposite
> of what it asks for (#109). The checked-in examples under
> [`examples/`](../examples) carry the same pins; refresh both with
> [`examples/refresh-digests.sh`](../examples/refresh-digests.sh).
>
> The digests below are a snapshot. Re-resolve them for your own build rather
> than trusting this page to be current — that is exactly what the refresh
> script is for.

## 1. Laravel — php-fpm + nginx

```dockerfile
# syntax=docker/dockerfile:1.7
# --- builder: composer + assets (NOT shipped) ---
FROM ghcr.io/zenchron-dynamics/php-cli:8.3-prod@sha256:1c75cf2f712f6fda66c9c624723032ff812eae2af9c9e43fa2724e91cc71cf35 AS vendor
USER root
WORKDIR /app
# Composer provided here only (copy the binary from the official image).
COPY --from=composer:2@sha256:4d71c3c2109c61d5415544264b59ad4087e4c5b7244481723664138fd36d5040 /usr/bin/composer /usr/bin/composer
COPY composer.json composer.lock ./
RUN composer install --no-dev --no-scripts --prefer-dist --no-interaction --optimize-autoloader
COPY . .
RUN composer dump-autoload --optimize --classmap-authoritative

# --- runtime: php-fpm (ships) ---
FROM ghcr.io/zenchron-dynamics/php-fpm:8.3-prod@sha256:2044d7b3aad61f234d949d8e406c14cdb6386e4735dbd87148a895304aaef038 AS app
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
FROM ghcr.io/zenchron-dynamics/php-cli:8.3-prod@sha256:1c75cf2f712f6fda66c9c624723032ff812eae2af9c9e43fa2724e91cc71cf35 AS vendor
USER root
WORKDIR /app
COPY --from=composer:2@sha256:4d71c3c2109c61d5415544264b59ad4087e4c5b7244481723664138fd36d5040 /usr/bin/composer /usr/bin/composer
COPY composer.json composer.lock symfony.lock ./
RUN composer install --no-dev --no-scripts --prefer-dist --no-interaction --optimize-autoloader
COPY . .
ENV APP_ENV=prod
RUN composer dump-autoload --optimize --classmap-authoritative \
 && php bin/console cache:warmup --env=prod

FROM ghcr.io/zenchron-dynamics/php-fpm:8.3-prod@sha256:2044d7b3aad61f234d949d8e406c14cdb6386e4735dbd87148a895304aaef038 AS app
WORKDIR /app
COPY --from=vendor --chown=10001:10001 /app /app
USER 10001:10001
```

Writable `var/` is externalized (`profiles/compose.symfony.yml` → `/app/var`).
See [examples/symfony](../examples/symfony).

## 4. FrankenPHP app

```dockerfile
FROM ghcr.io/zenchron-dynamics/php-cli:8.3-prod@sha256:1c75cf2f712f6fda66c9c624723032ff812eae2af9c9e43fa2724e91cc71cf35 AS vendor
USER root
WORKDIR /app
COPY --from=composer:2@sha256:4d71c3c2109c61d5415544264b59ad4087e4c5b7244481723664138fd36d5040 /usr/bin/composer /usr/bin/composer
COPY composer.json composer.lock ./
RUN composer install --no-dev --prefer-dist --no-interaction --optimize-autoloader
COPY . .

FROM ghcr.io/zenchron-dynamics/php-frankenphp:8.3-prod@sha256:e12c84ed1349492240bec14ef7eb9748eecf5288867569c1ac93ebcbe2a77b58 AS app
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

## Breaking changes to be aware of (2026-07-28)

### `caddy` — no TLS termination

The certified configuration sets `auto_https off` and 8443 is no longer exposed.
Terminate TLS at your load balancer and forward plaintext to `:8080`. This is a
security restriction, not a packaging tidy-up: see
[`security/triage-2026-07-28-ungoverned-findings.md`](security/triage-2026-07-28-ungoverned-findings.md).

### `nginx` — dynamic modules removed

`image_filter`, `xslt`, `njs` and `geoip` are no longer shipped, along with
`curl`, `libxml2`, `libaom3`, `libheif1`, `libssh2-1` and the krb5 stack. None was
loaded by any shipped config, and together they accounted for 74 of the image's
87 CRITICAL/HIGH findings.

If you loaded one of those modules yourself, choose:

1. the official upstream `nginxinc/nginx-unprivileged:1.27-bookworm` (no Foundry
   hardening);
2. a derived image that reinstalls the module — you then own its CVE surface;
3. pinning the previous Foundry digest temporarily, with your own recorded risk
   acceptance (that digest still carries `CVE-2026-6653`, CVSS 9.8).
