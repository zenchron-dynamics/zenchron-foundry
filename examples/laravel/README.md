# Example: Laravel on the Zenchron platform (php-fpm + nginx + worker)

Reference only — copy into a real Laravel repo and adapt. No app code shipped here.

## Build

```bash
docker compose build           # builds example-laravel:local from ./Dockerfile
```

## Run (hardened)

```bash
docker compose \
  -f compose.yml \
  -f ../../profiles/compose.security.yml \
  -f ../../profiles/compose.readonly.yml \
  -f ../../profiles/compose.laravel.yml up -d
```

App is served by nginx on <http://localhost:8080>.

## nginx site config

Copy the platform example and place it where compose mounts it:

```bash
mkdir -p deploy/nginx
cp ../../images/nginx/conf.d/app.conf.example deploy/nginx/app.conf
```

## Migrations / one-off

```bash
docker compose --profile cli run --rm migrate           # php artisan migrate --force
docker compose run --rm php-fpm php artisan about
```

## Production

Use `compose.prod.yml`, replace `sha256:REPLACE_WITH_DIGEST` with verified
digests (`scripts/verify-signatures.sh` first), terminate TLS at your LB.

## Writable paths

`storage/` and `bootstrap/cache/` are the only writable mounts; the rootfs is
read-only. Sessions/cache should use Redis in production.
