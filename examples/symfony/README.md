# Example: Symfony on the Zenchron platform (php-fpm + nginx + messenger)

Reference only. Copy into a real Symfony repo and adapt.

## Run (hardened)

```bash
docker compose \
  -f compose.yml \
  -f ../../profiles/compose.security.yml \
  -f ../../profiles/compose.readonly.yml \
  -f ../../profiles/compose.symfony.yml up -d
```

nginx serves <http://localhost:8080>. Copy the site config:

```bash
mkdir -p deploy/nginx
cp ../../images/nginx/conf.d/app.conf.example deploy/nginx/app.conf
```

## Migrations / console

```bash
docker compose --profile cli run --rm migrate     # doctrine:migrations:migrate
docker compose run --rm php-fpm php bin/console about
```

## Writable paths

Only `/app/var` (cache, log, sessions) is writable; rootfs is read-only. Use a
Redis/DB session + cache backend in production where possible.

## Messenger workers

`messenger:consume` runs with `--time-limit`/`--memory-limit` so workers recycle
cleanly; `stop_grace_period` lets in-flight messages finish on SIGTERM.
