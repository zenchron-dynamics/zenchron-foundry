# Example: FrankenPHP app (single binary, embedded server)

No separate php-fpm/nginx. FrankenPHP serves `/app/public` on `:8080`/`:8443`.
PHP ≥ 8.2 only (8.3/8.4).

```bash
docker compose -f compose.yml \
  -f ../../profiles/compose.security.yml up -d
```

When to choose FrankenPHP over php-fpm + nginx/caddy:
- Simpler topology (one container does serving + PHP).
- **Worker mode** keeps the app booted between requests → high throughput
  (enable in the base `Caddyfile`: uncomment `worker /app/public/index.php`).

Tradeoffs:
- Newer; validate your app (especially stateful globals) under worker mode.
- TLS: terminate upstream and keep :8080, or grant `NET_BIND_SERVICE` for :443.
- Writable `/data` + `/config` volumes for Caddy state under read-only rootfs.
