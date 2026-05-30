# Example: generic php-fpm + Caddy

Same app image; Caddy (`:8080`/`:8443`) replaces nginx. `php_fastcgi` proxies to
`php-fpm:9000`.

```bash
cp ../../images/caddy/conf.d/app.caddy.example ./app.caddy   # adjust root
docker compose -f compose.yml \
  -f ../../profiles/compose.security.yml \
  -f ../../profiles/compose.php-fpm.yml up -d
```

Notes:

- Caddy runs non-root on high ports. To bind :80/:443, add `NET_BIND_SERVICE`
  (see `profiles/compose.caddy.yml`) or terminate TLS upstream.
- `/data` and `/config` are writable volumes (cert/state) under read-only rootfs.
