# Example: generic php-fpm + nginx

Framework-agnostic edge pattern. nginx (`:8080`) serves static + proxies `*.php`
to `php-fpm:9000`.

```bash
cp ../../images/nginx/conf.d/app.conf.example ./app.conf   # adjust root/server_name
docker compose -f compose.yml \
  -f ../../profiles/compose.security.yml \
  -f ../../profiles/compose.php-fpm.yml up -d
```

Key points:
- nginx is the unprivileged image (non-root, :8080). Front it with a TLS LB.
- Only the front controller `index.php` is executable; other `.php` → 404.
- `.env`, `.git`, `vendor/`, `storage/` are denied (see the nginx site config).
