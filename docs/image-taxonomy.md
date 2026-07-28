# Image Taxonomy

| Image | Purpose | Entrypoint | Ports | Init | Healthcheck |
|-------|---------|-----------|-------|------|-------------|
| `php-fpm` | Web backend behind nginx/Caddy | `php-fpm --nodaemonize` | 9000 | FPM master (PID 1) | `php` TCP probe → :9000 |
| `php-cli` | Console/migrations/one-off jobs | `php` | — | — | n/a (short-lived) |
| `php-worker` | Queue / Messenger long-running | `tini -- worker-entrypoint <cmd>` | — | tini (PID 1) | heartbeat freshness (`/tmp/worker-heartbeat`) |
| `php-frankenphp` | App server (embedded Caddy) | `frankenphp run` | 8080/8443/8081 | frankenphp | HTTP `:8081/healthz` (readiness) |
| `caddy` | Reverse proxy / static | `caddy run` | 8080/8081 (**no TLS**) | caddy | HTTP `:8081/healthz` (readiness) |
| `nginx` | Reverse proxy / static / FPM front | `nginx -g daemon off` | 8080 | nginx master | `nginx -t` (config) |

## Versions

| Family | Versions | Status |
|--------|----------|--------|
| php-fpm / php-cli / php-worker | 8.3, 8.4 | Supported |
| php-fpm / php-cli / php-worker | 7.4, 8.0 | **Legacy / EOL** ([legacy-php-policy.md](legacy-php-policy.md)) |
| php-frankenphp | 8.3, 8.4 | Supported (PHP ≥ 8.2 only — no 7.4/8.0) |
| caddy / nginx | prod | Supported |

## Choosing a runtime

- **php-fpm + nginx/caddy** — classic, battle-tested, granular tuning. Default
  for most Laravel/Symfony apps.
- **php-frankenphp** — single binary, worker mode for high throughput, simpler
  topology (no separate web server). Newer; validate per app.
- **php-cli** — invoke via `docker compose run --rm`, k8s Job, or host cron.
- **php-worker** — one process per container; scale horizontally; never bake a
  supervisor unless strictly justified (see [runtime-hardening.md](runtime-hardening.md)).

## Naming & labels

Every image carries `org.opencontainers.image.*` labels plus:

- `com.zenchron.runtime` — family (`php-fpm`, `nginx`, …)
- `com.zenchron.php` — PHP version (where applicable)
- `com.zenchron.support` — `supported` | `legacy-eol`
- `com.zenchron.risk` — `high` on legacy images

> **Caddy terminates no TLS (2026-07-28).** The certified configuration sets
> `auto_https off` and the image no longer exposes 8443. This removes the
> TLS-SNI path to `CVE-2026-56852` (`x/text` `norm.Iter` infinite loop on invalid
> UTF-8, remote unauthenticated DoS). **TLS must terminate at the upstream load
> balancer** until Caddy ships `x/text >= 0.39.0`. Enabling TLS through a mounted
> or derived config leaves the certified topology and re-opens the path — see
> [security/triage-2026-07-28-ungoverned-findings.md](security/triage-2026-07-28-ungoverned-findings.md).
