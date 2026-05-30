# Distroless Strategy

## What "distroless" means here

"Distroless" = a final image with **no OS package manager, no shell where
feasible, and only the libraries the runtime actually needs.** It is a goal, not
a brand. We do **not** claim Google `gcr.io/distroless` compatibility, because
those images ship no PHP.

## Honest reality for PHP

True Google-distroless PHP is **not feasible**. PHP-FPM/CLI dynamically link a
long tail of shared libraries (libxml2, oniguruma, icu, openssl, zlib, libpng,
libzip, libsodium, postgres/mysql client libs…). Reconstructing that on a
`scratch`/static base is fragile and unmaintainable.

### Decision

| Family | Final base | Distroless level | Why |
|--------|-----------|------------------|-----|
| php-fpm 8.3/8.4 | **Chainguard Wolfi** (`cgr.dev/chainguard/wolfi-base` + `apk add php-8.x-*`) | Near-distroless (busybox shell retained for FPM healthcheck via `cgi-fcgi`) | Low-CVE, apk-pinnable, prebuilt PHP packages |
| php-cli 8.3/8.4 | Wolfi | Near-distroless | same |
| php-worker 8.3/8.4 | Wolfi (+`tini`) | Near-distroless | signal handling needs PID-1 init |
| php-frankenphp 8.3/8.4 | upstream `dunglas/frankenphp:*-alpine` (hardened) | Minimal | no distroless FrankenPHP exists upstream |
| caddy | `caddy:2-alpine` (non-root) | Minimal | official, small |
| nginx | `nginxinc/nginx-unprivileged:alpine` | Minimal | purpose-built non-root |
| **php-fpm/cli/worker 7.4, 8.0** | `php:7.4/8.0-*-alpine` (EOL) | **Not distroless** | Wolfi has no EOL PHP; quarantined, high risk |

We **do not** silently fall back to full Debian/Ubuntu. Where Alpine is used
(legacy + FrankenPHP/caddy/nginx upstream), it is minimal and justified above.

## Tradeoffs

| Concern | Approach |
|---------|----------|
| **PHP extensions** | Wolfi provides prebuilt `php-8.x-<ext>` apk packages — no compiler in final image. Legacy compiles via `docker-php-ext-install` in a build stage, build deps removed. |
| **Composer** | Never in the final image. Belongs in the app's own builder stage. |
| **Debugging / shell** | FPM keeps busybox + `cgi-fcgi` for the healthcheck. Pure-distroless would push the healthcheck to the orchestrator. Use `docker debug` / ephemeral debug containers rather than baking tools in. |
| **CA certificates** | `ca-certificates-bundle` (Wolfi) / present in Alpine. Required for TLS to DBs/APIs. |
| **Timezone data** | `tzdata` installed; default `UTC`. |
| **Native deps** | Pulled as explicit runtime apk packages, captured in the SBOM. |
| **Healthchecks** | FPM: `cgi-fcgi` against `ping.path`. nginx: `nginx -t`. caddy/franken: `version`. Distroless-pure services rely on orchestrator TCP/HTTP probes. |

## Future path

If Chainguard/Zenchron-internal fully shell-less PHP-FPM images become viable
(static healthcheck binary + no busybox), migrate FPM to them and move the
healthcheck to a tiny static binary. Track in `docs/vulnerability-management.md`
rebuild cadence.
