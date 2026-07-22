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

> **Superseded by [ADR-0001](adr/ADR-0001-remove-wolfi-chainguard.md).** The
> platform is now **Debian-first** on official images; the Wolfi rows below are
> historical. "Distroless" is retained as a **future experimental track**, not the
> current base.

| Family | Final base (current) | Minimization | Why |
|--------|----------------------|--------------|-----|
| php-fpm 8.3/8.4 | official `php:8.x-fpm-bookworm` (Debian 12) | multi-stage; toolchain stripped; no shell server tools | official, durable, official extension toolchain |
| php-cli 8.3/8.4 | official `php:8.x-cli-bookworm` | same | same |
| php-worker 8.3/8.4 | `php:8.x-cli-bookworm` (+`tini`) | same | signal handling needs PID-1 init |
| php-frankenphp 8.3/8.4 | `dunglas/frankenphp:1-php8.x-bookworm` (Debian) | minimal | official FrankenPHP, Debian variant |
| caddy | `caddy:2-alpine` (non-root) | minimal | official; no upstream Debian variant (ADR-0001 exception) |
| nginx | `nginxinc/nginx-unprivileged:1.27-bookworm` (Debian) | minimal | official non-root, Debian |

We build on the **official Debian PHP images**. The compiler toolchain inherited
from `buildpack-deps` is **purged in the runtime stage**, so the final image
carries no `gcc`/`make`/`autoconf`/`phpize`.

## Tradeoffs

| Concern | Approach |
|---------|----------|
| **PHP extensions** | Compiled from source in the builder stage with the official toolchain (`docker-php-ext-*`); no compiler in the final image. (Historical: the retired Wolfi images used prebuilt `php-8.x-<ext>` apk packages.) |
| **Composer** | Never in the final image. Belongs in the app's own builder stage. |
| **Debugging / shell** | FPM keeps busybox + `cgi-fcgi` for the healthcheck. Pure-distroless would push the healthcheck to the orchestrator. Use `docker debug` / ephemeral debug containers rather than baking tools in. |
| **CA certificates** | Debian `ca-certificates` package; present in Alpine for caddy. Required for TLS to DBs/APIs. (Historical: Wolfi used `ca-certificates-bundle`.) |
| **Timezone data** | `tzdata` installed; default `UTC`. |
| **Native deps** | Pulled as explicit runtime Debian (dpkg) packages, captured in the SBOM. |
| **Healthchecks** | FPM: `cgi-fcgi` against `ping.path`. nginx: `nginx -t`. caddy/franken: `version`. Distroless-pure services rely on orchestrator TCP/HTTP probes. |

## Future path

If a fully shell-less PHP-FPM image becomes viable (static healthcheck binary +
no busybox — Chainguard is history per ADR-0001, so this would be a
Zenchron-internal or Debian-based track), migrate FPM to it and move the
healthcheck to a tiny static binary. Track in `docs/vulnerability-management.md`
rebuild cadence.
