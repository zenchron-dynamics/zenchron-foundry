# Migration guide: Wolfi/Chainguard → Debian

What changed for consumers when Foundry images moved from Wolfi/Chainguard +
Alpine to a Debian-first platform. Decision: `docs/adr/ADR-0001-remove-wolfi-chainguard.md`.

## TL;DR for consumers

- Same image **names**, same **UID 10001**, same **ports**, same **entrypoints**,
  same **extensions** (plus a few additions). For most consumers **nothing
  changes** at the Compose/runtime layer.
- Internal PHP config paths moved from Wolfi's `/etc/php/*` to the official
  `/usr/local/etc/php/*`. Only matters if you mounted/overrode files there.
- FrankenPHP writable state moved from `/data` and `/config` to
  **`/tmp/caddy-data`** and **`/tmp/caddy-config`**, so a single `tmpfs /tmp`
  now covers a read-only rootfs.
- Pin the new **`8.x-debian`** provider-explicit tag if you want to track the
  Debian variant precisely; `8.x-prod` becomes Debian-backed at the stable
  release (Phase G).

## Base image: old → new

| Family | Old base (Wolfi/Alpine) | New base (Debian-first) |
|--------|-------------------------|-------------------------|
| `php-cli` / `php-fpm` / `php-worker` | `cgr.dev/chainguard/wolfi-base:latest@sha256:441d6709305552a3411e585ad98aacb9dadda00c80f3267483c38ac6f86f49d4` | `php:8.4-{cli,fpm}-bookworm@sha256:c442ba6df65a999ea50d0e3c836aaa4da9bd70090fc81db875adb25b330632b1` (cli 8.4) / `…66cf4b82…` (fpm 8.4) / `…4f520b09…` (cli 8.3) / `…07d1dd46…` (fpm 8.3) |
| `php-frankenphp` 8.4 | `dunglas/frankenphp:1-php8.4-alpine@sha256:d5c38299403cb20ad8ddb90bc2623bc38ed186c78e5ad7097064e74cdb8d5c5b` | `dunglas/frankenphp:1-php8.4-bookworm@sha256:d83ae8b7193120b51fbc6f4edbfd67eb897bf778837227a84292287c2300506c` |
| `php-frankenphp` 8.3 | (Alpine) | `dunglas/frankenphp:1-php8.3-bookworm@sha256:4c0ae6933ee2c08d82a2ce1593c37c754d3794a706c26eae7b3a6c21d2353918` |
| `nginx` | `nginxinc/nginx-unprivileged:1.27-alpine@sha256:65e3e85dbaed8ba248841d9d58a899b6197106c23cb0ff1a132b7bfe0547e4c0` | `nginxinc/nginx-unprivileged:1.27-bookworm@sha256:f9dfa9c20b2b0b7c5cc830374f22f23dee3f750b6c5291ca7e0330b5c88e6403` |
| `caddy` | `caddy:2-alpine@sha256:86deaf5e3d3408a6ccec08fbb79989783dd26e206ae10bcf78a801dc8c9ab794` | `caddy:2-alpine@sha256:77c07d5ebfa5be9fd6c820d2094ae662c9e7eeb9bf98346b7f639900263ee2a2` (unchanged provider — Alpine; ADR-0001 exception) |

## Extension differences

Parity is preserved; a few additions. See `docs/php-extension-matrix.md`.

- **Unchanged set:** bcmath, ctype, curl, dom, fileinfo, gd, iconv, intl,
  mbstring, opcache, openssl, pdo_mysql (mysqlnd), pdo_pgsql, phar, posix, redis,
  simplexml, sodium, tokenizer, xml, zip, json. `pcntl` in cli/worker.
- **Added on Debian:** `pgsql` (native libpq alongside `pdo_pgsql`), `sockets`,
  and `sqlite3`/`pdo_sqlite` (bundled in the official PHP image).
- **Now compiled from official PHP source** (was prebuilt Wolfi apks). `redis` is
  a pinned `pecl` build (`6.1.0`).

## Filesystem differences

| Concern | Wolfi (old) | Debian (new) |
|---------|-------------|--------------|
| PHP conf.d | `/etc/php/conf.d/` | `/usr/local/etc/php/conf.d/` |
| php-fpm.conf | `/etc/php/php-fpm.conf` | `/usr/local/etc/php-fpm.conf` |
| FPM pools | `/etc/php/php-fpm.d/` | `/usr/local/etc/php-fpm.d/` |
| FrankenPHP state | `/data`, `/config` | `/tmp/caddy-data`, `/tmp/caddy-config` |

## Unchanged

- **User / UID:GID:** `10001:10001` (nginx stays `101`).
- **Ports:** FPM `9000`; FrankenPHP `8080` (HTTP) + `8081` (readiness) + `8443`;
  nginx/caddy `8080`/`8443`/`8081`.
- **Entrypoints:** `php` (cli); `php-fpm --nodaemonize` (fpm);
  `tini -- worker-entrypoint` (worker); `frankenphp run` (frankenphp).
- **Worker heartbeat:** identical (`/tmp/worker-heartbeat`, `worker-healthcheck`).
- **Healthchecks:** FPM/worker identical (php-based). **FrankenPHP** changed from
  a `wget` probe (Alpine busybox) to a **php-based** probe (Debian ships no wget)
  — same endpoint `http://127.0.0.1:8081/healthz`, same semantics.

## Consumer Compose changes

Usually none. If you set FrankenPHP read-only volumes for `/data` and `/config`,
switch to a single `tmpfs: [/tmp]` (or mount `/tmp/caddy-data`). Example:

```yaml
# before (Wolfi/Alpine frankenphp)
read_only: true
tmpfs: [/tmp]
volumes: [caddy-data:/data, caddy-config:/config]

# after (Debian frankenphp) — XDG dirs live under /tmp
read_only: true
tmpfs: [/tmp]            # covers /tmp/caddy-data + /tmp/caddy-config
```

## Rollback

Wolfi images are **not deleted** from GHCR and remain pullable by digest/tag.

1. Re-pin the consumer to the previous Wolfi image tag or digest (table above).
2. Revert the FrankenPHP `/data`+`/config` tmpfs/volumes if you changed them.
3. No DB migration is tied to the image change; no secret changes required.
4. Healthcheck rollback is automatic (it ships in the image).

Triggers to roll back: missing extension, worker heartbeat failure, FPM
incompatibility, FrankenPHP HTTP failure, unexpected filesystem write, startup
regression, severe CVE regression, image size beyond budget, multi-arch
mismatch, or perf regression beyond the agreed threshold.
