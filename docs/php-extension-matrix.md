# PHP extension matrix (Debian-first)

Per-extension status across the Debian PHP images. Policy:
`docs/php-extension-policy.md`. How they get in:

- **bundled** — enabled in the official `php:*-bookworm` base (no action).
- **ext-install** — compiled from official source via `docker-php-ext-install`
  in the build stage (FrankenPHP uses the bundled `install-php-extensions`).
- **pecl** — `pecl install`, version-pinned, enabled with `docker-php-ext-enable`.

`-j$(nproc)` is used for the build. Build tooling (`$PHPIZE_DEPS`) is installed in
the throwaway build stage only and stripped from the final image.

## Matrix

| Extension | How | cli | fpm | worker | frankenphp | Runtime lib (Debian) | Required by consumers |
|-----------|-----|:---:|:---:|:------:|:----------:|----------------------|-----------------------|
| opcache | ext-install | ✅ | ✅ | ✅ | ✅ | — | yes (perf) |
| bcmath | ext-install | ✅ | ✅ | ✅ | ✅ | — | Laravel/money |
| intl | ext-install | ✅ | ✅ | ✅ | ✅ | libicu72 | yes |
| gd | ext-install (`--with-jpeg --with-freetype`) | ✅ | ✅ | ✅ | ✅ | libpng16-16, libjpeg62-turbo, libfreetype6 | image handling |
| zip | ext-install | ✅ | ✅ | ✅ | ✅ | libzip4 | Composer/exports |
| pdo_pgsql | ext-install | ✅ | ✅ | ✅ | ✅ | libpq5 | **ProxyFlux (Postgres)** |
| pgsql | ext-install | ✅ | ✅ | ✅ | ✅ | libpq5 | optional native pg |
| pdo_mysql | ext-install (mysqlnd) | ✅ | ✅ | ✅ | ✅ | — | MySQL consumers |
| sockets | ext-install | ✅ | ✅ | ✅ | ✅ | — | some queue drivers |
| pcntl | ext-install | ✅ | ➖ | ✅ | ✅ | — | **worker signals** |
| redis | pecl `6.1.0` | ✅ | ✅ | ✅ | ✅ | — | cache/queue/session |
| mbstring | bundled | ✅ | ✅ | ✅ | ✅ | libonig5 | yes |
| ctype | bundled | ✅ | ✅ | ✅ | ✅ | — | yes |
| openssl | bundled | ✅ | ✅ | ✅ | ✅ | libssl3 | yes |
| sodium | bundled | ✅ | ✅ | ✅ | ✅ | libsodium | yes |
| tokenizer | bundled | ✅ | ✅ | ✅ | ✅ | — | framework |
| dom / xml / simplexml / xmlreader / xmlwriter | bundled | ✅ | ✅ | ✅ | ✅ | libxml2 | framework |
| fileinfo | bundled | ✅ | ✅ | ✅ | ✅ | — | uploads |
| curl | bundled | ✅ | ✅ | ✅ | ✅ | libcurl4 | HTTP clients |
| json | bundled (core) | ✅ | ✅ | ✅ | ✅ | — | everywhere |
| iconv | bundled | ✅ | ✅ | ✅ | ✅ | — | text |
| phar / posix | bundled | ✅ | ✅ | ✅ | ✅ | — | tooling |
| sqlite3 / pdo_sqlite | bundled | ✅ | ✅ | ✅ | ✅ | libsqlite3-0 | testing/cache |

Legend: ✅ present · ➖ intentionally omitted (`pcntl` excluded from FPM — FPM
disables `pcntl_*` in `php.ini`; not needed for the web pool).

## Notes vs Wolfi

- `pdo_mysql` uses the bundled **mysqlnd** driver (no `mysqlnd` apk needed).
- `pgsql`, `sockets`, `sqlite3`/`pdo_sqlite` are **new** vs the Wolfi set
  (additions, not removals).
- `redis` moved from a prebuilt Wolfi apk to a **pinned pecl build** (`6.1.0`),
  giving an explicit, auditable version.

## CVE / size note

The added extensions pull only small runtime libs already present for the core
set. None introduce a fixable CRITICAL/HIGH (the PHP images currently report
**0 fixable** CRITICAL/HIGH; see `docs/vulnerability-management.md`).

## Validation

`php -m` is the source of truth. CI builds each image and the matrix is verified
at runtime; locally:

```bash
docker run --rm ghcr.io/zenchron-dynamics/php-cli:8.4-debian -m
```
