# PHP Extension Policy

## Principle

Ship the **minimum** extension set that the majority of Laravel/Symfony apps
need. Extra extensions = larger attack surface + more CVEs. Apps needing more
should request an addition (platform PR) rather than fork.

## Baseline (supported images)

| Extension | fpm | cli | worker | Reason |
|-----------|:--:|:--:|:------:|--------|
| opcache | ✓ | ✓(off) | ✓ | bytecode cache |
| pdo, pdo_mysql, pdo_pgsql | ✓ | ✓ | ✓ | DB access |
| mbstring, intl, iconv | ✓ | ✓ | ✓ | i18n / string handling |
| openssl, sodium | ✓ | ✓ | ✓ | crypto, encryption |
| curl | ✓ | ✓ | ✓ | HTTP clients |
| dom, xml, simplexml, tokenizer | ✓ | ✓ | ✓ | framework internals |
| ctype, fileinfo, phar | ✓ | ✓ | ✓ | framework + uploads |
| bcmath | ✓ | ✓ | ✓ | money/precision math |
| gd | ✓ | ✓ | ✓ | image handling |
| zip | ✓ | ✓ | ✓ | archives / Composer |
| session | ✓ | ✓ | ✓ | sessions |
| redis | ✓ | ✓ | ✓ | cache/queue/session driver |
| pcntl, posix | — | ✓ | ✓ | **workers only** — signal handling |

`pcntl`/`posix` are intentionally **absent from FPM** (web requests must not fork
processes) and **disabled** there via `disable_functions`.

## Not included by default

`imagick` (prefer gd), `xdebug` (dev only — never in prod images), `ffi`
(dangerous), `pdo_sqlite`, `soap`, `ldap`, `imap`, `gmp`, `mongodb`. Request via
PR with justification; document the consuming app.

## How extensions are added

- **Supported (Debian, current):** compiled **from source in the builder
  stage** with the official PHP toolchain (`docker-php-ext-configure` /
  `docker-php-ext-install`, PECL for `redis`); the runtime stage copies only
  the built extensions and config (under `/usr/local/etc/php/`) — **no
  compiler or build deps in the final image** (multi-stage).
- **FrankenPHP:** `install-php-extensions <ext>` in the build step.
- **Legacy (7.4/8.0, frozen):** were built with `docker-php-ext-install`/`pecl`
  in a build stage; never rebuilt.
- *(Historical: the retired Wolfi images used prebuilt `php-8.x-<ext>` apk
  packages — see ADR-0001.)*

## OPcache JIT

OPcache is enabled; **JIT is disabled by default** (`opcache.jit=disable`,
`opcache.jit_buffer_size=0`) to minimize attack surface — it rarely benefits
typical Laravel/Symfony web workloads. Enable it per project only after
benchmarking a CPU-bound workload. Full rationale, opt-in method, and validation:
[php-runtime-hardening.md](php-runtime-hardening.md).

## `disable_functions`

FPM disables high-risk process/command functions
(`exec, passthru, shell_exec, system, proc_open, popen, pcntl_exec, dl`).
Workers keep `pcntl_*`/`posix_*` (required for graceful shutdown) but still
disable shell-exec functions unless a job provably needs them — document and
scope narrowly.

## Review cadence

The baseline is reviewed each quarter against actual app usage and CVE history.
Drop unused extensions; promote frequently-requested ones into the baseline.
