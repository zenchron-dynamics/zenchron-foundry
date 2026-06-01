# PHP Runtime Hardening

Production PHP defaults baked into the images, and how to override them safely.

## OPcache JIT — disabled by default

```ini
opcache.jit = disable
opcache.jit_buffer_size = 0
```

Applied to: `images/php-fpm/{8.3,8.4}/php.ini` and
`images/php-frankenphp/{8.3,8.4}/php.ini`. (PHP 7.4 has no JIT; 8.0's is left off
for parity.)

### Why JIT is off by default

- **Attack surface.** The JIT emits executable machine code at runtime; it has
  produced RCE-class CVEs. For a "minimal, secure-by-default" platform, JIT is
  surface we don't enable unless a workload proves it needs it.
- **Marginal benefit for typical web apps.** Laravel/Symfony request handling is
  I/O- and framework-bound; JIT mainly helps CPU-heavy numeric/loops. Most web
  workloads see little to no throughput gain, so the default trade favors a
  smaller attack surface.

### When you may enable it

Enable JIT **per project, after benchmarking**, if the workload is genuinely
CPU-bound (image processing, math, long compute loops) and you have measured a
real improvement under production-like load — and you accept the added surface.

### How to enable it (per project, no base rebuild)

Mount a supplemental ini that overrides the base (loads after `zz-zenchron`):

```ini
; deploy/php/zz-jit.ini
opcache.jit = tracing
opcache.jit_buffer_size = 64M
```

```yaml
# compose
services:
  php-fpm:
    volumes:
      - ./deploy/php/zz-jit.ini:/etc/php/conf.d/zzz-jit.ini:ro   # Wolfi path
      # FrankenPHP path: /usr/local/etc/php/conf.d/zzz-jit.ini
```

Use a filename that sorts **after** `zz-zenchron` (e.g. `zzz-jit.ini`).

### How to validate the runtime value

```bash
# FrankenPHP (opcache active in its CLI) — direct:
docker run --rm --entrypoint php ghcr.io/zenchron-dynamics/php-frankenphp:8.3-prod \
  -i | grep -E "opcache.jit|opcache.jit_buffer_size"
# -> opcache.jit => disable => disable
# -> opcache.jit_buffer_size => 0 => 0

# php-fpm: opcache is NOT loaded in the image's CLI SAPI, so `php -i` (CLI) does
# not surface opcache.jit. The directive is set in the FPM-loaded scan dir:
docker run --rm --entrypoint sh ghcr.io/zenchron-dynamics/php-fpm:8.3-prod \
  -c 'grep opcache.jit /etc/php/conf.d/zz-zenchron.ini'
# -> opcache.jit = disable / opcache.jit_buffer_size = 0
# Authoritative observation in production: a phpinfo() page served via FPM shows
#   opcache.jit => disable.
```

## Other production defaults (recap)

`expose_php=Off`, `display_errors=Off`, `log_errors=On` to stderr, hardened
session cookies, `disable_functions` for shell/process execution (FPM), OPcache
on with `validate_timestamps=0`. See `images/php-fpm/8.3/php.ini` and
[php-extension-policy.md](php-extension-policy.md).

## Worker JIT

Workers run CLI; OPcache CLI is off, so JIT is not in play. If a worker is
CPU-bound and you enable OPcache CLI + JIT, treat it like the per-project opt-in
above and benchmark.
