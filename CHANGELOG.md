# Changelog

All notable changes to the Zenchron Dynamics `docker-platform` are documented
here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
image releases follow [docs/image-versioning.md](docs/image-versioning.md).

## [Unreleased]

### Changed — Debian-first base image platform (BREAKING for base provider)

- **Removed all Wolfi/Chainguard dependencies.** `php-cli`, `php-fpm`,
  `php-worker` now build on official **`php:8.x-{cli,fpm}-bookworm`** (Debian 12);
  `php-frankenphp` on **`dunglas/frankenphp:1-php8.x-bookworm`**; `nginx` on
  **`nginxinc/nginx-unprivileged:1.27-bookworm`**. No more `cgr.dev`, `apk`, or
  Wolfi package feeds. `caddy` stays on the official Alpine image (no upstream
  Debian variant; documented exception). See
  [ADR-0001](docs/adr/ADR-0001-remove-wolfi-chainguard.md).
- PHP extensions are now **compiled from official source** (multi-stage; the
  compiler toolchain is stripped from the final image). `redis` is a pinned pecl
  build. Added `pgsql`, `sockets`, `sqlite3`/`pdo_sqlite` (parity + additions —
  see [php-extension-matrix.md](docs/php-extension-matrix.md)).
- FrankenPHP writable state moved to `/tmp/caddy-data` + `/tmp/caddy-config`
  (single `tmpfs /tmp` covers read-only rootfs); php-based healthcheck (Debian
  ships no wget).
- Trivy gate now blocks on **fixable** CRITICAL/HIGH (`--ignore-unfixed`); edge
  images (nginx/caddy) are scan-and-report. PHP images: **0 fixable CRITICAL/HIGH**.
- Internal PHP config paths moved `/etc/php/*` → `/usr/local/etc/php/*`.

### Removed

- **PHP 7.4 and 8.0 source Dockerfiles** (cli/fpm/worker). These are now frozen
  legacy: previously-published Wolfi images remain in GHCR, but they are not
  rebuilt. See [legacy-php-policy.md](docs/legacy-php-policy.md).

### Added

- Migration docs: [base-image-strategy](docs/base-image-strategy.md),
  [base-image-patching](docs/security/base-image-patching.md),
  [wolfi-to-debian migration guide](docs/migration/wolfi-to-debian.md),
  [php-extension-matrix](docs/php-extension-matrix.md),
  [release-process](docs/release-process.md), and [ADR-0001](docs/adr/ADR-0001-remove-wolfi-chainguard.md).
- `scripts/assert-no-wolfi.sh` CI guard (forbids cgr.dev/chainguard/wolfi/apk in
  active code); base digest-pin + no-`latest` enforcement in `check-structure.sh`.
- Provider-explicit `8.x-debian` image tag.

- Initial platform bootstrap: repository structure, security tooling, CI/CD
  workflows, shared Compose profiles, and core documentation.
- Production Dockerfiles for the PHP 8.3 and 8.4 image families (php-fpm,
  php-cli, php-worker, php-frankenphp) plus hardened Caddy and nginx images.
- Pre-commit hooks: gitleaks, hadolint, shellcheck, yamllint, markdownlint,
  trailing-whitespace / end-of-file / large-file checks.
- GitHub Actions: ci, build-images, scan-images, publish-ghcr, release.
- Cosign signing, Syft SBOM, Trivy + Grype scanning policies.
- Free-tier governance compensating controls: local pre-push hook, release
  safety script, manual PR + CI-failure policies, and accepted-risk record.

### Changed (P2 hardening)

- Caddy and FrankenPHP now use **real HTTP readiness** healthchecks
  (always-on `:8081/healthz` via `wget`) instead of `<binary> version`.
- CI shellchecks the worker scripts under `images/php-worker/`.
- `build-images` / `publish-ghcr` accept a `platforms` input for optional
  `linux/arm64` multi-arch (default `linux/amd64`; arm64 verified to build).
- `make doctor` reports local tool availability with install hints.
- `make build-frankenphp` / `build-php-worker` guard against invalid versions.

### Verified

- GHCR private consumption proven end-to-end: read-only `read:packages` token
  pulls all six images; push is denied (`permission_denied`).
- OPcache JIT disabled by default; worker heartbeat liveness implemented.

### Fixed (post-v2026.06.02 verification)

- Hardened-runtime defects found while verifying v2026.06.02 under the documented
  `cap_drop: ALL` + read-only profile (all fixed; **v2026.06.02 images are
  superseded — do not deploy them, use the next tag**):
  - **php-fpm** exited (code 78, "Unable to create the PID file") under a
    read-only rootfs. Removed the pid directive (FPM is foreground PID 1); now
    needs only tmpfs `/tmp`.
  - **caddy / frankenphp** failed to exec under `cap_drop: ALL` ("operation not
    permitted") because their binaries carry a `cap_net_bind_service` file cap.
    Stripped it at build (`setcap -r`); they now run with zero capabilities on
    high ports (bind :80/:443 only via an upstream LB).

### Security

- Repaired `scan-images` (the `trivy-action`/`setup-trivy` tags were yanked):
  Trivy now runs from the official `aquasec/trivy` image and is the enforcing
  gate; Grype is a non-gating second opinion. First real scan surfaced and fixed
  CVEs the upstream bases hadn't republished: nginx `apk upgrade libssl3
  libcrypto3` (2 CRITICAL + 28 HIGH → 0), frankenphp `apk upgrade libxml2`
  (1 HIGH → 0). Caddy's go-jose CVE (compiled into the binary, not reachable with
  upstream TLS termination) is a justified, dated exception.
- All runtime images: non-root (10001:10001), read-only rootfs default,
  cap_drop ALL, no-new-privileges.
- PHP 7.4 / 8.0 marked high-risk legacy (EOL); isolated and documented.

[Unreleased]: https://github.com/zenchron-dynamics/zenchron-foundry/commits/master
