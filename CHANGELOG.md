# Changelog

All notable changes to the Zenchron Dynamics `docker-platform` are documented
here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
image releases follow [docs/image-versioning.md](docs/image-versioning.md).

## [Unreleased]

### Changed

- **Stable release now promotes exact RC digests instead of rebuilding** (rule
  #14 / Sprint 6). New `promote-stable.yml` + `scripts/promote-stable.sh` copy the
  already-signed RC image digests onto the `*-prod` aliases via registry retag
  (`docker buildx imagetools create`) — two-phase, atomic-at-the-alias, with
  digest-equality verification and rollback metadata. `release.yml` no longer
  builds: it only verifies + seals the GitHub Release over the promoted images.
- **Hardened self-hosted workspace-ownership reset** across all workflows: the
  `sudo chown … || true` pattern is replaced with a path-validated, fail-loud
  block (refuses to `chown` outside `$RUNNER_WORKSPACE`; errors if the tree is not
  ours and `sudo` is unavailable) (Sprint 7).

## [2026.06.21] — Debian-first STABLE promotion

This release **flips the generic production tags to the Debian line.**
`php-{cli,fpm,worker,frankenphp}:{8.3,8.4}-prod`, `nginx:prod`, and `caddy:prod`
now resolve to the Debian-backed images (provider-explicit `8.x-debian` tags also
published). Built multi-arch (linux/amd64 + linux/arm64), Cosign-signed, with
SPDX SBOM + provenance attestations. Promotes the validated RC1 source state
(commit `4425011`, image contents unchanged from `8.x-debian-rc1`).

Consumer validation: full Laravel + Symfony matrix (php-fpm+nginx, php-fpm+Caddy,
FrankenPHP, worker, CLI, scheduler) passed via `php-app-template` (master
`75a3d2b`) against the RC images — Postgres + Redis, migrations, queued job,
heartbeat, clean SIGTERM, non-root (10001), read-only rootfs.

### Rollback (previous Wolfi `*-prod` digests — retained, never deleted)

Emergency rollback = re-pin consumers to these digests (no tag mutation needed):

```text
php-cli:8.4-prod        sha256:bdc99337029787dc9ab63bdbad3e386f1ea1c5e6c74f9d3e1cf210e380a0e359
php-fpm:8.4-prod        sha256:4699b1bed89d115cd4ec1512513da2778bb149ad9d4eb19794e5b0a0e28fb3fb
php-worker:8.4-prod     sha256:bfd83613de911aeb43eb17c953ba531ec938a833b69cd239deb9979bc4d89b61
php-frankenphp:8.4-prod sha256:926d9b1db3ff4e15d2fb7b85c4112a16bbb8f4deb138be8ef8c4c8cef25e8011
php-cli:8.3-prod        sha256:433a73539d88e6e2f9028ae8d04429f91104b5be737b216808bfc996fd4060a5
php-fpm:8.3-prod        sha256:89838f2e1f1a9d641f8dba3c927d02043876280f55804ffbf7919cae71de7214
php-worker:8.3-prod     sha256:5188724af284b272ba17a728fce6ecf944af7e32b0235893e5fed5b62f5d6694
php-frankenphp:8.3-prod sha256:83021a9d56c0d17e866495e97e65ed8f29119e0f9bdc7fef73654b027a5d5043
nginx:prod              sha256:a0b1ade4583e64c00bc013f16b3ad95ff1de42cc358b6ed128063f533af65953
caddy:prod              sha256:3c02c618980d01f3d008801e0d5e429b4c515a0dcee07262efceb54b74bb04af
```

### Accepted CVE exceptions (review by 2026-07-20; see vulnerability-management.md)

Unfixed Debian distro CRITICALs, excluded by `--ignore-unfixed` + recorded in
`policies/.trivyignore`: `zlib1g` (CVE-2023-45853, will_not_fix), `perl-base`
(CVE-2026-42496/8376), `libsqlite3-0` (CVE-2025-7458), FrankenPHP base `libaom3`
(CVE-2023-6879), `linux-libc-dev` (CVE-2026-43185); caddy go-jose (CVE-2026-34986,
review 2026-07-02). PHP/nginx images: **0 fixable CRITICAL/HIGH**.

### Notes

- PHP 7.4 / 8.0 remain **frozen legacy** (Wolfi images retained, never rebuilt).
- Internal config path: old `/etc/php` → new `/usr/local/etc/php`.
- FrankenPHP serves HTTP `:8080` + readiness `:8081`; state under `/tmp`.

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
