# Changelog

All notable changes to the Zenchron Dynamics `docker-platform` are documented
here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
image releases follow [docs/image-versioning.md](docs/image-versioning.md).

## [Unreleased]

### Added

- Initial platform bootstrap: repository structure, security tooling, CI/CD
  workflows, shared Compose profiles, and core documentation.
- Production Dockerfiles for the PHP 8.3 image family (php-fpm, php-cli,
  php-worker, php-frankenphp) plus hardened Caddy and nginx images.
- Structured stubs and legacy Dockerfiles for PHP 7.4, 8.0, and 8.4.
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
