# Zenchron Dynamics — `docker-platform`

> Internal **container platform / golden images** repository.
> Hardened, signed, scanned, SBOM-backed base images for PHP workloads,
> published to `ghcr.io/zenchron-dynamics/*`.

This is **not an application repository.** It produces reusable runtime base
images plus shared Docker Compose security profiles, CI/CD, and docs that
multiple Laravel / Symfony / PHP apps consume.

---

## ⚠️ Legacy PHP Warning

`PHP 7.4` and `PHP 8.0` are **end-of-life** and receive no upstream security
patches. They are provided **only** for legacy compatibility, are isolated from
the supported runtimes, cannot be distroless, and carry accepted documented
risk. **Do not start new projects on them.** See
[docs/legacy-php-policy.md](docs/legacy-php-policy.md).

---

## Supported Images

| Image | Tags | Base strategy | Distroless? |
|-------|------|---------------|-------------|
| `php-fpm`        | `8.3-prod`, `8.4-prod` · `7.4-prod`, `8.0-prod` (legacy) | Wolfi/Chainguard hardened-minimal · Alpine (legacy) | Near-distroless |
| `php-cli`        | same as above | same | Near-distroless |
| `php-worker`     | same as above | same | Near-distroless |
| `php-frankenphp` | `8.3-prod`, `8.4-prod` | FrankenPHP (PHP ≥ 8.2 only) | Minimal |
| `caddy`          | `prod` | Hardened Caddy, non-root :8080/:8443 | Minimal |
| `nginx`          | `prod` | Hardened nginx, non-root :8080 | Minimal |

> True Google "distroless" ships no PHP. We use Chainguard/Wolfi hardened
> minimal images and document every tradeoff in
> [docs/distroless-strategy.md](docs/distroless-strategy.md).

## Security Model (defaults)

- Non-root runtime, deterministic `UID:GID = 10001:10001`.
- Read-only root filesystem; writable paths externalized via tmpfs/volumes.
- `cap_drop: ALL`, `no-new-privileges`, `pids_limit`, no privileged mode.
- No secrets in images, no Composer/shell in runtime where feasible.
- Pinned bases, reproducible builds, OCI labels, Cosign signatures, SBOMs.

Full model: [docs/threat-model.md](docs/threat-model.md),
[docs/runtime-hardening.md](docs/runtime-hardening.md).

## Quick Start (consume an image)

```bash
# Authenticate (read-only token on production hosts)
echo "$GHCR_READ_TOKEN" | docker login ghcr.io -u <user> --password-stdin

# Pull by tag (dev) — NEVER deploy :latest
docker pull ghcr.io/zenchron-dynamics/php-fpm:8.3-prod

# Production: pin by digest
docker pull ghcr.io/zenchron-dynamics/php-fpm@sha256:<digest>

# Verify the signature before running
cosign verify \
  --certificate-identity-regexp 'https://github.com/zenchron-dynamics/docker-platform/.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ghcr.io/zenchron-dynamics/php-fpm:8.3-prod
```

A minimal Laravel consumer Dockerfile and Compose stack live in
[examples/laravel](examples/laravel). Full guide:
[docs/consuming-images.md](docs/consuming-images.md).

## Local Build

```bash
make init            # bootstrap dev environment
make hooks           # install pre-commit hooks
make lint            # hadolint + shellcheck + yaml + md + gitleaks
make build-php-fpm   # build the php-fpm family locally
make scan            # trivy + grype
make sbom            # syft SBOMs
```

Run `make help` for the full target list.

## Versioning & Releases

Strict immutable tags, digest pinning, separate legacy lines, documented
rollback: [docs/image-versioning.md](docs/image-versioning.md).
Release process: [docs/sbom-and-signing.md](docs/sbom-and-signing.md) +
`.github/workflows/release.yml`.

## Repository Map

```text
images/     Dockerfiles + runtime config per family/version
profiles/   Shared Docker Compose security profiles
examples/   Reference app consumers (Laravel, Symfony, FrankenPHP)
policies/   Scanner / linter / signing configs
scripts/    build / scan / publish / sbom / hooks
docs/       Architecture, hardening, threat model, policies
.github/    CI/CD workflows + Dependabot
```

## Contributing

Internal only. See [CONTRIBUTING.md](CONTRIBUTING.md) and
[SECURITY.md](SECURITY.md). Sign commits, no direct pushes to `master`.

---
© 2026 Zenchron Dynamics — Internal / Proprietary. See [LICENSE](LICENSE).
