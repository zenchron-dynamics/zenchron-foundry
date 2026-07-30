# Zenchron Dynamics — `docker-platform`

> Internal **container platform / golden images** repository.
> Hardened, signed, scanned, SBOM-backed base images for PHP workloads,
> published to `ghcr.io/zenchron-dynamics/*`.

This is **not an application repository.** It produces reusable runtime base
images plus shared Docker Compose security profiles, CI/CD, and docs that
multiple Laravel / Symfony / PHP apps consume.

---

## ⚠️ Legacy PHP Warning

`PHP 7.4` and `PHP 8.0` are **end-of-life**. They are **frozen legacy artifacts**:
the previously-published Wolfi images remain pullable from GHCR, but their source
has been removed and **they are never rebuilt** (Debian-first migration,
[ADR-0001](docs/adr/ADR-0001-remove-wolfi-chainguard.md)). **Do not start new
projects on them; migrate off.** See [docs/legacy-php-policy.md](docs/legacy-php-policy.md).

---

## Supported Images

Base strategy is **Debian-first** — official, upstream, digest-pinned images; PHP
extensions compiled with the official toolchain. See
[docs/base-image-strategy.md](docs/base-image-strategy.md) and
[ADR-0001](docs/adr/ADR-0001-remove-wolfi-chainguard.md).

The release matrix is **10 images** — `php-cli`, `php-fpm`, `php-worker`, and
`php-frankenphp`, each in PHP **8.3** and **8.4**, plus `nginx` and `caddy` —
every one published multi-arch for **linux/amd64 + linux/arm64**.

| Image | Tags | Base strategy |
|-------|------|---------------|
| `php-fpm`        | `8.3-prod`, `8.4-prod`, `8.x-debian` | `php:8.x-fpm-bookworm` (Debian 12) |
| `php-cli`        | `8.3-prod`, `8.4-prod`, `8.x-debian` | `php:8.x-cli-bookworm` (Debian 12) |
| `php-worker`     | `8.3-prod`, `8.4-prod`, `8.x-debian` | `php:8.x-cli-bookworm` + tini |
| `php-frankenphp` | `8.3-prod`, `8.4-prod`, `8.x-debian` | `dunglas/frankenphp:1-php8.x-bookworm` |
| `caddy`          | `prod` | Official Caddy (Alpine; no Debian variant exists — ADR-0001 exception) |
| `nginx`          | `prod` | `nginxinc/nginx-unprivileged:1.27-bookworm` (Debian 12) |

> True Google "distroless" ships no PHP. We build on the **official Debian PHP
> images** and keep distroless/chiseled as future experimental tracks — every
> tradeoff is documented in
> [docs/distroless-strategy.md](docs/distroless-strategy.md).

## Security Model (defaults)

- Non-root runtime, deterministic `UID:GID = 10001:10001`.
- Read-only root filesystem; writable paths externalized via tmpfs/volumes.
- `cap_drop: ALL`, `no-new-privileges`, `pids_limit`, no privileged mode.
- No secrets in images, no Composer/shell in runtime where feasible.
- Pinned bases, reproducible builds, OCI labels, Cosign signatures, SBOMs.

Full model: [docs/threat-model.md](docs/threat-model.md),
[docs/runtime-hardening.md](docs/runtime-hardening.md).

## Governance (enforced by GitHub, machine-verified)

This repo is **public** on **GitHub Free**, where branch protection, rulesets and
tag protection *are* available. As of **2026-07-28** they are applied and active,
with **no bypass actors — administrators included**:

- `master` — pull request required, no direct push, no force-push, no deletion,
  linear history, conversation resolution, and the 5 PR-required status checks.
- `v*` tags — **immutable**: cannot be deleted, force-moved or repointed.

Declared in [`policies/repository-governance.yaml`](policies/repository-governance.yaml)
and checked against the live GitHub API by
[`scripts/verify-repo-governance.sh`](scripts/verify-repo-governance.sh)
(`make verify-governance`), which fails closed on divergence in **either**
direction — a claimed-but-missing control *and* undocumented drift. Dated
evidence: [`docs/audits/governance-verification-2026-07-28.json`](docs/audits/governance-verification-2026-07-28.json).

Local hooks (`scripts/install-hooks.sh`), the manual PR policy and the release
safety script (`scripts/prepare-release.sh`) remain as early, offline feedback —
they are no longer the only thing between an accident and `master`.

Still **not** enforced by GitHub, recorded as gaps rather than controls: a second
reviewer (single-maintainer repo, issue #112) and environment approval gates. See
[docs/repository-security.md](docs/repository-security.md),
[docs/manual-pr-policy.md](docs/manual-pr-policy.md),
[docs/ci-failure-policy.md](docs/ci-failure-policy.md); the former Free-plan
accepted risk is **superseded**:
[docs/audits/free-tier-governance-accepted-risk.md](docs/audits/free-tier-governance-accepted-risk.md).

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
  --certificate-identity-regexp 'https://github.com/zenchron-dynamics/zenchron-foundry/.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ghcr.io/zenchron-dynamics/php-fpm:8.3-prod
```

> Signature compatibility: the repo pins **cosign v2.5.2** and publishes
> v2-format `.sig`/`.pem` signatures — verify with a cosign v2-compatible
> client using `--certificate-identity-regexp` and the issuer above.

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
Release process: [docs/release-checklist.md](docs/release-checklist.md);
signing details: [docs/sbom-and-signing.md](docs/sbom-and-signing.md).

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
