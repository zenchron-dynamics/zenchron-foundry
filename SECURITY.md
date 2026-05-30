# Security Policy

## Scope

This repository produces **golden container images** for Zenchron Dynamics PHP
workloads. A vulnerability here can propagate to every downstream application,
so security issues are treated as high priority.

## Reporting a Vulnerability

**Do not open a public issue for security problems.**

- Email: `security@zenchron.com` (PGP key on request).
- Use GitHub **Private Vulnerability Reporting** (Security tab → Report a
  vulnerability) if enabled.
- Include: affected image/tag, PHP version, CVE (if known), reproduction, and
  impact.

Target response times:

| Severity | Acknowledge | Triage | Fix / mitigation |
|----------|-------------|--------|------------------|
| Critical | 24h         | 48h    | Emergency rebuild (see vulnerability-management.md) |
| High     | 48h         | 5d     | Next scheduled rebuild or sooner |
| Medium   | 5d          | 10d    | Next scheduled rebuild |
| Low      | 10d         | best effort | Backlog |

## Supported Images

| Family | Versions | Status |
|--------|----------|--------|
| php-fpm / php-cli / php-worker | 8.3, 8.4 | Supported |
| php-frankenphp | 8.3, 8.4 | Supported |
| caddy / nginx | prod | Supported |
| php-fpm / php-cli / php-worker | **7.4, 8.0** | **Legacy / EOL — best-effort only.** See [docs/legacy-php-policy.md](docs/legacy-php-policy.md) |

PHP 7.4 and 8.0 receive **no upstream security support**. They exist solely for
legacy compatibility and carry accepted, documented risk.

## Security Controls in This Repository

- Secret scanning (Gitleaks) in pre-commit and CI.
- Dockerfile linting (Hadolint), IaC/SAST (Semgrep) in CI.
- Image vulnerability scanning (Trivy + Grype) with SARIF upload.
- SBOM generation (Syft, SPDX + CycloneDX) per image.
- Keyless image signing and attestation (Cosign + GitHub OIDC).
- Branch protection, required reviews, CODEOWNERS, signed commits, Dependabot.

## Expectations for Consumers

- Pin images **by digest** in production (`@sha256:...`), never `latest`.
- Verify signatures before deploy (see `scripts/verify-signatures.sh`).
- Subscribe to release notifications for emergency rebuild advisories.
