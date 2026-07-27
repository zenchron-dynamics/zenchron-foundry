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
- Dependabot (GitHub Actions, Docker bases, Composer examples).
- **Governance (enforced, verified 2026-07-28):** the repository is public, so
  branch and tag rulesets are available and **applied** — `master` requires a
  pull request with all 26 status checks, linear history, conversation
  resolution, and blocks direct push, force-push and deletion; `v*` tags are
  immutable (no delete, force-move or repoint). **No bypass actors, including
  administrators.** Declared in `policies/repository-governance.yaml` and
  machine-checked against the live API by `scripts/verify-repo-governance.sh`
  (`make verify-governance`), which fails closed on drift in either direction.
  Evidence: [docs/audits/governance-verification-2026-07-28.json](docs/audits/governance-verification-2026-07-28.json).
  Alongside it: deployment branch/tag policies on the `foundry-rc` (branch
  `master`) and `foundry-production` (tags `v*.*.*`) environments,
  typed-confirmation workflow inputs, an exact-commit CI gate and local git hooks.
- **Known governance gaps (not controls):** a required second reviewer and
  CODEOWNERS enforcement cannot be satisfied by a single maintainer — GitHub
  forbids self-approval, so requiring them with no bypass actor would make every
  merge impossible. Both stay off, recorded via `ALLOW_FREE_TIER_NO_REVIEWERS=1`
  and issue #112, together with environment approval gates (now *available*,
  since the repo is public, but not yet applied). Signed commits remain policy,
  not enforcement. Superseded record:
  [docs/audits/free-tier-governance-accepted-risk.md](docs/audits/free-tier-governance-accepted-risk.md).

## Accepted Vulnerability Exceptions

Known CVEs that are accepted rather than fixed are recorded — with approver,
expiry, compensating controls, and an explicit release-blocking flag — in
[docs/vulnerability-exceptions.md](docs/vulnerability-exceptions.md). The
exception ledger is enforced in CI by
`scripts/validate-vulnerability-exceptions.sh` (expired or malformed entries
fail the pipeline).

## Expectations for Consumers

- Pin images **by digest** in production (`@sha256:...`), never `latest`.
- Verify signatures before deploy (see `scripts/verify-signatures.sh`).
- Subscribe to release notifications for emergency rebuild advisories.
