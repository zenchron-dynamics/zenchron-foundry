# Release process (Debian-first migration & ongoing)

Companion to `docs/release-governance.md` (governance) and
`docs/image-versioning.md` (tag scheme). This file describes the **phased
rollout** of the Debian-first images and the steady-state release flow.

## Tagging

- Provider-explicit immutable alias: **`<fam>:<ver>-debian`** (e.g.
  `php-cli:8.4-debian`) — always points at the Debian build of that version.
- Generic supported tag: **`<fam>:<ver>-prod`** (e.g. `php-fpm:8.4-prod`) —
  becomes Debian-backed at Phase G.
- Date/build tags: `<ver>-prod-YYYY.MM.DD`, `<ver>-prod-build.<run>`.
- No `latest`, no mutable production references. Stable images are signed
  (cosign keyless) with SBOM + provenance attestations.

## Phased rollout (this migration)

| Phase | What | Tags touched | Gate |
|-------|------|--------------|------|
| A — Audit | Inventory, ADR-0001, package mapping, matrices | none | — |
| B — Debian POC | Build 8.4 cli/fpm/worker/frankenphp | none (local) | builds green |
| C — Validation | Laravel + Symfony + ProxyFlux-shape, security, scans, SBOM, multi-arch | none | all validations pass |
| D — Candidate | Publish RC tags `8.4-debian-rc1` (clearly non-production) | `*-debian-rc*` | reviewed |
| E — Consumer validation | Verify `php-app-template` compat (no edits) | none | required consumer changes recorded |
| F — Stable release | New Foundry release `vYYYY.MM.DD`; publish `*-debian` + date/build tags | `*-debian`, dated | release approved |
| G — Default migration | Repoint generic `8.x-prod` to Debian builds | `8.x-prod` | explicit approval + release notes |
| H — Wolfi retirement | Mark Wolfi tags deprecated, freeze, stop rebuilds, keep rollback window | (Wolfi tags) | approval |

**Do not** repoint `8.x-prod` (Phase G) without release notes, migration doc,
compatibility validation, a rollback tag, and an explicit versioned release.

## Steady-state release

1. Clean, committed working tree on `master` (never build artifacts from a dirty
   tree). Signed commits.
2. Tag `vYYYY.MM.DD` → `release.yml` calls `publish-ghcr.yml`:
   - preflight: `check-structure.sh` + `assert-no-wolfi.sh`.
   - build multi-arch (amd64+arm64), push, **cosign sign**, **syft SBOM +
     cosign attest**, provenance `mode=max`.
3. GitHub Release collects SBOMs + checksums + `VERIFY.md`.

## Pre-release checklist (must all pass)

- `make check-structure` (layout + base pins + no-`latest`).
- `scripts/assert-no-wolfi.sh` clean.
- Build all supported targets (8.3 + 8.4) on amd64 **and** arm64.
- `php -m` matches `docs/php-extension-matrix.md`.
- Runtime: non-root, read-only rootfs, cap_drop ALL, no-new-privileges,
  healthchecks, worker heartbeat, FPM FastCGI, FrankenPHP HTTP/health.
- Trivy gate (fixable CRITICAL/HIGH) green for PHP images; nginx/caddy reviewed.
- SBOM generated; signing + attestation succeed.
- No secrets in layers (gitleaks); hadolint clean; shellcheck clean.

## Rollback

See `docs/migration/wolfi-to-debian.md` and
`docs/security/base-image-patching.md`. Previous digests are recorded; consumers
revert independently by re-pinning a prior immutable tag/digest.
