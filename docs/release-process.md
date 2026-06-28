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

## Workflow split (steady state)

Responsibilities are separated across workflows so each entry point can do only
one thing. See [security-model.md](security-model.md) for the publish-authority
matrix and [release-checklist.md](release-checklist.md) for the step list.

| Workflow | Trigger | Role |
|----------|---------|------|
| `ci.yml` | push/PR to `master` | structure, no-wolfi, pinned actions + containers, image matrix, lint (shell/yaml/md/hadolint), gitleaks, semgrep, build + smoke **all 10** images, compose validate. **Never** pushes canonical tags. |
| `build-images.yml` | dispatch / call | build-and-validate **only** (`load`, no push); `contents: read` only, so it cannot publish. |
| `publish-ghcr.yml` | `workflow_call` only | reusable publisher. `rc` empty ⇒ stable `*-prod`; `rc` set ⇒ immutable RC tags only. Preflight gates + stable-requires-`v*`-tag check. |
| `publish-rc.yml` | dispatch (`rc` required, `rc<N>`) | RC entry point; gated by the `rc` Environment; publishes RC tags only, never `*-prod`. |
| `release.yml` | push tag `v*` | gated stable release (see below), multi-arch, then verify + manifest + GitHub Release. |
| `scheduled-rebuild.yml` | weekly cron | rebuilds 10 images into dated **candidate** tags (`<fam>:rebuild-<date>` / `<ver>-rebuild-<date>`), multi-arch + signed; scans and opens an issue on new fixable CRITICAL/HIGH. Never mutates `*-prod`. |

### Stable-tag protection

`*-prod` is mutated **exclusively** by `release.yml`. Its `guard` job runs in the
protected `release` GitHub Environment and refuses to publish unless: the tag
matches `vYYYY.MM.DD[.N]`; the tagged commit is an ancestor of `origin/master`
(no releasing unmerged commits); and the repo invariants (pinned actions,
no-wolfi, image matrix) pass. `publish-ghcr.yml` adds a defensive check that a
stable publish (`rc==""`) must come from a valid `v*` tag ref. RC and scheduled
candidates can never write `*-prod`.

### Steady-state stable release

1. Clean, committed, reviewed commit merged to `master` (CI green). Signed
   commits.
2. Publish and validate a release candidate first via `publish-rc.yml`.
3. Tag `vYYYY.MM.DD[.N]` on the same merged commit → `release.yml`:
   - `guard`: tag format + master ancestry + invariants (in the `release` env).
   - `images`: `publish-ghcr.yml` builds multi-arch (amd64+arm64), pushes, **cosign
     sign**, **syft SBOM + cosign attest**, provenance `mode=max`.
   - `release`: `verify-release-artifacts.sh` proves signed + SBOM + provenance +
     multi-arch **10/10 from the registry**, generates `release-manifest.yaml`,
     collects 10 SBOMs strictly (fails if not 10).
4. GitHub Release collects the manifest, SBOMs, checksums, and `VERIFY.md`.

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
