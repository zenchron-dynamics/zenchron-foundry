# Release process (Debian-first migration & ongoing)

Companion to `docs/release-governance.md` (governance) and
`docs/image-versioning.md` (tag scheme). This file describes the **phased
rollout** of the Debian-first images and the steady-state release flow.
The evidence files each stage emits are specified in
[release-evidence.md](release-evidence.md) (the authoritative schema).

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
| `publish-ghcr.yml` | `workflow_call` only | reusable **builder/publisher**. Only caller is `publish-rc.yml` (always `rc` set ⇒ immutable RC tags). Its `rc==""` stable branch is retained as defence-in-depth but no workflow invokes it — stable tags are never *built*, only *promoted*. |
| `publish-rc.yml` | dispatch (`rc` required, `rc<N>`) | RC entry point; gated by the `foundry-rc` Environment; builds + signs RC tags only, never `*-prod`. |
| `promote-stable.yml` | dispatch **from `refs/tags/<version>`** (`version`, `rc`, `rc_manifest_run_id`) | **exact-digest promotion** — copies the already-signed RC digests onto `*-prod` aliases via registry retag (`docker buildx imagetools create`). **No `docker build`** (rule #14). Gated by the `foundry-production` Environment; two-phase + digest-equality verified; emits rollback metadata. |
| `release.yml` | dispatch **from `refs/tags/<version>`** (`version`, `rc`, `rc_manifest_run_id`) | **seals** the stable release over already-promoted images — verify + manifest + GitHub Release. **No build.** Refuses if the stable aliases have not been promoted yet. |
| `scheduled-rebuild.yml` | weekly cron | rebuilds 10 images into dated **candidate** tags (`<fam>:rebuild-<date>` / `<ver>-rebuild-<date>`), multi-arch + signed; scans and opens an issue on new fixable CRITICAL/HIGH. Never mutates `*-prod`. |

### Stable-tag protection

`*-prod` is mutated **exclusively** by `promote-stable.yml`, and only by copying
an already-validated RC digest — never by a build. It runs in the protected
`foundry-production` GitHub Environment (required reviewers) and validates the `version`
(`vYYYY.MM.DD[.N]`) and `rc` (`rc<N>`) inputs, verifies every RC digest is signed
and attested before touching an alias, and fails if any promoted alias does not
match its RC digest exactly. `release.yml`'s `guard` (also in the `foundry-production` env)
additionally requires the tag to match `vYYYY.MM.DD[.N]` and the tagged commit to
be an ancestor of `origin/master` (no releasing unmerged commits) before it seals
the release. RC and scheduled candidates can never write `*-prod`.

### Ceremony order (tag-first, artifact-sourced)

```text
publish-rc  →  create the stable tag on the SAME revision
            →  promote-stable  (dispatched from refs/tags/<version>)
            →  release         (dispatched from the same tag)
```

Two rules make this order mandatory, both learned from the first live attempt:

- **Tag before promotion.** `foundry-production` admits stable tags only, so a
  promotion dispatched from a branch is refused by the environment. Both
  workflows now assert `github.ref == refs/tags/<version>` themselves
  (`scripts/check-promotion-ref.sh`) so the failure is loud and local.
- **Never commit the generated RC manifest.** The signed manifest is downloaded
  from the successful `publish-rc` run that produced it
  (`scripts/fetch-rc-manifest.sh`, artifact `rc-manifest-<version>-<rc>`).
  Committing it under `release-evidence/<version>/` would create a *new* commit
  after the RC images were built, so the release tag would no longer point at the
  revision baked into the images — breaking the equality chain
  `tag commit == manifest.revision == provenance revision == OCI revision`.
  There is no fallback to locally committed evidence.

### Steady-state stable release

1. Clean, committed, reviewed commit merged to `master` (CI green, `scan-images`
   green on that exact commit). Signed commits.
2. Publish and validate a release candidate via `publish-rc.yml` (builds + signs
   the immutable `rc<N>` images, multi-arch). Record its **run ID** — it is the
   only source of the signed RC manifest.
3. Tag `vYYYY.MM.DD[.N]` on the **exact revision the RC was built from** and push
   the tag. Nothing is sealed by the tag push; the tag only makes the production
   environment reachable and binds the release to the commit.
4. **Promote** the validated RC via `promote-stable.yml`, dispatched **from
   `refs/tags/<version>`** (`version`, `rc`, `rc_manifest_run_id`,
   `expected_revision` = the tag commit), in the protected `foundry-production`
   Environment. It performs **no build** — for each of the 10 images it:
   - Phase 1: resolves the exact RC digest and verifies it is Cosign-signed +
     SBOM-attested; records the current `*-prod` digest for rollback. Mutates
     nothing until all 10 pass.
   - Phase 2: retags each exact RC digest onto its stable aliases
     (`<ver>-prod`, `<ver>-prod-<rel>`, `<ver>-debian`; edges `prod`, `prod-<rel>`).
     Signatures ride the digest, so no re-signing.
   - Phase 3: verifies every stable alias resolves to the exact RC digest.
   Rollback metadata (prior alias digests) is uploaded as an artifact.
5. **Seal** via `release.yml`, dispatched **from the same tag** with the same
   `version`, `rc` and `rc_manifest_run_id`, plus the **required**
   `verify_rc_run_id` — the `verify-rc` run that certified this exact commit.
   The guard verifies that run (workflow name, `success` conclusion,
   `head_sha == release commit`, 10/10 successful `certify` jobs) and derives
   `RUNTIME_RESULT` from it; the evidence verification counts
   (signature/SBOM/provenance/OCI-revision/arch) are read from the results file
   `verify-release-artifacts.sh` writes, never entered by hand:
   - `guard`: ref is the stable tag for `version`, master ancestry, invariants,
     exact-commit CI (incl. `scan-images`), RC manifest fetched + verified from
     the `publish-rc` artifact, and **stable aliases already equal the RC
     digests** (`verify-release-binding.sh`) — sealing before promotion fails here.
   - `release`: `verify-release-artifacts.sh` proves signed + SBOM + provenance +
     multi-arch **10/10 from the registry** (over the promoted images — no build),
     attaches the signed RC manifest **as fetched** (never regenerated), collects
     10 SBOMs strictly (fails if not 10).
6. GitHub Release collects the manifest, SBOMs, checksums, and `VERIFY.md`.

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
