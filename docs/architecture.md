# Architecture

## What this repository is

`docker-platform` is a **golden-image factory**. It produces hardened, signed,
scanned base images and the shared security scaffolding (Compose profiles, CI,
policies) that downstream PHP applications consume. It contains **no application
code**.

## Base image vs application image

```text
 ┌─────────────────────────────┐        ┌──────────────────────────────┐
 │  docker-platform (this repo) │        │  an app repo (e.g. billing)   │
 │  builds BASE images          │  --->  │  FROM ghcr.io/.../php-fpm:8.3 │
 │  ghcr.io/zenchron-dynamics/* │  pull  │  COPY . /app ; composer ...   │
 └─────────────────────────────┘        └──────────────────────────────┘
```

- **Base image** (here): runtime + extensions + hardened config. No app, no
  secrets, no Composer in the final stage.
- **Application image** (app repo): `FROM` a base, adds vendored code in its own
  builder stage, copies only artifacts into the runtime. See
  [consuming-images.md](consuming-images.md).

## Builder image vs runtime image

Every Dockerfile is **multi-stage**:

- **Builder stage** — may contain `apk`, compilers, `install-php-extensions`,
  Composer. Discarded.
- **Runtime stage** — minimal, non-root (`10001:10001`), read-only-rootfs
  capable, only runtime libraries. This is what ships.

Build tooling, package managers, and shells are kept out of the final image
wherever technically feasible (see [distroless-strategy.md](distroless-strategy.md)).

## Registry flow

```text
publish-rc.yml (dispatch, master) ──► publish-ghcr.yml (workflow_call)
                     ├─ buildx build (multi-stage, amd64+arm64)
                     ├─ push immutable RC tags (e.g. 8.4-vYYYY.MM.DD-rcN-sha-<12>)
                     ├─ cosign sign (keyless, OIDC)
                     └─ syft SBOM + cosign attest; signed RC manifest artifact
verify-rc.yml   ──► cold-build + smoke + multi-arch certification of the RC
tag vYYYY.MM.DD ──► on the exact RC revision
promote-stable.yml (dispatch FROM the tag)
                     └─ digest-only retag RC digests → *-prod (zero builds)
release.yml (dispatch FROM the same tag; no tag-push trigger)
                     └─ verify + seal GitHub Release (builds nothing)
production host ──► docker login ghcr.io (read-only token)
                     ├─ cosign verify  (REQUIRED)
                     └─ docker pull <image>@sha256:<digest>
```

## CI/CD flow

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `ci.yml` | PR, push | structure, lint, secrets, SAST, build-test, compose validate |
| `build-images.yml` | dispatch / called | matrix build validation only — no `packages: write`, cannot push |
| `scan-images.yml` | PR(images), weekly, dispatch | Trivy + Grype + Syft, SARIF upload |
| `publish-rc.yml` | dispatch (from `master`, `foundry-rc` environment) | build + push + sign + attest immutable RC tags; signs the RC manifest |
| `publish-ghcr.yml` | `workflow_call` **only** (sole caller: `publish-rc.yml`) | reusable build/push/sign/attest engine |
| `verify-rc.yml` | dispatch / called | cold-build, smoke, contract + multi-arch certification of a published RC |
| `promote-stable.yml` | dispatch from `refs/tags/<version>` | digest-only retag of RC digests onto `*-prod` — zero builds, no re-sign |
| `release-preflight.yml` | dispatch | read-only readiness checks before sealing |
| `release.yml` | dispatch from `refs/tags/<version>` — **no tag-push trigger, no build** | verifies promoted images + signed RC manifest (from the `publish-rc` artifact), seals the GitHub Release |
| `scheduled-rebuild.yml` | weekly cron / dispatch | dated candidate tags only; never mutates `*-prod` |
| `verify-signatures.yml` | dispatch | registry-side signature + attestation verification |

The `foundry-rc` / `foundry-production` environments gate the publish and
promote/seal dispatches via deployment branch (`master`) and tag (`v*.*.*`)
policies. Environment *required reviewers* are **not attached** — available since
the repo is public, but unusable with a single maintainer, so waived via
`ALLOW_FREE_TIER_NO_REVIEWERS=1`; see
[repository-security.md](repository-security.md) and issue #112.
`master` and `v*` themselves are protected by active rulesets with no bypass
actors (`make verify-governance`).

## Runtime profile flow

Apps layer shared Compose profiles over their own `compose.yml`:

```text
compose.yml                         # app services + image refs
+ profiles/compose.security.yml     # cap_drop, no-new-privileges, pids, ro user
+ profiles/compose.readonly.yml     # read-only rootfs + writable mounts
+ profiles/compose.laravel.yml      # framework-specific wiring
= hardened production stack
```

See [runtime-hardening.md](runtime-hardening.md) and the `profiles/` directory.
