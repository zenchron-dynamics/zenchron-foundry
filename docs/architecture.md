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
dev push tag v* ──► GitHub Actions (publish-ghcr.yml)
                     ├─ buildx build (multi-stage)
                     ├─ push ghcr.io/zenchron-dynamics/<fam>:<ver>-prod (+date,+build)
                     ├─ cosign sign (keyless, OIDC)
                     └─ syft SBOM + cosign attest
production host ──► docker login ghcr.io (read-only token)
                     ├─ cosign verify  (REQUIRED)
                     └─ docker pull <image>@sha256:<digest>
```

## CI/CD flow

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `ci.yml` | PR, push | structure, lint, secrets, SAST, build-test, compose validate |
| `build-images.yml` | manual / called | matrix build, cache, multi-arch ready |
| `scan-images.yml` | PR(images), weekly | Trivy + Grype + Syft, SARIF upload |
| `publish-ghcr.yml` | tag `v*` | build + push + sign + attest |
| `release.yml` | tag `v*` | GitHub Release with SBOMs, checksums, verify notes |

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
