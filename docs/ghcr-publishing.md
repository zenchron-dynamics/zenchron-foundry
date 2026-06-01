# GHCR Publishing

## Namespace

```text
ghcr.io/zenchron-dynamics/<family>:<tag>
```

Images map to the GitHub org `zenchron-dynamics`. Packages should be linked to
this repository (`docker-platform`) and inherit its access.

## GitHub Actions permissions

Publishing uses **least privilege** + OIDC keyless signing:

```yaml
permissions:
  contents: read
  packages: write          # push to GHCR
  security-events: write   # SARIF upload
  id-token: write          # cosign keyless (Fulcio/Rekor)
```

No broad `write-all`. No long-lived registry passwords — CI authenticates with
the ephemeral `GITHUB_TOKEN`.

## Package visibility

- Default **private** (internal platform). Grant pull access to deploy
  identities and consuming-app repos/teams.
- If a package must be public, that is an explicit, reviewed decision — update
  `LICENSE` first.

## Production server login (read-only)

Create a **read-only** token for pulls (fine-grained PAT with
`read:packages`, or a deploy identity):

```bash
echo "$GHCR_READ_TOKEN" | docker login ghcr.io -u <bot-user> --password-stdin
docker pull ghcr.io/zenchron-dynamics/php-fpm@sha256:<digest>
```

The production token must **not** have `write:packages`. Rotate per policy;
store in the host's secret manager, never in an image or repo.

## Pulling private images

- **Compose/host:** `docker login ghcr.io` once with the read-only token.
- **Kubernetes (future):** an `imagePullSecret` of type
  `kubernetes.io/dockerconfigjson` referencing the same read-only token.

## Verify before run

Always verify the Cosign signature before deploying — see
[sbom-and-signing.md](sbom-and-signing.md) and `scripts/verify-signatures.sh`.

## Linking packages to the repo (one-time)

In each GHCR package → *Package settings* → *Manage Actions access* / *Repository
access*, link `zenchron-foundry` and grant the deploy team `read`. This ensures
provenance and inherited permissions.

## Multi-arch (linux/arm64)

Images default to `linux/amd64`. The `build-images` and `publish-ghcr` workflows
accept a `platforms` input to publish multi-arch:

```bash
# build only (single arch — the docker exporter cannot load a manifest list):
gh workflow run build-images.yml -f push=false -f platforms=linux/amd64

# publish multi-arch (push uses the OCI exporter, so a manifest list is fine):
gh workflow run publish-ghcr.yml -f platforms=linux/amd64,linux/arm64
```

The Wolfi, Alpine, Caddy, nginx, and FrankenPHP bases all provide arm64, and the
Dockerfiles build natively on arm64 (verified). Note: arm64 legacy builds run
under QEMU emulation in CI and are slower. Pulling on an arm64 host needs the
arm64 variant present, or `docker pull --platform linux/amd64` with emulation.
