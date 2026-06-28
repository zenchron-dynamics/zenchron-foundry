# Base-image digest policy

How upstream base images are approved, pinned, and verified. This is the
operational companion to [base-image-strategy.md](base-image-strategy.md) (the
rationale and the full base inventory) and ADR-0001
([adr/ADR-0001-remove-wolfi-chainguard.md](adr/ADR-0001-remove-wolfi-chainguard.md)).

## Single source of truth

`config/base-images.env` is the authoritative list of every base image the
production matrix may build `FROM`. It is shell-sourceable and records, per
family:

- `<FAMILY>_REF` — the human-readable upstream tag (no digest).
- `<FAMILY>_DIGEST` — the immutable `sha256:` content digest.
- `<FAMILY>_VERSION` — the fully pinned `REF@DIGEST` used by the Dockerfiles.
- `<FAMILY>_ARCHES` — the platforms the digest is expected to provide.
- `LAST_VERIFIED` — the date the digests and arch lists were last confirmed.

The covered families are the 10-image matrix bases: `php-cli`, `php-fpm`,
`php-frankenphp` (each 8.3 and 8.4), `php-worker` (which reuses the `php-cli`
digests because the worker images `FROM` the CLI image), plus `nginx` and
`caddy`. Each Dockerfile pins the same `REF@DIGEST` in its `ARG *_BASE=` line.

## Multi-arch requirement

Every family must resolve on **both** `linux/amd64` and `linux/arm64`. Released
images are built multi-arch, so a base that silently drops an architecture would
break a release; the verifier fails if an expected arch is missing.

## Verification: `scripts/verify-base-images.sh`

The script cross-checks `config/base-images.env` against the live registry and
the Dockerfiles:

1. **Resolves** every `<FAMILY>_VERSION` (`ref@digest`) against the registry.
2. **Multi-arch**: confirms `linux/amd64` and `linux/arm64` both exist for every
   family (Caddy/Alpine included).
3. **Drift**: scans `images/**` and fails if any active `ARG *_BASE=` is not
   digest-pinned or points at a digest that is not in the inventory.

It runs in the `publish-ghcr.yml` preflight and the `scheduled-rebuild.yml`
preflight. Locally, `make validate` invokes it with `LOCAL=1`, which downgrades a
missing Docker to `SKIPPED`; in CI/release context a missing Docker is a hard
failure. `STRICT=1` clears `LOCAL`, making every gate hard.

## The Caddy / Alpine exception

Caddy publishes no official Debian image (Alpine and Windows only), so `caddy`
stays on the official `caddy:2-alpine` base — the single intentional non-Debian
base. It is still digest-pinned, still required to resolve on amd64 + arm64, runs
no `apk` commands in our Dockerfile, and clears every runtime gate. See ADR-0001
and [base-image-strategy.md](base-image-strategy.md) for the full reasoning.

## Updating a base digest

1. Choose the new upstream tag (keep it Debian/bookworm unless the family is the
   Caddy exception).
2. Resolve the multi-arch manifest-list digest:

   ```bash
   docker buildx imagetools inspect <ref>
   ```

3. Update `<FAMILY>_DIGEST` and `<FAMILY>_VERSION` in `config/base-images.env`.
4. Update the matching `ARG *_BASE=` in every Dockerfile under `images/` to the
   exact same `REF@DIGEST`.
5. Bump `LAST_VERIFIED` to today.
6. Run `bash scripts/verify-base-images.sh` and open a PR. Dependabot proposes
   most of these bumps automatically.
