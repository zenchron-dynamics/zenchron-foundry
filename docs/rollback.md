# Rollback

How to revert consumers to a known-good image when a release regresses. The
mechanism is consumer-side re-pinning, because every published tag and digest is
immutable — there is no in-place "undo" of a release, and tags are never
overwritten.

## Principle

Images are addressed by immutable identity. A release never mutates a previous
tag, so rolling back means **pointing your consumer at an earlier image** you
already trust, not changing anything in this repo or the registry.

## Roll back a consumer

1. Pick the prior known-good image. Prefer an immutable **digest**
   (`<image>@sha256:…`); a dated tag (e.g. `php-fpm:8.4-prod-2026.06.14`) or the
   previous `*-prod` digest also work. Every release records its exact digests in
   the attached `release-manifest.yaml`, so that file is the record of what each
   release shipped.
2. Re-pin the consumer (Compose `image:` / Dockerfile `FROM`) to that digest.
3. Verify before deploy:

   ```bash
   cosign verify \
     --certificate-identity-regexp 'https://github.com/zenchron-dynamics/zenchron-foundry/.*' \
     --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
     ghcr.io/zenchron-dynamics/php-fpm:8.4-prod@sha256:<digest>
   ```

4. Redeploy. No DB migration or secret change is tied to the base-image swap; the
   healthcheck ships inside the image, so probe behaviour reverts automatically.

Triggers that justify a rollback: missing extension, worker heartbeat failure,
FPM/FrankenPHP incompatibility, unexpected filesystem write under read-only
rootfs, startup or perf regression, multi-arch mismatch, or a severe CVE
regression.

## Wolfi digests are rollback-only history

The pre-Debian Wolfi/Chainguard + Alpine images are **not deleted** from GHCR and
remain pullable by digest. They are **historical artifacts for emergency rollback
only** — not an active, supported, or rebuilt path. New builds are Debian-backed
official images (see [wolfi-migration.md](wolfi-migration.md) and
[adr/ADR-0001-remove-wolfi-chainguard.md](adr/ADR-0001-remove-wolfi-chainguard.md)).

The stable pre-`2026.06.21` Wolfi `*-prod` rollback digests are listed in
[migration/wolfi-to-debian.md](migration/wolfi-to-debian.md#stable-rollback-digests-pre-20260621-wolfi--prod).
If you roll back to a Wolfi FrankenPHP image, also revert any `/data` + `/config`
tmpfs/volume changes you made for the Debian variant (XDG dirs moved under
`/tmp`).

## Forward fix is preferred

Rollback buys time; the durable fix is a new dated release. Bump the affected base
digest (or candidate from `scheduled-rebuild.yml`), then cut a fresh
`vYYYY.MM.DD[.N]` tag through the gated [release-checklist.md](release-checklist.md)
path. Never reissue an old tag.
