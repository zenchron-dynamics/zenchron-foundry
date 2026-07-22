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

   > Signature compatibility: the repo pins **cosign v2.5.2** and publishes
   > v2-format `.sig`/`.pem` signatures — use a cosign v2-compatible client
   > with `--certificate-identity-regexp` and the issuer above.

4. Redeploy. No DB migration or secret change is tied to the base-image swap; the
   healthcheck ships inside the image, so probe behaviour reverts automatically.

Triggers that justify a rollback: missing extension, worker heartbeat failure,
FPM/FrankenPHP incompatibility, unexpected filesystem write under read-only
rootfs, startup or perf regression, multi-arch mismatch, or a severe CVE
regression.

## Registry-side rollback (operator runbook)

Consumer re-pinning (above) is the normal path. `scripts/rollback-stable.sh`
handles the other case: a **stable promotion that mutated aliases and then
failed** (or a just-promoted release that must be backed out registry-side
before sealing). It replays the promotion's mutation journal in **reverse**,
restoring each mutated alias to the prior digest recorded in the rollback
manifest. `promote-stable.yml` runs it automatically on failure; this section
is for running it by hand. The mechanism was exercised **live** during the
v2026.07.21 ceremony (`rollback-results.json` in the release assets).

- **Required inputs** — both come from the **promotion evidence artifact**
  (`promotion-evidence-<version>`: `rollback-*.yaml*` +
  `promotion-journal-*.txt`) of the failed `promote-stable.yml` run:
  the **rollback manifest** (prior digest per alias) and the
  **mutation journal** (the aliases actually changed, in order):

  ```bash
  ALLOW_LOCAL_PROMOTE=1 scripts/rollback-stable.sh <rollback-manifest.yaml> <journal>
  ```

- **`ALLOW_LOCAL_PROMOTE=1` is required outside CI.** The registry primitives
  (`scripts/lib/registry-ops.sh`) refuse to mutate a production alias unless
  they are running inside GitHub Actions or this variable is set explicitly —
  the v2026.07.21 rollback exercise proved a laptop could silently retag
  `*-prod`, and that path is now closed. Setting it is a deliberate, logged
  operator decision; without it the script exits with
  `REFUSE: production alias mutation outside CI`.

- **Verification** — the script restores last-mutated-first and re-resolves
  every alias, requiring digest equality with the recorded prior. Afterwards,
  re-resolve the aliases yourself (`docker buildx imagetools inspect` /
  `cosign verify`) before trusting the registry state.
- **Exit 99 = EMERGENCY** — one or more aliases could not be restored. The
  script writes `ROLLBACK-INCIDENT.txt` listing every inconsistent alias, and
  release sealing is blocked until the registry state is reconciled.
- **Known limitation (GHCR)** — an alias that was newly *created* by the
  promotion (prior = `NONE`) cannot be untagged from CI on GHCR. It is left
  tagged, recorded as a non-fatal `LEFT-TAGGED` note; every alias that had a
  prior digest is fully restored.
- **Recovery path** — after fixing the root cause, **re-dispatch
  `promote-stable.yml` from the release tag** (`refs/tags/<version>`).
  Promotion is a digest-only retag driven by the same signed RC manifest, so
  re-running it converges the aliases without any rebuild.

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
