# Wolfi/Chainguard removal (top-level summary)

Zenchron Foundry no longer builds on Wolfi/Chainguard. This is the high-level
"why" and "what now". For the consumer-facing change details and old→new digest
tables see [migration/wolfi-to-debian.md](migration/wolfi-to-debian.md); for the
decision record see
[adr/ADR-0001-remove-wolfi-chainguard.md](adr/ADR-0001-remove-wolfi-chainguard.md).

## Why Wolfi/Chainguard was removed

The Wolfi/Chainguard approach delivered very low CVE counts but carried
durability and supply-chain risks tied to a community/OSS maintenance model
outside our control:

- **Provider dependence.** Wolfi PHP packages and `cgr.dev` access depended on
  Chainguard's free/paid feed policy; availability, retention, and the registry
  itself were not under our control and had changed before.
- **Rolling, unversioned PHP packages.** `apk add php-8.x` tracked a fast-moving
  feed; reproducibility leaned entirely on pinning the base digest, and exact PHP
  patch levels were whatever shipped that day.
- **Opaque package mapping** diverging from the mainstream ecosystem, making
  audits and consumer support harder.
- **No first-party toolchain** — extensions arrived as prebuilt apks rather than
  compiled from official PHP source.

## What now: Debian-first official images

New builds use official, upstream, digest-pinned Debian images
(`php:*-{cli,fpm}-bookworm`, `dunglas/frankenphp:1-php*-bookworm`,
`nginxinc/nginx-unprivileged:1.27-bookworm`), with extensions compiled from
official PHP source via the official toolchain. Caddy stays on the official
Alpine image — the single documented exception — because no official Debian Caddy
image exists. All runtime hardening is preserved (non-root 10001, cap_drop ALL,
read-only rootfs, digest pins, SBOM, signing, provenance).

## Wolfi is not an active path

Wolfi/Chainguard is **no longer a supported or rebuilt path**. The old Wolfi +
Alpine images are not deleted from GHCR and remain pullable by digest, but they
are **rollback-only historical artifacts** — kept solely so a consumer can revert
in an emergency. They are not scanned as a gate, not rebuilt, and not promoted.
The stable pre-`2026.06.21` Wolfi `*-prod` rollback digests are listed in
[migration/wolfi-to-debian.md](migration/wolfi-to-debian.md#stable-rollback-digests-pre-20260621-wolfi--prod);
see [rollback.md](rollback.md) for the procedure.
