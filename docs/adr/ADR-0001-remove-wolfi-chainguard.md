# ADR-0001 — Remove Wolfi/Chainguard, adopt a Debian-first base image platform

- Status: **Accepted**
- Date: 2026-06-20
- Deciders: Platform / Zenchron Dynamics
- Supersedes: the original "Wolfi/Chainguard hardened-minimal" base decision

## Context

Zenchron Foundry built its PHP runtime images (`php-cli`, `php-fpm`,
`php-worker`) on `cgr.dev/chainguard/wolfi-base`, installing PHP via Wolfi `apk`
packages. `php-frankenphp` and `nginx` used Alpine bases with `apk upgrade`;
`caddy` used the official Alpine Caddy image.

The Wolfi/Chainguard approach delivered very low CVE counts but introduced
durability and supply-chain risks we are no longer willing to carry:

- **Provider dependence.** Wolfi PHP packages and `cgr.dev` access depend on
  Chainguard's free/paid feed policy. Package availability, retention, and the
  registry itself are outside our control and have changed before.
- **Rolling, unversioned PHP packages.** `apk add php-8.x` tracks a fast-moving
  feed; reproducibility relied solely on pinning the base digest, and exact PHP
  patch levels were whatever the feed shipped that day.
- **Opaque package mapping.** Wolfi package names (`ca-certificates-bundle`,
  `php-8.x-mysqlnd`, extensions-as-apks) diverge from the rest of the ecosystem,
  making audits and consumer support harder.
- **No first-party toolchain.** Extensions came as prebuilt apks, not compiled
  from the official PHP source via a maintained toolchain.

## Decision

Replace Wolfi/Chainguard with **official, upstream, digest-pinned Debian images**:

| Family | New base |
|--------|----------|
| `php-cli`        | `php:<ver>-cli-bookworm` |
| `php-fpm`        | `php:<ver>-fpm-bookworm` |
| `php-worker`     | `php:<ver>-cli-bookworm` + `tini` + worker entrypoint |
| `php-frankenphp` | `dunglas/frankenphp:1-php<ver>-bookworm` |
| `nginx`          | `nginxinc/nginx-unprivileged:1.27-bookworm` (Debian) |
| `caddy`          | `caddy:2-alpine` (see exception below) |

PHP extensions are **compiled from the official PHP source** with the official
toolchain (`docker-php-ext-install` / `pecl`) in a throwaway build stage; the
runtime stage carries only the compiled `.so` files plus their shared libraries,
and the compiler toolchain inherited from `buildpack-deps` is stripped so no
build tools reach the final image.

Supported lines are **PHP 8.3 and 8.4**. PHP 7.4 and 8.0 are **frozen legacy**:
no Debian rebuild, no new artifacts (see "Legacy" below).

### Caddy exception

The official Caddy image publishes **only Alpine and Windows** variants — there
is no upstream Debian Caddy image. Rebuilding Caddy on Debian (xcaddy) would be
an **unofficial rebuild**, which this ADR forbids without its own ADR. Caddy
therefore stays on the **official Alpine base**: it is a durable official
upstream, digest-pinned, runs **no `apk` commands** in our Dockerfile, and
clears every runtime security gate (non-root, cap_drop ALL, read-only). This is
the single intentional non-Debian base; see `docs/base-image-strategy.md`.

## Rejected alternatives

- **Continue with Wolfi/Chainguard.** Rejected: provider dependence, rolling
  packages, and the audit/support friction above.
- **Alpine as the default.** Rejected: musl libc compatibility surprises for PHP
  workloads, and it does not advance the "official, durable, mainstream" goal.
  (Caddy on Alpine is a contained exception, not a default.)
- **Google Distroless as the default.** Rejected for the first production
  replacement: distroless ships no PHP and no shell; building a PHP runtime on it
  means hand-assembling every runtime library and forgoing the official PHP
  image contract. Kept as a **future experimental track** (see
  `docs/distroless-strategy.md`).
- **Ubuntu Chiseled as the default.** Rejected for now: promising minimal-Debian
  lineage but no official PHP chiseled image exists; same hand-assembly problem.
  Kept as a **future experimental track**.

## Consequences

### Positive

- Provider-independent, mainstream, well-documented base.
- Official toolchain; reproducible extension builds; pinned `pecl` versions.
- Familiar Debian package names → easier audits and consumer support.
- All runtime security controls preserved or improved (non-root 10001,
  cap_drop ALL, read-only rootfs, no build tools in final image, digest pins,
  SBOM, signing, provenance).

### Negative / tradeoffs

- **Larger images** (~700–900 MB vs ~100–150 MB on Wolfi). Accepted for
  durability and maintainability; honestly reported in
  `docs/migration/wolfi-to-debian.md`.
- **More distro CVEs reported.** Debian carries unfixed distro CVEs in essential
  packages (`perl-base`, `zlib1g`, `libsqlite3-0`, `ncurses`) that Wolfi did not
  surface. These are **unfixable** (no Debian fix available), triaged in
  `docs/vulnerability-management.md`. The enforcing gate blocks only on
  **fixable** CRITICAL/HIGH; the PHP images currently have **zero** fixable
  CRITICAL/HIGH.
- **Edge images depend on upstream rebuild cadence.** `nginx`/`caddy` ship
  whatever Debian/Alpine snapshot upstream last built; their fixable CVEs clear
  when upstream rebuilds (surfaced by the weekly scan + Dependabot).

## Rollback

Wolfi images remain published in GHCR and are not deleted. Consumers can pin the
previous Wolfi digest/tag. The Wolfi Dockerfiles remain in git history. See
`docs/migration/wolfi-to-debian.md` for old→new digests and the rollback runbook.

## Evidence required before promoting Debian tags to the generic `8.x-prod`

Build success, full extension parity, Laravel + Symfony + ProxyFlux-shape
validation, worker heartbeat, FPM FastCGI, FrankenPHP HTTP/health, non-root +
read-only validation, Trivy/Grype reviewed, SBOM + signing + attestation, and a
clean committed merge commit. See `docs/release-process.md` (phases A–H).
