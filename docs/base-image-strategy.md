# Base image strategy (Debian-first)

Authoritative list of base images, why each was chosen, and the rules for
changing them. Decision record: `docs/adr/ADR-0001-remove-wolfi-chainguard.md`.

## Principles

1. **Official upstream images only.** No unofficial rebuilds without an ADR.
2. **Pin by full digest** (`tag@sha256:…`). The tag documents intent; the digest
   is the identity. Never rely on a moving tag alone.
3. **Compile extensions with the official toolchain**, not third-party binary
   package feeds.
4. **Multi-stage**: build tools live in a throwaway stage; the final image holds
   runtime libraries + compiled extensions only.
5. **Patch by digest bump**, not by in-image `apt-get upgrade`
   (`docs/security/base-image-patching.md`).

## Current bases (pinned by digest in each Dockerfile's `*_BASE` ARG)

| Family | Registry / repo | Tag | Platform(s) | License | Lifecycle |
|--------|-----------------|-----|-------------|---------|-----------|
| `php-cli` 8.4 | docker.io `library/php` | `8.4-cli-bookworm` | amd64, arm64 | PHP License + Debian (mixed) | PHP 8.4 active; Debian 12 supported to ~2028 |
| `php-cli` 8.3 | docker.io `library/php` | `8.3-cli-bookworm` | amd64, arm64 | as above | PHP 8.3 active |
| `php-fpm` 8.4 | docker.io `library/php` | `8.4-fpm-bookworm` | amd64, arm64 | as above | PHP 8.4 active |
| `php-fpm` 8.3 | docker.io `library/php` | `8.3-fpm-bookworm` | amd64, arm64 | as above | PHP 8.3 active |
| `php-worker` 8.x | docker.io `library/php` | `8.x-cli-bookworm` | amd64, arm64 | as above | tracks the CLI base |
| `php-frankenphp` 8.x | docker.io `dunglas/frankenphp` | `1-php8.x-bookworm` | amd64, arm64 | MIT (FrankenPHP) + Debian | FrankenPHP 1.x; PHP ≥ 8.2 |
| `nginx` | docker.io `nginxinc/nginx-unprivileged` | `1.27-bookworm` | amd64, arm64 | BSD-2 (nginx) + Debian | nginx 1.27 stable |
| `caddy` | docker.io `library/caddy` | `2-alpine` | amd64, arm64 | Apache-2.0 (Caddy) + Alpine | Caddy 2.x |

> The exact pinned digests live in each Dockerfile and in
> `docs/migration/wolfi-to-debian.md`. Dependabot (`.github/dependabot.yml`)
> proposes digest bumps weekly.

## Why Debian bookworm

- `php:*-bookworm` is the official, freshly-rebuilt PHP image on the current
  Debian stable. We do **not** hardcode `bookworm` blindly — it is the supported
  Debian stable that the chosen PHP tags publish against. When Debian 13
  (`trixie`) becomes the PHP default, bump the tag + digest in one reviewed PR.
- Debian stable, not testing/unstable: predictable security support.

## The Caddy exception

Caddy publishes no official Debian image (Alpine + Windows only). We keep the
**official Alpine** Caddy image rather than an unofficial Debian rebuild. It runs
no `apk` commands, is non-root, digest-pinned, and passes all runtime gates. Its
fixable CVEs (Alpine openssl + the Go stdlib the binary was built with) clear
when Caddy upstream rebuilds; the weekly scan surfaces drift.

## Rules for adding/changing a base

1. Must be an official upstream image; otherwise write an ADR.
2. Pin `tag@sha256:`. CI (`scripts/check-structure.sh`) fails unpinned or
   `latest`-only bases.
3. Record registry, repo, tag, digest, platforms, license, lifecycle (this file).
4. Prefer the current supported Debian stable matching the PHP version.
5. No third-party APT repositories. If ever unavoidable: key-pinned, HTTPS-only,
   isolated, justified in a new ADR.
6. `scripts/assert-no-wolfi.sh` forbids reintroducing `cgr.dev`, `chainguard`,
   `wolfi`, `melange`, `apko`, or `apk add/upgrade` in active code.

## Future tracks (out of scope for the first replacement)

- **Distroless / Ubuntu Chiseled runtimes** for the PHP images: copy `/usr/local`
  onto a minimal base and auto-detect runtime libs (ldd). Would cut size and
  attack surface materially but forgoes the official PHP image contract. See
  `docs/distroless-strategy.md`.
