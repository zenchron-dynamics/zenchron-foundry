# Legacy PHP Policy (7.4 / 8.0)

## Status: HIGH RISK — compatibility only

| Version | EOL date | Security support |
|---------|----------|------------------|
| PHP 7.4 | 2022-11-28 | **None** (upstream) |
| PHP 8.0 | 2023-11-26 | **None** (upstream) |

These runtimes receive **no upstream security patches**. They exist **only** to
keep legacy applications running until migration. They are **not** suitable for
new systems and must never be presented as production-ideal.

## Frozen as of the Debian-first migration (ADR-0001)

The 7.4 and 8.0 **source Dockerfiles have been removed** from the repository.
The previously-published **Wolfi images remain pullable from GHCR** (not deleted)
for rollback/compatibility, but they are **never rebuilt**, are **excluded** from
the build/scan/publish matrices and Dependabot, and consumers **must migrate** to
the PHP 8.3/8.4 Debian images. Source remains recoverable from git history if a
frozen rebuild is ever forced under a documented risk exception.

## Differences from supported images

- Base is `php:7.4/8.0-*-alpine` (EOL), **not** Chainguard/Wolfi. No distroless.
- Extensions are compiled in a build stage (`docker-php-ext-install`), build
  deps removed afterward.
- No JIT (7.4) / parity-disabled JIT (8.0).
- FPM healthcheck not bundled (no `cgi-fcgi` in base) — use an orchestrator TCP
  probe on :9000, or add `fcgi` explicitly.
- FrankenPHP is **impossible** for 7.4/8.0 (requires PHP ≥ 8.2). No such images.

## Controls applied despite EOL status

Same platform hardening still applies: non-root `10001:10001`, read-only rootfs
compatibility, `cap_drop: ALL`, no-new-privileges, OCI labels, SBOM, scanning.

## Risk handling

This section used to describe a CI scan behind a per-image legacy matrix flag, a
monthly Dependabot watch on the legacy bases, and joint `CODEOWNERS` ownership.
**None of those exist**, and the claim contradicted the "Frozen" section directly
above it. What is true:

- There is **no legacy matrix entry** and no per-image legacy flag anywhere in
  `.github/workflows/`. `scripts/assert-image-matrix.sh` asserts the matrix is
  exactly the ten supported images and **fails** if a `php-*/7.4` or `php-*/8.0`
  directory reappears.
- **Nothing scans them.** They are not built, so there is no image for
  `scan-images.yml` to scan. Their CVE state is whatever it was on the day they
  were last published, and it only gets worse.
- **Dependabot does not watch them.** `.github/dependabot.yml` contains no legacy
  entry, and `scripts/assert-dependabot-manifests.sh` requires every declared
  directory to have a real manifest.
- Tags remain on a separate line (`7.4-prod`, `8.0-prod`) and must never be
  confused with supported tags. That part was, and remains, correct.

The practical consequence for a consumer: pulling a legacy tag gets an image
frozen at its last build, with no scan evidence, no rebuild and no update path.
That is the risk the migration deadline exists to end.

## Migration expectation

Every consumer of a legacy image must have a tracked migration plan to 8.3/8.4.
The platform team reviews legacy usage quarterly. Accepted risk is **temporary
by definition**; document the owning team and target migration date in the
consuming app's repository.

## Hard rules

- Do **not** start new projects on 7.4/8.0.
- Do **not** expose legacy FPM (:9000) to untrusted networks.
- Do **not** silence legacy CVEs in `.trivyignore` to make pipelines green for
  supported images — keep the gates separate.
