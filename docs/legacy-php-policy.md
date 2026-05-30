# Legacy PHP Policy (7.4 / 8.0)

## Status: HIGH RISK — compatibility only

| Version | EOL date | Security support |
|---------|----------|------------------|
| PHP 7.4 | 2022-11-28 | **None** (upstream) |
| PHP 8.0 | 2023-11-26 | **None** (upstream) |

These runtimes receive **no upstream security patches**. They exist **only** to
keep legacy applications running until migration. They are **not** suitable for
new systems and must never be presented as production-ideal.

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

- CI **scans** legacy images (Trivy/Grype) but **does not gate** the build on
  their CVEs — EOL CVEs frequently have no fix. Findings are recorded as
  awareness artifacts, not blockers (`legacy: true` matrix flag).
- Dependabot watches legacy bases **monthly** and PRs are reviewed manually.
- Legacy images are owned jointly by platform + security (see `CODEOWNERS`).
- Tags are kept on a separate line (`7.4-prod`, `8.0-prod`) and must never be
  confused with supported tags.

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
