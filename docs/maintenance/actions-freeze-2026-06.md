# Maintenance note — GitHub Actions freeze (2026-06)

## Status

GitHub Actions is temporarily **unable to start jobs** for this repository
(account-level Actions budget/spending limit reached). Jobs fail before any step
runs (even the dependency-free `repo structure` job), so **no CI, scan, or
release workflow can run** until the limit is restored (expected next month).

This is an account/runner-availability condition, not a code or workflow defect.

## What is NOT affected

- **Debian stable release `v2026.06.21`** is published and verified (multi-arch,
  Cosign-signed, SBOM + provenance attested). GHCR storage is unaffected.
- Generic `*-prod` tags are Debian-backed and unchanged.
- Wolfi rollback digests remain pullable (see
  [migration/wolfi-to-debian.md](../migration/wolfi-to-debian.md)).

## Dependabot during the freeze

One PR was merged + validated **before** the freeze:

- `#16 actions/checkout 4 → 7` (PR CI green pre-merge).

**Nine PRs remain open and DEFERRED.** They must **not** be merged while Actions
cannot run: the merge policy requires *fresh green GitHub CI*, which is
unavailable, and "green CI" / "never merge solely because CI is green" cannot be
satisfied. They are reviewed, rebased on `master`, and locally validated; final
merges wait for CI.

### Required processing order (when Actions returns)

Process **individually**, never batched, confirming `master` CI green between each.

Group A — lower-risk CI plumbing:

1. `#14 actions/upload-artifact 4 → 7`
2. `#4 docker/login-action 3 → 4`
3. `#9 github/codeql-action 3 → 4`
4. `#5 softprops/action-gh-release 2 → 3`
5. `#8 DavidAnson/markdownlint-cli2-action 16 → 23`

Group B — image/security pipeline (strict order; each needs a full image
build + Trivy/Grype/SBOM/Cosign/provenance comparison vs the stable release):

6. `#7 docker/setup-qemu-action 3 → 4`
7. `#2 docker/setup-buildx-action 3 → 4`
8. `#3 docker/build-push-action 6 → 7`
9. `#6 anchore/scan-action 4 → 7` (verify the CRITICAL/HIGH gate is **not** weakened)

## Action pinning

Repository policy pins actions by **major-version tag** (`@v7`, `@v4`, …), not by
full commit SHA. The Dependabot PRs preserve this convention; no SHA resolution
is required. (`ludeeus/action-shellcheck@master` is a pre-existing moving ref,
unrelated to these PRs.)

## Local validation performed during the freeze

A CI-equivalent local harness reproduces as much of GitHub CI as a workstation
allows (see the `Makefile`):

```text
make validate     # structure + supply-chain guard + lint (graceful) + compose config
make build-test   # build PHP 8.3 + 8.4 (fpm/cli/worker/frankenphp) + nginx + caddy
make scan-local   # Trivy enforcing gate + Grype/Syft (advisory; reports missing tools)
make smoke-all    # non-root, read-only, heartbeat, SIGTERM, FPM :9000, FrankenPHP HTTP/readiness
make ci-local     # all of the above in order
```

Tools not installed locally (shellcheck, hadolint, yamllint, markdownlint,
gitleaks, grype, syft) are reported **SKIPPED**, never silently passed.

## GitHub CI remains mandatory

Local validation is a bridge, **not** a substitute. Before merging any deferred
PR, the full GitHub CI + scan workflows must run and be green. Do not force-merge
with absent/failing checks, do not disable required checks, and do not weaken
vulnerability thresholds, provenance, SBOM, or signing.

## RC2 requirement (after Group B)

If **any** Group B PR is merged, the build/scan pipeline changes and the RC1
evidence no longer represents `master`. A new **RC2** must then be built from
clean committed `master` (multi-arch), signed, SBOM + provenance attested, and
fully re-validated (Trivy gate, Grype, Laravel/Symfony smoke, worker
heartbeat/SIGTERM, FPM FastCGI, FrankenPHP HTTP/readiness, hardening) **before**
any further stable promotion. RC2 must not overwrite RC1 or the stable tags. See
[release-process.md](../release-process.md).
