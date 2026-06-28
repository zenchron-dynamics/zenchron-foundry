# Release checklist

A literal, step-by-step checklist for cutting a release. It implements the flow
in [release-process.md](release-process.md) and the controls in
[security-model.md](security-model.md). Tick every box; the gates fail closed if
you skip one.

## Pre-release (on a branch / PR)

- [ ] Work is merged to `master` via reviewed PR; CI (`ci.yml`) is green on the
      merge commit (structure, no-wolfi, pinned actions/containers, image matrix,
      lint, gitleaks, semgrep, build + smoke all 10 images, compose validate).
- [ ] Run the local harness on the candidate commit:

      ```bash
      make ci-local STRICT=1
      ```

- [ ] Base digests current and multi-arch: `bash scripts/verify-base-images.sh`.
- [ ] Vulnerability gate green: no fixable CRITICAL/HIGH on the PHP images +
      nginx (see [vulnerability-management.md](vulnerability-management.md)); any
      exception is dated and approved.

## Release candidate first

- [ ] Dispatch `publish-rc.yml` with a required `rc` identifier matching `rc<N>`
      (e.g. `rc1`). Approve the `rc` GitHub Environment prompt.
- [ ] Confirm it published **only** immutable RC tags — `php-*:<ver>-debian-rc<N>`
      and edges `prod-rc<N>` (plus `.build.<run>`), and **no** `*-prod` tag.
- [ ] Validate the RC: pull the RC tags, run consumer/integration checks, confirm
      multi-arch (`linux/amd64,linux/arm64`).

## Stable promotion (same source)

- [ ] Push an annotated tag `vYYYY.MM.DD[.N]` pointing at the **same merged
      commit** you validated as the RC (it must be an ancestor of
      `origin/master`). Stable is rebuilt from that commit with the same pinned
      base digests — not an arbitrary branch.
- [ ] Approve the `release` GitHub Environment. The `guard` job enforces tag
      format, master ancestry, and repo invariants before anything publishes.
- [ ] `release.yml` builds multi-arch, pushes `*-prod` (+ dated, + `-build.<run>`,
      + `-debian` alias for PHP families), signs, and attests all 10 images.

## Verify from GHCR + publish the manifest

- [ ] The release job runs `verify-release-artifacts.sh` automatically and must
      report **10/10 on signed, sbom, provenance, and multiarch**.
- [ ] `generate-release-manifest.sh` produces `release-manifest.yaml`; 10 SBOMs
      are collected strictly (the job fails if fewer than 10) with
      `checksums.txt` and `VERIFY.md`.
- [ ] The GitHub Release for the tag carries the manifest, SBOMs, checksums, and
      `VERIFY.md`.

## Post-release

- [ ] Optionally run `verify-signatures.yml` to re-prove signatures + SBOM
      attestations from the registry.
- [ ] Announce the new digests; consumers re-pin by digest and verify with
      `cosign` (see [sbom-signing-provenance.md](sbom-signing-provenance.md)).
- [ ] If anything regresses, follow [rollback.md](rollback.md).

## Do not overwrite a published release

Published tags are immutable and `v2026.06.21` (the Debian stable promotion) must
not be re-pointed or overwritten. To ship a fix, cut a **new** dated tag
(`vYYYY.MM.DD` or `.N`); never mutate an existing release's tags or digests.
