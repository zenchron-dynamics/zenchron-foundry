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

- [ ] Release environments protected + reviewers assigned:
      `bash scripts/check-release-environments.sh --release-ready` passes (it is
      also enforced in-workflow and fails closed). See
      [release-environments.md](release-environments.md).
- [ ] Base digests current and multi-arch: `bash scripts/verify-base-images.sh`.
- [ ] Vulnerability gate green: no fixable CRITICAL/HIGH on the PHP images +
      nginx (see [vulnerability-management.md](vulnerability-management.md)); any
      exception is dated and approved.

## Preflight the seal gates (BEFORE building anything)

- [ ] Dispatch `release-preflight.yml` on `master` with
      `expected_revision` = the candidate commit. It rehearses every seal gate
      read-only on the real runner (ancestry, repo invariants, environment
      preflight, exact-commit CI) and publishes nothing. Four ceremonies died on
      gate defects that only surfaced live after ~24 h of builds; this catches
      that class in minutes. **Do not build an RC while preflight is red.**

## Release candidate first

- [ ] Dispatch `publish-rc.yml` with `version`, `rc` matching `rc<N>` (e.g.
      `rc1`), `expected_revision` (the candidate commit) and `confirmation` =
      `PUBLISH-<version>-<rc>-<revision>`. Approve the `foundry-rc` GitHub
      Environment prompt.
- [ ] Confirm it published **only** immutable RC tags — `php-*:<ver>-debian-rc<N>`
      and edges `prod-rc<N>` (plus `.build.<run>`), and **no** `*-prod` tag.
- [ ] Validate the RC: pull the RC tags, run consumer/integration checks, confirm
      multi-arch (`linux/amd64,linux/arm64`).
- [ ] **Record the `publish-rc` run ID.** It is the only source of the signed RC
      manifest for the rest of the ceremony. Never commit the manifest to git —
      see [rc-manifest.md](rc-manifest.md).
- [ ] Dispatch `verify-rc.yml` on the release revision (runtime certification:
      cold build + smoke + contract for all 10 images, plus amd64/arm64 on the
      published RC digests). **Record its run ID** — the seal derives
      `RUNTIME_RESULT` from it and refuses without it. Expect ~12 h serial.
- [ ] Dispatch `release-preflight.yml` a second time, now with `version`, `rc`
      and `rc_manifest_run_id`: it additionally fetches + fully verifies the
      signed RC manifest on the runner. Late in the ceremony the check-runs
      payload is at its largest — this is exactly when the ARG_MAX class bites.

## Exact-commit CI (what the seal gate reads)

- [ ] `ci.yml` green on the release revision (it runs on every push to `master`).
- [ ] **Dispatch `scan-images.yml` on the release revision.** It does *not* run on
      push to `master`, and the seal gate requires its 10 `scan <fam> <ver>`
      check-runs on that exact commit. A `workflow_dispatch` attaches them to the
      dispatched ref's commit.
- [ ] The required names live in `policies/required-release-checks.yaml` and are
      matched **verbatim**; `scripts/assert-required-checks.sh` (run in `ci.yml`
      and in the release guard) keeps them in sync with the workflow job names.

## Tag the release (before promotion)

- [ ] Push an annotated tag `vYYYY.MM.DD[.N]` pointing at the **exact commit the
      RC was built from** (it must be an ancestor of `origin/master`). Nothing is
      built or sealed by the tag push: the tag exists so `foundry-production`
      (stable tags only) becomes reachable and the release is bound to the commit.

## Stable promotion (dispatched from the tag)

- [ ] Dispatch `promote-stable.yml` **from `refs/tags/<version>`** with `version`
      (equal to the tag), `rc`, `rc_manifest_run_id`, `expected_revision` (the tag
      commit), `confirmation` = `PROMOTE-<version>-<revision>` and
      `risk_acceptance_confirmation` = `ACCEPT-RISK`. A branch ref or an RC tag is
      refused by `scripts/check-promotion-ref.sh`.
- [ ] Approve the `foundry-production` GitHub Environment.
- [ ] The gate also re-runs the **exact-commit CI check on the tag commit** — a
      red-CI commit is refused before any alias moves.
- [ ] Promotion retags the **exact** RC digests onto `*-prod` — no `docker build`.
      Confirm every stable alias matches its RC digest in the job output, and
      that `promotion-results.json` (derived from the real artifacts, canonical
      aliases last) is in the uploaded promotion evidence.

## Rollback exercise (dispatched from the same tag)

- [ ] Dispatch `rollback-exercise.yml` **from `refs/tags/<version>`** with
      `version`, `rc`, `rc_manifest_run_id`, `promotion_run_id` (the
      promote-stable run above) and `confirmation` =
      `ROLLBACK-EXERCISE-<version>`. It restores the recorded prior digests,
      verifies them, re-promotes the new release from the verified RC manifest,
      re-proves the binding, and uploads `rollback-results.json` with counts
      parsed from the actual run. **Do not seal a release whose rollback was
      never exercised.**

## Seal the release (dispatched from the same tag)

- [ ] Dispatch `release.yml` **from `refs/tags/<version>`** with the same
      `version`, `rc` and `rc_manifest_run_id`, plus `verify_rc_run_id` (the
      runtime-certification run recorded above) and `confirmation` =
      `SEAL-<version>-<tag commit sha>`.
- [ ] The `guard` job must pass: stable-tag ref policy, master ancestry, repo
      invariants, exact-commit CI (incl. `scan-images`), RC manifest fetched and
      verified from the `publish-rc` artifact, and **stable aliases already equal
      the RC digests**. Sealing before promotion fails here by design.
- [ ] The release job runs `verify-release-artifacts.sh` automatically and must
      report **10/10 on signed, sbom, provenance, and multiarch** (all aliases,
      OCI revision label checked on every linux child). Every verification value
      in `evidence.json` is **derived from verifier output**, never declared;
      `release-evidence-summary.json` is assembled, validated and attached. See
      [release-evidence.md](release-evidence.md) for the full evidence schema.
- [ ] The signed RC manifest is attached **as fetched** (never regenerated); 10
      SBOMs are collected strictly (the job fails if fewer than 10) with
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
