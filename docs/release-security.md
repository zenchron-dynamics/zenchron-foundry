# Release security & trust model

How a Zenchron Foundry release is made trustworthy, and what is verified where.

## Pipeline

```text
CI validates source
  -> publish-rc builds immutable candidates (signed + SBOM + provenance)
  -> RC artifacts verified from the registry
  -> signed RC manifest, kept as a workflow artifact (docs/rc-manifest.md)
  -> stable tag created on the exact RC revision
  -> promote-stable (from the tag) retags exact digests (docs/stable-promotion.md)
  -> compensating rollback on failure
  -> release (from the same tag) verifies revision + alias equality
  -> GitHub release seals the evidence bundle
```

The signed RC manifest is **downloaded from the `publish-rc` run artifact**, never
committed to the source tree: committing it would add a commit after the images
were built and break `tag commit == manifest.revision == provenance revision`.

Release tags do **not** build images. Stable publication does **not** rebuild.
Generic workflows cannot push production tags — only the protected
`promote-stable.yml` mutates `*-prod`.

## Signing & attestation

- Keyless **cosign** (OIDC issuer `https://token.actions.githubusercontent.com`).
- Every image carries a cosign signature, an SPDX **SBOM** attestation, and a
  **SLSA provenance** attestation.
- Verification: **`scripts/verify-release-artifacts.sh`** checks, per image and
  independently, four columns — `signed / sbom / provenance / multiarch
  (amd64+arm64)` — and exits nonzero unless **all four are 10/10** (no "at least
  one"). `LOCAL=1` prints SKIPPED when cosign is absent; strict mode treats a
  missing cosign as a hard failure.
- The evidence package's verification values are **derived, never hardcoded**:
  `verify-release-artifacts.sh` writes per-check-class pass counts to a
  machine-readable results file (`RESULTS_JSON`, default
  `release-verify-results.json`), and the release workflow reads
  `SIG/SBOM/PROV/OCIREV/ARCH_RESULT` from that file. `RUNTIME_RESULT` is derived
  by the seal guard from the `verify_rc_run_id` dispatch input: the referenced
  run must be `verify-rc`, concluded `success`, on the exact release commit,
  with 10/10 successful `certify` matrix jobs. `validate-release-evidence.sh`
  refuses any counted result that is not a full `n/n` (so a real `9/10` — or a
  missing/absent value — blocks the seal).

## Identity pinning — open hardening item

The current default identity regex is broad:
`https://github.com/zenchron-dynamics/zenchron-foundry/.*`. Per the release
policy this should be **narrowed** to the exact publisher workflow identities:

- RC publisher (`publish-rc.yml` job identity),
- stable promotion signer (where signing occurs),
- scheduled candidate publisher.

If reusable workflows change the certificate identity, document and test the exact
identity. Track this before claiming a hardened production trust gate.

## Revision / OCI-label equality

The non-negotiable invariant is:

```text
release tag SHA == RC manifest revision == RC provenance revision == RC OCI label
             == stable provenance revision == stable OCI label
stable digest == validated RC digest
```

**`scripts/verify-image-release-identity.sh`** is the single strict verifier that
binds an image to an expected commit: it verifies cosign signature (exact identity
if `EXPECTED_IDENTITY` is set, else the issuer + identity regexp), SBOM, and SLSA
provenance, then decodes the provenance predicate to extract the source repo +
revision and asserts `provenance revision == EXPECTED_REVISION`,
`repo == EXPECTED_REPO`, `OCI org.opencontainers.image.revision == EXPECTED_REVISION`,
and every expected platform. It handles SLSA provenance v1 and v0.2; its pure
extraction/comparison logic has a 12-case self-test (`--self-test`), and it follows
the `LOCAL=`/skip convention when cosign is absent.

`verify-signatures.yml` (manual dispatch) now invokes this verifier per image with
the release `revision` input — the weaker signature+SBOM-only version was removed.
The same script should be reused by RC verification, promotion, and release
sealing. Its cosign/registry path is exercised for the first time at the step-11
live verification; the `docker buildx`/`crane` fallback resolves the image index +
OCI config.

Still open: `IDENTITY_RE` defaults to the broad repo regexp — pass a narrow
`EXPECTED_IDENTITY` (exact publisher workflow) at verification time until the
default is tightened.

## Vulnerability gates

See `docs/vulnerability-exceptions.md`. The former Caddy CVE-2026-34986
accepted-risk gate is **resolved** — the pinned base already ships the fixed
`go-jose/v3 v3.0.5`, the exception is removed, and Caddy is a clean gate for it.
Remaining exceptions are unfixed Debian distro CVEs behind `--ignore-unfixed`.

## Protected environments

`foundry-rc` (RC publication only, cannot mutate canonical aliases) and
`foundry-production` (required reviewers, restricted refs/tags, no self-approval,
audit log). These are **repository settings** and cannot be proven from workflow
code — the preflight `scripts/check-release-environments.sh --release-ready` proves
them live and fails closed. Full spec, reviewer placeholders, and the owner action
checklist are in [release-environments.md](release-environments.md).
