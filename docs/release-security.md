# Release security & trust model

How a Zenchron Foundry release is made trustworthy, and what is verified where.

## Pipeline

```text
CI validates source
  -> publish-rc builds immutable candidates (signed + SBOM + provenance)
  -> RC artifacts verified from the registry
  -> signed RC manifest (docs/rc-manifest.md)
  -> promote-stable retags exact digests (docs/stable-promotion.md)
  -> compensating rollback on failure
  -> release tag verifies revision equality
  -> GitHub release seals the evidence bundle
```

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

## Identity pinning — open hardening item

The current default identity regex is broad:
`https://github.com/zenchron-dynamics/zenchron-foundry/.*`. Per the release
policy this should be **narrowed** to the exact publisher workflow identities:

- RC publisher (`publish-rc.yml` job identity),
- stable promotion signer (where signing occurs),
- scheduled candidate publisher.

If reusable workflows change the certificate identity, document and test the exact
identity. Track this before claiming a hardened production trust gate.

## Revision / OCI-label equality — open item

The non-negotiable invariant is:

```text
release tag SHA == RC manifest revision == RC provenance revision == RC OCI label
             == stable provenance revision == stable OCI label
stable digest == validated RC digest
```

`verify-release-artifacts.sh` today proves signature/SBOM/provenance/multiarch and
(via promotion) `stable digest == RC digest`, but does **not** yet decode
provenance to assert `provenance revision == release tag SHA` or check the OCI
revision label. A dedicated `verify-image-release-identity.sh` (decode predicate
→ extract repo+revision → compare to manifest + OCI label) is required to close
this and should be the single verifier reused by RC verification, promotion,
release sealing, and manual verification.

## Vulnerability gates

See `docs/vulnerability-exceptions.md`. Caddy is an **accepted-risk** gate
(CVE-2026-34986), not a clean gate — production must either reach 10/10 enforcing
or explicitly sign off the exception.

## Protected environments

`foundry-rc` (RC publication only, cannot mutate canonical aliases) and
`foundry-production` (required reviewers, restricted refs/tags, no self-approval,
audit log). These are **repository settings** and cannot be proven from workflow
code — attach settings evidence before a live production release.
