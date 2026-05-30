# SBOM & Signing

## Supply-chain controls

Every published image gets, in CI (`publish-ghcr.yml`):

1. **Build provenance** (`provenance: mode=max`) — SLSA-style attestation of how
   it was built.
2. **SBOM** — generated two ways:
   - BuildKit inline (`sbom: true`).
   - Syft post-build (`spdx-json`), attached as a Cosign attestation.
3. **Signature** — Cosign **keyless** (Fulcio cert via GitHub OIDC, logged in
   Rekor). No private key stored anywhere.

## Signing identity

- Issuer: `https://token.actions.githubusercontent.com`
- Identity: the `publish-ghcr.yml` workflow on a `v*` tag ref.

Branch/PR builds are **not** release-signed.

## Verifying (required before deploy)

```bash
cosign verify \
  --certificate-identity-regexp 'https://github.com/zenchron-dynamics/docker-platform/.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ghcr.io/zenchron-dynamics/php-fpm:8.3-prod

cosign verify-attestation --type spdxjson \
  --certificate-identity-regexp 'https://github.com/zenchron-dynamics/docker-platform/.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ghcr.io/zenchron-dynamics/php-fpm:8.3-prod
```

`scripts/verify-signatures.sh <image>` wraps both. See
[../policies/cosign-policy.md](../policies/cosign-policy.md).

## SBOM locally

```bash
IMAGE=ghcr.io/zenchron-dynamics/php-fpm:8.3-prod make sbom
# → artifacts/sbom/<image>.spdx.json  and  .cdx.json
```

## Release artifacts

`release.yml` attaches per-image SBOMs, `checksums.txt`, and `VERIFY.md` to the
GitHub Release for the tag.

## Consuming SBOMs

- Feed SBOMs into your vulnerability dashboard / dependency-track instance.
- Diff SBOMs across releases to see exactly which packages changed.
- Future k8s: enforce signature + attestation at admission (Kyverno / Sigstore
  policy-controller).
