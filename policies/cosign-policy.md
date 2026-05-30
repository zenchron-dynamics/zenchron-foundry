# Cosign Signing & Verification Policy

All published `ghcr.io/zenchron-dynamics/*` images are signed **keyless** with
Cosign using GitHub Actions OIDC (Fulcio + Rekor transparency log). No private
signing key is stored anywhere.

## Signing (CI only — `publish-ghcr.yml`)

```bash
cosign sign --yes \
  ghcr.io/zenchron-dynamics/php-fpm@${DIGEST}
# SBOM + provenance attestations
cosign attest --yes --predicate sbom.spdx.json --type spdxjson \
  ghcr.io/zenchron-dynamics/php-fpm@${DIGEST}
```

Identity bound into the certificate:

- **Issuer:** `https://token.actions.githubusercontent.com`
- **Subject (identity):** `https://github.com/zenchron-dynamics/zenchron-foundry/.github/workflows/publish-ghcr.yml@refs/tags/*`

## Verification (consumers — required before deploy)

```bash
cosign verify \
  --certificate-identity-regexp 'https://github.com/zenchron-dynamics/zenchron-foundry/.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ghcr.io/zenchron-dynamics/php-fpm:8.3-prod

# Verify the SBOM attestation too
cosign verify-attestation --type spdxjson \
  --certificate-identity-regexp 'https://github.com/zenchron-dynamics/zenchron-foundry/.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ghcr.io/zenchron-dynamics/php-fpm:8.3-prod
```

`scripts/verify-signatures.sh` wraps this. Admission in Kubernetes (future)
should enforce it via a policy controller (Kyverno / Sigstore policy-controller).

## Rules

- Unsigned images **must not** be deployed to production.
- Verification failure = hard stop. No "verify later".
- The signing identity is pinned to tag refs; PR/branch builds are **not**
  release-signed.
