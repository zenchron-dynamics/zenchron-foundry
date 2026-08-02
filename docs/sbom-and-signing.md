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
- Identity (role `rc-publisher` in
  [../policies/cosign-identities.yaml](../policies/cosign-identities.yaml)):
  `publish-(ghcr|rc).yml@refs/heads/master` — i.e. the `publish-ghcr.yml` /
  `publish-rc.yml` workflows running on `master` via GitHub OIDC.

Images are signed once, at RC publish. Stable aliases (`*-prod`) are
**digest-only retags** of the RC digests, so they **carry the RC signature via
the digest** — nothing re-signs at promotion. Branch/PR builds are **not**
release-signed, and `scheduled-rebuild.yml` signatures deliberately cannot
satisfy the rc-publisher identity.

**Compatibility:** the repo pins **cosign v2.5.2** and publishes v2-format
signatures (`.sig`/`.pem`). Verify with a cosign v2-compatible client using
`--certificate-identity-regexp` plus the issuer above.

## Verifying (required before deploy)

**Use the platform verifier.** It applies exactly the policy the release gates
apply, so a consumer cannot accidentally accept less than the release does:

```bash
# Pin by digest — an immutable reference is the whole point of verifying.
IMAGE='ghcr.io/zenchron-dynamics/php-fpm@sha256:<digest>'

# The 40-hex source commit the release claims to be built from (release notes /
# release evidence, or `git rev-parse v<version>`).
export EXPECTED_REVISION='<40-hex>'

# Production images carry the RC signature via digest-only promotion, so the
# expected signing role is rc-publisher — not a repository-wide wildcard.
export EXPECTED_ROLE='rc-publisher'

scripts/verify-image-release-identity.sh "$IMAGE"
```

One command, and it checks: signature, OIDC issuer, SPDX SBOM attestation, SLSA
provenance, provenance **source repo and revision**, the OCI revision label on
**every** architecture in the index, and that the required platforms are all
published. Raw `cosign verify` covers only the first two.

### Raw cosign (only when the script is unavailable)

The identity is **anchored to one workflow file and one ref class** — never
`…/zenchron-foundry/.*`, which would also accept `scheduled-rebuild.yml`
candidate images and any workflow added later. Roles are defined in
[`../policies/cosign-identities.yaml`](../policies/cosign-identities.yaml); the
one below is `rc-publisher`. This path does **not** verify provenance revision
or OCI labels, so treat it as a fallback, not an equivalent.

```bash
cosign verify \
  --certificate-identity-regexp \
  '^https://github\.com/zenchron-dynamics/zenchron-foundry/\.github/workflows/publish-(ghcr|rc)\.yml@refs/heads/master$' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ghcr.io/zenchron-dynamics/php-fpm:8.3-prod

cosign verify-attestation --type spdxjson \
  --certificate-identity-regexp \
  '^https://github\.com/zenchron-dynamics/zenchron-foundry/\.github/workflows/publish-(ghcr|rc)\.yml@refs/heads/master$' \
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
