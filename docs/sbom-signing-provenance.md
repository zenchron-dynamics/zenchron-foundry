# SBOM, signing, and provenance

How every published image gets a software bill of materials, a keyless
signature, and build provenance — and how a release proves all of it from the
registry. This is the operational companion to
[sbom-and-signing.md](sbom-and-signing.md), which covers the signing identity and
local SBOM commands.

## What every published image carries

`publish-ghcr.yml` attaches three supply-chain artifacts to each image it pushes:

1. **SBOM (SPDX)** — Syft generates `spdx-json` post-build and `cosign attest`
   attaches it as an `spdxjson` attestation. BuildKit also emits an inline SBOM
   (`sbom: true`).
2. **Cosign signature** — keyless via GitHub OIDC (Fulcio certificate, logged in
   Rekor). No private key exists anywhere.
3. **SLSA provenance** — `provenance: mode=max`, attesting how the image was
   built.

## Strict "10/10 or fail" at release

`release.yml` does not trust the build job alone; after publishing it
re-verifies everything **from the registry** and refuses to ship a partial set:

- `scripts/verify-release-artifacts.sh` checks each of the 10 canonical images
  independently across four columns — **signed**, **sbom**, **provenance**
  (accepts `slsaprovenance` or `slsaprovenance1`), and **multiarch** (the index
  advertises both `linux/amd64` and `linux/arm64`). Every image is tested even if
  one fails, and the script exits nonzero unless all four columns are 10/10.
- The SBOM-collection step runs Syft against all 10 `*-prod` images with **no**
  `|| true`: any failed SBOM fails the release, and it asserts exactly 10 SBOM
  files were produced before writing `checksums.txt`.
- `scripts/generate-release-manifest.sh` records each image's resolved index
  digest plus its signed/sbom/provenance booleans into
  `release-manifest.yaml`, attached to the GitHub Release.

The GitHub Release ships the per-image SBOMs, `checksums.txt`, `VERIFY.md`, and
the release manifest.

## Registry-side verification (consumers and CI)

`verify-signatures.yml` (manual, or run after a release) pulls each published
image and verifies its Cosign signature and SBOM attestation against the
identity regexp `https://github.com/zenchron-dynamics/zenchron-foundry/.*` and
issuer `https://token.actions.githubusercontent.com`. Legacy 7.4/8.0 references
were removed; it verifies the current 10-image set only.

Consumers verify before deploy:

```bash
cosign verify \
  --certificate-identity-regexp 'https://github.com/zenchron-dynamics/zenchron-foundry/.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ghcr.io/zenchron-dynamics/php-fpm:8.3-prod

cosign verify-attestation --type spdxjson \
  --certificate-identity-regexp 'https://github.com/zenchron-dynamics/zenchron-foundry/.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ghcr.io/zenchron-dynamics/php-fpm:8.3-prod
```

## Locally

`scripts/verify-release-artifacts.sh` and `generate-release-manifest.sh` honor
`LOCAL=1` (used by `make verify-local`): if `cosign` is absent they report
`SKIPPED` and exit 0, and an unreachable registry yields `UNRESOLVED` instead of
a hard failure. `STRICT=1` removes that leniency so local runs match the release
gate.
