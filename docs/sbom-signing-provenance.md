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

`release.yml` **publishes and builds nothing** — the images were built and
signed at RC publish and promoted by digest. At seal time it verifies
everything **from the registry** and refuses to ship a partial set:

- The signed RC manifest is **fetched from the `publish-rc` workflow artifact**
  (`scripts/fetch-rc-manifest.sh`, checksum + cosign-signature + schema
  verified) — it is never committed to the source tree and never regenerated at
  release time — and is attached to the GitHub Release **as fetched**.
- `scripts/verify-release-artifacts.sh` checks each of the 10 canonical images
  independently across four columns — **signed**, **sbom**, **provenance**
  (accepts `slsaprovenance` or `slsaprovenance1`), and **multiarch** (the index
  advertises both `linux/amd64` and `linux/arm64`). Every image is tested even if
  one fails, and the script exits nonzero unless all four columns are 10/10.
- The SBOM-collection step runs Syft against all 10 `*-prod` images with **no**
  `|| true`: any failed SBOM fails the release, and it asserts exactly 10 SBOM
  files were produced before writing `checksums.txt`.
- `scripts/verify-release-binding.sh` checks the equality chain: release tag
  commit == manifest revision == provenance revision == OCI revision, and each
  stable `*-prod` digest == the RC digest recorded in the manifest.

The GitHub Release ships the per-image SBOMs, `checksums.txt`, `VERIFY.md`, and
the RC manifest exactly as fetched from the `publish-rc` artifact.

## Registry-side verification (consumers and CI)

`verify-signatures.yml` (manual, or run after a release) pulls each published
image and verifies its Cosign signature and SBOM attestation against the
anchored per-role identity from
[`../policies/cosign-identities.yaml`](../policies/cosign-identities.yaml) and
issuer `https://token.actions.githubusercontent.com`. Legacy 7.4/8.0 references
were removed; it verifies the current 10-image set only.

Consumers verify before deploy:

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

## Locally

`scripts/verify-release-artifacts.sh` and `generate-release-manifest.sh` honor
`LOCAL=1` (used by `make verify-local`): if `cosign` is absent they report
`SKIPPED` and exit 0, and an unreachable registry yields `UNRESOLVED` instead of
a hard failure. `STRICT=1` removes that leniency so local runs match the release
gate.
