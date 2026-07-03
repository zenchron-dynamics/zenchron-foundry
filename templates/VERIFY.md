# Verifying Zenchron Foundry {{RELEASE}}

Every image is published by digest and signed keyless (Sigstore/Fulcio/Rekor)
with an SBOM and SLSA provenance attestation. Verify BEFORE you deploy. Consume
images by digest, never by a moving tag.

- Release: `{{RELEASE}}`
- Source revision: `{{REVISION}}`
- Cosign issuer: `{{ISSUER}}`
- Publisher identity (rc-publisher / release): `{{IDENTITY}}`

> `{{PLACEHOLDERS}}` are filled in by `scripts/build-release-evidence.sh` from
> `policies/cosign-identities.yaml` at seal time — the generated `VERIFY.md`
> attached to the GitHub release carries the exact strings.

## 1. Verify the signature (per image)

```sh
cosign verify \
  --certificate-oidc-issuer "{{ISSUER}}" \
  --certificate-identity "{{IDENTITY}}" \
  ghcr.io/zenchron-dynamics/<image>@<digest>
```

## 2. Verify the SBOM attestation

```sh
cosign verify-attestation --type spdxjson \
  --certificate-oidc-issuer "{{ISSUER}}" \
  --certificate-identity "{{IDENTITY}}" \
  ghcr.io/zenchron-dynamics/<image>@<digest>
```

## 3. Verify SLSA provenance and that it names this revision

```sh
cosign verify-attestation --type slsaprovenance \
  --certificate-oidc-issuer "{{ISSUER}}" \
  --certificate-identity "{{IDENTITY}}" \
  ghcr.io/zenchron-dynamics/<image>@<digest>
# provenance predicate .buildDefinition…resolvedDependencies / materials must
# reference revision {{REVISION}}
```

## 4. Confirm the immutable revision label

```sh
docker buildx imagetools inspect ghcr.io/zenchron-dynamics/<image>@<digest> \
  --format '{{ json .Provenance }}'
# org.opencontainers.image.revision == {{REVISION}}
```

## 5. One-shot: verify the whole release from the signed manifest

```sh
# manifest + signature + certificate are attached to this release
scripts/verify-release-manifest.sh release-manifest.yaml \
  release-manifest.yaml.sig release-manifest.yaml.pem
```
