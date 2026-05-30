# Image Versioning & Tagging

## Tag forms

| Tag | Meaning | Mutable? | Deploy? |
|-----|---------|----------|---------|
| `8.3-prod` | latest build of the 8.3 supported line | **mutable** | dev/staging only |
| `8.3-prod-2026.05.30` | dated immutable snapshot | immutable | yes |
| `8.3-prod-build.17` | CI run-number build | immutable | yes |
| `8.3.27-prod` | exact PHP patch (when pinned) | immutable | yes |
| `@sha256:<digest>` | content-addressed | immutable | **production REQUIRED** |
| `latest` | **not produced** | — | **NEVER** |

## Rules

1. **Never deploy `latest`.** It is not built or published by this platform.
2. **Production pins by digest** (`image@sha256:…`). The moving `*-prod` tag is
   for convenience in lower environments only.
3. Immutable tags (`-YYYY.MM.DD`, `-build.N`) are never overwritten.
4. Legacy lines (`7.4-prod`, `8.0-prod`) are tagged separately and never aliased
   to a supported tag.
5. Release tags on the repo are `v<calver>` (e.g. `v2026.05.30`); they trigger
   `publish-ghcr.yml` + `release.yml`.

## Resolving a digest

```bash
docker buildx imagetools inspect ghcr.io/zenchron-dynamics/php-fpm:8.3-prod \
  --format '{{json .Manifest.Digest}}'
# or after pull:
docker inspect --format '{{index .RepoDigests 0}}' ghcr.io/zenchron-dynamics/php-fpm:8.3-prod
```

Pin that digest in your app's `FROM`/compose for reproducible, tamper-evident
deploys.

## Rollback strategy

1. Production references a digest, recorded in the app's deploy manifest /
   GitOps repo.
2. To roll back, redeploy the **previous known-good digest** — it is immutable
   and still present in GHCR (retention policy keeps N prior dated tags).
3. Because tags like `8.3-prod-2026.05.23` are immutable, rollback is
   deterministic: `docker pull ...:8.3-prod-2026.05.23` always yields the same
   bits.
4. Keep at least the last **5 dated tags** per supported family un-pruned.
   Configure GHCR package retention accordingly.

## Promotion flow

```text
build.N  ──(scan pass)──►  8.3-prod-YYYY.MM.DD  ──(sign+attest)──►  8.3-prod (moves)
```

Lower environments track `8.3-prod`; production pins the dated/digest form after
verification.
