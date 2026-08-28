# Repository-material baseline — 2026-08-28 refresh

**Inclusion in this baseline is NOT equivalent to legal review.** The baseline
records which paths a reviewer has *seen*, so that unreviewed material refuses
rather than passing silently. It makes no statement about the licence status of
anything it lists.

| | |
|---|---|
| previous hash | `8ed5728b5df9f4b080659d8473990daa1cc418dbb51cd42aab76b5b558812b07` |
| previous path count | 742 |
| new hash | `93b1721573c936d8f3e9947f2c1ab43f8f219c90134dac4c00b2fa452d6a7a84` |
| new path count | 779 |
| additions | 37 |
| removals | **0** |
| `reviewed_at_revision` | **unchanged** — deliberately |

`reviewed_at_revision` is left at the full-review revision on purpose. It is not
machine-checked, and repointing it at a commit that never contained these files
would assert a review that did not happen.

## The 37 additions, enumerated

All are first-party audit documents produced by the real-inventory run; none is
third-party material.

```text
docs/audits/real-image-inventories-2026-08-28/BLOCKED.md
docs/audits/real-image-inventories-2026-08-28/README.md
docs/audits/real-image-inventories-2026-08-28/SHA256SUMS
docs/audits/real-image-inventories-2026-08-28/licence-identifier-reconciliation.md
docs/audits/real-image-inventories-2026-08-28/licence/composed-authorization-validation.log
docs/audits/real-image-inventories-2026-08-28/licence/identifier-reconciliation.json
docs/audits/real-image-inventories-2026-08-28/licence/image-licence-policy-diagnostic.log
docs/audits/real-image-inventories-2026-08-28/licence/image-sbom-binding-gate.log
docs/audits/real-image-inventories-2026-08-28/licence/rerun-composed-authorization-validation.log
docs/audits/real-image-inventories-2026-08-28/licence/rerun-image-binding.json
docs/audits/real-image-inventories-2026-08-28/licence/rerun-image-licence-policy.log
docs/audits/real-image-inventories-2026-08-28/licence/rerun-image-sbom-binding-gate.log
docs/audits/real-image-inventories-2026-08-28/licence/rerun-repository-material-composed.log
docs/audits/real-image-inventories-2026-08-28/registry-recoverability-probe.json
docs/audits/real-image-inventories-2026-08-28/rerun-against-fixed-consumer.md
docs/audits/real-image-inventories-2026-08-28/sbom-bindings/caddy-prod-linux-amd64.binding.json
docs/audits/real-image-inventories-2026-08-28/sbom-bindings/caddy-prod-linux-arm64.binding.json
docs/audits/real-image-inventories-2026-08-28/sbom-bindings/nginx-prod-linux-amd64.binding.json
docs/audits/real-image-inventories-2026-08-28/sbom-bindings/nginx-prod-linux-arm64.binding.json
docs/audits/real-image-inventories-2026-08-28/sbom-bindings/php-cli-8.3-linux-amd64.binding.json
docs/audits/real-image-inventories-2026-08-28/sbom-bindings/php-cli-8.3-linux-arm64.binding.json
docs/audits/real-image-inventories-2026-08-28/sbom-bindings/php-cli-8.4-linux-amd64.binding.json
docs/audits/real-image-inventories-2026-08-28/sbom-bindings/php-cli-8.4-linux-arm64.binding.json
docs/audits/real-image-inventories-2026-08-28/sbom-bindings/php-fpm-8.3-linux-amd64.binding.json
docs/audits/real-image-inventories-2026-08-28/sbom-bindings/php-fpm-8.3-linux-arm64.binding.json
docs/audits/real-image-inventories-2026-08-28/sbom-bindings/php-fpm-8.4-linux-amd64.binding.json
docs/audits/real-image-inventories-2026-08-28/sbom-bindings/php-fpm-8.4-linux-arm64.binding.json
docs/audits/real-image-inventories-2026-08-28/sbom-bindings/php-frankenphp-8.3-linux-amd64.binding.json
docs/audits/real-image-inventories-2026-08-28/sbom-bindings/php-frankenphp-8.3-linux-arm64.binding.json
docs/audits/real-image-inventories-2026-08-28/sbom-bindings/php-frankenphp-8.4-linux-amd64.binding.json
docs/audits/real-image-inventories-2026-08-28/sbom-bindings/php-frankenphp-8.4-linux-arm64.binding.json
docs/audits/real-image-inventories-2026-08-28/sbom-bindings/php-worker-8.3-linux-amd64.binding.json
docs/audits/real-image-inventories-2026-08-28/sbom-bindings/php-worker-8.3-linux-arm64.binding.json
docs/audits/real-image-inventories-2026-08-28/sbom-bindings/php-worker-8.4-linux-amd64.binding.json
docs/audits/real-image-inventories-2026-08-28/sbom-bindings/php-worker-8.4-linux-arm64.binding.json
docs/audits/real-image-inventories-2026-08-28/sbom-document-index.json
docs/audits/real-image-inventories-2026-08-28/scanner-identity.json
```

## Drift is refused in BOTH directions

Regenerating the list without updating the hash, or updating the hash without
regenerating the list, both refuse with `RM-BASELINE-UNVERIFIABLE`. Measured:

- current list + previous hash → `RM-BASELINE-UNVERIFIABLE`
- current hash + an extra path appended to the list → `RM-BASELINE-UNVERIFIABLE`

That is why the two are changed in a single commit: a half-applied refresh is
worse than the honest `RM-BASELINE-STALE` state it replaces.
