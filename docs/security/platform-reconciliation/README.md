# Per-platform reconciliation evidence

`scripts/assert-publish-platforms-reconciled.sh` refuses to publish a platform
unless this directory holds complete evidence for it. The gate runs in the
`publish-ghcr` preflight, before the first push.

## Why this exists

An empty exception ledger used to authorise every platform. That is the inverse
of what the gate is for: with a fully remediated ledger (#122), an **unscanned**
`linux/arm64` would have published freely.

*Nothing accepted* and *this architecture was reconciled* are different claims.
Only the second one authorises a publish, and only evidence can establish it.

## Contract

One file per platform. Every field is required; anything absent, malformed or
incomplete is treated as **not proven**, never as fine.

```json
{
  "schema_version": 1,
  "platform": "linux/arm64",
  "source_revision": "<40-hex commit the images were built from>",
  "trivy_db_snapshot": "<identifier of the vulnerability DB the scan used>",
  "scanner": "aquasec/trivy:0.71.0@sha256:...",
  "generated_at": "YYYY-MM-DD",
  "images": [
    {
      "image": "php-cli/8.3",
      "architecture": "linux/arm64",
      "manifest_digest": "sha256:<64-hex child manifest digest>",
      "reconciliation": "PASS"
    }
  ]
}
```

The six bindings the gate enforces:

| Binding | Field | Why |
|---|---|---|
| image family/version | `images[].image` | evidence for `nginx/prod` must not vouch for `php-cli/8.3` |
| child manifest digest | `images[].manifest_digest` | ties the result to the exact image, not a moving tag |
| architecture | `images[].architecture` | must equal the file's `platform` |
| source revision | `source_revision` | ties the result to the code that produced it |
| Trivy DB snapshot | `trivy_db_snapshot` | a scan is only as current as its database |
| reconciliation result | `images[].reconciliation` | must be `PASS` |

Additional rules:

- **All ten** canonical images must be present — the set is compared for
  equality against `matrix_image_labels()` in `scripts/lib/common.sh`, so a
  partial run cannot look complete and an image outside the matrix cannot pad it.
- No duplicate image labels.
- Exactly one file may declare a given platform; two are ambiguous and reject.

The ledger check still runs **on top of** this: a platform needs evidence *and*
must be covered by every active acceptance record.

## Current state

**No platform currently has complete evidence, so no platform is publishable.**

`docs/security/round2-evidence-2026-07-28.json` records a real ten-image
`linux/amd64` reconciliation with per-image digests and verdicts, but it predates
this contract and carries neither `source_revision` nor `trivy_db_snapshot`.
Those cannot be reconstructed after the fact without guessing, so it has not been
converted into an evidence file here.

- `linux/amd64` — needs an evidence run that records the revision and DB snapshot.
- `linux/arm64` — needs the ten-image reconciliation tracked in **#139**.
