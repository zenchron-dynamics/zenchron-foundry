# Repository-material baseline — restore-drill readback record refresh

**Inclusion in this baseline is NOT equivalent to legal review.** The baseline
records which paths a reviewer has *seen*, so that unreviewed material refuses
rather than passing silently. It makes no statement about the licence status of
anything it lists.

| | |
|---|---|
| previous hash | `2135786b941b606d0185669cdf020e3c2c038d657ec24a0022f87b65417944e6` |
| previous path count | 1013 |
| new hash | `d9750f329242245f432cb1bddbfb6341b5f6c0eb4bf209e3ea3a818943b0ecde` |
| new path count | 1019 |
| additions | 6 |
| removals | **0** |
| `reviewed_at_revision` | **unchanged** — deliberately |
| `observed_at_revision` | advanced to `84419f2` |

## What was added

The committed readback record for the evidence restore drill, and this file.

Two paths are REVIEWED: `README.md`, which is first-party prose written here,
and this refresh record. Four are GENERATED-AUDIT: `verdict.json` and
`storage-receipt.json` are deterministic output of named producers
(`scripts/ci/evidence-restore-drill.sh` and
`scripts/release/emit-storage-receipt.sh`), `artifact-observations.json` is a
capture of a GitHub REST API response, and `SHA256SUMS` is a checksum index over
the other three. None carries prose an author could have copied from anywhere,
which is the whole content class that cohort names — it is not a path rule and
`docs/audits/` is not blanket-exempt.

No claim is made that a human read anything else in this refresh.
`reviewed_at_revision` is deliberately unchanged for exactly that reason.

```text
docs/audits/evidence-restore-drill-2026-08-30/README.md
docs/audits/evidence-restore-drill-2026-08-30/SHA256SUMS
docs/audits/evidence-restore-drill-2026-08-30/artifact-observations.json
docs/audits/evidence-restore-drill-2026-08-30/storage-receipt.json
docs/audits/evidence-restore-drill-2026-08-30/verdict.json
docs/licensing/repository-material-baseline-refresh-2026-08-30-readback.md
```
