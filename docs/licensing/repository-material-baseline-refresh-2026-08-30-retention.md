# Repository-material baseline — evidence-retention audit refresh

**Inclusion in this baseline is NOT equivalent to legal review.** The baseline
records which paths a reviewer has *seen*, so that unreviewed material refuses
rather than passing silently. It makes no statement about the licence status of
anything it lists.

| | |
|---|---|
| previous hash | `d4b5e9c22d9a49a21e95b5a51e58d51ccaf33b9a5768f716a6691058c300c527` |
| previous path count | 996 |
| new hash | `23c5d17c5fd81974c10c00f935fb9a258ac7ab4eefa0eb0e2904a241e05b398f` |
| new path count | 1001 |
| additions | 5 |
| removals | **0** |
| `reviewed_at_revision` | **unchanged** — deliberately |
| `observed_at_revision` | advanced to `66966d96` |

## What was added

`docs/audits/evidence-retention-2026-08-30/` — the read-only retention audit, its
live API probe and the 535→723 notice reconciliation — and this file. All
first-party, authored in this change, copying no foreign material. The probe is
deterministic output of a `GET` against the GitHub REST API and the
reconciliation is deterministic output of the shipped notice producer; both are
recorded as reviewed on the basis that they are first-party machine output, and
on no broader one.

Nothing else was re-read. In particular the audit prose the earlier refreshes
recorded as UNREVIEWED is not absorbed into a review nobody performed.

```text
docs/audits/evidence-retention-2026-08-30/README.md
docs/audits/evidence-retention-2026-08-30/SHA256SUMS
docs/audits/evidence-retention-2026-08-30/artifact-retention-probe.json
docs/audits/evidence-retention-2026-08-30/notice-reconciliation.json
docs/licensing/repository-material-baseline-refresh-2026-08-30-retention.md
```
