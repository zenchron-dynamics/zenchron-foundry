# Repository-material baseline — retention-architecture packet refresh

**Inclusion in this baseline is NOT equivalent to legal review.** The baseline
records which paths a reviewer has *seen*, so that unreviewed material refuses
rather than passing silently. It makes no statement about the licence status of
anything it lists.

| | |
|---|---|
| previous hash | `23c5d17c5fd81974c10c00f935fb9a258ac7ab4eefa0eb0e2904a241e05b398f` |
| previous path count | 1001 |
| new hash | `744e45b8aa661e03e7ff94d85c4e1f2d5c9f63ddfe18d6b0712c055fe0976173` |
| new path count | 1007 |
| additions | 5 |
| removals | **0** |
| `reviewed_at_revision` | **unchanged** — deliberately |
| `observed_at_revision` | advanced to `a5e5094d` |

## What was added

The #241 retention-architecture decision packet, a provider-neutral
storage-receipt schema, its fail-closed verifier, the receipt fixture builder and
its sabotage suite. All first-party, authored in this change, copying no foreign
material, and recorded as reviewed on that basis and on no broader one.

Nothing else was re-read. In particular the audit prose the earlier refreshes
recorded as UNREVIEWED is not absorbed into a review nobody performed.

```text
docs/decisions/evidence-retention-architecture.md
schemas/storage-receipt-v1.schema.json
scripts/release/verify-storage-receipt.sh
tests/lib/make_storage_receipt.py
tests/release/test_storage_receipt.sh
```
