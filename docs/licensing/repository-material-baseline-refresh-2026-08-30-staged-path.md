# Repository-material baseline — staged storage-path refresh

**Inclusion in this baseline is NOT equivalent to legal review.** The baseline
records which paths a reviewer has *seen*, so that unreviewed material refuses
rather than passing silently. It makes no statement about the licence status of
anything it lists.

| | |
|---|---|
| previous hash | `744e45b8aa661e03e7ff94d85c4e1f2d5c9f63ddfe18d6b0712c055fe0976173` |
| previous path count | 1007 |
| new hash | `9c98f80e6a0f6bfee41f13f66dd6c34dfbec6c9ce88ca22a6586e7aa85b6b132` |
| new path count | 1010 |
| additions | 3 |
| removals | **0** |
| `reviewed_at_revision` | **unchanged** — deliberately |
| `observed_at_revision` | advanced to `bedb455` |

## What was added

The storage-receipt producer for the active staged path, the suite that executes
the workflow step's own body, and this record. All three are first-party,
authored in this change, copying no foreign material: shell and Python written
here, and a Markdown record written here. No third-party text, no vendored
source, no generated inventory.

No claim is made that a human read anything else in this refresh. The audit prose
that earlier refreshes recorded as UNREVIEWED stays unreviewed and is not
absorbed into a review nobody performed; `reviewed_at_revision` is deliberately
unchanged for exactly that reason.

```text
docs/licensing/repository-material-baseline-refresh-2026-08-30-staged-path.md
scripts/release/emit-storage-receipt.sh
tests/release/test_staged_storage_path.sh
```
