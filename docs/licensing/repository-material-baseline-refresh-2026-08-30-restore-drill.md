# Repository-material baseline — restore-drill refresh

**Inclusion in this baseline is NOT equivalent to legal review.** The baseline
records which paths a reviewer has *seen*, so that unreviewed material refuses
rather than passing silently. It makes no statement about the licence status of
anything it lists.

| | |
|---|---|
| previous hash | `9c98f80e6a0f6bfee41f13f66dd6c34dfbec6c9ce88ca22a6586e7aa85b6b132` |
| previous path count | 1010 |
| new hash | `2135786b941b606d0185669cdf020e3c2c038d657ec24a0022f87b65417944e6` |
| new path count | 1013 |
| additions | 3 |
| removals | **0** |
| `reviewed_at_revision` | **unchanged** — deliberately |
| `observed_at_revision` | advanced to `5638ebe` |

## What was added

The evidence restore drill, the suite that executes its workflow step bodies,
and this record. All three are first-party, authored in this change, copying no
foreign material: shell and Python written here, and a Markdown record written
here. No third-party text, no vendored source, no generated inventory.

No claim is made that a human read anything else in this refresh. The audit prose
that earlier refreshes recorded as UNREVIEWED stays unreviewed and is not
absorbed into a review nobody performed; `reviewed_at_revision` is deliberately
unchanged for exactly that reason.

```text
docs/licensing/repository-material-baseline-refresh-2026-08-30-restore-drill.md
scripts/ci/evidence-restore-drill.sh
tests/release/test_evidence_restore_drill.sh
```
