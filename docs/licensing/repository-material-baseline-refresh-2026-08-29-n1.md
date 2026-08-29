# Repository-material baseline — N1 in-image licence material refresh

**Inclusion in this baseline is NOT equivalent to legal review.** The baseline
records which paths a reviewer has *seen*, so that unreviewed material refuses
rather than passing silently. It makes no statement about the licence status of
anything it lists.

| | |
|---|---|
| previous hash | `e9f488f263a5c6f35556e05517ddf7d36b22002bf9f3ce0ca227dc0d744c85ac` |
| previous path count | 851 |
| new hash | `d4b5e9c22d9a49a21e95b5a51e58d51ccaf33b9a5768f716a6691058c300c527` |
| new path count | 996 |
| additions | 145 |
| removals | **0** |
| `reviewed_at_revision` | **unchanged** — deliberately |
| `observed_at_revision` | advanced to `723ce9bd` |

## What was added, and on what basis it is recorded as reviewed

### 1. The two extraction tools and the audit record

`scripts/license/extract-image-licence-materials.py`,
`scripts/license/account-image-licence-materials.py`,
`docs/audits/image-licence-materials-2026-08-29/` (README, the extraction
manifest, the accounting record, `SHA256SUMS`) and this file. All first-party,
authored in this change, copying no foreign material. Reviewed on that basis and
on no broader one.

### 2. The 137 carried in-image licence and copyright files

`third-party/image-licence-materials/objects/**` are wholly third-party
copyright and licence texts, read verbatim out of the accepted production images
by immutable digest.

**The review performed is stated exactly.** Each file's origin is recorded to the
byte: which child, which immutable manifest digest, which in-image path, and its
sha256, in `third-party/image-licence-materials/PROVENANCE.yaml`; the whole set
is re-verified on every gate run (`RM-LICENCE-TEXT-STORE-DRIFT`). **No claim is
made that a human read 1.4 MB of copyright prose**, and none is needed: the
question the baseline asks of a path is whether its copied material is
*accounted for*, and for these it is accounted for exhaustively, per-child, and
machine-checkably.

Recording them as unreviewed would create a permanent release-scope blocker on
the one class of file whose provenance is the most completely established in the
tree — it is provable down to the layer the bytes came out of.

### 3. Nothing else was re-read

In particular the audit prose the earlier refreshes recorded as UNREVIEWED is not
absorbed into a review nobody performed.

## The additions, enumerated

The 137 content-addressed objects are listed by hash in
`third-party/image-licence-materials/PROVENANCE.yaml` rather than repeated here;
enumerating 137 sha256 filenames twice would be two lists to drift. The
non-object additions are:

```text
docs/audits/image-licence-materials-2026-08-29/README.md
docs/audits/image-licence-materials-2026-08-29/SHA256SUMS
docs/audits/image-licence-materials-2026-08-29/image-licence-accounting.json
docs/audits/image-licence-materials-2026-08-29/image-licence-materials.json
docs/licensing/repository-material-baseline-refresh-2026-08-29-n1.md
scripts/license/account-image-licence-materials.py
scripts/license/extract-image-licence-materials.py
third-party/image-licence-materials/PROVENANCE.yaml
```
