# Repository-material baseline — notice/source-obligation refresh

**Inclusion in this baseline is NOT equivalent to legal review.** The baseline
records which paths a reviewer has *seen*, so that unreviewed material refuses
rather than passing silently. It makes no statement about the licence status of
anything it lists.

| | |
|---|---|
| previous hash | `ad9ffdd7996ff31256a46a1589da483ed0a2c17a0b8b5a3e0747e8432f114717` |
| previous path count | 785 |
| new hash | `e9f488f263a5c6f35556e05517ddf7d36b22002bf9f3ce0ca227dc0d744c85ac` |
| new path count | 851 |
| additions | 66 |
| removals | **0** |
| `reviewed_at_revision` | **unchanged** — deliberately |
| `observed_at_revision` | advanced to `033d51e0` — where the list came from |

`reviewed_at_revision` is left at the lane-R full-review revision on purpose. It
is not machine-checked, and repointing it at a commit that never contained these
files would assert a review that did not happen. The 39 paths the earlier
refreshes recorded as unreviewed or generated-audit stay in those cohorts,
unabsorbed.

## What was added, and on what basis it is recorded as reviewed

Three classes. Nothing here is a blanket exemption; each says what the review
consisted of.

### 1. First-party records authored in this change

`policies/source-obligations.yaml`, `policies/upstream-licence-attestations.yaml`,
`third-party/licence-texts/PROVENANCE.yaml`, `schemas/notice-bundle-v1.schema.json`,
`scripts/license/generate-notice-bundle.py`, `tests/license/test_notice_bundle.sh`,
`tests/lib/make_replay_inventory.py`, `tests/lib/make_notice_inputs.py`,
`docs/licensing/notice-and-source-obligations.md` and this file.

They copy no foreign material except the licence identifiers and copyright
attributions they exist to record. Reviewed on that basis and on no broader one.

### 2. The 56 canonical licence texts

`third-party/licence-texts/*.txt` are wholly third-party licence text, copied
verbatim from `spdx/license-list-data` at tag `v3.28.0` (commit `c4a7237e`).

**The review performed is stated exactly.** For each file: its upstream project,
pinned revision, upstream path and sha256 are recorded in
`third-party/licence-texts/PROVENANCE.yaml`, and every run of
`scripts/license/assert-repository-material.sh` re-verifies those bytes
(`RM-LICENCE-TEXT-STORE-DRIFT`). **No claim is made that a human read 656 KB of
licence prose**, and none is needed: the question the baseline asks of a path is
whether its copied material is *accounted for*, and for these it is accounted
for exhaustively and machine-checkably.

Recording them as unreviewed would create a permanent release-scope blocker on
the one class of file whose provenance is the most completely established in the
tree.

### 3. Nothing else was re-read

In particular the audit prose the earlier refreshes recorded as UNREVIEWED is
not absorbed into a review nobody performed.

## The additions, enumerated

```text
docs/licensing/notice-and-source-obligations.md
docs/licensing/repository-material-baseline-refresh-2026-08-28-notices.md
policies/source-obligations.yaml
policies/upstream-licence-attestations.yaml
schemas/notice-bundle-v1.schema.json
scripts/license/generate-notice-bundle.py
tests/lib/make_notice_inputs.py
tests/lib/make_replay_inventory.py
tests/license/test_notice_bundle.sh
third-party/licence-texts/0BSD.txt
third-party/licence-texts/Apache-2.0.txt
third-party/licence-texts/Artistic-2.0.txt
third-party/licence-texts/BSD-1-Clause.txt
third-party/licence-texts/BSD-2-Clause.txt
third-party/licence-texts/BSD-3-Clause-Clear.txt
third-party/licence-texts/BSD-3-Clause.txt
third-party/licence-texts/BSD-4-Clause-UC.txt
third-party/licence-texts/BSD-4-Clause.txt
third-party/licence-texts/BSL-1.0.txt
third-party/licence-texts/Beerware.txt
third-party/licence-texts/CC-BY-3.0.txt
third-party/licence-texts/CC0-1.0.txt
third-party/licence-texts/FSFAP.txt
third-party/licence-texts/FSFULLR.txt
third-party/licence-texts/FTL.txt
third-party/licence-texts/GFDL-1.2-only.txt
third-party/licence-texts/GFDL-1.2-or-later.txt
third-party/licence-texts/GFDL-1.3-only.txt
third-party/licence-texts/GPL-1.0-only.txt
third-party/licence-texts/GPL-1.0-or-later.txt
third-party/licence-texts/GPL-2.0-only.txt
third-party/licence-texts/GPL-2.0-or-later.txt
third-party/licence-texts/GPL-3.0-only.txt
third-party/licence-texts/GPL-3.0-or-later.txt
third-party/licence-texts/HPND-sell-variant.txt
third-party/licence-texts/HPND.txt
third-party/licence-texts/ISC.txt
third-party/licence-texts/Kazlib.txt
third-party/licence-texts/LGPL-2.0-only.txt
third-party/licence-texts/LGPL-2.0-or-later.txt
third-party/licence-texts/LGPL-2.1-only.txt
third-party/licence-texts/LGPL-2.1-or-later.txt
third-party/licence-texts/LGPL-3.0-only.txt
third-party/licence-texts/LGPL-3.0-or-later.txt
third-party/licence-texts/Latex2e.txt
third-party/licence-texts/Libpng.txt
third-party/licence-texts/MIT-CMU.txt
third-party/licence-texts/MIT.txt
third-party/licence-texts/MPL-1.1.txt
third-party/licence-texts/MPL-2.0.txt
third-party/licence-texts/MS-PL.txt
third-party/licence-texts/NTP.txt
third-party/licence-texts/OLDAP-2.8.txt
third-party/licence-texts/OpenSSL.txt
third-party/licence-texts/PHP-3.01.txt
third-party/licence-texts/PROVENANCE.yaml
third-party/licence-texts/PostgreSQL.txt
third-party/licence-texts/RSA-MD.txt
third-party/licence-texts/SMAIL-GPL.txt
third-party/licence-texts/Sleepycat.txt
third-party/licence-texts/TCL.txt
third-party/licence-texts/Unlicense.txt
third-party/licence-texts/X11.txt
third-party/licence-texts/Zlib.txt
third-party/licence-texts/curl.txt
third-party/licence-texts/libutil-David-Nugent.txt
```
