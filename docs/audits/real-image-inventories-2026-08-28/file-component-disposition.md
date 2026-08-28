# The file-component disposition: what was fixed, and what stayed visible

**Date:** 2026-08-28 · **Source revision under evidence:**
`7061caafb3ea09bd5b2342a1daf022151b33f822` · **Cohort:** the 20 accepted
production children · **Nothing was regenerated and nothing was rebuilt.**

`README.md` section 5 reported a second, independent measurement defect:
`scripts/license/license-inventory.sh` folded CycloneDX `type: "file"` components
into the package licence inventory as though a file path were a software
component. 7,972 of that run's 8,507 findings were that defect.

This file records the fix, the rule it implements, the evasion it refuses to
enable, and the corrected totals **by exact meaning**. It resolves no finding,
edits no policy and marks nothing as reviewed.

---

## 1. The evidence model — three things, not one

| # | thing | control that covers it |
|---|---|---|
| 1 | package / library / application components | package licence policy (`policies/license-policy.yaml`) |
| 2 | copied third-party material **in the repository** | `policies/repository-material.yaml` |
| 3 | independently licensed files **inside images** | **nothing, until this change** |

(2) does **not** cover (3), and must never be cited as covering it. Material
introduced only inside a container image is never in the tree, so a tracked-path
inventory cannot see it by construction. `repository-material.yaml` says so in
its own header about image SBOMs; the converse holds identically.

The wrong fix is "drop `type: "file"`". That converts a 7,972-line noise problem
into a **file-level blind spot**: an independently licensed file inside an image
would then be covered by no control at all, and any component could be hidden by
writing `"type": "file"` beside it. Reducing a count by hiding things is the
failure this change exists to prevent.

## 2. The classification rule, and what makes each branch mechanical

Every CycloneDX `type: "file"` component **and** every SPDX `files[]` entry —
the SPDX half was read by nothing at all before this change, which was the same
blind spot on the other format — is classified into exactly one of four classes.
The branches are evaluated in this order and the order is load-bearing.

```text
1  the document ASSERTS a licence for the file                -> independently-licensed   KEPT
2  the file carries its own purl                              -> independently-licensed   KEPT
3  the file names its own cpe / supplier / publisher /
   author / copyright / externalReferences                    -> independently-licensed   KEPT
4  an edge to the file from a component carrying a `pkg:`
   purl is SHOWN                                              -> attributable             excluded
5  an edge to the file is SHOWN, but its other endpoint
   carries no package identity, and the document
   establishes no licence, purl, cpe, supplier, publisher,
   author or external reference for the file                  -> observation              excluded
6  anything else                                              -> unresolved               KEPT
```

**Only branches 4 and 5 exclude, and both require an edge to have been SHOWN.**
That is the whole of the mechanical justification. Specifically:

* An **SPDX** owner is a `Package --CONTAINS--> File` relationship, or syft's
  `OTHER` relationship whose own comment reads
  `evident-by: indicates the package's existence is evident by the given file`.
  In both cases the owning package must carry a `pkg:` purl in its
  `externalRefs`, or it proves nothing.
* A **CycloneDX** owner is an edge in the document's `dependencies` graph whose
  other endpoint is a non-file component carrying a `pkg:` purl.
* CycloneDX has no containment concept, so syft's CycloneDX file components can
  arrive with no in-document owner. The **SPDX companion of the same image
  subject** is then read for the ownership fact — same producer, same scan, same
  subject digest, matched on the sha256 subject the document itself names, with
  paths normalised to one spelling (`bin/busybox` in SPDX, `/bin/busybox` in
  CycloneDX). If the two documents cannot be shown to describe the same subject,
  **no attribution is transferred** and the file stays visible.

What the rule refuses to do is reason from configuration.
`policies/syft.yaml` sets `file.metadata.selection: "owned-by-package"`, and it
is therefore *true* that these files are owned by packages. That is a statement
about a config file, not about the document in hand, and this parser will not
make it. An owner that is not shown is not an owner.

Nothing is deleted. Every file observation of every class is counted in the
inventory's `image_files` block, so any drop in the findings total arrives with
the exact number of files that moved and the class they moved into.

## 3. Proof that independently licensed image files remain visible

`independently-licensed` and `unresolved` files are **added to `components[]`**
and therefore reach `assert-license-policy.sh` exactly as a package would. They
are additionally tagged `component_type: "file"` with their `file_class` and the
justification, and listed by path in `image_files.independently_licensed` /
`image_files.unresolved`.

Measured, in `tests/license/test_licence_file_components.sh`:

* a CycloneDX file component with no owner edge anywhere is reported as
  `unresolved`, is present in `components[]`, and **refuses at the gate**, with
  the gate's own output naming the path;
* the same file, when its ownership evidence is removed from the document set,
  stops being excluded — the exclusion tracks the evidence, not the file.

## 4. The required sabotage — the evasion is refused

An independently licensed image file **cannot** be hidden by changing its
CycloneDX `type` to `"file"`. Fixture: four components relabelled `type: "file"`,
three of them independently licensed, all four given an owner edge from a real
`pkg:deb` package so that a type-based exclusion would swallow every one of
them.

| component (relabelled `type: "file"`) | identity it carries | class | in `components[]` |
|---|---|---|---|
| `/usr/share/vendor/libevil.so` | `licenses: [EVIL-1.0]` | independently-licensed | **yes** |
| `/opt/agpl-thing` | `expression: AGPL-3.0-only` | independently-licensed | **yes** |
| `/usr/bin/caddy` | `purl: pkg:golang/…/caddy@2.10.2` | independently-licensed | **yes** |
| `/etc/owned.conf` | nothing | attributable | no — owner shown |

The gate then **refuses**, naming `libevil.so` and `AGPL-3.0-only`. The licence
identity is tested at branch 1, before any type-based exclusion, so an owner edge
cannot suppress it.

The counterfactual was measured too. Replacing `classify_file()` with the naive
"every `type: "file"` component is excluded" implementation fails **7** of the
suite's 19 assertions, including all four sabotage assertions. Against the
*previous* parser, 13 of 19 fail. The suite therefore distinguishes the fix from
both the old behaviour and the blind-spot behaviour, rather than merely passing.

## 5. Non-vacuity against the real producer

One assertion runs over a **real, committed syft document**,
`docs/audits/caddy-openssl-2026-08-27/evidence/sbom-candidate-linux-amd64.spdx.json`
(syft 1.50.0, 179 packages, 224 files, 787 relationships), not a hand-written
fixture:

```text
224 file entries -> attributable 224, observation 0,
                    independently-licensed 0, UNRESOLVED 0
0 file paths leaked into the package component list
```

222 of the 224 are `CONTAINS`-owned; the remaining two — `usr/bin/caddy` and
`lib/apk/db/installed` — are owned only through syft's `evident-by`
relationship. `usr/bin/caddy` is the point: it is the Caddy binary, it is
independently distributed, and under a naive type-based exclusion it disappears
from every control. Here it is excluded **only** because the document names the
`pkg:golang` modules it is evident by. Remove that evidence and it becomes
`unresolved` and stays visible.

*A fixture that only carries the shape the consumer already reads cannot discover
that the producer disagrees.* That is how this repository's 113-assertion suite
missed a gate that bound nothing, and it is why one assertion here is pointed at
producer output nobody wrote for a test.

## 6. Corrected totals, by exact meaning

### 6a. The replayed cohort — what is measured, and from what

**The 40 documents are not in the tree.** They are 86,781,974 bytes,
`*.cdx.json` is gitignored repository-wide, and `README.md` section 3 records
that they were deliberately not committed. They are not present anywhere on this
machine either (`find /` over the whole filesystem for the index's own document
names returns nothing). Regenerating them was prohibited and would not have
reproduced them byte-for-byte in any case. So the replay is against **the
committed derived record**, not against the documents, and the following table
says which number came from where.

| category | count | derived from |
|---|---|---|
| total findings | **8,507** | `licence/image-licence-policy-diagnostic.log`, 8,507 finding lines, header-declared count verified line-for-line |
| missing policy assertions (all) | **8,292** | same |
| — of which CycloneDX `type: "file"` | **7,972** | same, split on the leading `/` of a file-component label |
| — of which package components | **320** | same |
| conflicting assertions | **196** | same |
| legal-review-required identifiers | **19** | same, on 5 distinct identifiers |
| substantive findings | **535** | 320 + 196 + 19 |
| independently licensed image files | **0 measured; not separately derivable** | see 6b |
| unresolved image files | **not derivable from the committed record** | see 6b |

`8,527` total components reconciles exactly:
`7,972 files + 555 non-file = 8,527`, and
`555 = 535 real packages + 20 pkg:oci image-root self-references`, and
`535 = 300 real packages with no assertion + 196 conflicting + 19 review + 20 clean`,
and `320 = 300 + the 20 image roots`. The apparent 300-vs-320 disagreement
between `licence/identifier-reconciliation.json` and
`rerun-against-fixed-consumer.md` is therefore **not an error**: the
reconciliation counts real packages and the finding total counts the image-root
components too. Both are right about different denominators, and neither said so.

### 6b. The gap this record does not close, stated as a gap

Splitting the 7,972 into `attributable` / `observation` /
`independently-licensed` / `unresolved` **requires the 20 CycloneDX documents and
their 20 SPDX companions**, because the split is a function of the
`dependencies` graphs and the `CONTAINS` / `evident-by` relationships those
documents carry. The committed record holds finding *labels*, not relationships.
Producing that split from anything else would be a guess with a number attached.

Two bounds are honest, and neither is the answer:

* every one of the 7,972 was `unknown` in the run, so **no file component in the
  cohort carried a licence assertion** — the `independently-licensed`-by-licence
  count is therefore **0** for this cohort;
* on the one real syft document available in-tree, **224 of 224** file entries
  were mechanically attributable and **0** were unresolved.

**Closure condition** — one run of

```bash
scripts/license/license-inventory.sh --sbom-dir <the 40 documents> --out inv.json
python3 -c "import json;print(json.load(open('inv.json'))['image_files']['by_class_observations'])"
```

over the same 40 documents, with the resulting `image_files` block committed
here. That is a maintainer action requiring the artifact set; it builds nothing
and dispatches nothing.

## 7. What this change does NOT do

* It does not change any allow/deny/review decision.
  `policies/license-policy.yaml` is untouched.
* It does not resolve, waive or suppress any of the 535 substantive findings.
* It does not fix the conflict-normalisation defect that produces 196 of them
  (see `docs/licensing/image-licence-backlog-2026-08-28.md`, groups
  `G-CONFLICT-RC1`…`RC4`). Fixing it would remove 192 findings, and removing
  findings is exactly the act that needs a reviewed decision rather than a
  parser change made in passing.
* It does not close pinned gap (b). The composed gate still refuses.
