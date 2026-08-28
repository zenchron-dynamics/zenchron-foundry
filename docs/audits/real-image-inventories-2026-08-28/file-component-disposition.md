# The file-component disposition: what was fixed, and what stayed visible

**Date:** 2026-08-28 · **Source revision under evidence:**
`7061caafb3ea09bd5b2342a1daf022151b33f822` · **Cohort:** the 20 accepted
production children · **Nothing was regenerated and nothing was rebuilt.**

`README.md` section 5 reported a second, independent measurement defect:
`scripts/license/license-inventory.sh` folded CycloneDX `type: "file"` components
into the package licence inventory as though a file path were a software
component. 7,972 of that run's 8,507 findings were that defect.

This file records the fix, the rule it implements, the four evasions it refuses
to enable, and the corrected totals **by exact meaning**. It resolves no
finding, edits no policy and marks nothing as reviewed.

---

## 1. The evidence model — three things, not one

| # | thing | control that covers it |
|---|---|---|
| 1 | package / library / application components | package licence policy (`policies/license-policy.yaml`) |
| 2 | copied third-party material **in the repository** | `policies/repository-material.yaml` |
| 3 | independently licensed files **inside images** | **nothing, until this change** |

(2) does **not** cover (3), and must never be cited as covering it. Material
introduced only inside a container image is never in the tree, so a tracked-path
inventory cannot see it by construction.

The wrong fix is "drop `type: "file"`". That converts a 7,972-line noise problem
into a **file-level blind spot**: an independently licensed file inside an image
would then be covered by no control at all, and any component could be hidden by
writing `"type": "file"` beside it. Reducing a count by hiding things is the
failure this change exists to prevent.

## 2. Four dispositions, each with a mechanically recorded reason

Every CycloneDX `type: "file"` component **and** every SPDX `files[]` entry —
the SPDX half was read by nothing at all before this change, which was the same
blind spot on the other format — receives exactly one of four classifications.
**No component may disappear without a recorded classification and reason.**

| class | withheld from package policy? | what it means |
|---|---|---|
| `scanner-observation` | yes | the scanner recorded a path and a hash and nothing else |
| `package-attributed` | yes | an owning package is **proven**; the obligation is **inherited** from it |
| `independently-licensed` | **no — stays in `components[]`** | the document gives the file a licence or an identity of its own |
| `unresolved` | **no — stays in `components[]`** | nothing has been established about it |

The branches are evaluated in this order, and the order is load-bearing:

```text
1  the document asserts MORE THAN ONE licence identifier      -> independently-licensed  KEPT
2  the document asserts a licence for the file                -> independently-licensed  KEPT
3  the file carries its own purl / cpe / supplier /
   publisher / author / copyright / externalReferences        -> independently-licensed  KEPT
4  the document records LOCAL MODIFICATION (`modified`,
   `pedigree` patches/variants/commits, notice or
   attribution text, fileContributors, or a digest that
   disagrees between the two documents)                       -> independently-licensed  KEPT
5  an owning package is PROVEN by a stable relationship       -> package-attributed      excluded
6  an edge to the file is shown, its other endpoint carries
   no package identity, and none of 1-4 applies               -> scanner-observation     excluded
7  anything else                                              -> unresolved              KEPT
```

### What makes branch 5 mechanical

Ownership is accepted **only** from a stable SBOM relationship or
package-manager evidence:

* SPDX `Package --CONTAINS--> File`;
* syft's `OTHER` relationship whose own comment reads
  `evident-by: indicates the package's existence is evident by the given file`;
* a CycloneDX `dependencies` edge.

In every case the owning component must carry a `pkg:` purl, or it proves
nothing. **Filename similarity, installation path and a shared version are never
used.** CycloneDX has no containment concept, so a CycloneDX file component's
ownership fact is read from the SPDX companion **of the same image subject** —
joined on the sha256 subject the documents themselves name, and on the exact
path within that one scan, with paths normalised to one spelling (`bin/busybox`
in SPDX, `/bin/busybox` in CycloneDX). Where both documents carry a digest for
the file and the digests **disagree**, the attribution is **revoked**: a shared
filename with different content is a different file.

Recorded for every `package-attributed` file: owning package identity, package
version, the relationship that proves it, the inherited licence expression, and
whether the file carries exceptional or conflicting licence metadata.

### De-duplication is counted-once, never obligation-removed

A `package-attributed` file is **de-duplicated against its owning package**. The
obligation inherited from that package still exists in full; it is counted
**once, on the package**, instead of once per path. The inventory says so in the
document it emits (`image_files.deduplication_note`), and an assertion checks
that wording, because "0 findings" and "no obligation" are different sentences.

### What the rule refuses to do

It refuses to reason from configuration. `policies/syft.yaml` sets
`file.metadata.selection: "owned-by-package"`, and it is therefore *true* that
these files are owned by packages. That is a statement about a config file, not
about the document in hand, and this parser will not make it. An owner that is
not shown is not an owner.

It also refuses the inverse inference. **Absence of licence metadata is not
evidence of absence of licence**: a file with nothing recorded about it and no
edge to it lands in `unresolved`, which is visible, and never in
`scanner-observation`, which is not.

## 3. The accounting invariant is ASSERTED, not reported

```text
input file components == scanner-observation
                       + package-attributed
                       + independently-licensed
                       + unresolved
```

The parser refuses — it does not warn — when:

* a file component carries a class outside the four;
* a file component was classified with no recorded reason;
* the four classes do not sum to the input count;
* a component in a visible class did not reach `components[]`
  (*"a visible class that does not reach the policy gate is a blind spot with a
  label on it"*).

Both counts are reported, never one: the **raw** file-component count and the
**normalised** policy-finding count that survives de-duplication.

## 4. Proof that independently licensed image files remain visible

`independently-licensed` and `unresolved` files are **added to `components[]`**
and reach `assert-license-policy.sh` exactly as a package would, under one
canonical `/path` spelling so the SPDX and CycloneDX entries for one file
collapse onto one record rather than being counted twice. They are tagged
`component_type: "file"` with their `file_class` and reason, and enumerated by
path in `image_files.independently_licensed` / `image_files.unresolved`.

Measured in `tests/license/test_licence_file_components.sh`: a file with no
owner edge anywhere is reported `unresolved`, is present in `components[]`, and
**refuses at the gate**, with the gate's own output naming the path.

## 5. The four sabotages

All four are in the suite, and all four **fail** against a naive "drop every
`type: "file"` component" implementation.

### (a) An independently licensed file cannot be hidden by relabelling its type

Fixture: seven components relabelled `type: "file"`, six of them carrying an
identity, all seven given an owner edge from a real `pkg:deb` package so that a
type-based exclusion would swallow every one of them.

| component (relabelled `type: "file"`) | identity it carries | class | in `components[]` |
|---|---|---|---|
| `/usr/share/vendor/libevil.so` | `licenses: [EVIL-1.0]` | independently-licensed | **yes** |
| `/opt/agpl-thing` | `expression: AGPL-3.0-only` | independently-licensed | **yes** |
| `/usr/bin/caddy` | `purl: pkg:golang/…/caddy@2.10.2` | independently-licensed | **yes** |
| `/opt/conflicted` | `GPL-3.0-only`, owner says `MIT` | independently-licensed | **yes** |
| `/opt/two-minds` | `MIT` **and** `GPL-2.0-only` | independently-licensed | **yes** |
| `/opt/patched.so` | `pedigree.patches` | independently-licensed | **yes** |
| `/etc/owned.conf` | nothing | package-attributed | no — owner proven |

The gate then **refuses**, naming `libevil.so` and `AGPL-3.0-only`. The licence
identity is tested before any type-based exclusion, so an owner edge cannot
suppress it.

### (b) Deleting licence metadata does not promote a file into an excludable class

Same fixture with `licenses` and `purl` stripped from two components and every
dependency edge removed. Both land in `unresolved`, both remain in
`components[]`, `scanner-observation` stays at **0**, and the gate still
refuses. The recorded reason says it in words: *the absence of licence metadata
is not evidence that no licence applies*.

### (c) Breaking the owning-package relationship un-attributes the file

Remove the SPDX `CONTAINS` relationship and the same file stops being
`package-attributed` and becomes `unresolved`, reaching the gate. A second
variant leaves the relationship intact but makes the two documents disagree
about the file's digest: the attribution is revoked there too, and the file
becomes visible rather than silently inheriting an owner it may not have.

### (d) A conflicting file/package licence stays visible

`/opt/conflicted` declares `GPL-3.0-only` while its proven owner declares `MIT`.
It is **not** attributed. It is `independently-licensed`, flagged
`conflicting_or_exceptional_licence_metadata: true`, its recorded reason names
the owner's differing identifier, and it reaches the gate. `/opt/two-minds`,
which asserts two identifiers for one file, is handled at branch 1 for the same
reason: a disagreement about an obligation is not inheritable.

### Counterfactuals, measured

| implementation | assertions failed (of 28) |
|---|---|
| the previous parser (file components counted as packages, SPDX `files[]` ignored) | **21** |
| a naive "drop every `type: "file"` component" | **16**, including all four sabotages |

The suite therefore distinguishes the fix from both the old behaviour and the
blind-spot behaviour, rather than merely passing.

## 6. Non-vacuity against the real producer

One assertion runs over a **real, committed syft document**,
`docs/audits/caddy-openssl-2026-08-27/evidence/sbom-candidate-linux-amd64.spdx.json`
(syft 1.50.0, 179 packages, 224 files, 787 relationships), not a hand-written
fixture:

```text
224 file entries -> package-attributed 224, scanner-observation 0,
                    independently-licensed 0, unresolved 0
raw file components 224, normalised policy findings from files 0
0 file paths leaked into the package component list
```

222 of the 224 are `CONTAINS`-owned; the remaining two — `usr/bin/caddy` and
`lib/apk/db/installed` — are owned only through syft's `evident-by`
relationship. `usr/bin/caddy` is the point: it is the Caddy binary, it is
independently distributed, and under a naive type-based exclusion it disappears
from every control. Here it is excluded **only** because the document names the
`pkg:golang` modules it is evident by. Remove that evidence and it becomes
`unresolved` and stays visible.

### The obligation is preserved, not dropped — shown on one real file

`/bin/busybox` was one of the 7,972 bare "no licence could be established"
findings. It is now a disposition, verbatim from the inventory the parser writes:

```json
{"path": "bin/busybox", "class": "package-attributed",
 "owning_package": ["pkg:apk/alpine/busybox@1.37.0-r30?arch=x86_64&distro=alpine-3.23.5",
                    "pkg:apk/alpine/busybox-binsh@1.37.0-r30?..."],
 "owning_package_version": ["1.37.0-r30"],
 "relationship_evidence": ["SPDX:CONTAINS"],
 "inherited_licence_expression": ["GPL-2.0-only"],
 "conflicting_or_exceptional_licence_metadata": false,
 "reason": "owned by ... via SPDX:CONTAINS; licence obligation INHERITED as
            GPL-2.0-only and counted once on the package rather than once per
            path — the obligation is not removed, it is de-duplicated"}
```

`GPL-2.0-only` on `busybox` is one of the **19 legal-review findings that
survive**. The file stopped being its own finding; the obligation did not stop
existing, and it is still refused at the gate on the package.

*A fixture that only carries the shape the consumer already reads cannot discover
that the producer disagrees.* That is how this repository's 113-assertion suite
missed a gate that bound nothing, and it is why one assertion here is pointed at
producer output nobody wrote for a test.

## 7. Corrected totals, by exact meaning

**The 40 documents are not in the tree.** They are 86,781,974 bytes,
`*.cdx.json` is gitignored repository-wide, and `README.md` section 3 records
that they were deliberately not committed. They are not present anywhere on this
machine either — a filesystem-wide search for the document names in
`sbom-document-index.json` returns nothing. Regenerating them was prohibited and
would not have reproduced them byte-for-byte in any case. The replay is
therefore against **the committed derived record**, and the table says which
number came from where.

| category | count | derived from |
|---|---|---|
| total findings | **8,507** | `licence/image-licence-policy-diagnostic.log`, 8,507 finding lines, header-declared counts verified line-for-line |
| missing policy assertions (all) | **8,292** | same |
| — of which CycloneDX `type: "file"` | **7,972** | same, split on the leading `/` of a file-component label |
| — of which package components | **320** | same |
| conflicting assertions | **196** | same |
| legal-review-required identifiers | **19** | same, on 5 distinct identifiers |
| substantive findings | **535** | 320 + 196 + 19 |
| independently licensed image files | **0 measured** | every one of the 7,972 was licence-unknown, so none carried a licence assertion |
| unresolved image files | **not derivable from the committed record** | see §8 |

Reconciliation back to every input component:

```text
8,527 inventory components = 7,972 file + 555 non-file
    555 = 535 real packages + 20 pkg:oci image-root self-references
    535 = 300 no assertion + 196 conflicting + 19 review + 20 clean
    320 = 300 + the 20 image roots
8,507 findings = 7,972 + 320 + 196 + 19
```

The apparent 300-vs-320 disagreement between
`licence/identifier-reconciliation.json` and `rerun-against-fixed-consumer.md`
is **not an error**: the reconciliation counts real packages and the finding
total also counts the 20 image-root components. Both are right about different
denominators, and neither said so.

The root-cause-grouped backlog for the 535 is
`docs/licensing/image-licence-backlog-2026-08-28.md`.

## 8. The gap this record does not close, stated as a gap

Splitting the 7,972 into the four classes **requires the 20 CycloneDX documents
and their 20 SPDX companions**, because the split is a function of the
`dependencies` graphs and the `CONTAINS` / `evident-by` relationships those
documents carry. The committed record holds finding *labels*, not relationships.
Producing that split from anything else would be a guess with a number attached.

Two bounds are honest, and neither is the answer: every one of the 7,972 was
licence-unknown, so the independently-licensed-by-licence count is **0** for
this cohort; and on the one real syft document available in-tree, **224 of 224**
file entries were mechanically attributable and **0** were unresolved.

**Closure condition** — one run of

```bash
scripts/license/license-inventory.sh --sbom-dir <the 40 documents> --out inv.json
python3 -c "import json;print(json.load(open('inv.json'))['image_files']['by_class_observations'])"
```

with the resulting `image_files` block committed here. It builds nothing and
dispatches nothing.

## 9. Validation, including what was INCONCLUSIVE

| check | result |
|---|---|
| `tests/license/test_licence_file_components.sh` | 28 assertions, 0 failures; 3× deterministic; clean under `bash -T` |
| `tests/license/test_license_gate.sh` | PASS |
| `tests/license/test_repository_material_gate.sh` | 64 proven, 4 pinned gaps, PASS |
| `scripts/license/license-inventory.sh --self-test` | OK |
| `scripts/license/assert-repository-material.sh --self-test` | OK |
| `shellcheck -S warning` | clean |
| Linux (`bash 5.2`, `python:3.12-slim`) | the licence suites pass |
| Linux, git-dependent suites | **INCONCLUSIVE, not passing** — see below |

**The container cross-check for the git-dependent suites is INCONCLUSIVE, and is
recorded as inconclusive rather than as a pass.** The repository-material gate
establishes the tracked file set with `git ls-files`. Inside the container that
call cannot succeed — `python:3.12-slim` carries no `git` binary, and where one
is installed the checkout's git metadata still lies outside the bind mount — so
the gate refuses:

```text
REFUSE [RM-TREE-UNREADABLE]: `git ls-files` failed in /w. The set of files to
scan cannot be established, and scanning a guessed set would report clean about
whatever it happened to miss.
```

That refusal is the gate behaving correctly: it fails closed rather than
reporting a clean verdict over a file set it could not establish. **No
workaround was added.** Every available workaround — installing git and marking
the mount safe, or letting the gate fall back to a filesystem walk — weakens
exactly the tracked-tree verification the refusal is protecting. Required CI
runs on a normal clone and is the authority. The suites that do not depend on
git (`license-inventory` and `assert-license-policy` self-tests,
`test_licence_file_components.sh`, `test_license_gate.sh`) all pass on Linux
bash 5.2.37.

## 10. What this change does NOT do

* It does not change any allow/deny/review decision.
  `policies/license-policy.yaml` is untouched.
* It does not resolve, waive or suppress any of the 535 substantive findings,
  and marks none of them reviewed.
* It does not fix the conflict-normalisation defect that produces 196 of them.
  Fixing it would remove 192 findings, and removing findings needs a reviewed
  decision of its own, not a parser change made in passing.
* It does not close pinned gap (b). The composed gate still refuses.
* It does not close issue #120. #120 carries an unmet **engineering** criterion —
  *"Produce third-party notices and preserve corresponding license
  texts/source-offer obligations"* — and `scripts/license/generate-notice.sh` is
  referenced by no workflow, with no NOTICE existing for image components. #120
  stays open on that criterion regardless of any finding total here.
