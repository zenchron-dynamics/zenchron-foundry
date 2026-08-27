# Repository material and the licence gate's blind spot

**Issue:** [#120](https://github.com/zenchron-dynamics/zenchron-foundry/issues/120) ·
**Inventory:** [`policies/repository-material.yaml`](../../policies/repository-material.yaml) ·
**Gate:** [`scripts/license/assert-repository-material.sh`](../../scripts/license/assert-repository-material.sh)

## The defect

`scripts/license/assert-license-policy.sh` consumes **image SBOMs**. An SBOM of a
built image enumerates what is in that image and nothing else. Material that
lives in the repository but in no image is therefore invisible to it **by
construction** — not by oversight, not by a missing rule.

That hole holds copied configuration, seccomp profiles, scripts, workflow
fragments, documentation excerpts, fixtures, vendored schemas, patches and
generated or transformed third-party files.

It is not hypothetical. `security/seccomp/zenchron-default.json` is 832 lines
copied verbatim from Moby v27.3.1. It sat unattributed under a first-party
filename, `security/README.md` described it accurately as an upstream copy, and
**no control in this repository could see it**.

The first attempt at a fix was a hardcoded two-element array inside one test.
That does not compose with anything, and it had already gone stale: it named two
files while five carry an obligation today.

## One inventory

`policies/repository-material.yaml` is the single canonical record. Every entry
carries, and the schema requires:

| field | what it answers |
| --- | --- |
| `path` | repository path |
| `material_identity` | what the material actually is |
| `upstream.project` / `.source_url` / `.revision` / `.path` | which upstream, where, at what revision, from which path |
| `acquisition.method` | verbatim copy, derived work, excerpt, generated, patch, transformed |
| `local_modifications.modified` / `.changes` | what was changed here |
| `licence.declared_spdx` / `.determination` | the licence, and how it was established |
| `obligations.required_license_text` | where the licence text is carried |
| `obligations.required_notice` / `.local_notice` | the upstream NOTICE, and any local attribution |
| `obligations.copyright_attribution` | the copyright line to retain |
| `obligations.source_offer` / `.reciprocity` | source-offer and reciprocity exposure |
| `hashes.repository_content_sha256` / `.upstream_content_sha256` | immutable content identity |
| `review.status` / `.reviewed_by` / `.reviewed_on` / `.tracked_issue` | who looked, when, under what ticket |

`dispositions` records tracked files that **trip a discovery signal and are not
material** — each with a classification, a reason and a reviewer. It is not an
exception list: the gate refuses anything that appears in neither array, and the
gate itself contains no path-specific logic. A scanner that hardcodes which of
its own hits to ignore is a scanner whose findings nobody can audit.

## The gate composes four sources

Each source alone reports clean about the thing it cannot see. The composition is
the control.

1. **image SBOM licence evidence** — `--image-inventory`, a
   `foundry.license-inventory/v1` document
2. **the repository-material inventory** — `policies/repository-material.yaml`
3. **required licence texts and notices** — the files named by source 2
4. **project-level outbound licence state** — `LICENSE` plus
   `policies/license-policy.yaml`

Source 4 is not decoration. Every per-file obligation is **derived** from that
policy's `obligations` list for the declared SPDX identifier. The gate contains
no licence judgement of its own and cannot approve anything the policy does not
classify as `allowed`.

## Every refusal, and its diagnostic

| code | fires when |
| --- | --- |
| `RM-LICENCE-TEXT-MISSING` | an inventoried copied file's licence text is absent or empty |
| `RM-NOTICE-MISSING` | a required upstream NOTICE is absent or empty |
| `RM-HASH-DRIFT` | the material changed after the review that recorded its licence facts |
| `RM-LICENCE-UNRECOGNISED` | no SPDX id, or one the policy does not classify as `allowed` |
| `RM-UNINVENTORIED-MATERIAL` | a discovery signal fired on a file in neither inventory array |
| `RM-OUTBOUND-TERMS-PLACEHOLDER` | placeholder terms were presented as final |
| `RM-REPOSITORY-EVIDENCE-ABSENT` | image evidence supplied while no repository evidence is reviewed |
| `RM-ENTRY-UNREVIEWED` | an entry nobody has recorded a review for |
| `RM-COPYRIGHT-MISSING` | `retain-copyright-notice` is unmet |
| `RM-CHANGES-NOT-STATED` | `state-changes` is unmet, or the method and the changes contradict each other |
| `RM-MATERIAL-PATH-MISSING` | an inventoried path is not a tracked file |
| `RM-BASELINE-UNVERIFIABLE` | the reviewed baseline is missing or was edited without review |
| `RM-BASELINE-STALE` | tracked paths sit outside the reviewed baseline (release scope) |
| `RM-INVENTORY-UNREADABLE` / `RM-INVENTORY-MALFORMED` | an input is absent or is not what it claims to be |
| `RM-TREE-UNREADABLE` | the tracked file set cannot be established |

`RM-OUTBOUND-TERMS-PLACEHOLDER` deserves a note. `LICENSE` says of itself, in its
last paragraph, that it is a placeholder to be replaced before publication, and
`policies/license-policy.yaml` records `publication.decision: undetermined`. The
gate reads both as facts. It refuses only when a caller **asserts final terms**
(`--require-final-outbound-terms`); on every other run it reports `NOT FINAL`
loudly. Choosing the outbound licence is [#98](https://github.com/zenchron-dynamics/zenchron-foundry/issues/98),
it belongs to the owner and counsel, and nothing here touches it.

## How discovery works, and what it cannot prove

**Read this before trusting a green run.**

Deciding that an arbitrary file was copied from somewhere is **undecidable in
general**. There is no scan that establishes a file is first-party. So the gate
does not claim universal discovery, and neither does this document.

### Tier 1 — refusing signals, chosen for precision

A hit means a human must account for the file. It is refused
(`RM-UNINVENTORIED-MATERIAL`) until it is inventoried or disposed of.

| signal | pattern |
| --- | --- |
| `path-third-party` | the path is under `third-party/`, `third_party/`, `vendor/`, `external/`, `contrib/`, `patches/` or `upstream/` |
| `embedded-licence-grant` | the body contains the operative words of a licence grant — `Permission is hereby granted`, `Licensed under the Apache License`, `Redistribution and use in source and binary forms`, `GNU GENERAL PUBLIC LICENSE`, `Mozilla Public License Version`, `SPDX-License-Identifier:` |
| `foreign-copyright-header` | the first 40 lines carry a copyright **statement** — the word followed within 40 characters by `(c)`, `©` or a four-digit year — that does not name Zenchron |

The copyright signal deliberately requires a statement rather than the word, so
that `retain-copyright-notice` in a policy obligation list is not read as an
attribution.

### Tier 2 — advisory only, and it refuses nothing

Prose provenance phrases (`copied verbatim`, `pinned copy of`, `vendored from`,
`derived from the moby…`) are reported under an `ADVISORY` label. They are
ordinary English, they match roughly twenty files in this repository, and
treating them as a control would be a check that is literally true and
substantively false. They are a reading aid, not a gate.

### What the signals miss, demonstrated on this repository

Two of the five inventoried materials —
`installer-gd-branch.txt` and `installer-gd-configure.txt` — are verbatim MIT
source from `mlocati/docker-php-extension-installer`. They carry **no copyright
line, no licence reference, no upstream URL and no distinctive filename**. No
signal fires on either. They were found by a human reading the directory
file-by-file, and `tests/license/test_repository_material_gate.sh` pins that fact
as an explicit gap rather than describing the scanner as complete.

**Absence of a signal is not evidence that a file is first-party.**

### The non-heuristic half: the reviewed baseline

`policies/repository-material-baseline.txt` is the exact set of tracked paths a
human reviewed, pinned by sha256 in the inventory. It is the answer to "what
about material that trips no signal": everything inside the baseline was looked
at, and anything outside it is unreviewed.

Unreviewed is a **refusal** (`RM-BASELINE-STALE`) at release scope
(`--require-reviewed-baseline`), and a **reported drift** at PR scope — never a
silent pass. The split is deliberate and it is a trade-off, recorded as a pinned
gap: enforcing the baseline on every PR would turn every open PR red the moment
anyone added a file. Reporting it at PR scope keeps the fact visible without
making the repository unusable, and the release path still refuses.

Regenerate it **only after actually reviewing the delta**:

```sh
git ls-files | LC_ALL=C sort > policies/repository-material-baseline.txt
shasum -a 256 policies/repository-material-baseline.txt
# then update baseline.path_list_sha256, path_count and reviewed_at_revision
```

## Adding material

1. Put the file in the tree.
2. Add an entry to `policies/repository-material.yaml` with every field.
3. Carry the licence text, and the upstream NOTICE if the licence requires one,
   under `third-party/<project>-<revision>/`.
4. Record `hashes.repository_content_sha256` with `shasum -a 256 <path>`.
5. Regenerate the baseline.

If the file is not third-party material but trips a signal, add a `dispositions`
entry with a reason and a reviewer. Do not silence the signal in the scanner.

## What this does not do

- It does **not** choose an outbound licence, replace the `LICENSE` placeholder,
  or assert ownership or copyright subsistence in anything.
- It does **not** establish a right to distribute. It accounts for **inbound**
  obligations that attach today, to material already in this tree, regardless of
  how the repository is eventually licensed.
- It does **not** prove that no unmarked copied material exists. Nothing can.
