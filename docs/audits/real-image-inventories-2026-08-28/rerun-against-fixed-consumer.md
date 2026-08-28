# Re-run against the fixed consumer

**Date:** 2026-08-28. **Same 40 documents, same 20 children, same frozen
scanner, nothing regenerated.** The only thing that changed is the consumer:
`scripts/license/assert-image-sbom-licences.sh` now resolves an SPDX subject
from the `DESCRIBES` relationship as well as from `documentDescribes`
(`fix/sbom-subject-describes`).

`README.md` records the first run, whose verdict was REFUSED for a plumbing
reason. This file records the second. **The refusal has moved from plumbing to
substance**, which is the outcome that was worth measuring.

## Result

| gate | first run | re-run |
|---|---|---|
| image binding | **rc=1** — 20 × `IL-SBOM-SUBJECT-ABSENT` | **rc=0 — 20/20 children bound to staged digests at `7061caaf…`** |
| image licence policy | rc=1 — no `image_binding` to read | **rc=1 — 8,507 findings across 8,527 components** |
| repository half, composed | rc=1 — `RM-INVENTORY-UNREADABLE` | **rc=0 — 5 reviewed materials, 0 findings** |
| composed licence authorization | `REFUSED`, 0/0 bound | **`REFUSED`, 20/20 bound** |
| canonical authorization | `AR-LICENCE-INCOMPLETE` | **`AR-LICENCE-REFUSED`** |

The new refusal code is `AR-LICENCE-REFUSED`, not `AR-LICENCE-INCOMPLETE`: the
matrix is no longer partial, so the validator no longer refuses for
incompleteness. It refuses because the image half's *policy* verdict is a
refusal, and both halves are required.

Nothing was adjusted to reach a pass. The image policy gate refuses on measured
licence content, and that content is reported below rather than changed.

## What the binding now proves

`licence/rerun-image-binding.json` carries the `image_binding` block the gate
stamped into the inventory:

```json
"children_expected": 20, "children_bound": 20, "all_children_bound": true,
"matrix_images": 10, "platforms": ["linux/amd64", "linux/arm64"],
"source_revision": "7061caafb3ea09bd5b2342a1daf022151b33f822",
"sbom_schemas": ["SPDX-2.3"], "producers": ["scripts/generate-sbom.sh"],
"execution_modes": ["native", "qemu"]
```

Twenty children, each bound on all five facts the gate requires — image name and
version, platform, immutable digest, source revision, content hash — with the
document's own subject equal to that child's platform manifest digest. The
emulation disclosure survives the licence path: `execution_modes` records both
`native` and `qemu` rather than flattening them.

Bound inventory sha256:
`eab83ae9a4e9a98f0179bc6d00826a0d70d0336be03059c090611c7ef8052721`.

## Why the policy half still refuses — 8,507 findings, split by cause

| finding class | total | from CycloneDX `type: "file"` entries | from real package components |
|---|---|---|---|
| no licence could be established | 8,292 | **7,972** | 320 |
| sources disagree about the licence | 196 | 0 | 196 |
| licence needs legal review and has not had it | 19 | 0 | 19 |
| **total** | **8,507** | **7,972** | **535** |

**7,972 of the 8,507 are the second defect this audit reported** and which is
still unfixed: `scripts/license/license-inventory.sh` folds CycloneDX components
of `type: "file"` into the inventory as though they were software components.
`policies/syft.yaml` sets `file.metadata.selection: "owned-by-package"`, so syft
emits 70,028 file components across the cohort; deduplicated by (name, version)
they become 7,972 inventory entries, every one of them licence-unknown because a
file path does not have a licence.

**535 findings survive that filter, and they are real**: 320 package components
with no licence assertion, 196 whose SBOMs disagree, and 19 whose licence needs
legal review and has not had it — `busybox`, `apk-tools`, `libapk`,
`alpine-baselayout`, `curl`/`libcurl`, the krb5 libraries, `libmpc3`, `libmpfr6`,
`libseccomp2`, `libzip4`, `scanelf`, `ssl_client`.

So fixing the file-component defect would **not** turn this run green. It would
reduce a 8,507-finding refusal to a 535-finding one, and those 535 are the
licence backlog issue #98 exists for. That is the honest reading and no part of
it is a reason to edit `policies/license-policy.yaml`, which this branch does
not touch.

## Pinned gap (b)

Still **not closed**, and now for a different and better-understood reason.

The composed gate has now genuinely executed over real image package
inventories: 20/20 children bound, the repository half composed clean, the
canonical validator consumed the verdict. That half of the gap is met, and met
buildlessly with no dispatch. What is not met is a **passing** composed verdict,
because the image licence policy refuses on 535 real findings after the file-
entry noise is set aside.

Gap (b) is therefore no longer "unmeasured". It is measured, it binds, and what
stands between it and closure is a licence backlog with a named owner — not a
missing run and not a gate that cannot read its own producer's output.

## Files

| file | what it is |
|---|---|
| `licence/rerun-image-sbom-binding-gate.log` | the binding gate's own output: 20/20 bound |
| `licence/rerun-image-binding.json` | the `image_binding` block the gate stamped, plus inventory counts |
| `licence/rerun-image-licence-policy.log` | the policy refusal: header and the 19 legal-review findings |
| `licence/rerun-repository-material-composed.log` | the composed repository half, rc=0 |
| `licence/rerun-composed-authorization-validation.log` | the composed record and `AR-LICENCE-REFUSED` |
