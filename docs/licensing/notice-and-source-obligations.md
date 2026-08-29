# Distribution notices and source obligations

This is the engineering half of issue #120's last criterion:

> Produce third-party notices and preserve corresponding license texts/source-offer obligations.

It is four separate things, and answering them as one is how the criterion sat
open while a licence gate shipped and passed:

| # | question | answered by | state |
|---|---|---|---|
| 1 | is every component's licence accounted for? | the licence gate (`assert-license-policy.sh`, `assert-repository-material.sh`) | shipped; **refuses** on measured content |
| 2 | are the corresponding licence **texts** carried? | `third-party/licence-texts/` + its `PROVENANCE.yaml` | shipped; 56 identifiers |
| 3 | is a **notice** produced, bound to a candidate? | `scripts/license/generate-notice-bundle.py` | shipped; **refuses** |
| 4 | are the **source** obligations discharged? | `policies/source-obligations.yaml` + the manifest | facts collected; **unresolved by design** |

**A green verdict is not the goal.** The goal is a fail-closed system whose
remaining refusals name their owner, and whose owner is engineering or a rights
holder rather than "somebody".

---

## 1. The producer

```text
image SBOM inventory (identity-bound, 20/20 children)  ─┐
post-build authorization record (matrix, digests, rev) ─┤
policies/repository-material.yaml                      ─┤
policies/license-policy.yaml                           ─┼─> generate-notice-bundle.py
third-party/licence-texts/PROVENANCE.yaml              ─┤
policies/upstream-licence-attestations.yaml            ─┤
policies/source-obligations.yaml                       ─┘
                                                          │
                     ┌────────────────────────────────────┘
                     ▼
   authorization/notice/
     notice-manifest.json             the verdict record, schema-validated
     THIRD-PARTY-NOTICES.txt          human-readable, candidate-scoped
     licence-text-references.json     immutable references to the carried texts
     source-obligation-manifest.json  162 components, source-resolved
     unresolved-obligations.json      every finding, with its code
     SHA256SUMS                       covering all of the above
```

Every input is **required**. An absent input is `NB-INPUT-ABSENT`, never a skip.

### It is scoped to a candidate, never to the project

The bundle is written under a release-evidence path and **never** as a root
`NOTICE`. A root `NOTICE` sitting beside a `LICENSE` that tells the reader to
replace it before publication would be read as Zenchron Foundry's own outbound
terms, and those are undetermined (#98). The bundle says what the *candidate
images* carry. It says nothing about what Foundry grants.

### It is deterministic

The same ordered inputs produce byte-identical output. There is no generation
timestamp, no hostname and no run id anywhere in the manifest, and every
collection is sorted. Two runs into different directories are compared byte for
byte in the suite, and a separate assertion walks every key of the manifest to
prove no field is a clock.

---

## 2. Four evidence sources, never interchangeable

| source | what it means | may it FILL a silence? | may it OVERRIDE an observation? |
|---|---|---|---|
| `scanner-observed` | the SBOM asserted it | — | — |
| `upstream-attested` | the upstream project states it at a pinned revision | **yes** | **no** — `NB-ATTESTATION-CONFLICT` |
| `policy-asserted` | `license-policy.yaml` classifies the identifier | no | no |
| `legally-approved` | a rights holder decided | **does not exist yet (#98)** | — |

The manifest records which source decided each component, and counts them, so a
reader can see at a glance that `legally-approved` is 0.

### The PHP-3.01 case, which is the reason this exists

`policies/license-policy.yaml` classifies `PHP-3.01` as
`legal-review-required`. Across the 20 accepted production children `PHP-3.01`
is measured **absent**. PHP is in four of the ten image families. The policy row
is right and the scanner is blind: syft catalogues the PHP binary and its
bundled extensions as `pkg:generic` with `NOASSERTION`, so the identifier never
reaches the inventory and the row never fires. 46 findings.

The wrong fix is to edit an SBOM so it says `PHP-3.01`. A measured document is
evidence *because* nobody edited it.

`policies/upstream-licence-attestations.yaml` binds 46 exact
`(component, version)` pairs to `php/php-src` at four pinned tags. Each records
the tag, the commit, the upstream path of the `LICENSE` blob and its sha256
(`b42e4df5…`, byte-identical across all four tags), and each of the ten bundled
extensions was verified to have `ext/<name>/config.m4` and **no**
`ext/<name>/LICENSE` at every tag — so the repository `LICENSE` is what covers
that path.

Those 46 components moved from *"no disposition from any source"* to
*"upstream-attested `PHP-3.01`, and the policy says counsel must look"*. That is
progress in **evidence completeness** and nothing else. The policy state is
unchanged.

### No widening

An attestation reaches a component only on an **exact** `(name, version)` match,
and only where its declared families, versions and platforms cover the candidate
cohort. `php-8.3.32` says nothing about `php-8.4.24`. Sabotaged three ways in the
suite: version widening (0 components attested), platform widening
(`NB-ATTESTATION-SCOPE`), and no scope at all (*"an attestation that would reach
anything"*).

---

## 3. The carried licence texts

`third-party/licence-texts/` holds the canonical text of **56** identifiers —
every one the licence policy classifies, every one the production cohort
resolved, plus `PHP-3.01`. Copied verbatim from `spdx/license-list-data` at tag
`v3.28.0` (commit `c4a7237e`), one HTTPS GET each, each recorded in
`PROVENANCE.yaml` with its upstream path, byte count and sha256.

**Carrying a text discharges `retain-license-text` and nothing else.** In
particular it does not discharge the corresponding-source obligation that
GPL-2.0, GPL-3.0, LGPL-2.0, LGPL-2.1 and LGPL-3.0 each impose.

The store is declared once in `policies/repository-material.yaml` under
`carried_licence_texts`. It is deliberately **not** `materials` (nothing in this
repository *incorporates* the text of GPL-2.0 into a first-party file) and
deliberately not `dispositions` (a disposition asserts *"this is not copied
material"*, and a licence text plainly is). Four codes refuse an untracked,
absent, empty or byte-drifted text.

---

## 3a. The licence material inside the images (#120 action N1)

Section 3 carries the canonical text of an **identifier** — `GPL-2.0` as SPDX
publishes it. That is a different artifact from `busybox`'s own copyright
statement, or from the Debian `copyright` file recording who holds copyright in
*this* build of *this* package. `retain-copyright-notice` is an obligation about
the second.

`third-party/image-licence-materials/` carries **137 distinct files, 1.4 MB**,
read out of the 20 accepted production images by immutable digest and stored
content-addressed, so a file shared by many packages across eighteen children
exists once and every consumer is bound to its hash.

### Buildless, and verified three ways per child

Registry HTTP API only: no image built, no Dockerfile run, no package manager
run, no mutable tag read, no SBOM regenerated, no container runtime involved.
Before a single byte is attributed to a child:

* the **manifest bytes are re-hashed** and must equal the accepted digest — the
  registry's own claim is not the check;
* the **config blob's own `os`/`architecture`** must equal the platform the
  accepted run recorded;
* every **layer blob** must hash to the digest its manifest names.

Layers are read with **overlayfs whiteout semantics** applied. Reporting a
copyright file that a later layer deleted would be reporting a file that is not
in the image.

### `/usr/share/doc/<pkg>/copyright` is not universal coverage

| ecosystem | what the image actually ships |
|---|---|
| Debian | one `copyright` per binary package — sometimes a symlink to a sibling's file, sometimes a symlinked *directory*, sometimes **chained** through two, frequently deferring to `/usr/share/common-licenses/<NAME>` |
| Alpine | **nothing.** apk strips documentation; the database's `L:` field is a licence *identifier*, not a notice and not a text |
| Go | modules compile into a binary; a runtime image has no vendored licence tree, so no path was ever expected |
| PHP | the interpreter and `docker-php-ext-install` extensions leave nothing behind; PEAR ships under `/usr/local/lib/php/doc/` |

### Every implicated component gets exactly one class

| class | components | meaning |
|---|---|---|
| `extracted` | **191** | material present and captured, directly or through a symlink chain resolved inside that same image |
| `ambiguous` | **1** | present but not self-sufficient |
| `absent` | **22** | package-managed, and the ecosystem ships no such material; no path was expected |
| `path-expected-unavailable` | **0** | the convention applies and the file is missing |
| `non-package-managed` | **320** | no package manager in the image governs it |
| `legal-review-required` | **1** | what is owed cannot be decided mechanically |

```text
implicated = extracted + ambiguous + absent + non-package-managed + legal-review-required
535 = 191 + 1 + 22 + 320 + 1
```

The tool refuses if they do not reconcile. `absent` is the union of the two
absence classes and both sub-counts are reported, because "this ecosystem ships
nothing" and "the file that should be here is missing" are different findings
with different owners.

The two residual findings are real and are left refusing rather than papered
over: **`gzip`** defers to `/usr/share/common-licenses/GFDL-3`, which Debian does
not ship (the image carries `GFDL`, `GFDL-1.2`, `GFDL-1.3`) — an upstream defect
in the package's own copyright file; and **`../@UNKNOWN`** is a nameless
cataloguer artifact whose very existence as a distributed component cannot be
decided from the image.

### The mapping is checked, not trusted

A recorded symlink chain must start at the package's own documentation path,
each hop must link to the next, and the last hop must be the file being claimed.
A package mapped to another package's copyright file refuses; so does a
redirected symlink, a carried file whose bytes changed, material from a child the
candidate does not stage, a partial 19-of-20 cohort and an accounting taken at
another revision.

### An attestation is not a file the image carries

Where a component ships no copyright material, an upstream attestation is
**recorded beside the gap and does not close it**
(`NB-ATTESTATION-NOT-IN-IMAGE`). Letting it close the gap takes an explicit
policy decision — `defaults.may_substitute_for_in_image_material` in
`policies/upstream-licence-attestations.yaml`, **shipped `false`** — because what
evidence class is acceptable is #98's call, not an engineering one. The suite
proves both directions, so the control is real and its default is the closed one.

---

## 4. Source obligations — facts, not conclusions

`policies/source-obligations.yaml` records **162** components in the accepted
cohort that carry a reciprocal identifier:

* **143 Debian** binaries, each resolved to its exact source package and version
  through `snapshot.debian.org`, which serves every version ever published and
  is therefore immutable. 143 of 143 resolved, no guesses.
* **19 Alpine** binaries, resolved through the `aports` release tag `v3.23.5`
  (commit `1fa9ca1a`), matched on `pkgver`-`pkgrel` across 10 origins. The
  mutable `dl-cdn` `APKINDEX` was used only to *discover* candidate origins and
  is not cited as an authority — it had already moved past two of these versions.
* **28** of them carry an `LGPL-2.0` identifier.

> **Count correction.** An earlier audit note said `LGPL-2.0` sat on *"25
> distinct core Debian packages"*. The measurement is **28** `(package,
> version)` pairs over 27 distinct binary names — `liblzma5` appears at two
> versions. The earlier figure was prose; it is corrected here, not carried
> forward.

Every component is `source_obligation: unresolved`, and **there is no field an
engineer can set to change that**. It becomes `satisfied` only when a rights
holder approves a delivery mechanism, and every mechanism carries a duration or
availability commitment that only a rights holder can make:

| mechanism | executable today? | blocked on |
|---|---|---|
| accompany with source | no | no source artifact is built, published or retained — **engineering** work, not a legal decision |
| written offer | no | a duration commitment. GPL-2.0 §3(b) attaches three years; GPL-3.0 §6(b) ties it to the support period |
| upstream URL pass-through | no | **sufficiency**. A URL to somebody else's archive is not on its face a conforming source offer, and nothing here claims it is |
| no distribution | no | #98 |

What is **not** determined, and is recorded as not determined rather than
assumed: linkage. Proving dynamic versus static linkage requires reading the
shipped binaries, the 40 SBOM documents for this cohort are 86 MB and are not
committed, and this work was required to rebuild nothing. The file records the
convention, labels it a convention, and gives the exact command that would turn
it into a measurement.

Five legal questions are recorded (`SO-Q1`…`SO-Q5`), every one owned by #98.

---

## 5. The composition

```text
licence evidence ──┐
notice bundle    ──┼──> validate-authorization-record.sh ──> authorization
publication auth ──┘
```

| licence evidence | notice bundle | publication authority | result |
|---|---|---|---|
| PASS | PASS | present | eligible for the next independent release control |
| PASS | REFUSE or missing | any | **REFUSE** |
| REFUSE or missing | PASS | any | **REFUSE** |
| REFUSE or missing | REFUSE or missing | any | **REFUSE** |
| PASS | PASS | missing | **REFUSE** (`AR-PUBLICATION-AUTHORITY-MISSING`) |

**"Eligible" is not published, promoted, signed or released.** It means the
candidate may be presented to the next control, and the record still carries
`public_exposure_authorized: false`.

The three axes are deliberately kept apart inside the bundle. `verdict` is about
the notice and source material; `publication_authority_present` is separate.
Folding authority into the verdict would make the independent publication
refusal unreachable — every bundle would already be a draft for some other
reason, and the code would never fire.

### Consequence, stated plainly

While `publication.decision` is `undetermined` in `policies/license-policy.yaml`,
`stage-and-authorize.yml`'s authorize job **cannot go green**, and the licence
half refuses independently on 535 substantive findings. That is the fail-closed
behaviour, not a defect in it. One owner action in that file changes it, and no
engineering act can.

---

## 6. What refuses, and who owns it

| code | owner |
|---|---|
| `NB-INPUT-*`, `NB-BINDING-*`, `NB-*-MISMATCH`, `NB-MATRIX-MISMATCH` | engineering — the evidence did not arrive or does not describe this candidate |
| `NB-DISPOSITION-MISSING` | engineering — evidence completeness (a cataloguer or an attestation) |
| `NB-CONFLICT-UNRESOLVED` | engineering — licence-expression normalisation |
| `NB-FILE-*`, `NB-ATTRIBUTION-UNSUPPORTED` | engineering — the four-way file accounting |
| `NB-LICENCE-TEXT-*`, `NB-NOTICE-*` | engineering — carry the artifact |
| `NB-ATTESTATION-*` | engineering — scope or acquire the attestation |
| `NB-SOURCE-OBLIGATION-UNRESOLVED` | **#98** — approve a mechanism and commit to a duration |
| `NB-LEGAL-REVIEW-REQUIRED` | **#98** — counsel |
| `NB-PUBLICATION-AUTHORITY-MISSING` | **#98** — the rights holder |

The full owner partition of the 535 substantive licence findings is in
`docs/licensing/image-licence-backlog-2026-08-28.md` §1a.

---

## 7. What none of this does

It does not select an outbound licence, replace the root `LICENSE`, change
repository or package visibility, publish, promote, sign, release, tag, rebuild
an image, dispatch acceptance, or touch the vulnerability ledger. It does not
mark any finding resolved and it reduces no count by redefining evidence away.

Verified by assertion, not by assurance: the suite re-reads
`policies/license-policy.yaml` at the end of every run and asserts
`publication.decision` is still `undetermined`, `denied` and `exceptions` are
still empty, `default_state` is still `legal-review-required`, the root `LICENSE`
still tells the reader to replace it, and no root `NOTICE` exists.
