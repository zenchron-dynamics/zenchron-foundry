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
