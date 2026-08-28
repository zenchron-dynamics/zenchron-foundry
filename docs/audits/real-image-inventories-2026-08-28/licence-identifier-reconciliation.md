# Licence identifiers: measured against policy

Measured from the 40 real SBOMs of the 20 accepted production children
(section 2 of `README.md` for the scanner identity). Compared against the
17-entry `legal-review-required` table in `policies/license-policy.yaml`.

**No policy file was edited.** A scanner disagreeing with policy is a finding,
not an instruction, and every discrepancy below is reported rather than
reconciled away. The machine-readable form is `licence/identifier-reconciliation.json`.

## How "resolved" was decided

Not by a hand-written list of spellings that look vague — that would be this
audit inventing a judgement. The **scanner's own** resolution signal decides it:

| signal | meaning |
|---|---|
| CycloneDX `licenses[].license.id` | syft mapped it onto the SPDX list |
| CycloneDX `licenses[].license.name` | syft could **not** map it; free text |
| CycloneDX `licenses[].expression` | an SPDX expression, decomposed into its identifiers |
| SPDX `LicenseRef-*`, declared in `hasExtractedLicensingInfos` | syft's own marker for "not on the SPDX list" |

So `GPL` and `LicenseRef-GPL` are unresolved because syft says so, and
`GPL-2.0-only` is resolved because syft says so.

## The four-way classification

| class | count |
|---|---|
| **measured present** (policy-listed, and the images carry it) | **12** of 17 |
| **policy-listed but absent** | **5** of 17 |
| **measured but missing from policy** (SPDX-resolved identifiers policy names in no state) | **34** |
| **ambiguous or scanner-unresolved** | **263** |

Measurement base: 40 documents, 535 package components, 7,972 file components,
300 package components carrying no licence assertion at all.

### measured present — 12

`Artistic-2.0`, `BSD-4-Clause`, `GPL-2.0-only`, `GPL-2.0-or-later`,
`GPL-3.0-only`, `GPL-3.0-or-later`, `LGPL-2.1-only`, `LGPL-2.1-or-later`,
`LGPL-3.0-only`, `LGPL-3.0-or-later`, `MPL-2.0`, `OpenSSL`.

Per-identifier occurrence counts are in the JSON. Two worth naming:

* `MPL-2.0` — 22 occurrences, all `ca-certificates` / `ca-certificates-bundle`,
  declared as `(MPL-2.0 AND MIT)`. The policy's stated reason ("per-file
  reciprocity requires a source offer this project does not yet operate") is
  exactly on point for the Mozilla CA bundle.
* `OpenSSL` — 32 occurrences, all inside one long conjunction on `libsasl2-2`
  and `libsasl2-modules-db`. It is not asserted by any OpenSSL package itself;
  it arrives through Cyrus SASL's Debian copyright file.

### policy-listed but absent — 5

`AGPL-3.0-only`, `AGPL-3.0-or-later`, `CDDL-1.0`, `EPL-2.0`, `PHP-3.01`.

Four of those five are unsurprising: no component in any of the 20 children
asserts AGPL, CDDL or EPL, and a table entry that never fires is a table entry
doing its job cheaply. **`PHP-3.01` is not in that category and was investigated.**

> **Discrepancy 1 — `PHP-3.01` is absent from the measurement of four PHP image
> families, and the policy is right while the scanner is blind.**
>
> `php-cli` and `php-fpm` appear in every PHP child's SBOM as
> `pkg:generic` binary-cataloguer components with
> `licenseConcluded = NOASSERTION` and `licenseDeclared = NOASSERTION`. They are
> compiled binaries installed outside the distribution package manager, so
> nothing on the filesystem declares their licence and syft asserts nothing.
> `PHP-3.01` appears in **zero** components across all 40 documents.
>
> The correct reading is that the PHP interpreter, which is licensed PHP-3.01
> and is the reason four of the ten image families exist, is invisible to the
> licence inventory. **Do not remove `PHP-3.01` from the policy table to make
> the numbers agree.** The finding is the opposite: an identifier that must be
> measured is not being measured, and the licence inventory's coverage of
> first-party-installed binaries is the gap.

### measured but missing from policy — 34

These are SPDX-resolved identifiers the images actually carry that the policy
table names in **no** state. Under `default_state: legal-review-required` they
already resolve to legal review, so this is not an open gate — it is the list of
identifiers the table has never been shown. The highest-volume ones:

| identifier | occurrences |
|---|---|
| `LGPL-2.0-only` | 864 |
| `LGPL-2.0-or-later` | 680 |
| `X11` | 552 |
| `GPL-1.0-only` | 308 |
| `GFDL-1.3-only` | 252 |
| `BSD-4-Clause-UC` | 236 |
| `FSFULLR` | 236 |
| `GFDL-1.2-only` | 232 |
| `Beerware` | 220 |
| `Latex2e` | 216 |
| `Kazlib` | 180 |
| `GPL-1.0-or-later` | 132 |
| `FSFAP` | 104 |
| `curl` | 72 |
| `BSL-1.0` | 68 |

> **Discrepancy 2 — the LGPL row of the table has a hole at 2.0.**
>
> The table lists `LGPL-2.1-only`, `LGPL-2.1-or-later`, `LGPL-3.0-only` and
> `LGPL-3.0-or-later` with the reason "relinking and source-offer obligations
> depend on the image form shipped (#98)". It does not list `LGPL-2.0-only` or
> `LGPL-2.0-or-later`, which together are the **highest-volume** identifiers in
> the whole measurement (1,544 occurrences) and sit on 25 distinct core Debian
> packages including `bsdutils`, `diffutils`, `e2fsprogs`, `findutils`,
> `liblzma5`, `libmount1`, `libcom-err2`, `libext2fs2`, `libhogweed6`,
> `libkeyutils1`, `libisl23`. The same reasoning that put 2.1 and 3.0 in the
> table applies verbatim to 2.0.
>
> The default state means nothing ships on it silently. It is still a visible
> gap in a table that otherwise enumerates the LGPL family, and it is the
> owner's to close — this audit does not edit it.

#### Discrepancy 3 — `curl` appears as a licence identifier, 72 times

`curl` and `libcurl` on the Alpine children declare their licence as the string
`curl`. That *is* a real SPDX identifier (the curl licence), added to the SPDX
list after several of the entries in this table were written. It reads like
scanner noise and is not; it belongs in the table for the same reason `Zlib`
does.

#### Discrepancy 4 — `X11` and `Expat` are licences the table already classifies, under their pre-SPDX names

`X11` (552 occurrences) is SPDX-resolved and reaches this class; `Expat` (280)
is *not* SPDX-resolved and reaches the ambiguous class below. Both denote
licences the table already handles under other identifiers (`MIT` is `allowed`;
`X11` is a distinct SPDX identifier for a near-identical grant). An `allowed`
decision on `MIT` does not automatically extend to `X11`, and this audit will
not extend it.

### ambiguous or scanner-unresolved — 263

Identifiers the scanner itself could not map onto the SPDX list. They cannot be
classified against the policy table because they do not name a licence precisely
enough to classify. The highest-volume ones, each appearing in both its bare and
its `LicenseRef-` spelling:

| identifier | occurrences |
|---|---|
| `public-domain` / `LicenseRef-public-domain` | 576 each |
| `GPL` / `LicenseRef-GPL` | 466 each |
| `LGPL` / `LicenseRef-LGPL` | 394 each |
| `Expat` / `LicenseRef-Expat` | 280 each |
| `Artistic` / `LicenseRef-Artistic` | 198 each |
| `BSLA` / `LicenseRef-BSLA` | 144 each |
| `GFDL-NIV-1.3+` / `LicenseRef-GFDL-NIV-1.3-` | 76 each |
| `BSD-tcp_wrappers` / `LicenseRef-BSD-tcp-wrappers` | 72 each |

> **Discrepancy 5 — a bare `GPL` (466) or `LGPL` (394) is not classifiable, and
> must not be read as its `-only` or `-or-later` cousin.**
>
> Debian `copyright` files routinely say "GPL" without a version or a
> "or later" clause. `GPL-2.0-only` and `GPL-2.0-or-later` are materially
> different grants, and the policy table classifies them as separate rows for
> that reason. 466 occurrences of a bare `GPL` are 466 components whose actual
> grant is unestablished. The honest classification is *unresolved*, and the
> fix is upstream of policy: better cataloguing, not a policy row for the string
> `GPL`.

## Counts, restated

| | |
|---|---|
| policy `legal-review-required` entries | 17 |
| policy `allowed` entries | 10 |
| policy `denied` entries | 0 (empty by design) |
| measured present | 12 |
| policy-listed but absent | 5 |
| measured but missing from policy | 34 |
| ambiguous or scanner-unresolved | 263 |
| package components measured | 535 |
| package components with no licence assertion | 300 |
| file components the inventory wrongly counts as components | 7,972 |
