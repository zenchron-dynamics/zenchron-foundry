# Image licence backlog — the 20 accepted production children

**Cohort:** the 20 accepted children of the multi-architecture acceptance run ·
**Source revision:** `7061caafb3ea09bd5b2342a1daf022151b33f822` ·
**Evidence:** `docs/audits/real-image-inventories-2026-08-28/` ·
**Machine-readable form:** `image-licence-backlog-2026-08-28.json`

This is the licence backlog **grouped by root cause and licence expression** —
not one row per image and not one row per finding. It resolves nothing, waives
nothing, and marks nothing reviewed. `policies/license-policy.yaml` is untouched.

Reproduce it, byte for byte, from committed evidence:

```bash
python3 scripts/license/group-licence-backlog.py \
  --diagnostic docs/audits/real-image-inventories-2026-08-28/licence/image-licence-policy-diagnostic.log \
  --out docs/licensing/image-licence-backlog-2026-08-28.json
```

The tool refuses if its group totals do not reconcile to the input totals, so a
grouping cannot quietly lose a finding.

---

## 1. Totals, by exact meaning

| category | count |
|---|---|
| **total findings** | **8,507** |
| missing policy assertions | 8,292 |
| — of which CycloneDX `type: "file"` components | 7,972 |
| — of which package components | 320 |
| conflicting assertions | 196 |
| legal-review-required identifiers | 19 (on 5 distinct identifiers) |
| **substantive findings** | **535** |
| independently licensed image files | **0 measured** (no file component in the cohort carried a licence assertion) |
| unresolved image files | **not derivable from the committed record** — see §5 |

### Reconciliation back to every input component

```text
8,527 inventory components
  = 7,972 file components
  +   555 non-file components
             555 = 535 real packages + 20 pkg:oci image-root self-references
             535 = 300 no assertion + 196 conflicting + 19 review + 20 clean
             320 = 300 + the 20 image roots
8,507 findings = 7,972 + 320 + 196 + 19
  535 substantive = 320 + 196 + 19
```

The apparent 300-vs-320 disagreement between
`licence/identifier-reconciliation.json` (300) and
`rerun-against-fixed-consumer.md` (320) is **not an error**: the reconciliation
counts real packages, the finding total also counts the 20 image-root
components. Both are right about different denominators and neither said which.

## 2. The backlog

Owners. This repository has **one maintainer**, Bogdan Olteanu / Zenchron
Dynamics (`policies/governance-model.yaml`: `single_maintainer: true`). There is
**no appointed legal owner**; that absence is issue #98 and is itself a finding,
not a field to fill in with a plausible name.

| group | findings | type | licence expression | component | version | class | root cause |
|---|---|---|---|---|---|---|---|
| `G-FILE-NOASSERTION` | 7972 | no licence assertion | NOASSERTION (a file path has no licence of its own) | image file paths | n/a | technical | CycloneDX `type: "file"` components counted as software components |
| `G-NOASSERT-PKG-GOLANG-GO-MODULE` | 248 | no licence assertion | NOASSERTION | pkg:golang  Go module | various — see components | technical | the cataloguer that produced these components emits no licence field for them |
| `G-NOASSERT-PKG-GENERIC-PHP-BINARY-EXTENSION` | 46 | no licence assertion | NOASSERTION | pkg:generic  PHP binary/extension | various — see components | technical | the cataloguer that produced these components emits no licence field for them |
| `G-NOASSERT-PKG-OCI-IMAGE-ROOT` | 20 | no licence assertion | NOASSERTION | pkg:oci  image root | various — see components | technical | the cataloguer that produced these components emits no licence field for them |
| `G-NOASSERT-PKG-GENERIC-UNCLASSIFIED` | 3 | no licence assertion | NOASSERTION | pkg:generic  unclassified | various — see components | technical | the cataloguer that produced these components emits no licence field for them |
| `G-NOASSERT-PKG-GENERIC-DISTRO-IDENTITY` | 2 | no licence assertion | NOASSERTION | pkg:generic  distro identity | various — see components | technical | the cataloguer that produced these components emits no licence field for them |
| `G-NOASSERT-PKG-PEAR-PEAR-PECL` | 1 | no licence assertion | NOASSERTION | pkg:pear  PEAR/PECL | various — see components | technical | the cataloguer that produced these components emits no licence field for them |
| `G-CONFLICT-RC1` | 163 | sources disagree | see licence_expression_canonicalised (lowercased, LicenseRef- strip… | package components | various — see components | technical | RC1 SPDX expression vs CycloneDX enumeration of its members |
| `G-CONFLICT-RC2` | 24 | sources disagree | see licence_expression_canonicalised (lowercased, LicenseRef- strip… | package components | various — see components | technical | RC2 one identifier, two spellings |
| `G-CONFLICT-RC4` | 5 | sources disagree | see licence_expression_canonicalised (lowercased, LicenseRef- strip… | package components | various — see components | technical | RC4 licence text hash used as an identifier |
| `G-CONFLICT-RC3` | 4 | sources disagree | see licence_expression_canonicalised (lowercased, LicenseRef- strip… | package components | various — see components | technical | RC3 no source states the whole expression |
| `G-REVIEW-GPL-2-0-only` | 13 | legal review required | GPL-2.0-only | alpine-baselayout-data@3.7.2-r0, alpine-baselayout@3.7.2-… | ['1.20.1-2+deb12u5', '1.3.8-r2', '1.37.0 | legal | the policy classifies this identifier as legal-review-required and no review is  |
| `G-REVIEW-curl` | 2 | legal review required | curl | curl@8.19.0-r0, libcurl@8.19.0-r0 | ['8.19.0-r0'] | legal | the policy classifies this identifier as legal-review-required and no review is  |
| `G-REVIEW-LGPL-3-0-only` | 2 | legal review required | LGPL-3.0-only | libmpc3@1.3.1-1, libmpfr6@4.2.0-1 | ['1.3.1-1', '4.2.0-1'] | legal | the policy classifies this identifier as legal-review-required and no review is  |
| `G-REVIEW-LGPL-2-1-only` | 1 | legal review required | LGPL-2.1-only | libseccomp2@2.5.4-1+deb12u1 | ['2.5.4-1+deb12u1'] | legal | the policy classifies this identifier as legal-review-required and no review is  |
| `G-REVIEW-GPL-3-0-only` | 1 | legal review required | GPL-3.0-only | libzip4@1.7.3-1+b1 | ['1.7.3-1+b1'] | legal | the policy classifies this identifier as legal-review-required and no review is  |

Affected image families and platforms, per group, are in the JSON. They are
**derived from package-manager version syntax** (`-rN` = apk, `+debNuM`/`+bN`/
`+nmuN` = dpkg, `vX.Y.Z` = Go module, `8.x.y` = the PHP binary cataloguer),
cross-checked against the per-child package counts in
`sbom-document-index.json`. They are **not** a per-child package list: the 40
documents are 86 MB and are not committed, so a per-child attribution is not
derivable from the committed record and is not guessed here. Every group spans
both `linux/amd64` and `linux/arm64` unless the package name encodes an
architecture (`binutils-aarch64-linux-gnu`).

## 3. What each group needs, and from whom

| group | policy owner | legal owner | evidence needed |
|---|---|---|---|
| `G-FILE-NOASSERTION` | maintainer — `scripts/license/license-inventory.sh` | none; not a legal question | a per-file disposition with a proven owner, or the file stays visible. **Fixed on this branch** — see `docs/audits/real-image-inventories-2026-08-28/file-component-disposition.md` |
| `G-NOASSERT-*` | maintainer — `policies/syft.yaml` cataloguer selection | external counsel (#98) once an identifier exists | an upstream licence identifier per component, from the project's own metadata rather than from the scanner |
| `G-CONFLICT-RC1…RC4` | maintainer — the conflict rule in `license-inventory.sh` | none — **no source names a different licence** | a licence-expression normaliser that treats an expression and the enumeration of its members as one assertion, reviewed on its own merits |
| `G-REVIEW-*` | maintainer — `policies/license-policy.yaml` | **external counsel, NOT APPOINTED (#98)** | a recorded legal decision under the shipped distribution model, or a time-boxed exception carrying `granted_by`, `expires` and `tracked_issue` |

## 4. The findings inside the findings

Four things were verified rather than inherited. Each is a finding for the
maintainer; none is fixed here.

### 4a. Not one of the 196 "conflicts" is a legal disagreement

Every conflict decomposes into a normalisation defect:

| root cause | count | what it is |
|---|---|---|
| RC1 | 163 | SPDX `licenseDeclared` states `A AND B AND C`; CycloneDX enumerates `A`, `B`, `C` separately. The same fact at two granularities, recorded as a disagreement. |
| RC2 | 24 | one identifier spelled two ways — `LicenseRef-BSD-tcp-wrappers` vs `BSD_tcp_wrappers`, `MIT/X11` vs `LicenseRef-MIT-X11`, `GFDL-NIV-1.3+` vs `LicenseRef-GFDL-NIV-1.3-`. |
| RC3 | 4 | the perl packages: the members are enumerated but no source states the whole expression. |
| RC4 | 5 | `libcrypt1`, `libcrypt-dev` and friends: the scanner resolved nothing and emitted the licence TEXT HASH, `LicenseRef-<64 hex>` vs `sha256:<the same 64 hex>`. |
| RC5 | **0** | two sources naming genuinely different licences. **There are none.** |

So 196 of the 535 substantive findings are **technical**, and the correct fix is
a normaliser in the inventory — a change that removes 192 findings and therefore
needs a reviewed decision of its own, not a parser edit made in passing. It is
**not** done on this branch.

### 4b. PHP-3.01 is measured absent across all four PHP families — confirmed

`policies/license-policy.yaml` classifies `PHP-3.01` as `legal-review-required`
("naming restrictions interact with a proprietary LICENSE; counsel must
confirm"). `licence/identifier-reconciliation.json` records it under
`policy_listed_but_absent`, with `AGPL-3.0-only`, `AGPL-3.0-or-later`,
`CDDL-1.0` and `EPL-2.0`.

The reason is visible in the findings. The PHP binaries and extensions are
catalogued as `pkg:generic` with `NOASSERTION`, 46 of them:

```text
php-cli@8.3.32  php-cli@8.3.33  php-cli@8.4.23  php-cli@8.4.24
php-fpm@8.3.32  php-fpm@8.4.23
bcmath gd intl opcache pcntl pdo_mysql pdo_pgsql pgsql sockets sodium
        each at 8.3.32 / 8.3.33 / 8.4.23 / 8.4.24
```

**The policy is right and the scanner is blind.** PHP is in every one of the
four PHP families; the binary cataloguer that finds it emits no licence field,
so `PHP-3.01` never reaches the inventory and the policy entry never fires.
Group `G-NOASSERT-PKG-GENERIC-PHP-BINARY-EXTENSION`. Removing `PHP-3.01` from
the policy on the grounds that it was "not measured" would be exactly backwards.

### 4c. The LGPL-2.0 hole — confirmed, and it is the highest-volume one

`licence/identifier-reconciliation.json` records 34 identifiers measured in the
cohort that the policy table does not list at all. Ranked by occurrences:

| identifier | occurrences | policy |
|---|---|---|
| `LGPL-2.0-only` | **864** | **absent** — the table lists 2.1 and 3.0 only |
| `LGPL-2.0-or-later` | **680** | **absent** |
| `X11` | 552 | absent |
| `GPL-1.0-only` | 308 | absent |
| `BSD-4-Clause-UC` | 236 | absent |
| `FSFULLR` | 236 | absent |
| `GFDL-1.3-only` | 252 | absent |
| `GFDL-1.2-only` | 232 | absent |
| `Beerware` | 220 | absent |
| `Latex2e` | 216 | absent |

They do not appear as findings only because the packages carrying them are
already refused for conflicting assertions — the same packages, one refusal
each. `LGPL-2.0-only` / `-or-later` appear across the core Debian set
(`findutils`, `libnsl2`, `libpam-*`, `binutils-*`, `gzip`, `libgdbm*` and the
rest). Under the fail-closed default they would all resolve to
`legal-review-required`; the policy simply has no row for them.

**This is a policy gap for the maintainer.** It is not edited here.

### 4d. The 19 legal-review-required identifiers — verified, and one more than reported

Measured on 19 components across 5 identifiers:

| identifier | components |
|---|---|
| `GPL-2.0-only` (13) | `alpine-baselayout@3.7.2-r0`, `alpine-baselayout-data@3.7.2-r0`, `apk-tools@3.0.6-r0`, `busybox@1.37.0-r30`, `busybox-binsh@1.37.0-r30`, `libapk@3.0.6-r0`, `scanelf@1.3.8-r2`, `ssl_client@1.37.0-r30`, **`hostname@3.23+nmu1`**, `libgssapi-krb5-2`, `libk5crypto3`, `libkrb5-3`, `libkrb5support0` (all `@1.20.1-2+deb12u5`) |
| `curl` (2) | `curl@8.19.0-r0`, `libcurl@8.19.0-r0` |
| `LGPL-3.0-only` (2) | `libmpc3@1.3.1-1`, `libmpfr6@4.2.0-1` |
| `LGPL-2.1-only` (1) | `libseccomp2@2.5.4-1+deb12u1` |
| `GPL-3.0-only` (1) | `libzip4@1.7.3-1+b1` |

`hostname@3.23+nmu1` is in the measurement and was **not** in the prose list
carried forward from the audit. The list is 13 + 2 + 2 + 1 + 1 = 19 either way;
the prose was one component short of its own number.

`curl` is not in the policy table at all — it reaches `legal-review-required`
through the fail-closed default, which is the default working exactly as
designed.

## 5. What is not derivable, stated as a gap

Splitting the 7,972 file components into `scanner-observation` /
`package-attributed` / `independently-licensed` / `unresolved` requires the 20
CycloneDX documents and their 20 SPDX companions: the split is a function of the
`dependencies` graphs and the `CONTAINS` / `evident-by` relationships those
documents carry, and the committed record holds finding *labels*, not
relationships. Producing that split from anything else would be a guess with a
number attached.

**Closure condition:** one run of

```bash
scripts/license/license-inventory.sh --sbom-dir <the 40 documents> --out inv.json
```

with the resulting `image_files` block committed beside this file. It builds
nothing and dispatches nothing.
