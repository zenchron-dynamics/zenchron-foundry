# Exception expiry re-evaluation — 2026-08-25

**Status: ANALYSIS ONLY. Nothing was renewed, re-dated, widened, narrowed or
removed. `policies/vulnerability-exceptions.yaml` is byte-identical to `master`.**

Companion to `README.md` in this directory; same measurement identity (trivy
0.73.0, DB `UpdatedAt 2026-08-25 00:59:57 UTC`, children built from this
repository's Dockerfiles, `--severity HIGH,CRITICAL`, no ignore file).

## The scheduling risk, named first

`policies/vulnerability-exceptions.yaml` on `a828e07` holds **59** exceptions.

| `expires_at` | count |
|---|---|
| 2026-08-31 | 55 |
| 2026-09-01 | 4 |

**Every exception in the ledger carries one of two adjacent expiry dates,
`2026-08-31` or `2026-09-01`.** The absence of staggering is itself a scheduling
risk worth naming, independently of any individual finding:

- It concentrates 59 independent risk decisions onto two adjacent dates rather
  than distributing them across the review capacity of the **maintainer** role.
  There is no delegated approval path: `approval_mode` on every record is
  sole-maintainer risk acceptance and `independent_approval` is recorded as
  unavailable, so the decisions cannot be shared out under load.
- `scripts/reconcile-vulnerabilities.sh` requires `expires_at` strictly in the
  future, so each date is a hard per-entry boundary rather than a soft review
  prompt. Which entries carry which date is recorded per entry in the table
  below; this document deliberately does not rank or sequence them.
- The alignment exists because dates were repeatedly **set to a single cohort**
  rather than staggered: entries created on 2026-06-21, 07-03, 07-11, 07-14,
  07-23, 07-24, 07-25, 07-28, 08-11, 08-13, 08-14 and 08-17 all carry the same
  `2026-08-31`. Alignment makes batch review convenient and makes batch failure
  certain.
- A concentrated review load is the condition under which a blanket re-date
  becomes tempting. The ledger's own text refuses that: "Expiry on 2026-09-01
  triggers a NEW decision, not a renewal."
- **Staggering the replacement dates is itself a maintainer decision and is not
  taken here.** This lane cannot edit the ledger and does not propose a schedule.

## Method

Each of the 59 records was evaluated against evidence measured today, not
against its own recorded evidence:

1. Ten gated children were rebuilt from this repository's Dockerfiles and
   scanned (`php-cli`/`php-fpm`/`php-worker` 8.3 + 8.4, `php-frankenphp`
   8.3 + 8.4, `nginx`, `caddy`).
2. Each scan was run through the repository's own gate,
   `scripts/reconcile-vulnerabilities.sh <scan> <family> <version> --arch <arch>`,
   which reports `matched_exception_ids` — the stable
   `cve|image|package|installed_version` identity of the record that governed
   each finding (`scripts/lib/exception_id.py`).
3. A record was called **matched** only if the gate itself paired it with a real
   finding. Nothing was inferred from the record's own claims.

Twelve reconciliations were run:

| image | arch | verdict | findings | governed | not-affected | violations |
|---|---|---|---|---|---|---|
| `caddy/prod` | linux/arm64 | PASS | 19 | 19 | 0 | 0 |
| `nginx/prod` | linux/arm64 | PASS | 32 | 27 | 5 | 0 |
| `php-cli/8.3` | linux/arm64 | PASS | 47 | 42 | 5 | 0 |
| `php-cli/8.4` | linux/arm64 | PASS | 47 | 42 | 5 | 0 |
| `php-fpm/8.3` | linux/arm64 | PASS | 47 | 42 | 5 | 0 |
| `php-fpm/8.4` | linux/arm64 | PASS | 47 | 42 | 5 | 0 |
| `php-worker/8.3` | linux/arm64 | PASS | 47 | 42 | 5 | 0 |
| `php-worker/8.4` | linux/arm64 | PASS | 47 | 42 | 5 | 0 |
| `php-frankenphp/8.3` | linux/arm64 | **FAIL** | 81 | 75 | 4 | **2** |
| `php-frankenphp/8.4` | linux/arm64 | **FAIL** | 81 | 75 | 4 | **2** |
| `php-frankenphp/8.3` | linux/amd64 | **FAIL** | 81 | 75 | 4 | **2** |
| `php-frankenphp/8.4` | linux/amd64 | **FAIL** | 81 | 75 | 4 | **2** |

`shadowed_exception_ids` was empty in all twelve — no record is unreachable
behind another.

### Coverage limits, stated rather than glossed

- Eight of the twelve reconciliations are `linux/arm64`; **both** FrankenPHP
  children were also built and reconciled under QEMU for `linux/amd64`, and every upstream
  FrankenPHP artifact was scanned on **both** platforms directly from the
  registry (see `README.md` §3). `caddy`, `nginx` and the `php-cli`/`php-fpm`/
  `php-worker` families were **not** re-measured on `linux/amd64` in this lane.
- Debian and Alpine binary versions are identical across the two platforms for
  every package involved, and the Go module versions were confirmed identical
  across platforms — but that is an argument, not an amd64 measurement, and the
  maintainer should treat the amd64 column as inherited for those six images.
- No entry's classification below depends on the amd64 gap: every one of them
  was matched by a real finding on at least one measured image.

## Classification rule

Each record is assigned to **exactly one** bucket. The assignment rule:

- **upstream now patched** — the scanner reports the installed version at or
  above the fixed version, or the advisory no longer applies to it.
- **installed version changed** — the advisory still applies, but the package
  moved off the version the record pins, so the record's binding no longer holds.
- **finding disappeared** — the advisory is absent from every scanned child.
- **evidence too old to decide** — the finding is present, but the record's own
  acceptance basis is marked as never independently verified, so re-deciding it
  on 2026-08-31 needs work this evidence cannot supply.
- **risk still present** — the finding is present at the bound version and the
  record's acceptance basis is intact and re-checkable.

## Result

| bucket | count |
|---|---|
| upstream now patched | **0** |
| installed version changed | **0** |
| finding disappeared | **0** |
| risk still present | **45** |
| evidence too old to decide | **14** |

**All 59 findings are physically present today at exactly the versions their
records pin.** Not one exception has become stale, so
`scripts/ci/assert-no-stale-exceptions.sh` has nothing to demand the removal of,
and there is no record the maintainer can simply delete. The 14 in the last
bucket are present too; they are separated because their own text says the
acceptance rationale was never re-verified (below).

## Full table — all 59 expiring entries

"matched today" counts the image/architecture reconciliations in which the
repository's own gate paired this record with a real finding.

| # | advisory | ledger scope | package(s) | bound version | expires | classification | matched today |
|---|---|---|---|---|---|---|---|
| 1 | `CVE-2023-45853` | `php-8.3-8.4` | `zlib1g` | `1:1.2.13.dfsg-1` | 2026-08-31 | evidence too old to decide | 9 image/arch |
| 2 | `CVE-2026-42496` | `php-8.3-8.4` | `libperl5.36,perl,perl-base,perl-modules-5.36` | `5.36.0-7+deb12u3` | 2026-08-31 | evidence too old to decide | 9 image/arch |
| 3 | `CVE-2026-8376` | `php-8.3-8.4` | `libperl5.36,perl,perl-base,perl-modules-5.36` | `5.36.0-7+deb12u3` | 2026-08-31 | evidence too old to decide | 9 image/arch |
| 4 | `CVE-2025-7458` | `php-8.3-8.4` | `libsqlite3-0` | `3.40.1-2+deb12u2` | 2026-08-31 | evidence too old to decide | 9 image/arch |
| 5 | `CVE-2023-6879` | `php-frankenphp-8.3-8.4` | `libaom3` | `3.6.0-1+deb12u2` | 2026-08-31 | evidence too old to decide | 3 image/arch |
| 6 | `CVE-2026-27145` | `caddy` | `stdlib` | `v1.26.3` | 2026-08-31 | evidence too old to decide | 1 image/arch |
| 7 | `CVE-2026-42504` | `caddy` | `stdlib` | `v1.26.3` | 2026-08-31 | evidence too old to decide | 1 image/arch |
| 8 | `CVE-2026-33630` | `caddy` | `c-ares` | `1.34.6-r0` | 2026-08-31 | evidence too old to decide | 1 image/arch |
| 9 | `CVE-2026-6276` | `caddy` | `curl,libcurl` | `8.19.0-r0` | 2026-08-31 | evidence too old to decide | 1 image/arch |
| 10 | `GHSA-hrxh-6v49-42gf` | `caddy` | `google.golang.org/grpc` | `v1.81.0` | 2026-08-31 | evidence too old to decide | 1 image/arch |
| 11 | `GHSA-hrxh-6v49-42gf` | `php-frankenphp-8.3-8.4` | `google.golang.org/grpc` | `v1.81.1` | 2026-08-31 | evidence too old to decide | 3 image/arch |
| 12 | `CVE-2026-5773` | `caddy` | `curl,libcurl` | `8.19.0-r0` | 2026-08-31 | evidence too old to decide | 1 image/arch |
| 13 | `CVE-2026-39822` | `caddy` | `stdlib` | `v1.26.3` | 2026-08-31 | evidence too old to decide | 1 image/arch |
| 14 | `GHSA-r277-6w6q-xmqw` | `php-frankenphp-8.3-8.4` | `github.com/getkin/kin-openapi` | `v0.140.0` | 2026-08-31 | evidence too old to decide | 3 image/arch |
| 15 | `CVE-2026-57433` | `php-frankenphp-8.3-8.4` | `libperl5.36,perl,perl-base,perl-modules-5.36` | `5.36.0-7+deb12u3` | 2026-08-31 | risk still present | 3 image/arch |
| 16 | `CVE-2026-42497` | `php-frankenphp-8.3-8.4` | `libperl5.36,perl,perl-base,perl-modules-5.36` | `5.36.0-7+deb12u3` | 2026-08-31 | risk still present | 3 image/arch |
| 17 | `CVE-2026-9538` | `php-frankenphp-8.3-8.4` | `libperl5.36,perl,perl-base,perl-modules-5.36` | `5.36.0-7+deb12u3` | 2026-08-31 | risk still present | 3 image/arch |
| 18 | `CVE-2026-48962` | `php-frankenphp-8.3-8.4` | `libperl5.36,perl,perl-base,perl-modules-5.36` | `5.36.0-7+deb12u3` | 2026-08-31 | risk still present | 3 image/arch |
| 19 | `CVE-2026-57432` | `php-8.3-8.4` | `libperl5.36,perl,perl-base,perl-modules-5.36` | `5.36.0-7+deb12u3` | 2026-08-31 | risk still present | 9 image/arch |
| 20 | `CVE-2026-6653` | `php-8.3-8.4` | `libxml2` | `2.9.14+dfsg-1.3~deb12u6` | 2026-08-31 | risk still present | 9 image/arch |
| 21 | `CVE-2026-8286` | `php-8.3-8.4` | `curl,libcurl4` | `7.88.1-10+deb12u15` | 2026-08-31 | risk still present | 9 image/arch |
| 22 | `CVE-2026-8927` | `php-8.3-8.4` | `curl,libcurl4` | `7.88.1-10+deb12u15` | 2026-08-31 | risk still present | 9 image/arch |
| 23 | `CVE-2026-12064` | `php-8.3-8.4` | `curl,libcurl4` | `7.88.1-10+deb12u15` | 2026-08-31 | risk still present | 9 image/arch |
| 24 | `CVE-2026-7598` | `php-8.3-8.4` | `libssh2-1` | `1.10.0-3+b1` | 2026-08-31 | risk still present | 9 image/arch |
| 25 | `CVE-2023-2953` | `php-8.3-8.4` | `libldap-2.5-0` | `2.5.13+dfsg-5` | 2026-08-31 | risk still present | 9 image/arch |
| 26 | `CVE-2025-69720` | `php-8.3-8.4` | `libtinfo6,ncurses-base,ncurses-bin` | `6.4-4` | 2026-08-31 | risk still present | 9 image/arch |
| 27 | `CVE-2026-53615` | `php-8.3-8.4` | `bsdutils,libblkid1,libmount1,libsmartcols1,…` | `1:2.38.1-5+deb12u3,2.38.1-5+deb…` | 2026-08-31 | risk still present | 9 image/arch |
| 28 | `CVE-2026-54369` | `php-8.3-8.4` | `libacl1` | `2.3.1-3` | 2026-08-31 | risk still present | 9 image/arch |
| 29 | `CVE-2026-41992` | `php-8.3-8.4` | `gzip` | `1.12-1` | 2026-08-31 | risk still present | 9 image/arch |
| 30 | `CVE-2026-56211` | `php-frankenphp-8.3-8.4` | `libaom3` | `3.6.0-1+deb12u2` | 2026-08-31 | risk still present | 3 image/arch |
| 31 | `CVE-2026-56208` | `php-frankenphp-8.3-8.4` | `libaom3` | `3.6.0-1+deb12u2` | 2026-08-31 | risk still present | 3 image/arch |
| 32 | `CVE-2026-56209` | `php-frankenphp-8.3-8.4` | `libaom3` | `3.6.0-1+deb12u2` | 2026-08-31 | risk still present | 3 image/arch |
| 33 | `CVE-2026-56210` | `php-frankenphp-8.3-8.4` | `libaom3` | `3.6.0-1+deb12u2` | 2026-08-31 | risk still present | 3 image/arch |
| 34 | `CVE-2023-39616` | `php-frankenphp-8.3-8.4` | `libaom3` | `3.6.0-1+deb12u2` | 2026-08-31 | risk still present | 3 image/arch |
| 35 | `CVE-2026-6276` | `php-8.3-8.4` | `curl,libcurl4` | `7.88.1-10+deb12u15` | 2026-08-31 | risk still present | 9 image/arch |
| 36 | `CVE-2026-42496` | `nginx` | `libperl5.36,perl,perl-base,perl-modules-5.36` | `5.36.0-7+deb12u3` | 2026-08-31 | risk still present | 1 image/arch |
| 37 | `CVE-2026-8376` | `nginx` | `libperl5.36,perl,perl-base,perl-modules-5.36` | `5.36.0-7+deb12u3` | 2026-08-31 | risk still present | 1 image/arch |
| 38 | `CVE-2026-57432` | `nginx` | `libperl5.36,perl,perl-base,perl-modules-5.36` | `5.36.0-7+deb12u3` | 2026-08-31 | risk still present | 1 image/arch |
| 39 | `CVE-2023-45853` | `nginx` | `zlib1g` | `1:1.2.13.dfsg-1` | 2026-08-31 | risk still present | 1 image/arch |
| 40 | `CVE-2025-69720` | `nginx` | `libtinfo6,ncurses-base,ncurses-bin` | `6.4-4` | 2026-08-31 | risk still present | 1 image/arch |
| 41 | `CVE-2026-41992` | `nginx` | `gzip` | `1.12-1` | 2026-08-31 | risk still present | 1 image/arch |
| 42 | `CVE-2026-53615` | `nginx` | `bsdutils,libblkid1,libmount1,libsmartcols1,…` | `1:2.38.1-5+deb12u3,2.38.1-5+deb…` | 2026-08-31 | risk still present | 1 image/arch |
| 43 | `CVE-2026-54369` | `nginx` | `libacl1` | `2.3.1-3` | 2026-08-31 | risk still present | 1 image/arch |
| 44 | `CVE-2026-56852` | `caddy` | `golang.org/x/text` | `v0.37.0` | 2026-08-31 | risk still present | 1 image/arch |
| 45 | `CVE-2026-8458` | `php-8.3-8.4` | `curl,libcurl4` | `7.88.1-10+deb12u15` | 2026-08-31 | risk still present | 9 image/arch |
| 46 | `CVE-2026-58050` | `php-8.3-8.4` | `libssh2-1` | `1.10.0-3+b1` | 2026-08-31 | risk still present | 9 image/arch |
| 47 | `CVE-2026-46600` | `caddy` | `golang.org/x/net` | `v0.55.0` | 2026-08-31 | risk still present | 1 image/arch |
| 48 | `CVE-2026-46600` | `caddy` | `stdlib` | `v1.26.3` | 2026-08-31 | risk still present | 1 image/arch |
| 49 | `CVE-2026-39821` | `caddy` | `stdlib` | `v1.26.3` | 2026-08-31 | risk still present | 1 image/arch |
| 50 | `CVE-2026-33818` | `caddy` | `stdlib` | `v1.26.3` | 2026-08-31 | risk still present | 1 image/arch |
| 51 | `CVE-2026-56853` | `caddy` | `stdlib` | `v1.26.3` | 2026-08-31 | risk still present | 1 image/arch |
| 52 | `CVE-2026-56858` | `caddy` | `stdlib` | `v1.26.3` | 2026-08-31 | risk still present | 1 image/arch |
| 53 | `CVE-2026-56859` | `caddy` | `stdlib` | `v1.26.3` | 2026-08-31 | risk still present | 1 image/arch |
| 54 | `CVE-2026-56860` | `caddy` | `stdlib` | `v1.26.3` | 2026-08-31 | risk still present | 1 image/arch |
| 55 | `CVE-2026-56862` | `caddy` | `stdlib` | `v1.26.3` | 2026-08-31 | risk still present | 1 image/arch |
| 56 | `CVE-2026-14456` | `php-8.3-8.4` | `openssl,libssl3` | `3.0.20-1~deb12u2` | 2026-09-01 | risk still present | 9 image/arch |
| 57 | `CVE-2026-14456` | `nginx` | `openssl,libssl3` | `3.0.20-1~deb12u2` | 2026-09-01 | risk still present | 1 image/arch |
| 58 | `CVE-2026-53613` | `php-8.3-8.4` | `bsdutils,libblkid1,libmount1,libsmartcols1,…` | `1:2.38.1-5+deb12u3,2.38.1-5+deb…` | 2026-09-01 | risk still present | 9 image/arch |
| 59 | `CVE-2026-53613` | `nginx` | `bsdutils,libblkid1,libmount1,libsmartcols1,…` | `1:2.38.1-5+deb12u3,2.38.1-5+deb…` | 2026-09-01 | risk still present | 1 image/arch |

## The 14 in "evidence too old to decide"

Entries **1–14** — the records created between 2026-06-21 and 2026-07-25 —
each carry two self-declared weaknesses, verbatim from the ledger:

```yaml
arch_note: "pre-existing entry; reconciled on linux/amd64 only. Does NOT
  authorise linux/arm64 — an arm64 publish fails until an arm64 evidence run exists."
reachability_evidence: >-
  … [CARRIED FORWARD: this is the classification of the acceptance rationale
  already recorded in `reason` when the record was written. It was NOT
  independently re-verified during the 2026-07-30 schema migration;
  external_review_trigger applies.]
```

So for these 14 the *finding* is fresh (all matched today) but the *acceptance*
rests on a rationale that the record itself says was never independently
verified, and on an architecture note that contradicts its own
`verified_architectures: [linux/amd64, linux/arm64]`. A 2026-08-31 re-decision
on these is not a confirmation; it is a first decision.

Two of the fourteen are directly relevant to the risk packet in `README.md`:

- **#11** `GHSA-hrxh-6v49-42gf` — grpc `v1.81.1` on `php-frankenphp-8.3-8.4`.
- **#14** `GHSA-r277-6w6q-xmqw` — kin-openapi `v0.140.0` on `php-frankenphp-8.3-8.4`.

Both are in the same binary as `CVE-2026-76905` and `CVE-2026-77354`, so the
FrankenPHP gobinary decision on 2026-08-31 covers three ledgered advisories plus
two ungoverned ones.

An oddity worth flagging to the maintainer: **entry #11 pins
`installed_version: v1.81.1` while entry #10 (the same advisory on `caddy`) pins
`v1.81.0`, and both matched today.** Measured: `caddy` ships grpc `v1.81.0`,
`php-frankenphp` ships `v1.81.1`. The two records are correctly split — but it
demonstrates that a single advisory can require different version bindings per
image, which is the same shape as the per-package binding discussed below.

## `CVE-2026-53613` — util-linux, eight packages, per-package binding

Records **58** (`php-8.3-8.4`) and **59** (`nginx`), `expires_at: 2026-09-01`.

**Classification: risk still present.** Matched today on all nine PHP-family
image/arch reconciliations and on `nginx/prod`.

The interesting part is the binding, and it survived re-measurement intact:

```yaml
installed_version: ["1:2.38.1-5+deb12u3", 2.38.1-5+deb12u3]
package_versions:
  bsdutils:        ["1:2.38.1-5+deb12u3"]
  libblkid1:       [2.38.1-5+deb12u3]
  libmount1:       [2.38.1-5+deb12u3]
  libsmartcols1:   [2.38.1-5+deb12u3]
  libuuid1:        [2.38.1-5+deb12u3]
  mount:           [2.38.1-5+deb12u3]
  util-linux:      [2.38.1-5+deb12u3]
  util-linux-extra:[2.38.1-5+deb12u3]
```

Observed today across the scanned children: `bsdutils` at `1:2.38.1-5+deb12u3`
(epoch 1) and the other seven at `2.38.1-5+deb12u3` (no epoch) — exactly the
split the record encodes. `package_versions` binds each binary package to its own
observed version, so a cross-matched tuple (say `mount` appearing at the epoch-1
string) refuses instead of quietly matching. That guard is doing real work: the
flat `installed_version` list alone would accept either version for any of the
eight packages.

Status per Trivy today: `affected`, `FixedVersion` empty — Debian bookworm still
publishes no fixed `util-linux`. Ownership is `upstream-base`; under ADR-0001 no
Foundry rebuild changes an upstream distro package.

Also note what did **not** happen: `CVE-2026-53615` covers the *same eight
packages at the same versions* on the same images (records 27 and 42) and did
**not** absorb 53613. Both matched independently today. The records document that
a 2026-08-20 preflight refused 18 children precisely because 53615 could not
cover 53613 — that separation is still holding.

`reachability: unresolved-no-concrete-path-identified` — the record claims no
mitigation. Re-deciding it on 2026-09-01 therefore turns entirely on impact,
exposure and appetite, not on new scan data.

## `CVE-2026-14456` — openssl/libssl3, the bounded bridge

Records **56** (`php-8.3-8.4`) and **57** (`nginx`), `expires_at: 2026-09-01`,
carrying `reaffirmed_at: 2026-08-20`, a `reaffirmed_by` attribution to the
maintainer role, and a long
`reaffirmation_evidence` block.

**Classification: risk still present.** Matched on all nine PHP-family
reconciliations and on `nginx/prod`.

Re-verified today, point by point against the reaffirmation text:

| reaffirmation claim (2026-08-20) | re-measured 2026-08-25 |
|---|---|
| still reported against `openssl` and `libssl3` at exactly `3.0.20-1~deb12u2` | **holds** — `dpkg-query` on the `php-cli/8.4` child returns `libssl3 3.0.20-1~deb12u2` and `openssl 3.0.20-1~deb12u2` |
| `FixedVersion` NONE | **holds** — Trivy status `affected`, no fixed version |
| a newer official base exists but a patched one does not | **holds, and re-tested** — the FrankenPHP `1-php8.3-bookworm` head moved again on 2026-08-25 and still carries the same openssl build |
| observed on both architectures | **arm64 re-observed; amd64 inherited** in this lane for the PHP and nginx families |

The re-dating itself is the notable governance act: expiry moved
`2026-08-26 -> 2026-09-01` with an explicit `reaffirmation_evidence` record
saying it is "a second bounded bridge, to be decided again at expiry", not a
renewal. That distinction is only meaningful if the second bridge actually ends
at its stated date, **2026-09-01**; a third bridge would need its own
justification on its own evidence. This lane cannot and does not extend it.

### Why `caddy/prod` is deliberately NOT covered — verified

Neither record lists `caddy`, and that is correct, not an oversight. Measured
today inside the built `caddy` child:

```console
$ docker run --rm --entrypoint sh lane4/caddy:prod-arm64 -c \
    "cat /etc/alpine-release; apk list -I | grep -iE 'ssl|crypto'"
3.23.5
libcrypto3-3.5.7-r0 aarch64 {openssl} (Apache-2.0) [installed]
libssl3-3.5.7-r0    aarch64 {openssl} (Apache-2.0) [installed]
```

`caddy/prod` is Alpine 3.23.5 and ships `libssl3-3.5.7-r0` — OpenSSL **3.5.7**
from the Alpine `openssl` aport, not Debian's **3.0.20-1~deb12u2**. It is a
different package build, tracked in a different advisory namespace, and the
record's `installed_version: 3.0.20-1~deb12u2` binding could not match it even if
the scope were widened. Its full HIGH/CRITICAL OS set today is five findings —
`curl` ×2, `libcurl` ×2, `c-ares` ×1 — and **zero** openssl-family findings.
Widening `CVE-2026-14456` to cover `caddy` would grant scope no evidence
supports; leaving it out is the ledger behaving correctly.

## Scope of the decision carried by the maintainer role

Stated as a scope of work, not as a recommendation, and not ordered by date:

1. **59 records, none droppable.** No entry can be retired on the grounds that
   the finding went away, because none did.
2. **14 records (1–14) need a first real reachability decision**, not a
   re-confirmation, and their `arch_note` contradicts their
   `verified_architectures`.
3. **2 records (56, 57)** are on their second bounded bridge, `expires_at:
   2026-09-01`.
4. **2 records (58, 59)**, `expires_at: 2026-09-01`, were written explicitly as
   "a NEW decision, not a renewal" at expiry.
5. **2 advisories (`CVE-2026-76905`, `CVE-2026-77354`) have no record at all**
   and already fail the gate — see `README.md`, where the three options are set
   out without a recommendation.
6. **The two-date structure itself** — whether replacement dates are staggered,
   and under what approval path — is a decision nobody has taken.

## Not done in this lane

No exception was created, widened, narrowed, renewed, re-dated or removed. No
`reaffirmed_at`, `reaffirmed_by` or `reaffirmation_evidence` field was written.
`policies/vulnerability-exceptions.yaml` is untouched, which
`git diff master -- policies/` will confirm.
