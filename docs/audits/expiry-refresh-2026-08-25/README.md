# Exception expiry refresh — buildless cohort rescan, 2026-08-25

**Status: ANALYSIS AND EVIDENCE ONLY.** No exception was created, widened,
narrowed, renewed, re-dated or removed. `policies/vulnerability-exceptions.yaml`
is byte-identical to `master`, which `git diff master -- policies/` confirms.
Every disposition below is a **proposal to the maintainer role**, not a decision
taken by this lane.

## 1. What was measured, and what makes it different from a rebuild

The cohort here is the **retained production cohort**: the twenty immutable
child manifest digests recorded in the accepted acceptance evidence
`docs/audits/acceptance-multiarch-2026-08-20/acceptance-evidence.json`
(ten image definitions x two platforms), all representing source revision
`7061caafb3ea09bd5b2342a1daf022151b33f822`.

Nothing was rebuilt. Each digest was pulled from the staging package and scanned
as it stands. That distinction is load-bearing: rebuilding the same Dockerfile
today produces a **different artifact**, because six of the eight pinned base
tags have moved (section 3). A rebuild-and-scan answers "what would we ship if
we built today"; an expiry decision needs "is the cohort that was accepted still
governed", and only a digest rescan answers that.

Evidence class of the child measurements: **staged-candidate**. Base
measurements are separately labelled **upstream-base** and are used only to
establish upstream ownership and patched-base availability — never as a child
inventory. That separation is enforced by `policies/evidence-classes.yaml` and
matters here concretely: a PHP base carries package sets the child does not,
and the child carries packages the base does not (section 4).

## 2. Measurement identity

| axis | value |
|---|---|
| scanner | `aquasec/trivy:0.73.0@sha256:7cced7cae583819fc7806d4cbc0dbbc7cad18b99f7d3e235192e6da8c091045c` |
| frozen vulnerability database | `v2+updated:2026-08-25T13:00:57.303086402Z+next:2026-08-26T13:00:57.30308573Z` |
| frozen Java database | `v1+updated:2026-08-25T01:03:11.931341203Z` |
| scanner flags | `--severity CRITICAL,HIGH --exit-code 0 --skip-db-update --skip-java-db-update`, no ignore file |
| source revision represented | `7061caafb3ea09bd5b2342a1daf022151b33f822` |
| exception ledger digest (sha256) | `babc89714281f5d7c4b34d179ef5a24a14593a3cabc4b1c897d0575768fb307c` |
| evidence-class policy digest (sha256) | `9cde7a7d632874efb2b4bf387f51955e26eb8fddf4330bac7f36d0e8b982b422` |
| children scanned | 20 of 20 (`linux/amd64` 10, `linux/arm64` 10) |
| reconciliation gate | `scripts/reconcile-vulnerabilities.sh`, run per child with `--arch` |

**This is a NEW database snapshot, acquired for this refresh.** Three distinct
snapshots exist in this repository and they are not interchangeable:

| snapshot | where it is retained | what it is evidence for |
|---|---|---|
| `v2+updated:2026-08-20T13:14:11.601761173Z` | `docs/audits/acceptance-multiarch-2026-08-20/acceptance-evidence.json` | the 2026-08-20 acceptance run |
| `trivy-db:v2+updated:2026-08-25T06:59:59.307495517Z` | `docs/audits/experimental-php-8.5-linux-amd64/frozen-scan-basis.json` | the experimental PHP 8.5 `linux/amd64` cohort |
| `v2+updated:2026-08-25T13:00:57.303086402Z` | this directory, `frozen-db-identity.txt` | **this refresh, and only this refresh** |

Neither of the first two is presented here as current evidence, and neither was
reused. The scanner image also differs from the acceptance run's
(`aquasec/trivy@sha256:016eae51…`, Trivy 0.71.0) and from the PHP 8.5 basis; the
scanner used here is recorded above by digest.

**Ledger binding.** Every classification below was computed against
`policies/vulnerability-exceptions.yaml` at sha256
`babc89714281f5d7c4b34d179ef5a24a14593a3cabc4b1c897d0575768fb307c` — 59
`exceptions` and 20 `not_affected`, expiries `55 x 2026-08-31` and
`4 x 2026-09-01` — which is the file as it stands on `master` at `663ab93d`.
That digest is recorded per child in the `binding` block of every
reconciliation. A separately authorized change adding `kin-openapi` records is
in flight in another lane; when it lands the ledger digest changes and this
refresh's numbers describe the ledger state named here, not the state after that
change. The two advisories in section 7 are the ones that change would govern.

The
database was downloaded exactly once and every one of the twenty children was
scanned against that same snapshot with `--skip-db-update`, so a difference
between two children is attributable to the children and not to a database that
moved between them. `scripts/rescan-retained-cohort.sh` refuses to re-download
on a resumed run for that reason.

Every child measurement is bound, in
`docs/audits/expiry-refresh-2026-08-25/reconciliations/*.reconcile.json` under
`binding`, to all of: immutable child digest, platform, source revision, scanner
image digest, frozen database identity, exception-ledger digest, evidence-class
policy digest, and evidence class.

The raw scanner JSON is regenerable from those bindings and is recorded by
SHA-256 in `SHA256SUMS-raw-scans.txt` rather than committed; the complete
CRITICAL/HIGH finding set for each child is committed in full under `findings/`.

## 3. Upstream base movement, measured

Recorded in `upstream-base-heads/base-head-movement.json`. Six of eight pinned
base tags have moved to a new digest since the cohort was built:

| base tag | pinned digest (cohort) | head digest 2026-08-25 | moved |
|---|---|---|---|
| `php:8.3-cli-bookworm` | `sha256:a4fcf31f…` | `sha256:17752973…` | yes |
| `php:8.4-cli-bookworm` | `sha256:138a2109…` | `sha256:6003a060…` | yes |
| `php:8.3-fpm-bookworm` | `sha256:2a397791…` | `sha256:84ffb6f8…` | yes |
| `php:8.4-fpm-bookworm` | `sha256:66a10c4b…` | `sha256:d19afbcc…` | yes |
| `dunglas/frankenphp:1-php8.3-bookworm` | `sha256:ae143d38…` | `sha256:9725e5d4…` | yes |
| `dunglas/frankenphp:1-php8.4-bookworm` | `sha256:cef99f10…` | `sha256:a6e78fd9…` | yes |
| `caddy:2-alpine` | `sha256:5f5c8640…` | `sha256:5f5c8640…` | no |
| `nginxinc/nginx-unprivileged:1.28-bookworm` | `sha256:cd33960e…` | `sha256:cd33960e…` | no |

Every moved head was scanned against the same frozen database and its full
`dpkg` inventory captured. **In every case the moved head still carries the
bound package at the same unpatched version.** Movement is therefore not
remediation here: re-pinning to any of these six heads would change the artifact
without clearing a single one of the findings involved.

## 4. A material contradiction of the earlier review

The earlier review (`docs/audits/kin-openapi-risk-packet-2026-08-25/exception-expiry-review.md`)
rebuilt children and classified 45 records "risk still present" and 14 "evidence
too old to decide". Four things measured here contradict or materially extend it.

**4.1 `libaom3` is not in the FrankenPHP base.** Six records (entries 5, 30-34)
place `libaom3` in the base — the first states it verbatim: *"libaom3 AV1 decoder
in frankenphp base"* — and a compensating control on four of them says
*"dropping AVIF support from the frankenphp base would remove this entirely"*.
Measured on both the pinned base and the current head:

```console
$ docker run --rm --entrypoint sh dunglas/frankenphp@sha256:ae143d38… -c 'dpkg-query -W "libaom*"'
dpkg-query: no packages found matching libaom*
$ docker run --rm --entrypoint sh dunglas/frankenphp@sha256:9725e5d4… -c 'dpkg-query -W "libaom*"'
dpkg-query: no packages found matching libaom*
```

`libaom3 3.6.0-1+deb12u2` is nevertheless present in all four FrankenPHP
children. It enters through the Foundry Dockerfile's own
`install-php-extensions … gd` step, which pulls AVIF support and its `libaom3`
dependency into the child. The remediation owner recorded against these six
findings is therefore wrong in a way that matters: the action is a **Foundry
Dockerfile change**, available now, not a wait on an upstream base that does not
ship the package at all. `scripts/classify-remediation-owner.sh` also returns
`owner=upstream-base` for `libaom3`, because it classifies by package name; the
inventory evidence overrides that.

**4.2 A rebuild ticket for the FrankenPHP Go modules would not remediate.**
`scripts/classify-remediation-owner.sh` returns `rebuild_can_remediate=yes` for
`google.golang.org/grpc` and `github.com/getkin/kin-openapi` once a newer base
is available, and a newer base *is* available. Measured: the current
FrankenPHP heads still vendor `grpc v1.81.1` and `kin-openapi v0.140.0` — the
same versions as the accepted children. The heuristic's "yes" is unsupported by
the artifact.

**4.3 Both architectures are directly evidenced for all 59 records.** The
earlier review measured eight of twelve reconciliations on `linux/arm64` only
and stated plainly that `caddy`, `nginx` and the `php-cli`/`php-fpm`/
`php-worker` families had their `linux/amd64` column **inherited by argument
rather than measured**. Here all twenty children were scanned, so every one of
the 59 records is matched by a real finding on `linux/amd64` **and** on
`linux/arm64`. The inherited-amd64 gap is closed.

This has a second consequence, which the earlier review raised only for its
fourteen: **36 of the 59 records carry an `arch_note` asserting that the record
was reconciled on `linux/amd64` only and does not authorise `linux/arm64`** — 22
in one wording and 14 in another — while all 59 list
`verified_architectures: [linux/amd64, linux/arm64]`. Every one of those notes
is now contradicted by direct measurement on both platforms. The notes are
stale; the findings they annotate are not. Correcting them is a ledger edit and
therefore a maintainer action, not one this lane takes.

**4.4 The "evidence too old to decide" bucket does not survive contact with this
evidence set.** That bucket described the *acceptance rationale*, not the
finding. Against measured evidence each of those 14 records resolves into an
evidence-based classification: entries 1, 2, 3, 4, 11 and 14 into *upstream
artifact moved but remains unpatched*; entries 6, 7, 8, 9, 10, 12 and 13 into
*still present at the exact bound package/version*; entry 5 into *ownership
boundary changed*. Not one of the fourteen lands in *evidence unavailable*. The
`arch_note` those records carry — *"reconciled on linux/amd64 only … does NOT
authorise linux/arm64"* — is now contradicted by direct measurement on both
platforms, so the note is stale even though the finding is not.

What this refresh **confirms**: no finding disappeared, no bound version moved,
and no record can be retired on the grounds that the problem went away. On that
the earlier review was right.

## 5. Phase 1 — refreshed status of all 59 ledger entries

Classification rules, each record in exactly one bucket:

- **still present at the exact bound package/version** — reported on a bound
  package, at a version the record's binding accepts, and the pinned upstream
  artifact has not moved.
- **absent** — the advisory is not reported on any in-scope child.
- **installed version changed** — reported on a bound package at a version the
  record's binding does not accept, so the binding no longer holds.
- **fix now available** — the scanner offers a fixed version where the record
  declares none exists, or a patched official base is published.
- **upstream artifact moved but remains unpatched** — the pinned base tag moved
  to a new digest and the new head still carries the bound package at the same
  unpatched version.
- **evidence unavailable** — no measurement covers the record's scope.
- **selector no longer resolves** — the image or package selector matches no
  measured child, or no finding on a bound package.
- **ownership boundary changed** — the component is not owned by the party the
  record names, established by inventory rather than by package naming.

Every one of the 59 was independently paired with a real finding by the
repository's own gate (`matched_exception_ids`); the machine-readable form is
`refresh-classification.json`, which records `matched_by_gate` per entry.
`shadowed_exception_ids` was empty in all twenty reconciliations.

| # | advisory | ledger selector | package(s) observed | bound version holds | arch directly evidenced | refreshed classification |
|---|---|---|---|---|---|---|
| 1 | `CVE-2023-45853` | `php-8.3-8.4` | `zlib1g` | `1:1.2.13.dfsg-1` | amd64+arm64 | upstream artifact moved but remains unpatched |
| 2 | `CVE-2026-42496` | `php-8.3-8.4` | `libperl5.36,perl,perl-base,perl-modules-5.36` | `5.36.0-7+deb12u3` | amd64+arm64 | upstream artifact moved but remains unpatched |
| 3 | `CVE-2026-8376` | `php-8.3-8.4` | `libperl5.36,perl,perl-base,perl-modules-5.36` | `5.36.0-7+deb12u3` | amd64+arm64 | upstream artifact moved but remains unpatched |
| 4 | `CVE-2025-7458` | `php-8.3-8.4` | `libsqlite3-0` | `3.40.1-2+deb12u2` | amd64+arm64 | upstream artifact moved but remains unpatched |
| 5 | `CVE-2023-6879` | `php-frankenphp-8.3-8.4` | `libaom3` | `3.6.0-1+deb12u2` | amd64+arm64 | ownership boundary changed |
| 6 | `CVE-2026-27145` | `caddy` | `stdlib` | `v1.26.3` | amd64+arm64 | still present at the exact bound package/version |
| 7 | `CVE-2026-42504` | `caddy` | `stdlib` | `v1.26.3` | amd64+arm64 | still present at the exact bound package/version |
| 8 | `CVE-2026-33630` | `caddy` | `c-ares` | `1.34.6-r0` | amd64+arm64 | still present at the exact bound package/version |
| 9 | `CVE-2026-6276` | `caddy` | `curl,libcurl` | `8.19.0-r0` | amd64+arm64 | still present at the exact bound package/version |
| 10 | `GHSA-hrxh-6v49-42gf` | `caddy` | `google.golang.org/grpc` | `v1.81.0` | amd64+arm64 | still present at the exact bound package/version |
| 11 | `GHSA-hrxh-6v49-42gf` | `php-frankenphp-8.3-8.4` | `google.golang.org/grpc` | `v1.81.1` | amd64+arm64 | upstream artifact moved but remains unpatched |
| 12 | `CVE-2026-5773` | `caddy` | `curl,libcurl` | `8.19.0-r0` | amd64+arm64 | still present at the exact bound package/version |
| 13 | `CVE-2026-39822` | `caddy` | `stdlib` | `v1.26.3` | amd64+arm64 | still present at the exact bound package/version |
| 14 | `GHSA-r277-6w6q-xmqw` | `php-frankenphp-8.3-8.4` | `github.com/getkin/kin-openapi` | `v0.140.0` | amd64+arm64 | upstream artifact moved but remains unpatched |
| 15 | `CVE-2026-57433` | `php-frankenphp-8.3-8.4` | `libperl5.36,perl,perl-base,perl-modules-5.36` | `5.36.0-7+deb12u3` | amd64+arm64 | upstream artifact moved but remains unpatched |
| 16 | `CVE-2026-42497` | `php-frankenphp-8.3-8.4` | `libperl5.36,perl,perl-base,perl-modules-5.36` | `5.36.0-7+deb12u3` | amd64+arm64 | upstream artifact moved but remains unpatched |
| 17 | `CVE-2026-9538` | `php-frankenphp-8.3-8.4` | `libperl5.36,perl,perl-base,perl-modules-5.36` | `5.36.0-7+deb12u3` | amd64+arm64 | upstream artifact moved but remains unpatched |
| 18 | `CVE-2026-48962` | `php-frankenphp-8.3-8.4` | `libperl5.36,perl,perl-base,perl-modules-5.36` | `5.36.0-7+deb12u3` | amd64+arm64 | upstream artifact moved but remains unpatched |
| 19 | `CVE-2026-57432` | `php-8.3-8.4` | `libperl5.36,perl,perl-base,perl-modules-5.36` | `5.36.0-7+deb12u3` | amd64+arm64 | upstream artifact moved but remains unpatched |
| 20 | `CVE-2026-6653` | `php-8.3-8.4` | `libxml2` | `2.9.14+dfsg-1.3~deb12u6` | amd64+arm64 | upstream artifact moved but remains unpatched |
| 21 | `CVE-2026-8286` | `php-8.3-8.4` | `curl,libcurl4` | `7.88.1-10+deb12u15` | amd64+arm64 | upstream artifact moved but remains unpatched |
| 22 | `CVE-2026-8927` | `php-8.3-8.4` | `curl,libcurl4` | `7.88.1-10+deb12u15` | amd64+arm64 | upstream artifact moved but remains unpatched |
| 23 | `CVE-2026-12064` | `php-8.3-8.4` | `curl,libcurl4` | `7.88.1-10+deb12u15` | amd64+arm64 | upstream artifact moved but remains unpatched |
| 24 | `CVE-2026-7598` | `php-8.3-8.4` | `libssh2-1` | `1.10.0-3+b1` | amd64+arm64 | upstream artifact moved but remains unpatched |
| 25 | `CVE-2023-2953` | `php-8.3-8.4` | `libldap-2.5-0` | `2.5.13+dfsg-5` | amd64+arm64 | upstream artifact moved but remains unpatched |
| 26 | `CVE-2025-69720` | `php-8.3-8.4` | `libtinfo6,ncurses-base,ncurses-bin` | `6.4-4` | amd64+arm64 | upstream artifact moved but remains unpatched |
| 27 | `CVE-2026-53615` | `php-8.3-8.4` | `bsdutils,libblkid1,libmount1,libsmartcols1,libuuid1,mount,ut` | `1:2.38.1-5+deb12u3,2.38.1-5+deb12u3` | amd64+arm64 | upstream artifact moved but remains unpatched |
| 28 | `CVE-2026-54369` | `php-8.3-8.4` | `libacl1` | `2.3.1-3` | amd64+arm64 | upstream artifact moved but remains unpatched |
| 29 | `CVE-2026-41992` | `php-8.3-8.4` | `gzip` | `1.12-1` | amd64+arm64 | upstream artifact moved but remains unpatched |
| 30 | `CVE-2026-56211` | `php-frankenphp-8.3-8.4` | `libaom3` | `3.6.0-1+deb12u2` | amd64+arm64 | ownership boundary changed |
| 31 | `CVE-2026-56208` | `php-frankenphp-8.3-8.4` | `libaom3` | `3.6.0-1+deb12u2` | amd64+arm64 | ownership boundary changed |
| 32 | `CVE-2026-56209` | `php-frankenphp-8.3-8.4` | `libaom3` | `3.6.0-1+deb12u2` | amd64+arm64 | ownership boundary changed |
| 33 | `CVE-2026-56210` | `php-frankenphp-8.3-8.4` | `libaom3` | `3.6.0-1+deb12u2` | amd64+arm64 | ownership boundary changed |
| 34 | `CVE-2023-39616` | `php-frankenphp-8.3-8.4` | `libaom3` | `3.6.0-1+deb12u2` | amd64+arm64 | ownership boundary changed |
| 35 | `CVE-2026-6276` | `php-8.3-8.4` | `curl,libcurl4` | `7.88.1-10+deb12u15` | amd64+arm64 | upstream artifact moved but remains unpatched |
| 36 | `CVE-2026-42496` | `nginx` | `perl-base` | `5.36.0-7+deb12u3` | amd64+arm64 | still present at the exact bound package/version |
| 37 | `CVE-2026-8376` | `nginx` | `perl-base` | `5.36.0-7+deb12u3` | amd64+arm64 | still present at the exact bound package/version |
| 38 | `CVE-2026-57432` | `nginx` | `perl-base` | `5.36.0-7+deb12u3` | amd64+arm64 | still present at the exact bound package/version |
| 39 | `CVE-2023-45853` | `nginx` | `zlib1g` | `1:1.2.13.dfsg-1` | amd64+arm64 | still present at the exact bound package/version |
| 40 | `CVE-2025-69720` | `nginx` | `libtinfo6,ncurses-base,ncurses-bin` | `6.4-4` | amd64+arm64 | still present at the exact bound package/version |
| 41 | `CVE-2026-41992` | `nginx` | `gzip` | `1.12-1` | amd64+arm64 | still present at the exact bound package/version |
| 42 | `CVE-2026-53615` | `nginx` | `bsdutils,libblkid1,libmount1,libsmartcols1,libuuid1,mount,ut` | `1:2.38.1-5+deb12u3,2.38.1-5+deb12u3` | amd64+arm64 | still present at the exact bound package/version |
| 43 | `CVE-2026-54369` | `nginx` | `libacl1` | `2.3.1-3` | amd64+arm64 | still present at the exact bound package/version |
| 44 | `CVE-2026-56852` | `caddy` | `golang.org/x/text` | `v0.37.0` | amd64+arm64 | still present at the exact bound package/version |
| 45 | `CVE-2026-8458` | `php-8.3-8.4` | `curl,libcurl4` | `7.88.1-10+deb12u15` | amd64+arm64 | upstream artifact moved but remains unpatched |
| 46 | `CVE-2026-58050` | `php-8.3-8.4` | `libssh2-1` | `1.10.0-3+b1` | amd64+arm64 | upstream artifact moved but remains unpatched |
| 47 | `CVE-2026-46600` | `caddy` | `golang.org/x/net` | `v0.55.0` | amd64+arm64 | still present at the exact bound package/version |
| 48 | `CVE-2026-46600` | `caddy` | `stdlib` | `v1.26.3` | amd64+arm64 | still present at the exact bound package/version |
| 49 | `CVE-2026-39821` | `caddy` | `stdlib` | `v1.26.3` | amd64+arm64 | still present at the exact bound package/version |
| 50 | `CVE-2026-33818` | `caddy` | `stdlib` | `v1.26.3` | amd64+arm64 | still present at the exact bound package/version |
| 51 | `CVE-2026-56853` | `caddy` | `stdlib` | `v1.26.3` | amd64+arm64 | still present at the exact bound package/version |
| 52 | `CVE-2026-56858` | `caddy` | `stdlib` | `v1.26.3` | amd64+arm64 | still present at the exact bound package/version |
| 53 | `CVE-2026-56859` | `caddy` | `stdlib` | `v1.26.3` | amd64+arm64 | still present at the exact bound package/version |
| 54 | `CVE-2026-56860` | `caddy` | `stdlib` | `v1.26.3` | amd64+arm64 | still present at the exact bound package/version |
| 55 | `CVE-2026-56862` | `caddy` | `stdlib` | `v1.26.3` | amd64+arm64 | still present at the exact bound package/version |
| 56 | `CVE-2026-14456` | `php-8.3-8.4` | `libssl3,openssl` | `3.0.20-1~deb12u2` | amd64+arm64 | upstream artifact moved but remains unpatched |
| 57 | `CVE-2026-14456` | `nginx` | `libssl3,openssl` | `3.0.20-1~deb12u2` | amd64+arm64 | still present at the exact bound package/version |
| 58 | `CVE-2026-53613` | `php-8.3-8.4` | `bsdutils,libblkid1,libmount1,libsmartcols1,libuuid1,mount,ut` | `1:2.38.1-5+deb12u3,2.38.1-5+deb12u3` | amd64+arm64 | upstream artifact moved but remains unpatched |
| 59 | `CVE-2026-53613` | `nginx` | `bsdutils,libblkid1,libmount1,libsmartcols1,libuuid1,mount,ut` | `1:2.38.1-5+deb12u3,2.38.1-5+deb12u3` | amd64+arm64 | still present at the exact bound package/version |

| refreshed classification | count |
|---|---|
| still present at the exact bound package/version | **27** |
| absent | **0** |
| installed version changed | **0** |
| fix now available | **0** |
| upstream artifact moved but remains unpatched | **26** |
| evidence unavailable | **0** |
| selector no longer resolves | **0** |
| ownership boundary changed | **6** |
| **total** | **59** |

## 5b. CORRECTIONS TO THIS DOCUMENT — 2026-08-27

This audit is a decision input. Two of its cells were materially wrong and are
retracted here rather than silently rewritten, because a reader who acted on the
original text would have reached a different decision.

### C-1 — G21 clearing floor was INCOMPLETE

| | |
|---|---|
| was | exit condition: *"a FrankenPHP image is published vendoring `kin-openapi 0.141.0` or later"* |
| is | an official **consumable** FrankenPHP artifact embedding `kin-openapi >= 0.144.0` |
| why it was wrong | Trivy reports per-CVE FixedVersions `0.141.0` (CVE-2026-76905) and `0.142.0` (CVE-2026-77354). The same binary also carries `GHSA-r277-6w6q-xmqw` (CRITICAL, fixed `0.144.0`). Acting on `0.141.0` would clear the two HIGH findings and **leave the CRITICAL one**. |
| blast radius if acted on | a maintainer could accept an artifact believing the group cleared, while a CRITICAL finding remained ungoverned |
| ledger status | **the ledger was always correct** — both authorized records state `>= 0.144.0` and explicitly *"NOT 0.141.0 or 0.142.0"*. Only this audit's prose was wrong. |

`fix_available: true` on those records is **scanner metadata** (a `FixedVersion` exists for the module) and is NOT a claim that a consumable remediation is available to Foundry.

### C-2 — G03 asserted a Foundry remediation path that does not exist

| | |
|---|---|
| was | *"a Foundry-side removal path exists today and is not blocked on upstream"* |
| is | **no contract-preserving Foundry remediation exists today** |
| disproven by | the ownership investigation merged as `5cfe665` (#224), which built and measured every candidate |

Proven determination, replacing the retracted claim:

- Foundry selects **GD**;
- the upstream-owned `install-php-extensions` helper selects **AVIF and its dependency chain**;
- **Debian owns and patches `libaom3`**;
- **no contract-preserving Foundry remediation exists today**;
- package purge removes `libavif15` too and **breaks GD loading entirely** (not just AVIF);
- `IPE_GD_WITHOUTAVIF=1` is **ineffective on Debian 12** — the knob lives in the `< 12` arm;
- disabling AVIF is a **capability deprecation**, not remediation;
- a **Debian Trixie migration** is a separate major-distribution change.

The records' *source attribution* still needs correcting — they name the base, and the base does not ship the package — but that is an attribution fix, not a remediation path.

### C-3 — the expiring population is 61 records, not 59

This document was bound to the ledger at sha256 `babc8971…` (59 exceptions). The
maintainer-authorized `kin-openapi` records landed as `d369f20` (#220). At master
`d4f1f6f` the ledger is sha256 `babb3fb9…` with **61 exceptions, 57 expiring
2026-08-31 and 4 expiring 2026-09-01**. The two advisories described in section 7
as having *no ledger record* now have records.

### C-4 — what "suspension" means, and the four kinds of work an option can owe

**Suspension does not remove the risk.** It withdraws the affected artifacts from
supported production availability, eliminating supported deployment exposure while
the underlying vulnerability remains in the withdrawn images and in anything
already pulled. Any wording that says suspension "removes" or "eliminates" the
risk is wrong and must not be used in a decision packet.

Every option is scored on four independent axes. They are routinely conflated,
and conflating them is how a decision acquires unbudgeted cost:

| axis | question |
|---|---|
| **image rebuild owed** | does any production image byte change? |
| **acceptance owed** | is prior acceptance evidence staled, and for which children? |
| **governance/policy evidence owed** | must a policy, ledger record or evidence artifact change, and must a gate prove it fails closed? |
| **publication/promotion owed** | is any registry, tag or visibility action required? |

Worked example — **G03 option B (suspend the FrankenPHP family)**: image rebuild
owed **NO** (no Dockerfile or image byte changes); acceptance owed **NO** (no child
is rebuilt); governance/policy evidence owed **YES** — fail-closed suspension and
release-path enforcement must be recorded and proven, not merely intended;
publication/promotion owed **NO** under the current refusal stub, but a withdrawal
action would be owed the moment publication is enabled.

## 5c. UPSTREAM RE-VERIFICATION — 2026-08-27T09:11Z–09:24Z

Independent recheck of everything that could have changed. Every row states its
source, retrieval time, and the immutable digest actually resolved.

| subject | source | retrieved (UTC) | tag | immutable digest | installed version | tag moved? | consumable patched artifact? |
|---|---|---|---|---|---|---|---|
| `libaom3` bookworm | security-tracker.debian.org `source-package/aom` | 2026-08-27T09:11:47Z | — | — | bookworm `3.6.0-1+deb12u2`; **bookworm-security `3.6.0-1+deb12u1` (OLDER)** | n/a | **NO** |
| `libaom3` CVE status | same, per-CVE pages | 2026-08-27T09:19:26Z | — | — | all six CVEs **vulnerable** in bookworm and bookworm-security | n/a | **NO** |
| DSA-6411-1 | security-tracker.debian.org | 2026-08-27T09:19:11Z | — | — | fixes 56208/56209/56210/56211 in **trixie only** (`3.12.1-1+deb13u1`) | n/a | **NO for bookworm** |
| apt policy in current base | `dunglas/frankenphp` base, `apt-cache policy` | 2026-08-27T09:16:58Z | `1-php8.3-bookworm` | `sha256:a00d750e…` (amd64) | candidate `3.6.0-1+deb12u2`; `libaom*` **not installed in base** | n/a | **NO** |
| retained child | `foundry-staging` by digest | 2026-08-27T09:20:09Z | — | `sha256:54992c07…` | `libaom3 3.6.0-1+deb12u2`; `--only-upgrade` → *already the newest* | n/a | **NO** |
| FrankenPHP release | `repos/dunglas/frankenphp/releases/latest` (redirects to `php/frankenphp`) | 2026-08-27T09:12:12Z | `v1.12.7` | — | released 2026-08-07T07:49:19Z | — | — |
| FrankenPHP 8.3 | `docker buildx imagetools inspect` | 2026-08-27T09:13:04Z | `1-php8.3-bookworm` | index `sha256:55dc84d1…`; amd64 `sha256:a00d750e…`; arm64 `sha256:388fdcaa…` | `kin-openapi v0.140.0`, `grpc v1.81.1` | **index moved, but BOTH Foundry platforms unchanged** (only `linux/arm`) | **NO** |
| FrankenPHP 8.4 | same | 2026-08-27T09:13:29Z | `1-php8.4-bookworm` | index `sha256:4484f5fc…`; amd64 `sha256:447ac21c…`; arm64 `sha256:da669918…` | `kin-openapi v0.140.0`, `grpc v1.81.1` | yes, both Foundry platforms | **NO — movement is not remediation** |
| clearing floor | OSV `POST /v1/query` | 2026-08-27T09:15:17Z | — | — | fixed: 76905→`0.141.0`, 77354→`0.142.0`, GHSA-r277→`0.144.0`, GHSA-jpcw→`0.144.0` | — | floor = **`>= 0.144.0`** |
| `caddy:2-alpine` | `docker buildx imagetools inspect` | 2026-08-27T09:22:55Z | `2-alpine` | `sha256:5f5c8640…` | — | **NOT moved** — equals the cohort pin | **NO** |
| nginx base | same | 2026-08-27T09:23:16Z | `1.28-bookworm` | `sha256:cd33960e…` | — | **NOT moved** — equals the cohort pin | **NO** |

**Disappearance check.** All 20 retained child digests rescanned buildless against a
newly frozen database `trivy-db v2+updated:2026-08-27T02:16:59Z` (downloaded
2026-08-27T09:17:36Z) — deliberately NOT the `2026-08-25T13:00:57Z` snapshot this
document was built on. Result: **0 findings gone, 0 severity changes, 0 newly
appearing FixedVersions** on any ledger-backing finding. Confirmed with a second
scanner artifact (`aquasec/trivy@sha256:4bbf3824…`): identical sets. The
`fix now available = 0` bucket is unchanged under a two-day-newer database.

**Newly appearing findings, ungoverned today** (not present when this document was written):

| advisory | package @ version | children | FixedVersion | ledger |
|---|---|---|---|---|
| CVE-2026-11822 | `libsqlite3-0 @ 3.40.1-2+deb12u2` | all 16 PHP-family | none (deferred) | **no record** |
| CVE-2026-11824 | `libsqlite3-0 @ 3.40.1-2+deb12u2` | all 16 PHP-family | none (deferred) | **no record** |
| CVE-2026-14456 | `libssl3`, `libcrypto3 @ 3.5.7-r0` (Alpine) | `caddy/prod` ×2 | **`3.5.8-r0`** | **no record** — the existing CVE-2026-14456 records are scoped `php-8.3-8.4` and `nginx` on Debian `3.0.20-1~deb12u2` |

The `caddy` case vindicates the deliberate exclusion recorded in the ledger — Alpine,
a different package build, a different advisory — and that advisory has now landed
there, with a fix available. A fourth `kin-openapi` advisory
(`GHSA-jpcw-4wr7-c3vq` / CVE-2026-73502, floor `0.144.0`) also matches `v0.140.0`
and is in neither the risk packet nor the ledger.

**Renewing all 61 records does not restore a green reconciliation** while these
three remain ungoverned.

## 6. Phase 2 — consolidated decisions, one row per root-cause group

The 59 records reduce to **21 root-cause groups**, keyed on the upstream owner
and the vulnerable component at its exact version — deliberately not on the
image, because the same Debian source package at the same build is one problem
whether it surfaces on `nginx` or on the PHP family, and grouping by image would
present it as several.

Column meanings: *fix availability* is what the frozen scanner reports for the
observed build. *Upstream status* is the measured state of the pinned upstream
artifact. *Existing expiry* is the date the record stops being valid — both
gates compare `expires_at <= today`, so the date shown is the first date on
which the record is **invalid**, not a "valid through" date. *Proposed next
expiry* is a proposal only; the maintainer role decides, and no date in this
column has been written anywhere.

| # | root cause / upstream owner | ledger entries | advisories | component and observed version | affected selectors | arch directly evidenced | fix availability (frozen DB) | upstream status | reachability (as recorded) | existing expiry | proposed disposition | proposed next expiry if continued | exit condition | consequence of refusal |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| G01 | Debian bookworm security — `perl` | 2, 3, 15, 16, 17, 18, 19, 36, 37, 38 (10) | CVE-2026-8376, CVE-2026-9538, CVE-2026-42496, CVE-2026-42497, CVE-2026-48962, CVE-2026-57432, CVE-2026-57433 | `perl`, `perl-base`, `perl-modules-5.36`, `libperl5.36` @ `5.36.0-7+deb12u3` | `php-8.3-8.4`, `php-frankenphp-8.3-8.4`, `nginx` | amd64+arm64 | none — no fixed version offered | PHP and FrankenPHP base heads moved and still ship `5.36.0-7+deb12u3`; nginx base tag unmoved | not-reachable-under-intended-use | 2026-08-31 | continue as accepted risk — maintainer decision; no removal is supportable, the finding is present at the bound version on every in-scope child | 2026-11-30 | Debian bookworm publishes a fixed `perl` source package, or the images move to a base line that does | ten records lapse; reconciliation refuses the findings as ungoverned and every PHP-family and nginx child fails the release gate |
| G02 | Caddy project — Go toolchain (`stdlib`) statically linked into the Caddy binary | 6, 7, 13, 48, 49, 50, 51, 52, 53, 54, 55 (11) | CVE-2026-27145, CVE-2026-33818, CVE-2026-39821, CVE-2026-39822, CVE-2026-42504, CVE-2026-46600, CVE-2026-56853, CVE-2026-56858, CVE-2026-56859, CVE-2026-56860, CVE-2026-56862 | `stdlib` @ `v1.26.3` | `caddy` | amd64+arm64 | yes — fixed toolchains published (`1.25.11`/`1.26.4` through `1.25.13`/`1.26.6`/`1.27.0-rc.3` depending on advisory) | `caddy:2-alpine` tag has NOT moved; no rebuilt upstream image exists to re-pin to | mixed as recorded: conditionally-reachable-outside-the-certified-topology, conditionally-reachable-via-consuming-application, unresolved-no-concrete-path-identified | 2026-08-31 | continue as accepted risk with a shortened window — a fix exists upstream and the exposure is a pinning lag, not an unfixable defect; no Foundry rebuild can relink a vendored toolchain | 2026-09-30 | the `caddy:2-alpine` tag publishes an image built with a fixed Go toolchain and the pin is moved to it | eleven records lapse; `caddy/prod` fails reconciliation on both platforms and cannot be released |
| G03 | Foundry Dockerfile (`php-frankenphp` gd/AVIF layer) — `libaom3` | 5, 30, 31, 32, 33, 34 (6) | CVE-2023-6879, CVE-2023-39616, CVE-2026-56208, CVE-2026-56209, CVE-2026-56210, CVE-2026-56211 | `libaom3` @ `3.6.0-1+deb12u2` | `php-frankenphp-8.3-8.4` | amd64+arm64 | none — no fixed version offered | package is **absent from both the pinned FrankenPHP base and the current head**; it enters through the Foundry `install-php-extensions … gd` step | conditionally-reachable-via-consuming-application (four records carry an encoder-only analysis) | 2026-08-31 | **RETRACTED AND REPLACED 2026-08-27.** The claim this cell previously made about a Foundry-side removal path is WITHDRAWN — it is quoted in full and dispositioned in section 5b (C-2), and is not restated here so it cannot be skim-read as live. It was disproven by the ownership investigation merged as `5cfe665` (#224). PROVEN DETERMINATION: Foundry selects GD; the upstream-owned `install-php-extensions` helper selects AVIF and its dependency chain; **Debian owns and patches `libaom3`**; **no contract-preserving Foundry remediation exists today**; package purge takes `libavif15` with it and breaks GD loading entirely; `IPE_GD_WITHOUTAVIF=1` is INEFFECTIVE on Debian 12 (the knob lives in the `< 12` arm); disabling AVIF is a CAPABILITY DEPRECATION, not remediation; a Debian Trixie migration is a separate major-distribution change. The records' source attribution still needs correcting — they name the base, and the base does not ship the package — but that is an attribution fix, not a remediation path | 2026-10-31 | either the gd build stops pulling AVIF support, or a fixed `libaom` reaches the packages the Foundry layer installs | six records lapse; both FrankenPHP versions fail reconciliation on both platforms — on top of the two already-ungoverned advisories in section 7 |
| G04 | Debian bookworm security — `curl` | 21, 22, 23, 35, 45 (5) | CVE-2026-6276, CVE-2026-8286, CVE-2026-8458, CVE-2026-8927, CVE-2026-12064 | `curl`, `libcurl4` @ `7.88.1-10+deb12u15` | `php-8.3-8.4` | amd64+arm64 | none — no fixed version offered | PHP base heads moved and still ship `7.88.1-10+deb12u15` | conditionally-reachable-via-consuming-application | 2026-08-31 | continue as accepted risk — maintainer decision; conditional reachability means the decision turns on consumer guidance, not on new scan data | 2026-10-31 | Debian bookworm publishes a fixed `curl` source package | five records lapse; all six PHP-family children fail reconciliation on both platforms |
| G05 | Debian bookworm security — `util-linux` | 27, 42, 58, 59 (4) | CVE-2026-53613, CVE-2026-53615 | `bsdutils` @ `1:2.38.1-5+deb12u3`; `libblkid1`, `libmount1`, `libsmartcols1`, `libuuid1`, `mount`, `util-linux`, `util-linux-extra` @ `2.38.1-5+deb12u3` | `php-8.3-8.4`, `nginx` | amd64+arm64 | none — no fixed version offered | PHP base heads moved and still ship the same eight builds; nginx base tag unmoved | not-reachable-under-intended-use (53615) and unresolved-no-concrete-path-identified (53613) | 2026-08-31 (53615), 2026-09-01 (53613) | continue as separate records — the two advisories were deliberately not merged and both still match independently; the per-package `package_versions` binding, including the `bsdutils` epoch split, was re-verified and holds exactly | 2026-11-30 (53615), 2026-09-30 (53613) | Debian bookworm publishes a fixed `util-linux` source package | four records lapse; PHP-family and nginx children fail reconciliation on both platforms |
| G06 | Alpine aports — `curl` | 9, 12 (2) | CVE-2026-5773, CVE-2026-6276 | `curl`, `libcurl` @ `8.19.0-r0` | `caddy` | amd64+arm64 | yes — `8.20.0-r0` | `caddy:2-alpine` tag has NOT moved | not-reachable-under-intended-use | 2026-08-31 | continue as accepted risk with a shortened window — a fixed aport exists and the exposure is a pinning lag | 2026-09-30 | the `caddy:2-alpine` tag publishes an image carrying `curl 8.20.0-r0` or later and the pin is moved | two records lapse; `caddy/prod` fails reconciliation on both platforms |
| G07 | Debian bookworm security — `zlib` | 1, 39 (2) | CVE-2023-45853 | `zlib1g` @ `1:1.2.13.dfsg-1` | `php-8.3-8.4`, `nginx` | amd64+arm64 | none — Debian records will-not-fix (the affected MiniZip is not shipped) | PHP base heads moved and still ship the same build; nginx base tag unmoved | not-reachable-under-intended-use | 2026-08-31 | continue as accepted risk — zlib is an essential package and cannot be removed; the will-not-fix disposition means no upstream fix is coming on this line | 2026-11-30 | the images move to a base line whose `zlib` is not affected | two records lapse; PHP-family and nginx children fail reconciliation |
| G08 | Debian bookworm security — `libssh2` | 24, 46 (2) | CVE-2026-7598, CVE-2026-58050 | `libssh2-1` @ `1.10.0-3+b1` | `php-8.3-8.4` | amd64+arm64 | none — no fixed version offered | PHP base heads moved and still ship `1.10.0-3+b1` | conditionally-reachable-via-consuming-application | 2026-08-31 | continue as accepted risk — maintainer decision | 2026-10-31 | Debian bookworm publishes a fixed `libssh2` source package | two records lapse; all six PHP-family children fail reconciliation |
| G09 | Debian bookworm security — `ncurses` | 26, 40 (2) | CVE-2025-69720 | `libtinfo6`, `ncurses-base`, `ncurses-bin` @ `6.4-4` | `php-8.3-8.4`, `nginx` | amd64+arm64 | none — no fixed version offered | PHP base heads moved and still ship `6.4-4`; nginx base tag unmoved | not-reachable-under-intended-use | 2026-08-31 | continue as accepted risk — maintainer decision | 2026-11-30 | Debian bookworm publishes a fixed `ncurses` source package | two records lapse; PHP-family and nginx children fail reconciliation |
| G10 | Debian bookworm security — `acl` | 28, 43 (2) | CVE-2026-54369 | `libacl1` @ `2.3.1-3` | `php-8.3-8.4`, `nginx` | amd64+arm64 | none — no fixed version offered | PHP base heads moved and still ship `2.3.1-3`; nginx base tag unmoved | not-reachable-under-intended-use | 2026-08-31 | continue as accepted risk — maintainer decision | 2026-11-30 | Debian bookworm publishes a fixed `acl` source package | two records lapse; PHP-family and nginx children fail reconciliation |
| G11 | Debian bookworm security — `gzip` | 29, 41 (2) | CVE-2026-41992 | `gzip` @ `1.12-1` | `php-8.3-8.4`, `nginx` | amd64+arm64 | none — no fixed version offered | PHP base heads moved and still ship `1.12-1`; nginx base tag unmoved | not-reachable-under-intended-use | 2026-08-31 | continue as accepted risk — maintainer decision | 2026-11-30 | Debian bookworm publishes a fixed `gzip` source package | two records lapse; PHP-family and nginx children fail reconciliation |
| G12 | Debian bookworm security — `openssl` | 56, 57 (2) | CVE-2026-14456 | `openssl`, `libssl3` @ `3.0.20-1~deb12u2` | `php-8.3-8.4`, `nginx` | amd64+arm64 | none — no fixed version offered | PHP base heads moved and still ship `3.0.20-1~deb12u2`; nginx base tag unmoved | unresolved-no-concrete-path-identified | 2026-09-01 | these records are already on a declared second bounded bridge carrying `reaffirmed_at: 2026-08-20`; the reaffirmation's four claims were re-verified point by point and all four hold. A third bridge would need its own justification on its own evidence, which this lane does not supply and cannot authorise | 2026-09-30 only if the maintainer records a fresh justification; otherwise no proposal | Debian bookworm publishes a fixed `openssl`, or a patched official base is published on a tracked tag | two records lapse; PHP-family and nginx children fail reconciliation on both platforms |
| G13 | Debian bookworm security — `sqlite3` | 4 (1) | CVE-2025-7458 | `libsqlite3-0` @ `3.40.1-2+deb12u2` | `php-8.3-8.4` | amd64+arm64 | none — no fixed version offered | PHP base heads moved and still ship `3.40.1-2+deb12u2` | conditionally-reachable-via-consuming-application | 2026-08-31 | continue as accepted risk — maintainer decision | 2026-10-31 | Debian bookworm publishes a fixed `sqlite3` source package | one record lapses; all six PHP-family children fail reconciliation |
| G14 | Debian bookworm security — `libxml2` | 20 (1) | CVE-2026-6653 | `libxml2` @ `2.9.14+dfsg-1.3~deb12u6` | `php-8.3-8.4` | amd64+arm64 | none — no fixed version offered | PHP base heads moved and still ship `2.9.14+dfsg-1.3~deb12u6` | conditionally-reachable-via-consuming-application | 2026-08-31 | continue as accepted risk — maintainer decision | 2026-10-31 | Debian bookworm publishes a fixed `libxml2` source package | one record lapses; all six PHP-family children fail reconciliation |
| G15 | Debian bookworm security — `openldap` | 25 (1) | CVE-2023-2953 | `libldap-2.5-0` @ `2.5.13+dfsg-5` | `php-8.3-8.4` | amd64+arm64 | none — no fixed version offered | PHP base heads moved and still ship `2.5.13+dfsg-5` | conditionally-reachable-via-consuming-application | 2026-08-31 | continue as accepted risk — maintainer decision | 2026-10-31 | Debian bookworm publishes a fixed `openldap` source package | one record lapses; all six PHP-family children fail reconciliation |
| G16 | Alpine aports — `c-ares` | 8 (1) | CVE-2026-33630 | `c-ares` @ `1.34.6-r0` | `caddy` | amd64+arm64 | yes — `1.34.8-r0` | `caddy:2-alpine` tag has NOT moved | not-reachable-under-intended-use | 2026-08-31 | continue as accepted risk with a shortened window — a fixed aport exists and the exposure is a pinning lag | 2026-09-30 | the `caddy:2-alpine` tag publishes an image carrying `c-ares 1.34.8-r0` or later and the pin is moved | one record lapses; `caddy/prod` fails reconciliation on both platforms |
| G17 | Caddy project — `google.golang.org/grpc` vendored into the Caddy binary | 10 (1) | GHSA-hrxh-6v49-42gf | `google.golang.org/grpc` @ `v1.81.0` | `caddy` | amd64+arm64 | yes — `1.82.1` | `caddy:2-alpine` tag has NOT moved | not-reachable-under-intended-use | 2026-08-31 | continue as accepted risk with a shortened window — no Foundry rebuild can relink a vendored module | 2026-09-30 | the Caddy image publishes a build vendoring `grpc 1.82.1` or later and the pin is moved | one record lapses; `caddy/prod` fails reconciliation on both platforms |
| G18 | Caddy project — `golang.org/x/net` vendored into the Caddy binary | 47 (1) | CVE-2026-46600 | `golang.org/x/net` @ `v0.55.0` | `caddy` | amd64+arm64 | yes — `0.56.0` | `caddy:2-alpine` tag has NOT moved | unresolved-no-concrete-path-identified | 2026-08-31 | continue as accepted risk with a shortened window; reachability is recorded as unresolved, so the re-decision turns on impact and appetite, not on scan data | 2026-09-30 | the Caddy image publishes a build vendoring `x/net 0.56.0` or later and the pin is moved | one record lapses; `caddy/prod` fails reconciliation on both platforms |
| G19 | Caddy project — `golang.org/x/text` vendored into the Caddy binary | 44 (1) | CVE-2026-56852 | `golang.org/x/text` @ `v0.37.0` | `caddy` | amd64+arm64 | yes — `0.39.0` | `caddy:2-alpine` tag has NOT moved | conditionally-reachable-outside-the-certified-topology | 2026-08-31 | continue as accepted risk with a shortened window | 2026-09-30 | the Caddy image publishes a build vendoring `x/text 0.39.0` or later and the pin is moved | one record lapses; `caddy/prod` fails reconciliation on both platforms |
| G20 | FrankenPHP project — `google.golang.org/grpc` vendored into the FrankenPHP binary | 11 (1) | GHSA-hrxh-6v49-42gf | `google.golang.org/grpc` @ `v1.81.1` | `php-frankenphp-8.3-8.4` | amd64+arm64 | yes — `1.82.1` | base tag moved; **the new head still vendors `v1.81.1`**, so re-pinning would not remediate | not-reachable-under-intended-use | 2026-08-31 | continue as accepted risk with a shortened window; record explicitly that a rebuild on the current head cannot clear it, contradicting the `rebuild_can_remediate=yes` the ownership heuristic returns | 2026-09-30 | a FrankenPHP image is published vendoring `grpc 1.82.1` or later and the pin is moved to it | one record lapses; both FrankenPHP versions fail reconciliation on both platforms |
| G21 | FrankenPHP project — `github.com/getkin/kin-openapi` vendored into the FrankenPHP binary | 14 (1) | GHSA-r277-6w6q-xmqw | `github.com/getkin/kin-openapi` @ `v0.140.0` | `php-frankenphp-8.3-8.4` | amd64+arm64 | yes — `0.144.0` | base tag moved; **the new head still vendors `v0.140.0`**, so re-pinning would not remediate | not-reachable-under-intended-use | 2026-08-31 | continue as accepted risk with a shortened window; this is the same binary and the same module version as the two ungoverned advisories in section 7, so one upstream publication clears all three | 2026-09-30 | **CORRECTED 2026-08-27** — an official CONSUMABLE FrankenPHP artifact embedding `kin-openapi >= 0.144.0`. This cell previously read `0.141.0 or later`, which is an INCOMPLETE clearing floor: Trivy reports per-CVE FixedVersions of `0.141.0` (CVE-2026-76905) and `0.142.0` (CVE-2026-77354), but the same binary also carries `GHSA-r277-6w6q-xmqw` (CRITICAL, fixed `0.144.0`). Moving only to 0.141.x or 0.142.x would clear the two HIGH findings and LEAVE THE CRITICAL ONE. `fix_available: true` remains correct scanner metadata and is not a claim that remediation is available | one record lapses; both FrankenPHP versions fail reconciliation on both platforms |

Group sizes sum to 59. No group proposes removal: removal requires the finding
to have disappeared, the installed version to have moved, or a patched official
base to exist, and **none of those three conditions is met by any of the 59** —
so there is no record for which regression proof could be produced, and none is
offered. Nothing in this table is proposed in order to obtain a green acceptance
verdict; four of the twenty children fail reconciliation today and continue to
fail it for the reason in section 7.

## 6b. SELECTOR APPENDIX — what each family label in section 6 actually governs

Section 6 uses family labels for width. They are NOT selectors. The governed
selector is the immutable cohort string in the ledger, and it is what
`reconcile-vulnerabilities.sh` matches. A label such as "php" governs nothing.

| governed selector (ledger `image:`) | production children it resolves to |
|---|---|
| `caddy` | caddy:prod  (1 image x 2 platforms = 2 children) |
| `nginx` | nginx:prod  (1 image x 2 platforms = 2 children) |
| `php-8.3-8.4` | php-cli:8.3, php-cli:8.4, php-fpm:8.3, php-fpm:8.4, php-worker:8.3, php-worker:8.4  (6 images x 2 platforms = 12 children) |
| `php-frankenphp-8.3-8.4` | php-frankenphp:8.3, php-frankenphp:8.4  (2 images x 2 platforms = 4 children) |

Production matrix is `MATRIX_COUNT=10` images x 2 platforms = **20 children**.
The cohort selectors are immutable by design: re-adding a future PHP line (for
example the experimental 8.5 cohort) cannot widen a historical risk decision,
because `php-8.3-8.4` and `php-frankenphp-8.3-8.4` cannot reach it.

## 7. Two advisories with no ledger record at all

Not part of the 59, and reported here because omitting them would understate the
cohort's state. Reconciliation FAILS on all four FrankenPHP children — both
versions on both platforms — with:

| advisory | module | installed | fixed | children affected |
|---|---|---|---|---|
| CVE-2026-76905 | `github.com/getkin/kin-openapi` | `v0.140.0` | `0.141.0` | `php-frankenphp/8.3` and `8.4`, `linux/amd64` and `linux/arm64` |
| CVE-2026-77354 | `github.com/getkin/kin-openapi` | `v0.140.0` | `0.142.0` | `php-frankenphp/8.3` and `8.4`, `linux/amd64` and `linux/arm64` |

Both are also present in the **current** upstream FrankenPHP base heads at the
same module version, so no rebuild and no re-pin available today clears them.
They are the same module and the same version as group G21. This lane does not
propose a record for them: creating one is a risk acceptance, which is the
maintainer role's decision and not an analysis output.

The other sixteen children pass reconciliation: `caddy/prod` 19 governed
findings, `nginx/prod` 27 governed plus 5 not-affected, each PHP-family child 42
governed plus 5 not-affected.

## 8. Per-child reconciliation results

| child | platform | verdict | findings | governed | not-affected | ungoverned |
|---|---|---|---|---|---|---|
| `caddy/prod` | linux/amd64 | PASS | 19 | 19 | 0 | 0 |
| `caddy/prod` | linux/arm64 | PASS | 19 | 19 | 0 | 0 |
| `nginx/prod` | linux/amd64 | PASS | 32 | 27 | 5 | 0 |
| `nginx/prod` | linux/arm64 | PASS | 32 | 27 | 5 | 0 |
| `php-cli/8.3` | linux/amd64 | PASS | 47 | 42 | 5 | 0 |
| `php-cli/8.3` | linux/arm64 | PASS | 47 | 42 | 5 | 0 |
| `php-cli/8.4` | linux/amd64 | PASS | 47 | 42 | 5 | 0 |
| `php-cli/8.4` | linux/arm64 | PASS | 47 | 42 | 5 | 0 |
| `php-fpm/8.3` | linux/amd64 | PASS | 47 | 42 | 5 | 0 |
| `php-fpm/8.3` | linux/arm64 | PASS | 47 | 42 | 5 | 0 |
| `php-fpm/8.4` | linux/amd64 | PASS | 47 | 42 | 5 | 0 |
| `php-fpm/8.4` | linux/arm64 | PASS | 47 | 42 | 5 | 0 |
| `php-frankenphp/8.3` | linux/amd64 | **FAIL** | 81 | 75 | 4 | 2 |
| `php-frankenphp/8.3` | linux/arm64 | **FAIL** | 81 | 75 | 4 | 2 |
| `php-frankenphp/8.4` | linux/amd64 | **FAIL** | 81 | 75 | 4 | 2 |
| `php-frankenphp/8.4` | linux/arm64 | **FAIL** | 81 | 75 | 4 | 2 |
| `php-worker/8.3` | linux/amd64 | PASS | 47 | 42 | 5 | 0 |
| `php-worker/8.3` | linux/arm64 | PASS | 47 | 42 | 5 | 0 |
| `php-worker/8.4` | linux/amd64 | PASS | 47 | 42 | 5 | 0 |
| `php-worker/8.4` | linux/arm64 | PASS | 47 | 42 | 5 | 0 |

## 9. Not done in this lane

- `policies/vulnerability-exceptions.yaml` was not edited. No `expires_at`,
  `reaffirmed_at`, `reaffirmed_by` or `reaffirmation_evidence` field was written.
- No exception was renewed or extended. Every date in the *proposed next expiry*
  column is a proposal for the maintainer role and exists only in this document.
- No record was removed. See section 6 for why no removal is supportable.
- No production acceptance rebuild, no QEMU matrix, no publication, promotion,
  production signing, release or tag creation.
- `tests/vulnerability-policy/`, `tests/release/`,
  `.github/workflows/native-arm64-smoke.yml` and
  `policies/native-arch-requirements.yaml` were not touched.

## 10. Reproducing this

```console
$ bash scripts/rescan-retained-cohort.sh \
    --evidence docs/audits/acceptance-multiarch-2026-08-20/acceptance-evidence.json \
    --out docs/audits/expiry-refresh-2026-08-25
$ python3 scripts/classify-expiry-refresh.py \
    --refresh-dir docs/audits/expiry-refresh-2026-08-25 \
    --moved-bases <(python3 -c "…") \
    --out docs/audits/expiry-refresh-2026-08-25/refresh-classification.json
```

The rescan is buildless and reuses an already-frozen database, so a repeat run
against the same frozen cache reproduces the same numbers. Reproducing against a
*newer* database is a different measurement and must be recorded as one.
