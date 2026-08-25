# Maintainer decision packet — `kin-openapi` CVE-2026-76905 / CVE-2026-77354

**Status: DECISION REQUIRED. No decision is made here, and nothing was changed
in `policies/vulnerability-exceptions.yaml`.**

Prepared 2026-08-25 against `master` = `a828e077d153b581e9906a537a945dcf4304b9ec`.
Every claim below is backed by a command whose output is reproduced in this
directory (`evidence.json`, checksums in `SHA256SUMS`).

This packet exists because two fixable HIGH findings on `php-frankenphp` are
present in the shipping children and matched by **no** record in the ledger, and
because the entire ledger expires within a week. Both are maintainer decisions.

## Contents

| file | what it is |
|---|---|
| `README.md` | this packet — Task A, the two new advisories |
| `exception-expiry-review.md` | Task B — re-evaluation of all 59 expiring entries |
| `evidence.json` | machine-readable evidence bundle for both |
| `SHA256SUMS` | checksums of the evidence files |

## Measurement identity

| | |
|---|---|
| scanner | `trivy` 0.73.0 (local binary, `/opt/homebrew/bin/trivy`) |
| vulnerability DB | schema 2, `UpdatedAt: 2026-08-25 00:59:57.325486492 +0000 UTC`, `DownloadedAt: 2026-08-25 07:48:46 +0000 UTC` |
| flags | `--scanners vuln --severity HIGH,CRITICAL --format json` — **no `--ignore-unfixed`, no ignore file** |
| children | built locally from the repository's own Dockerfiles, exactly as `.github/workflows/scan-images.yml` builds them (`docker buildx build <ctx>`) |
| advisory source | OSV API (`https://api.osv.dev/v1/vulns/<id>`), retrieved 2026-08-25 |
| upstream module source | Go module proxy (`https://proxy.golang.org/github.com/getkin/kin-openapi/@v/list`), retrieved 2026-08-25 |
| registry source | `docker buildx imagetools inspect`, Docker Hub tags API, retrieved 2026-08-25 |

Because this was measured on a `darwin/arm64` workstation, `linux/arm64` children
are **native** and `linux/amd64` children are **QEMU-emulated**. Per
`docs/audits/acceptance-multiarch-2026-08-20/README.md` that is acceptable for
build/scan/reconciliation evidence and is **not** native-runtime evidence.
Upstream artifacts were scanned per-platform directly from the registry with
`--platform`, which involves no emulation at all.

## 1. Every inherited fact, re-verified

None of the following was taken on trust; each row was measured today.

| inherited claim | verdict | evidence |
|---|---|---|
| `CVE-2026-76905` affects `github.com/getkin/kin-openapi` | **CONFIRMED** | OSV: `GHSA-mmfr-pmjx-hw9w`, Go ecosystem, range `[0.10.0, 0.141.0)` |
| `CVE-2026-77354` affects `github.com/getkin/kin-openapi` | **CONFIRMED** | OSV: `GHSA-xhj3-7xw9-vr34`, Go ecosystem, range `[0.124.0, 0.142.0)` |
| installed module is `v0.140.0` | **CONFIRMED** | Trivy, `usr/local/bin/frankenphp` (gobinary), every artifact scanned |
| fixed in `0.141.0` / `0.142.0` respectively | **CONFIRMED, but incomplete — see §2** | OSV fixed events; both tags exist on the Go proxy |
| severity HIGH | **CONFIRMED** | GitHub advisory DB `severity: HIGH` for both; Trivy reports `HIGH` for both |
| present in FrankenPHP children only | **CONFIRMED** | present on `php-frankenphp` 8.3/8.4; absent from `php-cli`, `php-fpm`, `php-worker`, `nginx`, `caddy` (§4) |
| absent from the ledger | **CONFIRMED** | `grep -rn "CVE-2026-76905\|CVE-2026-77354" .` → no matches on `a828e07` |
| no patched official upstream artifact | **CONFIRMED — and re-measured against an artifact that did not exist yesterday** | §3 |

### Facts I found to be WRONG or materially incomplete

1. **"reported fixed in 0.141.0/0.142.0" is true but is not the version that
   clears this component.** The same binary also carries `GHSA-r277-6w6q-xmqw`
   (**CRITICAL**, fixed `0.144.0`) which *is* ledgered. A hypothetical upstream
   move to `0.142.x` would clear the two new HIGHs and leave the CRITICAL in
   place. The single clearing floor for all three `kin-openapi` advisories is
   **`>= 0.144.0`** — identical to the exit condition already recorded on #79.
   Treating `0.141.0`/`0.142.0` as "the fix" would understate the exit condition.

2. **"HIGH severity" describes these two findings, not the component.** The
   `frankenphp` gobinary carries **four** HIGH/CRITICAL findings, not two:
   one CRITICAL (`GHSA-r277-6w6q-xmqw`), and three HIGH
   (`CVE-2026-76905`, `CVE-2026-77354`, `GHSA-hrxh-6v49-42gf` on grpc).

3. **The "there is no newer official artifact" framing was stale by one day.**
   The upstream `1-php8.3-bookworm` tag head **moved at 2026-08-25T04:20 UTC** —
   after the 2026-08-24 disposition on #79 — from `sha256:295e22a1…` to
   `sha256:9725e5d498b49d01036baec385c07ff787f96ce60a1b79250ce103f6d92dbfda`. A
   newer official artifact **does** exist. It was scanned today and still ships
   `kin-openapi v0.140.0` and `grpc v1.81.1`, so the *conclusion* survives, but
   only because it was re-measured rather than inherited.

4. **Minor date correction to the 2026-08-24 disposition on #79.** It describes
   upstream release `1.12.7` as "published 2026-08-20". The GitHub release
   `v1.12.7` was published **2026-08-07T07:49:19Z**; 2026-08-20 is when the
   `php8.4` image tags were (re)built, and the `php8.3` image tags were rebuilt
   again on 2026-08-25. Release date and image build date are different facts.

## 2. The two advisories

### CVE-2026-76905 — `GHSA-mmfr-pmjx-hw9w`

- kin-openapi `openapi3filter`: nil-pointer panic in `ConvertErrors` on a
  malformed `multipart/form-data` body — unauthenticated DoS.
- CWE-476. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`. GitHub severity **HIGH**.
- Affected range `>= 0.10.0, < 0.141.0`. Installed `v0.140.0` → **in range**.
- OSV published `2026-08-21T20:43:07Z`; GitHub-reviewed `2026-08-21T20:55:46Z`;
  `nvd_published_at: null` (no NVD record yet).
- <https://osv.dev/vulnerability/GHSA-mmfr-pmjx-hw9w> (retrieved 2026-08-25)

### CVE-2026-77354 — `GHSA-xhj3-7xw9-vr34`

- kin-openapi: uncontrolled resource consumption in `openapi3filter` `deepObject`
  query-parameter decoding.
- CWE-400, CWE-789. `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N`.
  GitHub severity **HIGH**.
- Affected range `>= 0.124.0, < 0.142.0`. Installed `v0.140.0` → **in range**.
- OSV published `2026-08-21T20:44:47Z`; GitHub-reviewed `2026-08-21T20:56:56Z`;
  `nvd_published_at: null`.
- <https://osv.dev/vulnerability/GHSA-xhj3-7xw9-vr34> (retrieved 2026-08-25)

**Why they are absent from the ledger and not a governance failure.** Both were
published `2026-08-21`. The multi-architecture acceptance run that produced the
current evidence baseline (`docs/audits/acceptance-multiarch-2026-08-20`) used a
**frozen** database identity `v2+updated:2026-08-20T13:14:11Z` — one day older
than the advisories. They could not have been seen by it. They are visible now
because today's database is `2026-08-25T00:59:57Z`.

**Upstream fix availability.** Both fix versions are real, published Go module
releases, not placeholders:

```text
v0.140.0  2026-06-02T15:47:47Z   <- installed
v0.141.0  2026-07-10T08:49:45Z   <- fixes CVE-2026-76905
v0.142.0  2026-07-11T22:04:27Z   <- fixes CVE-2026-77354
v0.144.0  2026-07-23T23:08:15Z   <- fixes GHSA-r277-6w6q-xmqw (already ledgered)
v0.147.0  2026-08-18T14:12:06Z   <- current latest
```

Source: `https://proxy.golang.org/github.com/getkin/kin-openapi/@v/list` and
`.../@v/<version>.info`, retrieved 2026-08-25.

## 3. Is there a patched OFFICIAL upstream artifact? — measured, not assumed

A vulnerability database says a *module* is fixed. It says nothing about whether
`dunglas/frankenphp` has absorbed it. So the registry was inspected directly and
every candidate artifact was scanned.

Current tag heads (`docker buildx imagetools inspect`, 2026-08-25):

| tag | index digest | last pushed |
|---|---|---|
| `dunglas/frankenphp:1-php8.3-bookworm` | `sha256:9725e5d498b49d01036baec385c07ff787f96ce60a1b79250ce103f6d92dbfda` | 2026-08-25T04:19:59Z |
| `dunglas/frankenphp:1-php8.4-bookworm` | `sha256:a6e78fd9da1640784cb07d606e313ae9f6013b1de39741643f0c256ecd87c8ae` | 2026-08-20T04:38:20Z |
| `dunglas/frankenphp:latest` (= `1.12.7-php8-trixie`) | `sha256:e2fb833fac0135f9a070647a8c70eb80ba282de4a035de56b6a3371cb555eca0` | 2026-08-20 |

Repository pins (`images/php-frankenphp/<ver>/Dockerfile:15`):

| image | pinned base digest | is it the current tag head? |
|---|---|---|
| `php-frankenphp/8.3` | `sha256:ae143d38335e4d8faf3f73205c91b69562b4154a85bf3fdd9ef63d59c8727ead` | **no** — tag moved 2026-08-25 |
| `php-frankenphp/8.4` | `sha256:cef99f108009ed60c6d60261c8edc17104fce06aafaf24c21119cd4b4c704aa7` | **no** — tag head is `a6e78fd9…` |

Go-module inventory of every one of those artifacts, per platform
(`trivy image --platform … --severity HIGH,CRITICAL`, 2026-08-25):

| artifact | platform | `kin-openapi` | `grpc` | HIGH/CRIT total |
|---|---|---|---|---|
| pinned 8.3 `ae143d38…` | linux/arm64 | v0.140.0 | v1.81.1 | 256 |
| pinned 8.3 `ae143d38…` | linux/amd64 | v0.140.0 | v1.81.1 | 256 |
| pinned 8.4 `cef99f10…` | linux/arm64 | v0.140.0 | v1.81.1 | 256 |
| pinned 8.4 `cef99f10…` | linux/amd64 | v0.140.0 | v1.81.1 | 256 |
| **current** 8.3 head `9725e5d4…` | linux/arm64 | v0.140.0 | v1.81.1 | 256 |
| **current** 8.3 head `9725e5d4…` | linux/amd64 | v0.140.0 | v1.81.1 | 256 |
| **current** 8.4 head `a6e78fd9…` | linux/arm64 | v0.140.0 | v1.81.1 | 256 |
| **current** 8.4 head `a6e78fd9…` | linux/amd64 | v0.140.0 | v1.81.1 | 256 |
| `latest` (Debian 13.6 trixie) `e2fb833f…` | linux/amd64 | v0.140.0 | v1.81.1 | 185 |

The newest upstream release is **v1.12.7**, published `2026-08-07T07:49:19Z`
(`gh api repos/php/frankenphp/releases`); there is no 1.13 or 2.x line. Every
`bookworm`, `trixie` and `latest` artifact built from it carries the same
`kin-openapi v0.140.0`.

**Conclusion: no patched official upstream artifact exists as of 2026-08-25 —
including one published this morning.** Bumping the pinned digest — to the
current head, to `latest`, or across to the trixie line — would change a digest
and remediate none of the four gobinary findings.

## 4. Exactly which children and platforms are affected

Children were built from this repository's Dockerfiles and scanned, so this is
child evidence, not base evidence. That distinction is load-bearing here: the
FrankenPHP Dockerfile runs
`apt-get purge -y --auto-remove gcc g++ cpp make autoconf binutils dpkg-dev libc6-dev linux-libc-dev m4 patch re2c`,
which removes an enormous distro-CVE surface that the base carries:

| artifact | HIGH/CRIT total | of which `linux-libc-dev` |
|---|---|---|
| upstream base `cef99f10…` (8.4) | 256 | **181** |
| **child** `php-frankenphp` 8.4, linux/arm64 | **81** | **0** |

Reporting the base numbers as if they were the product would overstate the
finding count by roughly 3×. The four gobinary findings, however, survive the
purge unchanged — the Dockerfile only strips a file capability from
`/usr/local/bin/frankenphp` (`setcap -r`) and never rebuilds it.

All four FrankenPHP children were built and scanned — 8.3 and 8.4 on both
`linux/amd64` and `linux/arm64` — and all four report the identical gobinary set.
Child scan, target `usr/local/bin/frankenphp` (gobinary), 81 HIGH/CRITICAL total each:

```text
GHSA-r277-6w6q-xmqw  github.com/getkin/kin-openapi  v0.140.0 -> 0.144.0  CRITICAL  fixed
CVE-2026-76905       github.com/getkin/kin-openapi  v0.140.0 -> 0.141.0  HIGH      fixed
CVE-2026-77354       github.com/getkin/kin-openapi  v0.140.0 -> 0.142.0  HIGH      fixed
GHSA-hrxh-6v49-42gf  google.golang.org/grpc         v1.81.1  -> 1.82.1   HIGH      fixed
```

Affected / not affected, from measured child and per-platform upstream evidence:

| image | 8.3 | 8.4 | `linux/amd64` | `linux/arm64` |
|---|---|---|---|---|
| `php-frankenphp` | **affected** | **affected** | **affected** (built + reconciled, both versions) | **affected** (built + reconciled, both versions) |
| `php-cli` | not affected | not affected | — | — |
| `php-fpm` | not affected | not affected | — | — |
| `php-worker` | not affected | not affected | — | — |
| `nginx` | n/a | n/a | not affected | not affected |
| `caddy` | n/a | n/a | not affected | not affected |

`caddy` is worth stating explicitly because it *does* carry `grpc` findings and
Go `stdlib` findings: its binary does **not** embed `kin-openapi` at all, so
neither new CVE applies to it. `php-cli`/`php-fpm`/`php-worker`/`nginx` ship no
Go binary and therefore no gobinary result section.

Architecture: both new CVEs are identical on `linux/amd64` and `linux/arm64`.
`kin-openapi` is a pure-Go module and the same version is linked into both
per-platform manifests — verified on all four per-platform upstream scans above
**and** on all four locally built children.

The repository's own gate agrees. Run today against those children,
`scripts/reconcile-vulnerabilities.sh` refuses all four:

```text
REFUSE: 2 ungoverned CRITICAL/HIGH finding(s) in php-frankenphp/8.3:
  CVE-2026-76905  github.com/getkin/kin-openapi v0.140.0  no in-scope exception in the ledger
  CVE-2026-77354  github.com/getkin/kin-openapi v0.140.0  no in-scope exception in the ledger
```

and PASSES on `caddy/prod`, `nginx/prod` and all six `php-cli`/`php-fpm`/
`php-worker` children. Full per-image verdicts: `exception-expiry-review.md`.
`php-frankenphp` 8.5 exists in the tree but is **not** in the `scan-images.yml`
gate matrix and is not published; it is out of scope for this packet.

## 5. Classification under ADR-0001

Per `docs/ownership-boundary.md` and
`docs/decisions/adr-0001-upstream-only-binary-consumption.md`:

```text
advisories       CVE-2026-76905 (GHSA-mmfr-pmjx-hw9w), CVE-2026-77354 (GHSA-xhj3-7xw9-vr34)
module           github.com/getkin/kin-openapi  v0.140.0
images           php-frankenphp/8.3, php-frankenphp/8.4
architectures    linux/amd64 and linux/arm64 — identical module version on both
owner            upstream-vendor-binary
rebuild fixes it NO
root_cause_key   upstream-vendor-binary:github.com/getkin/kin-openapi:v0.140.0
```

Three statements this packet makes explicitly, because ADR-0001 requires them:

1. **`upstream-vendor-binary`.** The module is statically linked into
   `/usr/local/bin/frankenphp`, a binary Foundry consumes and does not build.
   `scripts/classify-remediation-owner.sh` returns exactly this owner for
   `--image php-frankenphp/8.4 --package github.com/getkin/kin-openapi`.
2. **No Foundry source compilation.** Compiling, forking, patching or vendoring
   the FrankenPHP binary is not proposed here and is not approved:
   `ownership_change.approved_adrs` is empty and enforced by
   `scripts/assert-upstream-ownership.sh`. Nothing in this lane compiled anything.
3. **No claim that rebuilding the same Dockerfile remediates them.** It does
   not. Re-running Foundry's own layers over the same upstream digest cannot
   move a vendored Go module. Neither can bumping to the current upstream digest
   — measured in §3, which is the stronger statement.

## 6. Consolidation with #79 — CONSOLIDATE, do not file new tickets

**Decision on shape (not on risk): these two advisories belong on #79.** No new
issue was created and no per-image ticket was created.

Grounds:

- **Same root cause key.** #79 already tracks
  `upstream-vendor-binary:github.com/getkin/kin-openapi:v0.140.0`. These two
  advisories are additional advisory identities against *that same module at
  that same version in that same binary*.
- **Same exit condition.** #79's exit condition is an official artifact with
  `kin-openapi >= 0.144.0`. That single event clears `GHSA-r277-6w6q-xmqw`,
  `CVE-2026-76905` and `CVE-2026-77354` simultaneously, because `0.144.0`
  exceeds both `0.141.0` and `0.142.0`. There is no scenario in which these need
  separate tracking.
- **#79 already records the premise.** Its 2026-08-24 disposition states that the
  newest 1.x base still ships `kin-openapi v0.140.0` and `grpc v1.81.1`, and
  already flags both CVEs as ungoverned owner work. Re-verified today (§3), plus
  the newer 8.3 head that appeared since.
- **`policies/rebuild-ticket-contract.yaml`** exists to prevent the #88–#95
  shape: eight per-image tickets with no CVE, package, version or owner.
  Splitting one upstream module version across per-image tickets reproduces
  exactly that failure.

What consolidation does **not** do: it does not govern the findings. #79 is a
tracking issue; the gate reads `policies/vulnerability-exceptions.yaml`, and
these advisories appear in neither. That is the maintainer decision in §7.

## 7. The maintainer's three options — presented neutrally, no recommendation

Common ground for all three: `scripts/reconcile-vulnerabilities.sh` requires
every CRITICAL/HIGH finding to be matched, per image and per architecture, by an
in-scope unexpired record. Two findings on `php-frankenphp` 8.3 and 8.4 currently
match nothing, so the required checks `scan php-frankenphp 8.3` and
`scan php-frankenphp 8.4` fail on the next run. **Doing nothing is not a neutral
state; it is option 3 with the failure left unannounced.**

### Option 1 — exact, version-bound, architecture-bound, expiring governance

Add two exception records to `policies/vulnerability-exceptions.yaml`, each bound
to one advisory id, `image: php-frankenphp-8.3-8.4`,
`package: [github.com/getkin/kin-openapi]`, `installed_version: v0.140.0`,
`verified_architectures: [linux/amd64, linux/arm64]`, `fix_available: true`, and
a hard `expires_at` in the future.

Concrete consequences:

- The two required `scan php-frankenphp` checks pass again; `php-frankenphp`
  8.3/8.4 remain releasable.
- Foundry ships, on purpose and on the record, a binary with a known
  unauthenticated-DoS path, with the accepted-risk rationale that the path is in
  `openapi3filter` and no shipped Caddyfile wires an OpenAPI validation handler
  (`grep -rniE "openapi|validat|deepobject|multipart"` over all four shipped
  Caddyfiles → **0 matches**, verified 2026-08-25). That is the same reachability
  argument already recorded for `GHSA-r277-6w6q-xmqw`; it is an argument about
  configuration, and consumers can override the Caddyfile.
- Binding `installed_version: v0.140.0` means the record self-invalidates if the
  module moves — including moving to a different *still vulnerable* version.
  That closes the unpinned-entry asymmetry described in
  `docs/ownership-boundary.md` for these two records specifically.
- Reversible: delete the two records. Because
  `scripts/ci/assert-no-stale-exceptions.sh` fails CI when an active exception
  matches no finding, the records cannot outlive the problem silently.
- The expiry date is itself a decision, and §Task B is directly relevant: if the
  new records are dated `2026-08-31` they join a 55-entry cliff; if dated later
  they become the only entries surviving it.

### Option 2 — suspend the affected family

Stop shipping `php-frankenphp` 8.3 and 8.4 until upstream ships a patched
artifact: remove them from the `scan-images.yml` / release matrices, or withdraw
per `docs/release-withdrawal.md`.

Concrete consequences:

- No governed acceptance of an unauthenticated DoS is required, and the gate is
  satisfied without a suppression, because the artifact is no longer produced.
- The FrankenPHP path disappears for consumers. Per #79, `php-app-template`'s
  strict gate is *already* blocked on this family; the certified nginx path
  (`php-cli`/`php-fpm`/`php-worker` + `nginx`) is unaffected and carries no
  gobinary findings at all.
- Withdrawal is consumer-visible and has its own governance
  (`docs/release-withdrawal.md`, `docs/audits/withdrawals/`); un-suspending later
  is a re-admission, not a no-op.
- Duration is open-ended and controlled by a third party: it lasts until upstream
  moves, which has not happened in the 31 days since #79 was filed.

### Option 3 — wait for a patched official upstream artifact

Change nothing; keep #79 as the tracker; keep re-measuring with
`bash scripts/assert-supply-chain-inputs.sh --check-upstream` on the
`dependency-drift.yml` schedule.

Concrete consequences:

- `php-frankenphp` 8.3 and 8.4 **cannot pass** their required scan checks from
  the next scan onward, because two HIGHs match no ledger record. The family is
  effectively suspended — but by gate failure rather than by an explicit
  decision, and without a withdrawal record.
- No new risk is accepted and no new record is written; the fail-closed posture
  holds by construction.
- Detection of the fix stays automatic: when upstream ships `>= 0.144.0` the
  findings disappear.
- The waiting period is not bounded by anything Foundry controls. Upstream
  rebuilt the 8.3 image as recently as this morning without moving the module.

**No option is chosen in this packet. All three are live, and all three are the
maintainer's to take.**

## 8. What this lane did NOT do

- Did **not** modify `policies/vulnerability-exceptions.yaml` — not one line.
- Did **not** create, widen, narrow, renew or re-date any exception.
- Did **not** dispatch acceptance, publish, promote, sign, or release anything.
- Did **not** compile, fork or vendor any upstream binary.
- Did **not** open a new issue or a per-image ticket (see §6).
- Did **not** touch `config/base-images.env`, whose six-Dockerfile drift is
  separately flagged on #79 and is an approval act, not a documentation act.
