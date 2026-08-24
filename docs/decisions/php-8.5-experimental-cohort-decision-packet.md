# Decision packet — PHP 8.5 experimental cohort, `linux/amd64`

**Status: OPEN — NOTHING HERE HAS BEEN DECIDED.** Prepared 2026-08-24 from the
child evidence at
[`docs/audits/experimental-php-8.5-linux-amd64/`](../audits/experimental-php-8.5-linux-amd64/README.md),
source revision `e84c2155cfcde8e179a007b13653bc8e124535a4`.

**No exception was added, widened or renewed to produce this document.**
`policies/vulnerability-exceptions.yaml` is byte-identical to master. Writing a
packet is not deciding one; the ledger changes only when the maintainer decides.

## Why a packet at all, when nothing ships

PHP 8.5 is an experimental cohort. It is not in `MATRIX_IMAGES`, is never
published, and cannot reach acceptance, promotion, sealing, signing or
publication — the plan refuses each by name. So the honest question is not "how
do we accept this risk" but **"what would have to be true before any of it could
ship, and what is already true today."**

The evidence answers the second half. This packet states the first half, in the
form of decisions a maintainer must make deliberately rather than by default.

## The measurement

```text
children          4, linux/amd64, built from e84c2155, one frozen database
scanner           aquasec/trivy@sha256:016eae51…  (digest-pinned)
database          trivy-db:v2+updated:2026-08-24T13:01:06.952742724Z
execution         emulated on an arm64 host  (build/scan evidence, NOT native runtime)
target            the CHILDREN.  linux-libc-dev findings: 0 on all four
```

| child | CRITICAL | HIGH | total | installed packages |
|---|---|---|---|---|
| `php-cli/8.5/linux/amd64` | 6 | 41 | 47 | 127 |
| `php-fpm/8.5/linux/amd64` | 6 | 41 | 47 | 127 |
| `php-worker/8.5/linux/amd64` | 6 | 41 | 47 | 128 |
| `php-frankenphp/8.5/linux/amd64` | 17 | 64 | 81 | 181 |

47 on the Debian trio is the **same number the accepted PHP 8.4 child reports**,
and for the same reason: the build toolchain is purged, so the headers the base
carries are not in the child at all.

## Root causes, grouped

35 distinct advisories reduce to **15 root causes**. Every one is a package
Foundry consumes and does not build (ADR-0001), so the remediation owner is
upstream in every case.

### Group A — an analogous 8.3/8.4 decision exists at the IDENTICAL tuple

Same source package, same installed version, same `fix_available: false` (except
where noted). **The 8.5 children are ungoverned anyway**, because every PHP
selector is bound to the immutable `php-8.3-8.4` cohort. That is the control
working, not a defect.

| root cause | version | advisories | families | existing 8.3/8.4 record |
|---|---|---|---|---|
| `perl` (`perl-base` only) | `5.36.0-7+deb12u3` | CVE-2026-13221, CVE-2026-42496, CVE-2026-42497, CVE-2026-48962, CVE-2026-57432, CVE-2026-57433, CVE-2026-8376, CVE-2026-9538 | all 4 | mixed: exceptions on `php-8.3-8.4`, `not_affected` on `php-{cli,fpm,worker}-8.3-8.4`, exceptions on `php-frankenphp-8.3-8.4` |
| `libaom3` | `3.6.0-1+deb12u2` | CVE-2023-39616, CVE-2023-6879, CVE-2026-56208, CVE-2026-56209, CVE-2026-56210, CVE-2026-56211 | frankenphp | exceptions on `php-frankenphp-8.3-8.4` |
| `curl` / `libcurl4` | `7.88.1-10+deb12u15` | CVE-2026-12064, CVE-2026-6276, CVE-2026-8286, CVE-2026-8458, CVE-2026-8927 | all 4 | exceptions on `php-8.3-8.4` |
| `util-linux` (8 binaries) | `2.38.1-5+deb12u3` / `1:2.38.1-5+deb12u3` | CVE-2026-53613, CVE-2026-53615 | all 4 | exceptions on `php-8.3-8.4` |
| `libssh2-1` | `1.10.0-3+b1` | CVE-2026-58050, CVE-2026-7598 | all 4 | exceptions on `php-8.3-8.4` |
| `openssl` / `libssl3` | `3.0.20-1~deb12u2` | CVE-2026-14456 | all 4 | exception on `php-8.3-8.4`, **expires 2026-09-01** |
| `zlib1g` | `1:1.2.13.dfsg-1` | CVE-2023-45853 | all 4 | exception on `php-8.3-8.4` |
| `libxml2` | `2.9.14+dfsg-1.3~deb12u6` | CVE-2026-6653 | all 4 | exception on `php-8.3-8.4` |
| `libsqlite3-0` | `3.40.1-2+deb12u2` | CVE-2025-7458 | all 4 | exception on `php-8.3-8.4` |
| `ncurses` (`libtinfo6`, `ncurses-base`, `ncurses-bin`) | `6.4-4` | CVE-2025-69720 | all 4 | exception on `php-8.3-8.4` |
| `libldap-2.5-0` | `2.5.13+dfsg-5` | CVE-2023-2953 | all 4 | exception on `php-8.3-8.4` |
| `libacl1` | `2.3.1-3` | CVE-2026-54369 | all 4 | exception on `php-8.3-8.4` |
| `gzip` | `1.12-1` | CVE-2026-41992 | all 4 | exception on `php-8.3-8.4` |
| `google.golang.org/grpc` | `v1.81.1` | GHSA-hrxh-6v49-42gf (fix 1.82.1) | frankenphp | exception on `php-frankenphp-8.3-8.4`, `fix_available: true` |
| `github.com/getkin/kin-openapi` | `v0.140.0` | GHSA-r277-6w6q-xmqw (fix 0.144.0) | frankenphp | exception on `php-frankenphp-8.3-8.4`, `fix_available: true` |

**The perl group deserves its own note.** The 8.3/8.4 `not_affected` records for
CVE-2026-57433, CVE-2026-42497, CVE-2026-9538 and CVE-2026-48962 are classified
`vulnerable-component-not-installed`: the vulnerable code lives in
`perl-modules-5.36`, and the cli/fpm/worker families carry `perl-base` only. The
same is true of the 8.5 children — their smoke tests assert `Storable`,
`Archive::Tar` and `IO::Compress::Gzip` are absent, and all three assertions
passed. **That is evidence a `not_affected` record could be built from. It is not
a decision, and this document does not make one.**

### Group B — NO record exists for any family, at any version

| advisory | package | installed | fixed | severity | families |
|---|---|---|---|---|---|
| CVE-2026-76905 | `github.com/getkin/kin-openapi` | `v0.140.0` | `0.141.0` | HIGH | frankenphp |
| CVE-2026-77354 | `github.com/getkin/kin-openapi` | `v0.140.0` | `0.142.0` | HIGH | frankenphp |

These are the only genuinely ungoverned root causes in the strong sense: no
exception, no `not_affected`, no selector of any shape reaches them.

**And they are probably not an 8.5 problem.** The ledger already governs
GHSA-r277-6w6q-xmqw against `github.com/getkin/kin-openapi` **`v0.140.0`** for
`php-frankenphp-8.3-8.4` — the *same module at the same version*. The 8.5
FrankenPHP base carries that version too. So on the current database snapshot
these two advisories most likely apply to the **production** `php-frankenphp/8.3`
and `php-frankenphp/8.4` children as well, and are simply newer than the database
their accepted evidence was bound to.

This packet **does not confirm that** — confirming it means scanning the
production frankenphp children, which is a separate, production-scoped action
that was not authorized here. It is flagged because the alternative is knowing it
and not saying so.

## Decisions required

Each of these is a decision the maintainer must make. None is made here.

### D1 — may the experimental cohort carry governance at all?

Today it cannot: there is no selector that reaches `php-8.5` and creating one is
refused by `scripts/experimental/experimental-plan.sh capability php-8.5
governance-selector`.

- **Option 1 (default, no action):** 8.5 stays ungoverned. Correct while it is
  experimental — nothing is published, so nothing is being shipped with
  unaccepted risk. It also means every 8.5 scan will keep reporting 35
  ungoverned advisories, which is *true* and should not be silenced.
- **Option 2:** introduce a **new immutable cohort selector** `php-8.5` (and
  `<family>-8.5`) alongside `php-8.3-8.4`, and decide each root cause afresh
  from 8.5 evidence.
- **NOT AN OPTION:** widening `php-8.3-8.4` to `php-8.3-8.5`, or restoring
  `php-all`. Both are refused by `in_scope()`, and both would retroactively
  govern an artifact the historical decisions were never made from.

### D2 — Group A: re-decide, or leave ungoverned?

15 root causes with an identical-tuple precedent. Re-deciding them is a real
review, not a copy: the 8.3/8.4 decisions were made on 8.3/8.4 evidence, and
"the package version is the same" is an argument, not an authorization.

Bound to D1: with Option 1, nothing to do.

### D3 — Group B: `kin-openapi` CVE-2026-76905 / CVE-2026-77354

Two questions, and the second is more urgent than the first:

1. **For 8.5:** ungoverned, like everything else in the cohort. Falls out of D1.
2. **For production 8.3/8.4:** scan the production `php-frankenphp` children
   under the current database and find out. If they are affected, that is an
   ungoverned finding on a **shipped** family, and it needs its own decision on
   the production timeline — not this one. A fix exists upstream (0.141.0 /
   0.142.0), so the remediation path is a FrankenPHP base bump, consistent with
   ADR-0001. No compilation, no vendoring.

### D4 — arm64

**Nothing may be claimed.** No arm64 8.5 child exists. Any future arm64 claim
needs its own children, its own digests, its own inventories and its own
findings. The plan refuses `linux/arm64` for this cohort so an amd64 result
cannot be quietly promoted into an arm64 one.

### D5 — the 2026-08-31 / 2026-09-01 cohort expiry

Most Group A exceptions expire 2026-08-31; the `openssl` and `util-linux`
bridges expire 2026-09-01. That expiry is a **re-decision date for 8.3/8.4** and
this packet neither renews nor extends it. If D1 Option 2 is ever taken, the 8.5
decisions should be given their own expiry rather than inheriting a date set for
a different cohort.

## What was NOT done, deliberately

- No exception added, widened or renewed. The ledger is untouched.
- No `not_affected` record created, including for the perl group where the
  absence evidence already exists.
- No production child scanned, and no claim made about production 8.3/8.4 beyond
  the flagged, explicitly unconfirmed inference in Group B.
- No arm64 anything.
- No upstream binary compiled, forked, patched or vendored. ADR-0001 is
  unchanged and `ownership_change.approved_adrs` remains empty.
