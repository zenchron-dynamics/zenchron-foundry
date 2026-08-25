# PHP version entry and retirement policy

**Owner:** Zenchron Dynamics / Platform Security *(single maintainer — see #112)*
**Written:** 2026-08-12
**Machine-readable state:** [`policies/lifecycle.yaml`](../policies/lifecycle.yaml)
**Issue:** #106

This file says **when a PHP line enters the platform and when it leaves**. The
dates themselves are php.net's, not ours, and are recorded in the inventory with
their source so a reviewer can re-derive them rather than trust a document.

## Support states, and what each one promises a consumer

Every image carries two labels, because they answer different questions:

| label | means |
| --- | --- |
| `com.zenchron.support` | Foundry supports this **image** — it is built, scanned, gated and reconciled |
| `com.zenchron.support_state` | what state the **upstream PHP line** is in |

Before this policy existed, all ten images said `support="supported"` and nothing
distinguished a line in active upstream support from one receiving security
fixes only. A consumer's inventory tooling could not tell PHP 8.3 from 8.4.

| `support_state` | upstream meaning | what Foundry does |
| --- | --- | --- |
| `active` | bug **and** security fixes upstream | recommended for new consumers |
| `security-only` | security fixes only | still built, scanned and gated identically; **recommended only for consumers who have not yet migrated** |
| `not-yet-offered` | in upstream support, no Foundry image exists | tracked as a gap in the inventory, not silence |
| `frozen` | no longer rebuilt; last build remains pullable | see [legacy-php-policy.md](legacy-php-policy.md) |
| `eol` | no upstream security fixes | must not be shipped |

## Current state (php.net, retrieved 2026-08-12)

| line | active support until | security support until | Foundry |
| --- | --- | --- | --- |
| 8.3 | **ended 2025-12-31** | 2027-12-31 | shipped, `security-only` |
| 8.4 | 2026-12-31 | 2028-12-31 | shipped, `active` — **recommended** |
| 8.5 | 2027-12-31 | 2029-12-31 | **not offered** — experimental cohort, `linux/amd64` only; see below |

## Entry criteria — when a new PHP line is added

A line is added when **all** of these hold:

1. it is in **active** upstream support;
2. official `library/php` images exist for every variant we ship
   (`<v>-cli-<debian>`, `<v>-fpm-<debian>`) on **both** amd64 and arm64;
3. a FrankenPHP base exists for it (`dunglas/frankenphp:1-php<v>-<debian>`), or
   the family is explicitly launched without FrankenPHP and that is documented;
4. every compiled extension in `contracts/php-extensions/` builds against it;
5. the full matrix builds, smokes and **reconciles** — a new line that cannot pass
   `scripts/reconcile-vulnerabilities.sh` is not ready regardless of its dates.

**Lead time:** begin the work within **90 days** of a line reaching active
support, so adoption is not gated on us.

## Retirement criteria — when a line leaves

| trigger | action |
| --- | --- |
| line leaves **active** support upstream | flip `support_state` to `security-only`; announce; recommend the next line for new consumers. **Keep building.** |
| **180 days** before upstream security support ends | deprecation notice to consumers; the lifecycle gate begins warning automatically |
| upstream security support **ends** | stop building. Last images remain pullable and become `frozen` under [legacy-php-policy.md](legacy-php-policy.md) — never rebuilt, never rescanned, no update path |
| a line becomes unbuildable before its dates | ADR, then early retirement — do not ship a line whose findings cannot be reconciled |

Retirement is never silent: `com.zenchron.support_state` changes on the image, the
inventory changes, and the lifecycle gate fails the build if the two disagree.

## PHP 8.5 — an EXPERIMENTAL cohort, not a shipped line

PHP 8.5 has been in **active upstream support** since 2025-11 and Foundry does
not offer it. That has not changed. What HAS changed is the reason, and the
reason matters more than the verdict.

**State:** `foundry_release_state: experimental-amd64-only`.

This document and `policies/lifecycle.yaml` must name the SAME value, and
`tests/governance/test_doc_truth_sync.sh` reads both files and fails if they
disagree — the machine-readable line is the authority, this sentence is the
claim, and a claim that drifts from its fact is the #121 defect class.

> **CORRECTED 2026-08-25.** This section previously stated
> `foundry_release_state: blocked-does-not-build` and described the failing
> component as "not yet isolated". Both were false by then. The component WAS
> isolated — `opcache` is statically built into the PHP 8.5 base, so
> `docker-php-ext-install opcache` produces no shared module — and all four
> families build on `linux/amd64` (`blocker.status: RESOLVED 2026-08-23`). The
> retired value is recorded here rather than deleted so a reader who met it in
> an older revision, an older PR, or a cached copy can see that it was withdrawn
> and why, instead of assuming the two revisions describe different images.

**The images build.** They did not, and the failure was real, measured and
specific — see the resolved `blocker` block on the `php-8.5` line in
`policies/lifecycle.yaml`. Two root causes, both Foundry Dockerfile sequencing
rather than anything wrong with PHP 8.5:

1. **`opcache`.** The official PHP 8.5 base already ships Zend OPcache linked
   into the binary. Asking `docker-php-ext-install` to build it produces no
   SHARED module and the build dies at `cp: cannot stat 'modules/*'`. Fixed by
   removing `opcache` from the 8.5 install list only — it is still present,
   still enabled, and now supplied by the base. 8.3 and 8.4 are unchanged.
2. **php-redis 6.1.0.** `ext/standard/php_smart_string.h` was removed in 8.5.
   Pinned 6.3.0.

**Four `linux/amd64` children have been built, smoked, SBOM'd and scanned** —
`php-cli`, `php-fpm`, `php-worker`, `php-frankenphp`. The evidence is committed
under `docs/audits/experimental-php-8.5-linux-amd64/`, one `foundry-child` record
per child, all four under ONE frozen vulnerability database.

### Why it is still not in `MATRIX_IMAGES`

`used_by: []` was an accurate statement about the LINE and said nothing about the
four Dockerfiles, which were left as unreachable dead configuration. That is now
fixed in the other direction: 8.5 is an **enumerated experimental cohort**.

```text
policies/experimental-cohorts.yaml            the registry (which directories)
policies/lifecycle.yaml  (php-8.5)            the authorization (what state)
scripts/experimental/experimental-plan.sh     the ONE canonical plan
scripts/experimental/assert-experimental-isolation.sh   the production-side gate
tests/experimental/test_experimental_plan.sh  reachability AND isolation
```

The plan is explicitly invocable for **build, smoke, extension verification,
SBOM, child vulnerability scanning and evidence generation**, and REFUSES —
each with its own diagnostic — production acceptance, release manifests,
promotion, sealing, signing, publication, and the `php-8.3-8.4` /
`<family>-8.3-8.4` governance selectors.

Neither file can move an image on its own: the registry says which directories
are in the cohort, `policies/lifecycle.yaml` says what state the line is in, and
the plan refuses when they disagree.

### What is still missing before 8.5 could ship

- **No arm64 child exists.** Not "unverified" — *nonexistent*. There is no arm64
  digest, no arm64 installed inventory and no arm64 finding set, and the plan
  refuses `linux/arm64` for this cohort so an amd64 result cannot speak for it.
- **No production contracts.** `contracts/images/` and
  `contracts/php-extensions/` hold production contracts only, and their count is
  asserted against `MATRIX_COUNT`.
- **No governance decisions.** Every PHP selector in
  `policies/vulnerability-exceptions.yaml` is bound to the immutable
  `php-8.3-8.4` cohort, so 8.5 begins **ungoverned by construction** — every
  CRITICAL/HIGH finding on an 8.5 child is currently unaccepted risk. The
  findings and the decisions they demand are set out in
  [decisions/php-8.5-experimental-cohort-decision-packet.md](decisions/php-8.5-experimental-cohort-decision-packet.md).
  **Nothing in that packet has been decided by writing it.**
- **Signing, attestation and release remain closed platform-wide** pending the
  protected exposure path (#139).

**Unblocking order:** maintainer decisions on the 8.5 root causes → production
contracts → arm64 children and their own evidence → matrix expansion → #139
publication path → release. #106 stays open.

## What this policy does not do

- It does not create the consumer notification channel. That is **#125**; this
  file states *when* a notice is owed, not *how* it is delivered.
- It does not set support periods for the Foundry **product** (as distinct from
  the upstream PHP lines). Also #125.
- It does not decide the Debian release under each PHP line — see
  [migration/debian-13-trixie.md](migration/debian-13-trixie.md).
