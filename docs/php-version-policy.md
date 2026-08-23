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
| 8.5 | 2027-12-31 | 2029-12-31 | **not offered** — see below |

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

## PHP 8.5 — the current, tracked gap

PHP 8.5 has been in **active upstream support** since 2025-11 and Foundry does
not offer it. Entry criteria 1–4 are believed satisfiable today; criterion 5, and
the acceptance criteria on #106 itself, are **not**:

> *"PHP 8.5 is built, scanned, signed, attested, smoke-tested, and released on
> amd64/arm64."*

Signing, attestation and release are **closed** platform-wide pending the
protected exposure path (#139). Adding four `php-*/8.5` image definitions would
also change the authoritative image matrix from ten to fourteen, which
`scripts/assert-image-matrix.sh` enforces and which several release-evidence
paths assume.

So #106 stays open, and the honest interim state is what the inventory now
records: `php-8.5`, `support_state: active` (that field tracks **upstream**),
`foundry_release_state: blocked-does-not-build`, `used_by: []`.

### The blocker is measured, not inferred (2026-08-23)

The four `php-*/8.5` image definitions were added to the matrix in an earlier
batch **without ever building a child**, then withdrawn once a build was
attempted. PHP 8.5 does not merely lack release plumbing — **the images do not
build**:

```text
Installing shared extensions: .../no-debug-non-zts-20250925/
cp: cannot stat 'modules/*': No such file or directory
make: *** [Makefile:89: install-modules] Error 1
```

Reproduced twice on `linux/amd64` (~160 s each) with php-redis **6.1.0** and
again with **6.3.0**, so it is not the redis pin. The failing component sits
inside the `docker-php-ext-install` list and is not yet isolated.

**Do not re-add 8.5 to `MATRIX_IMAGES` until a representative child builds.**
Left in the matrix it fails 8 of 28 children at build time — after the native
half of a ~10-hour acceptance run has already been spent.

**Unblocking order:** isolate the extension failure → one built `php-cli/8.5`
child with a real digest → scan the **child**, never the base → child-level
governance on amd64 → arm64 evidence → matrix expansion to fourteen → #139
publication path → release.

## What this policy does not do

- It does not create the consumer notification channel. That is **#125**; this
  file states *when* a notice is owed, not *how* it is delivered.
- It does not set support periods for the Foundry **product** (as distinct from
  the upstream PHP lines). Also #125.
- It does not decide the Debian release under each PHP line — see
  [migration/debian-13-trixie.md](migration/debian-13-trixie.md).
