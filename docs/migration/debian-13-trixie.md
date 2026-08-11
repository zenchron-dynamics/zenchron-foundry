# Debian 13 (trixie) migration plan

**Status:** planned, not started
**Owner:** Zenchron Dynamics / Platform Security *(single maintainer — see #112)*
**Written:** 2026-08-12
**Next review:** 2026-11-12 *(the `review_every_days` cadence in `policies/lifecycle.yaml`)*
**Issue:** #105

## Why now, and why not urgently

Debian 12 (bookworm) is **oldstable**. Debian 13 (trixie) is the current stable.
Bookworm is not expired — it has regular security support to **2028-06-30** and
then LTS to **2030-06-30** — so this is a planned migration with roughly two
years of runway, not a fire.

The reason to write the plan now is the failure mode #105 names: *"an outdated
lifecycle assumption can delay migration until upstream support pressure becomes
urgent."* Until this file existed, `docs/base-image-strategy.md` called bookworm
"the current Debian stable", and nothing in the repository could notice
otherwise.

Lifecycle state is now machine-readable in
[`policies/lifecycle.yaml`](../../policies/lifecycle.yaml) and enforced by
`scripts/assert-lifecycle.sh`, which begins **warning 180 days** before
`support_ends` and **fails** 90 days after it. So the calendar pressure arrives
as a build signal rather than as a surprise.

## What actually gates the move

We do not choose the Debian release. We follow what our upstream bases publish,
and they do not move together:

| base | trixie available? | measured |
| --- | --- | --- |
| `nginxinc/nginx-unprivileged` | **yes** — `stable-trixie`, `mainline-trixie`, `1.28-trixie` all resolve | 2026-08-12 |
| `library/php` (`8.x-cli/fpm-*`) | not yet confirmed for every tag we consume | — |
| `dunglas/frankenphp` (`1-php8.x-*`) | not yet confirmed | — |
| `caddy` | not applicable — Alpine, not Debian | — |

**The gating input is PHP, not nginx.** nginx could move today; moving it alone
would split the platform across two Debian releases, which multiplies the
package-remediation surface (the nginx image already carries a targeted
security-upgrade layer whose package list is bookworm-specific) without reducing
any risk. So: move together, or not yet.

## Compatibility matrix to fill in before committing

Per image family, on **both** architectures:

- [ ] upstream tag exists for trixie and is digest-pinnable
- [ ] all compiled PHP extensions build (`intl`, `pdo_pgsql`, `zip`, `gd`, `redis`)
- [ ] runtime shared libraries still exist under the same package names —
      trixie renames some `lib*` packages, and the nginx image's targeted upgrade
      list (`libssl3`, `libgnutls30`, `libpam*`, `libnghttp2-14`, `perl-base`,
      `zlib1g`, …) must be re-derived rather than copied
- [ ] the attack-surface purge still holds: the `curl → libssh2 → krb5` chain and
      the four nginx dynamic modules must still be removable (#102/#103)
- [ ] UID/GID contract unchanged — 10001 for the PHP families, and whatever the
      trixie `nginx-unprivileged` base uses for nginx (**re-verify: do not assume
      101 carries over**, see #118)
- [ ] read-only rootfs + `cap_drop ALL` + NNP smoke passes
- [ ] healthchecks pass, including the nginx readiness listener added in #127
- [ ] `scripts/reconcile-vulnerabilities.sh` PASSES against a trixie build, or the
      new findings are triaged as a fresh round — trixie has a different CVE
      surface and **every existing exception's `installed_version` binding will
      stop matching**, which is by design and will surface as ungoverned findings

## Exit criteria

The migration is done when all of the following hold, not before:

1. every one of the ten images builds on a digest-pinned trixie base;
2. `bash tests/run-all.sh`, `bash scripts/macro-validate.sh` and every smoke suite
   pass;
3. the vulnerability ledger has been re-reconciled against trixie and contains no
   record whose version binding no longer matches;
4. `policies/lifecycle.yaml` shows `debian-trixie` in `used_by` for all ten
   images and `debian-bookworm` in `used_by: []`;
5. the consumer transition window below has elapsed.

## Consumer transition window

Foundry image tags do not encode the Debian release, so a consumer pulling
`8.4-prod` would cross this boundary silently. That is not acceptable for a base
image, so:

- **announce** at least **90 days** before the first trixie-based publish;
- both lines are **built and scanned in parallel** for at least **30 days** before
  the switch, so a consumer can pin a digest from either;
- the `com.zenchron.base` OCI label already distinguishes them
  (`debian-bookworm` → `debian-trixie`), and is contract-checked per image, so
  the change is machine-detectable by a consumer's inventory tooling;
- the announcement mechanism itself is **#125** (advisory channel) — this plan
  depends on it and does not invent a substitute.

## What this plan deliberately does not do

- **It does not set a start date.** The gating input (upstream PHP trixie tags) is
  not ours; committing to a date we do not control is how a plan becomes fiction.
  The lifecycle gate supplies the pressure instead.
- **It does not migrate nginx early**, for the reason above.
- **It does not promise arm64 parity separately** — arm64 evidence is #139, and
  this migration inherits whatever that resolves to.
