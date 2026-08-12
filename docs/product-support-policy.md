# Product support policy

**Issue:** #125
**Machine-readable:** [`policies/support-policy.yaml`](../policies/support-policy.yaml)
**Upstream dates:** [`policies/lifecycle.yaml`](../policies/lifecycle.yaml)

Two files, because two different parties make two different promises.
`lifecycle.yaml` records what **upstream** does — when PHP 8.3 leaves security
support, when Debian 12 stops getting fixes. `support-policy.yaml` records what
**Zenchron** commits to on top of that. Upstream dates are read from the first,
never copied into the second: a duplicated EOL date is a second thing to forget.

## What each support state buys you

| state | upstream | Foundry rebuilds | recommended for |
| --- | --- | --- | --- |
| `active` | bug + security fixes | yes | new consumers |
| `security-only` | security fixes only | yes | existing consumers, until you migrate |
| `not-yet-offered` | in support | — no image exists | nobody |
| `frozen` | — | **never** | nobody — migrate |
| `withdrawn` | — | **never** | nobody — act on the advisory |

Current state:

| family | selector | upstream | until |
| --- | --- | --- | --- |
| php-cli / php-fpm / php-worker / php-frankenphp | 8.4 | **active** | 2026-12-31 active, 2028-12-31 security |
| php-cli / php-fpm / php-worker / php-frankenphp | 8.3 | **security-only** since 2025-12-31 | 2027-12-31 |
| nginx | prod | supported (1.28 stable) | no published calendar EOL |
| caddy | prod | supported (2.x) | no published calendar EOL |

Every image also carries `com.zenchron.support_state` as an OCI label, so your
inventory tooling can read this without parsing a document.

## Update commitments

| | commitment |
| --- | --- |
| scheduled rebuild | weekly |
| emergency path | **72 hours** from awareness, for a fixable CRITICAL or a known-exploited HIGH |
| acknowledgement | 24h critical, 48h high (see [SECURITY.md](../SECURITY.md)) |

**72 hours is what one maintainer can commit to.** It is not a 24/7 SLA and this
document does not describe it as one. The operating model, including what it
cannot provide, is in
[`policies/governance-model.yaml`](../policies/governance-model.yaml).

"Awareness" means the same thing here as in
[`policies/incident-reporting.yaml`](../policies/incident-reporting.yaml), so a
support promise and a regulatory clock cannot start from two different moments.

## Deprecation

A line is deprecated when it leaves active upstream support, or 180 days before
upstream security support ends — whichever comes first. `assert-lifecycle.sh`
begins warning automatically at that point, so the notice is triggered by a
build signal rather than by someone remembering.

You get **180 days** notice before deprecation and **90 days** before withdrawal.

## Withdrawal

For a release that must stop being used: a compromised build, a mis-signed
artefact, a critical vulnerability with no fix and no viable mitigation.

**Published digests are immutable and are not deleted.** Withdrawal means
publishing that a digest must not be used. There is no technical recall, and the
consumers most affected are exactly the ones following this platform's advice to
pin by digest — which is why the advisory names digests, not tags.

Procedure: [release-withdrawal.md](release-withdrawal.md). It is
**exercised**, not just written: `scripts/exercise-withdrawal.sh --simulate`
resolves every shipping image to its live digest, produces the advisory and the
consumer notice, and asserts the package is complete. Artefacts are stamped
`SIMULATED`.

## How you hear from us

| channel | direction | status |
| --- | --- | --- |
| `security@zenchron.com` | reports in | **available** (MX verified 2026-08-13) |
| [GitHub Security Advisories](https://github.com/zenchron-dynamics/zenchron-foundry/security/advisories) | advisories out | **available** |
| GitHub Private Vulnerability Reporting | reports in | **not enabled** — tracked human action |
| Repository Watch → Releases | releases out | available (self-serve) |

Note that #125 asked for an *authenticated advisory subscription*. GitHub Security
Advisories plus repository watching is what exists today without operating a
mailing list. That is recorded as a limitation in `support-policy.yaml`, not as
a solved requirement.

## Shared responsibility

See [shared-responsibility.md](shared-responsibility.md). In short: this platform
controls what the image **contains and emits**. Retention, network exposure,
orchestration, secrets, and your application code are yours.
