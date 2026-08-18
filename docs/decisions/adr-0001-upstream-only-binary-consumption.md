# ADR-0001 — Foundry consumes official upstream binaries and does not build them

**Status: ACCEPTED — 2026-08-18. Decided by the maintainer (Bogdan Olteanu).**

This supersedes `vendor-binary-source-build-proposal.md`, which asked the
question. The question has been answered, and this file is the answer rather
than an open invitation.

## Decision

**Selected model: official upstream artifacts only.**

Foundry consumes official upstream images pinned by digest and builds its own
golden image layers on top. It does **not** compile, fork, patch, vendor or
replace the FrankenPHP, Caddy, nginx or PHP binaries.

**Source compilation: NOT APPROVED.**

## Response to upstream lag

When an upstream-owned binary is vulnerable and no patched official image
exists:

1. **Track the upstream release.** Record the reference and the exact fixed
   version being waited for.
2. **Govern the risk temporarily** with an exact, version-bound,
   architecture-bound, expiring exception — when the risk is acceptable.
3. **Escalate by removing or suspending the affected image family** when the
   risk is not acceptable.

There is no fourth option. In particular:

- **Exception expiry does not authorize source compilation.** An expiry is a
  date to re-decide, not a deadline after which a prohibited action becomes
  permitted.
- **A prolonged upstream lag does not make Foundry the upstream maintainer.**
  Waiting a long time is not consent to acquire a Go build, its dependency
  graph, its provenance and its reproducibility obligations.
- **Renewal is not automatic.** The 2026-08-31 cohort expiry triggers
  re-evaluation: adopt a patched image if one exists, re-affirm with fresh
  evidence if the risk is still acceptable, or suspend the family. Not a
  rubber stamp, and not an escalation to compiling.

## Reconsideration

Reversing this requires **explicit maintainer authorization and a new,
separately approved ADR**, listed in `ownership_change.approved_adrs` in
`policies/component-ownership.yaml`. That list is empty and
`scripts/assert-upstream-ownership.sh` fails closed if an upstream-owned binary
is marked compilable while it stays empty.

**This document does not satisfy that requirement.** It approves the
upstream-only model; it does not approve an ownership change. A test asserts it
cannot be mistaken for one.

## What forced the question

Ten findings across two image families, statically linked into binaries Foundry
consumes rather than builds:

| finding | package | installed | fixed | image |
|---|---|---|---|---|
| GHSA-r277-6w6q-xmqw | kin-openapi | v0.140.0 | 0.144.0 | php-frankenphp 8.3, 8.4 |
| GHSA-hrxh-6v49-42gf | grpc | v1.81.1 | 1.82.1 | php-frankenphp, caddy |
| CVE-2026-46600 | x/net + stdlib | v0.55.0 / v1.26.3 | 0.56.0 / 1.26.6 | caddy |
| CVE-2026-56852 | x/text | v0.37.0 | 0.39.0 | caddy |
| CVE-2026-39821 and five more | stdlib | v1.26.3 | 1.25.13 / 1.26.6 | caddy |

Verified 2026-08-17: the pinned digests **are** the current upstream digests, so
no rebuild changes any of them. All are governed to 2026-08-31.

## Alternatives considered and rejected

### B — compile from source with patched module versions (REJECTED)

Would remove the lag, and would make Foundry the owner of a Go build, its module
graph, its update cadence, and every regression from a version upstream has not
shipped. It also breaks the provenance story — the artifact would no longer be
the one upstream tests or signs — and adds determinism work to an image set
whose reproducibility (#101) already has two measured blockers. With a single
maintainer (`policies/governance-model.yaml`, RISK-001), this is a materially
larger standing obligation than the problem it solves.

### C — hybrid: source-build only past an unacceptable-gap threshold (REJECTED)

The capability would have to be built and kept exercised, or it would fail the
day it was needed. That is the cost of B, paid permanently, for a path used
rarely — plus two provenance stories and a decision made under time pressure.

## Controls that make Option A honest

- Every affected finding is governed with an exact version, the architectures it
  was reconciled on, an expiry and an exit condition.
- No reachability mitigation is claimed where none was established.
- `scripts/classify-remediation-owner.sh` refuses to raise a rebuild ticket for
  an `upstream-binary` finding, so the impossible action stops being requested.
- `scripts/ci/assert-no-stale-exceptions.sh` fails CI once upstream patches
  arrive and an exception stops matching, so adoption is noticed rather than
  assumed.
- `scripts/assert-upstream-ownership.sh` fails closed on any source-build
  tooling, upstream source fetch, or binary replacement.

## Consequences

Accepted: Foundry's exposure window for upstream-owned binaries is set by
upstream, and that is now a recorded, deliberate position rather than a drift.

If the 2026-08-31 re-evaluation finds the lag has become structural, the
escalation is **suspension of the affected image family** — not source
compilation — unless and until a new ADR says otherwise.
