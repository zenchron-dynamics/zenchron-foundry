# ADR proposal — should Foundry compile FrankenPHP and Caddy from source?

**Status: PROPOSED. Not decided, not implemented.** This exists because the
alternative is implementing a product-architecture change inside a vulnerability
ticket, which is how a maintenance obligation gets acquired without anyone
choosing it.

No recommendation is made here. The decision is the maintainer's.

## What forces the question

A recurring class of finding that **no Foundry action can remediate**:

| finding | package | installed | fixed | image |
|---|---|---|---|---|
| GHSA-r277-6w6q-xmqw | github.com/getkin/kin-openapi | v0.140.0 | 0.144.0 | php-frankenphp 8.3, 8.4 |
| GHSA-hrxh-6v49-42gf | google.golang.org/grpc | v1.81.1 | 1.82.1 | php-frankenphp 8.3, 8.4 |
| CVE-2026-46600 | golang.org/x/net + stdlib | v0.55.0 / v1.26.3 | 0.56.0 / 1.26.6 | caddy |
| CVE-2026-56852 | golang.org/x/text | v0.37.0 | 0.39.0 | caddy |
| CVE-2026-39821 + 5 more | stdlib | v1.26.3 | 1.25.13 / 1.26.6 | caddy |

Ten findings across two image families, all statically linked into binaries
Foundry consumes rather than builds. Verified 2026-08-17: the pinned digests are
the **current** upstream digests, so there is nothing to bump to. Every one is
currently governed as time-boxed accepted risk expiring 2026-08-31.

The pattern is not incidental. Go's release cadence means a security release
lands and the images that embed it lag by days to weeks. Each lag becomes a
Foundry risk acceptance for something Foundry cannot fix.

## Option A — status quo: consume official images, accept the lag

Bump the digest when upstream publishes; govern the gap as time-boxed accepted
risk with an explicit exit condition.

**For:** no new maintenance surface; the upstream signing and provenance chain is
preserved; the base stays digest-pinned to an artifact many others also consume.

**Against:** the exposure window is set by upstream, not by us. Repeated renewals
of the same acceptance look like — and eventually become — a permanent exception.
The EU enterprise buyer is precisely the reader who will ask why a CRITICAL sat
governed for months.

## Option B — compile from source with patched module versions

Build FrankenPHP and Caddy in Foundry, pinning module versions ourselves.

**For:** the lag disappears; `upstream-vendor-binary` stops being an owner class;
Foundry can respond to a Go security release directly.

**Against — and this is the part that must not be understated:**

- **A new product.** Foundry would own the build, the module graph, the update
  cadence, and every regression from a version upstream has not shipped.
- **Provenance changes.** We stop inheriting the upstream image's identity and
  must produce our own attestation for a binary nobody else builds.
- **Reproducibility.** #101 is still open with two measured blockers on images we
  merely assemble. A from-source Go build adds its own determinism work.
- **Divergence risk.** A binary built from patched modules is no longer the
  artifact upstream tests. Bugs land on us, and "works with official FrankenPHP"
  stops being a claim we can make.
- **Ongoing dependency automation** — the thing that made this necessary — becomes
  a Foundry responsibility for a graph of hundreds of modules.
- **Single maintainer.** `policies/governance-model.yaml` records one maintainer
  and RISK-001. This materially increases what one person must keep current.

## Option C — hybrid: source-build only on an unacceptable gap

Stay on official images; build from source only when a CRITICAL with a published
fix has been unremediated upstream beyond a defined threshold.

**For:** bounded exposure without permanent ownership; the capability exists but
is not the default.

**Against:** the capability must be built and *maintained in working order*
anyway, or it will not work the day it is needed — a break-glass path nobody
exercises is a break-glass path that fails. Two build paths also means two
provenance stories and a decision to make under time pressure.

## What each option needs before it could be adopted

| | A | B | C |
|---|---|---|---|
| ADR | not required | **required** | **required** |
| Threat analysis of a self-built binary | — | required | required |
| Reproducibility design | — | required | required |
| Dependency-update automation | — | required | required |
| Signing/provenance change | — | required | required |
| Long-term ownership sign-off | — | required | required |
| Exercise cadence for the alternate path | — | — | required |

## What is NOT in scope

This proposal does not implement any option, add a build path, or change a pin.
The audit that produced it deliberately stopped here: adopting source compilation
is a product-architecture decision requiring explicit authorization.

## Interim position, in force today

Option A, with these controls already in place:

- every affected finding governed with an explicit expiry (2026-08-31) and exit
  condition;
- no reachability mitigation claimed where none was established;
- `scripts/classify-remediation-owner.sh` refuses to raise a rebuild ticket for
  an `upstream-vendor-binary` finding, so the impossible action stops being
  requested;
- `scripts/ci/assert-no-stale-exceptions.sh` fails CI once upstream patches
  arrive and the exception stops matching, so remediation is noticed rather than
  assumed.

The forcing question for whoever decides: **if the 2026-08-31 cohort needs
renewing again with upstream still unpatched, is Option A still acceptable, or
has the lag become structural?**
