# Foundry's build and ownership boundary

Which findings Foundry can fix, which it can only wait on, and why "rebuild
requested" is not a remediation plan. Authoritative unless superseded by an
approved ADR.

Executable form: `scripts/classify-remediation-owner.sh`. Contract for any
automation that raises rebuild tickets: `policies/rebuild-ticket-contract.yaml`.

## What Foundry builds

| Foundry owns | Foundry does NOT own |
|---|---|
| Its own Dockerfile layers and configuration | Official upstream base images |
| Packages it installs or purges | Distro package contents |
| PHP extensions it compiles from a pinned version | Go modules statically linked into upstream binaries |
| Image metadata, hardening posture, runtime contract | The FrankenPHP and Caddy binaries themselves |
| The vulnerability ledger and release gates | Consumer application code |

Foundry **consumes official upstream base images pinned by digest**. It does not
currently compile FrankenPHP or Caddy from source.

## The rule that keeps being missed

> **Building the same Dockerfile from the same upstream digest cannot remediate a
> vulnerable statically linked vendor binary.**

A rebuild re-runs Foundry's layers. It cannot change a Go module compiled into a
binary Foundry did not build. For those findings the only real options are:

1. **Bump the pinned upstream digest** once a patched image is published — the
   normal release path; or
2. **Compile the vendor binary from source** — a new product and maintenance
   responsibility, requiring an ADR (see `docs/decisions/`), threat analysis,
   reproducibility design, dependency automation, signing/provenance changes and
   long-term ownership. **Never an implementation detail.**

## Owner classes

| class | example | can a rebuild fix it? |
|---|---|---|
| `foundry-dockerfile` | a file Foundry adds or fails to delete | **yes** |
| `foundry-extension` | `redis` compiled from a pinned version | **yes** — bump the pin |
| `upstream-base` | `zlib1g`, `perl-base` from the base image | **only if a newer base digest exists** |
| `upstream-vendor-binary` | `kin-openapi`, `grpc`, Go `stdlib` in FrankenPHP/Caddy | **no** — patched image or ADR |
| `consumer-application` | reachable only via the consuming app's use of ext-curl | no — advisory to consumers |
| `not-affected` | vulnerable module absent, or range does not apply | n/a — `not_affected` record |

## Worked example — #79, verified 2026-08-17

```text
CVE / advisory   GHSA-r277-6w6q-xmqw    github.com/getkin/kin-openapi  v0.140.0 -> 0.144.0  CRITICAL
                 GHSA-hrxh-6v49-42gf    google.golang.org/grpc         v1.81.1  -> 1.82.1   HIGH
images           php-frankenphp/8.3, php-frankenphp/8.4
architectures    linux/amd64 and linux/arm64 (identical versions on both)
owner            upstream-vendor-binary
rebuild fixes it NO
```

Confirmed present in three independent runs — 31792482449 (amd64), 31941819983
and 31870799648 (arm64) — all built on the **current** pinned bases
`ae143d38…` (8.3) and `cef99f10…` (8.4).

And those pinned digests **are** the current upstream digests, verified
2026-08-17: `dunglas/frankenphp:1-php8.3-bookworm` and `:1-php8.4-bookworm`
resolve to exactly what this repository already pins. There is no newer base to
move to, so **no rebuild changes these modules**, and the issue title "rebuild
requested" describes an action that cannot work.

Both are governed as time-boxed accepted risk to 2026-08-31 on both
architectures. Exit condition: a FrankenPHP image embedding kin-openapi ≥ 0.144.0
and grpc ≥ 1.82.1, at which point the remediation is a digest bump.

## Why #88–#95 were the wrong shape

Eight tickets, one per image, each saying only:

> Candidate `…` reports fixable CRITICAL/HIGH the current stable may not.

No CVE, no package, no installed or fixed version, no scanner or database
identity, no owner, and no statement of whether a rebuild could change anything.
They were closed 2026-08-10 as **NOT APPLICABLE / SUPERSEDED**: the candidate
digests, the producer workflow and the remediation path had all been replaced.

The generating automation no longer exists — `scheduled-rebuild.yml` is a refusal
stub, deleted along with the production publication path it fed. The contract in
`policies/rebuild-ticket-contract.yaml` exists so that when scheduled rebuild
returns (gated on #139) it cannot regress to this shape.

The surviving issue-raising automation, `dependency-drift.yml`, already behaves
correctly: **one** tracking issue, edited in place rather than duplicated, and
closed automatically when the drift clears.

## A known asymmetry, and its compensating control

`not_affected` records **require** a version binding — without one they keep
applying after the package moves into the vulnerable range. Exceptions do **not**
require `installed_version`, and 43 of 55 currently omit it, so they nominally
govern any version of the named package including a patched one.

The exposure is bounded by `scripts/ci/assert-no-stale-exceptions.sh`, which
**fails CI when an active exception matches no finding** across the shipping
matrix. When upstream patches a module, the finding disappears, the exception
matches nothing, and the gate demands its removal — so remediation cannot pass
unnoticed. Wired into `scan-images.yml` and `trusted-validation.yml`.

The residual risk is narrower: a package moving to a *different but still
vulnerable* version would remain governed by an unpinned entry. Pinning all 43 is
a separate, evidence-driven change — every pin must come from an observed scan,
and entries covering several packages at differing versions need splitting first,
exactly as the caddy `stdlib` entries did.
