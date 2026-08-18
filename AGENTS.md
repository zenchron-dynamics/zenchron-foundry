# Agent instructions — read before changing anything

## The rule

> **Zenchron Foundry builds Zenchron golden images from official upstream bases.
> It does not fork, patch, vendor, or compile upstream-owned runtime/server
> binaries unless an explicitly approved ADR changes that ownership model.**

No such ADR exists. `approved_adrs` in `policies/component-ownership.yaml` is
empty, and `scripts/assert-upstream-ownership.sh` fails CI if that changes
without one.

**This does not mean "never run docker build".** Foundry builds its own golden
images constantly and must keep doing so. The prohibition is on forking,
patching, vendoring or compiling upstream-**owned** binaries in this repository.

## Allowed / forbidden, concretely

### Allowed

- Bump the pinned official FrankenPHP digest.
- Rebuild the Zenchron FrankenPHP golden image after that bump.
- Compile approved PHP extensions with the official toolchain
  (`docker-php-ext-configure`, `docker-php-ext-install`, `pecl install`) from a
  pinned, checksum-verified archive.
- Purge a distro package Foundry does not need.
- Add a scoped, version-bound, architecture-bound, **expiring** exception while
  waiting for upstream.

### Forbidden without an approved ADR

- Compile FrankenPHP with manually upgraded Go modules.
- Run `xcaddy` to replace upstream Caddy.
- `go build` / `go install` / `go get` a replacement server or runtime binary.
- Clone or download upstream server/runtime source for compilation.
- `COPY --from=builder` a self-built binary over an official one.
- Maintain a Zenchron fork of an upstream project.
- Override or `replace` upstream Go modules.

### Incorrect, and the specific mistake to avoid

- Rebuilding the same upstream digest and calling the embedded CVE fixed.

A rebuild re-runs Foundry's layers. It cannot change a module statically linked
into a binary Foundry did not build. If the pinned digest did not change, an
`upstream-binary` finding did not change either.

## Before you "fix" a vulnerability

Ask **who owns the vulnerable component**, then act accordingly:

```bash
scripts/classify-remediation-owner.sh --image php-frankenphp/8.4 \
    --package github.com/getkin/kin-openapi --installed v0.140.0 \
    --fixed 0.144.0 --newer-base-available no
```

It answers `owner`, `rebuild_can_remediate`, `ticket_warranted`, `remediation`
and `root_cause_key`. If `rebuild_can_remediate=no`, **do not open a rebuild
ticket and do not compile anything** — track upstream, or govern it in the
ledger.

| owner | what to do |
|---|---|
| `foundry` / `foundry-selected-extension` | fix it directly, or bump the pinned version |
| `upstream-base` | bump the pinned base digest **if** a patched one exists |
| `upstream-binary` | wait for a patched official image; govern the gap; never compile |

## If upstream has no patched image

1. Verify digest, package/module, installed version, architecture, scanner and
   database identity.
2. Record an upstream-tracking reference.
3. Govern it with a **narrow** exception: named images, exact installed version
   where the scanner reports one, the architectures actually reconciled, an
   expiry, an owner, an approver, compensating controls and an **exit
   condition**.
4. Never claim a reachability mitigation you have not established.
5. If the risk is unacceptable, **suspend the image family**. Do not hide it
   behind a broader exception.

## Downstream reports

A consumer repository may report a vulnerability in a published Foundry image
and should include digest, scanner identity, CVE, module, versions,
architecture and impact.

A downstream report is **evidence, not a work order**. It cannot require Foundry
to fork, patch or compile upstream software. Foundry owns triage and picks the
remedy within its ownership boundary.

## If source ownership looks necessary

**Stop and ask.** Do not create an ADR to get around this policy. Present the
strategic decision, costs, alternatives and maintenance burden. The options are
already written up, with no recommendation, in
`docs/decisions/adr-0001-upstream-only-binary-consumption.md`.

## Other standing rules

- **Never dispatch expensive builders** (`stage-and-authorize`, full matrices)
  without explicit, SHA-pinned authorization. A full run is ~10 hours on one of
  two trusted runners.
- **Fail closed.** Missing tools, unreadable evidence, network failures, empty
  discovery and unknown status are failures — never successes.
- **Every check must be non-vacuous.** Prove a new assertion fails on the
  previous state. A check that has never failed is indistinguishable from one
  that cannot.
- **Strip comments before matching.** Checks in this repository have repeatedly
  matched their own explanatory prose and reported correct files as broken.
- **Watch `pipefail`.** `cmd | grep -q X` reports *cmd's* status. For an
  assertion about a deliberately-failing command, capture the output first. This
  has bitten four separate times here.

## Authoritative sources

| topic | file |
|---|---|
| component ownership (machine-readable) | `policies/component-ownership.yaml` |
| ownership prose and worked examples | `docs/ownership-boundary.md` |
| rebuild-ticket contract | `policies/rebuild-ticket-contract.yaml` |
| vulnerability ledger | `policies/vulnerability-exceptions.yaml` |
| CI cost baseline and reuse contract | `docs/ci-cost-baseline.md` |
| source-build decision (undecided) | `docs/decisions/adr-0001-upstream-only-binary-consumption.md` |

Do not restate authoritative facts in a second document. Derive or validate.
