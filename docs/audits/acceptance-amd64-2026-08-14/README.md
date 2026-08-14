# amd64 acceptance — run 31792482449

The first valid linux/amd64 acceptance run for Zenchron Foundry, accepted by the
maintainer on 2026-08-14.

```
run_id            31792482449
run_number        6
run_attempt       1
source_revision   47609df75736a5860651be98177cfe8f9388f496
platform          linux/amd64
verdict           PASS
refusals          0
```

## Why this is in git

The authorization artifact expires **2026-11-12** and the frozen vulnerability
database artifact expired **2026-08-15**. An acceptance whose only evidence is a
workflow artifact stops being verifiable on GitHub's retention schedule, not on
ours. `post-build-authorization.json` and its `SHA256SUMS` are therefore
committed here.

Durable evidence bundling is #128; this directory is not that. It is the one
record that would otherwise be lost.

## What these files do and do not prove

`post-build-authorization.json` carries, per child: the staging tag, the manifest
digest, the independently tag-resolved digest, the config architecture, the
staging visibility, the frozen Trivy database identity, the four evaluation
results, and an `evidence_sha256` binding that child's evidence directory.

That binding is the point. The raw child evidence — `trivy.json`, `smoke.log`,
`reconcile.json`, `contract.log`, `oci-labels.json`, ~6.6 MB across ten children
— stays in the workflow artifact and is **not** committed. If it is retrieved
before it expires, `scripts/release/evidence-checksum.sh` re-derives each hash
and they must equal the values recorded here. After it expires, the hashes remain
as a statement of what was measured; the underlying logs do not.

## What was verified, and by whom

Agent, from the artifact and the registry:

```
expected children 10, observed 10, duplicates 0
per-child contract failures            NONE
evidence_sha256 recomputed             10/10 match
tag -> digest resolved from ghcr.io    10/10 agree, all image manifests
distinct manifest digests              10 (no collisions)
distinct trivy_db_identity             1
GHCR side effects                      only foundry-staging written; every
                                       production package untouched since
                                       2026-08-02/03; all packages private
```

Maintainer, independently:

```
artifact SHA256SUMS                    PASS, every file
child evidence_sha256 recomputed       PASS 10/10
authorization job permissions          contents: read, packages: read
```

The maintainer could not repeat the GHCR package inventory (connector token
lacks `read:packages`) and recorded the agent's registry check as operator
evidence for that one external observation.

## Scope of the acceptance

These ten amd64 digests are accepted as authorized **immutable-RC-manifest
inputs** for source `47609df7…`. Not authorization to publish publicly, write
production images, create a public RC, sign or attest, or promote stable.
`public_exposure_authorized: false` remains load-bearing.

The frozen database timestamp is not a qualification on the PASS — it defines
what the PASS means. These ten digests passed against the single vulnerability
knowledge snapshot `v2+updated:2026-08-14T07:14:31.886440784Z`. Later data may
correctly reach a different conclusion about the same digests.

**This evidence does not transfer to another source revision.** Any change to
master produces a new SHA, and acceptance must be re-established for it.

## How it was reached

Six dispatches, five refusals, each a different defect, every one of them only
reachable by a real dispatch because nothing else executes this workflow:

| run | outcome | cause |
|-----|---------|-------|
| 31340810647 | FAIL | superseded, never re-run |
| 31696927539 | FAIL | guard job read git with no checkout |
| 31701249058 | FAIL | `--arch amd64` matched no ledger entry; unfrozen Java DB; a wedge that stopped nothing |
| 31749810234 | FAIL | Java DB mirror 404 — an external dependency that should not have been on the release path |
| 31783088713 | FAIL | real findings: Go stdlib CVEs, one of them new in that day's database |
| **31792482449** | **PASS** | fully governed matrix |

The sequence exercised the gate in both directions — broken execution, missing
evidence, bad reconciliation input, a real vulnerability, and new vulnerability
data all produced refusals, and only a fully governed matrix produced PASS.
