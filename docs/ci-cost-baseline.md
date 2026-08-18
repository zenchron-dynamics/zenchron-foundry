# CI-COST-01 — acceptance cost baseline and reuse contract

What the acceptance run costs, what was optimised, and what was deliberately
**not** optimised. Numbers here are measured, not estimated; where a figure is an
extrapolation it says so.

## Measured baseline

| run | platform | children | wall time | per child |
|---|---|---|---|---|
| 31792482449 | linux/amd64 | 10 | ~50 min | ~5 min |
| 31941819983 | linux/arm64 (QEMU) | 10 | ~9 h | ~53 min |
| 31870799648 | linux/arm64 (QEMU) | 9 + 1 lost | ~8 h | ~53 min |

`php-fpm/8.3` on arm64 measured **53 min 20 s** against roughly five minutes
native — emulation is **~10× slower** and is the entire critical path.

**Extrapolated**, `max-parallel: 1`, 20 children: **≈10 hours**, one of two
trusted runners held for the duration.

## What this batch changed

| change | effect |
|---|---|
| Platform axis on the stage matrix | the 20-child run becomes *possible*; previously it produced 10 refusals and no evidence |
| Cheap platform validation in `guard` | a malformed list costs seconds, not a matrix |
| `timeout-minutes` on every job | a hung child caps at 150 min instead of GitHub's 360 default |
| Per-child `child_wall_seconds` + `runner_name` | the cost baseline comes from the evidence, not from API timestamps that expire |
| Cost table in the run summary | native vs emulated split, slowest child, runners used |

### The expensive-run risk this removes

The previous shape guaranteed a wasted dispatch. Every assertion added here runs
in milliseconds and would have caught it. Concretely: the 20-child shape, the
one-platform-per-child invariant, staging-tag uniqueness across platforms, and
planner/authorizer arithmetic agreement are now proven before any builder starts.

## Deliberately NOT optimised

**`max-parallel` stays 1.** The trusted runner is ~2 vCPU / 4 GB. BuildKit and
Trivy resident twice over is an OOM, not a speedup, and this repository has a
recorded history of disk exhaustion on that host. Raising it requires a resource
model and a cheap proof; guessing would trade wall time for failure rate, and a
failed 10-hour run costs more than a slow one. **Recorded as the largest
outstanding optimisation target.**

**No build or scan reuse in the acceptance path.** See the contract below: the
telemetry and the key definition land now, the reuse does not.

**QEMU is not replaced.** A native arm64 runner would remove ~8 hours from the
critical path and is the single biggest available saving, but enrolling one is a
control-plane change and outside this batch. It is also what #111 actually needs
— emulation cannot establish native runtime behaviour.

## The four reuse claims — kept separate on purpose

Conflating these is how a build-cache hit becomes a false security claim. Each
has its own identity key, freshness boundary and trust boundary.

### 1. Build-layer cache reuse

| | |
|---|---|
| identity key | BuildKit layer content key (parent + instruction + inputs) |
| freshness boundary | none — layers are content-addressed and timeless |
| invalidation | Dockerfile change, build-arg change, base digest change |
| architecture | per-platform; layers never cross architectures |
| trust boundary | BuildKit's own content addressing |
| **allowed claim** | "these bytes were produced from these inputs" |
| **prohibited claim** | anything about vulnerabilities, runtime behaviour, or currency |

### 2. Complete immutable child-image reuse

| | |
|---|---|
| identity key | child manifest digest |
| freshness boundary | none for the artifact; the artifact does not decay |
| invalidation | any input change, **including `VCS_REF`** — see below |
| architecture | per-platform child manifests, never an index |
| trust boundary | registry content addressing |
| **allowed claim** | "this exact artifact exists and is immutable" |
| **prohibited claim** | that it represents a different source SHA, or that its old scan still applies |

### 3. Runtime / smoke evidence reuse

| | |
|---|---|
| identity key | child digest + smoke suite version + execution mode |
| freshness boundary | none — behaviour is a property of the artifact |
| invalidation | new child digest, changed smoke suite, changed execution mode |
| architecture | strict; **QEMU never satisfies native arm64** |
| trust boundary | the runtime harness |
| **allowed claim** | "this digest behaved this way under this execution mode" |
| **prohibited claim** | anything about vulnerabilities; and emulated ≠ native |

### 4. Vulnerability scan and reconciliation evidence reuse

| | |
|---|---|
| identity key | child digest + scanner version + **frozen database identity** + policy/ledger digest + reconciler version |
| freshness boundary | **the database identity** — this is the one that decays |
| invalidation | new database, new ledger, new reconciler, new digest |
| architecture | strict; amd64 never authorizes arm64 |
| trust boundary | the frozen snapshot, recorded per child |
| **allowed claim** | "this digest had this verdict against that snapshot" |
| **prohibited claim** | that an older verdict is current evidence |

### The rules that follow

- A build-cache hit **never** implies current image evidence.
- Image reuse **never** implies a current scan.
- Runtime evidence **never** implies vulnerability evidence.
- Scan evidence **never** implies runtime behaviour.
- A new database identity invalidates cross-run scan evidence.
- A new policy/ledger or reconciler invalidates reconciliation evidence.
- amd64 never authorizes arm64, and vice versa.
- QEMU never satisfies native arm64 runtime evidence (#111).
- **Ambiguous or incomplete provenance is a cache MISS**, never a soft hit.

Measured, not assumed: the accepted amd64 caddy child passed with 10 CRITICAL/HIGH
on 2026-08-14 and reported **19** when the same digest was rescanned three days
later. The artifact did not change; the knowledge did.

## `VCS_REF` and policy-only commits — investigated 2026-08-17

**Finding: `VCS_REF` is consumed only as a LABEL.** In every Dockerfile it
appears solely in `org.opencontainers.image.revision="${VCS_REF}"`. It is never
written into image content.

Labels live in the image **config**, and the config digest is part of the
manifest. So a policy-only commit — no Dockerfile change, no base change —
**still produces a different child manifest digest**, because the revision label
changed.

Consequences, stated at the level the evidence supports:

- A prior child image **cannot** truthfully represent the new source SHA. Its
  recorded revision names a different commit, and the release verifiers read
  that label.
- Build-input identity and policy-decision identity are therefore **currently
  assumed to be the same thing**, and today they genuinely are: the SHA is baked
  into the artifact.
- Separating them — an artifact SHA distinct from a policy SHA — would change
  what `org.opencontainers.image.revision` means to every downstream verifier,
  and would need the provenance and release-verification contracts to be
  re-specified.

**Not implemented in this batch, deliberately.** A split-SHA model is not
supported by the existing trust contract, so adopting it is an **ADR-level**
decision rather than an optimisation. Recorded as a future option, not a plan.

One thing this investigation did **not** establish: whether layer content is
stable across rebuilds of the same inputs. A same-arguments rebuild of caddy
produced only 6 of 9 identical layers — but that comparison was not controlled
(`--no-cache` on one side), and it is the already-known #101 non-determinism
rather than a `VCS_REF` effect. Treated as unresolved, not as a measurement.

## Safe current default

Until proven otherwise:

- BuildKit layers **may** be reused when their normal content keys match.
- The final current-SHA child artifact **must** be produced or recovered with
  truthful provenance.
- Every child **must** be scanned against the newly frozen database.
- Every scan **must** be reconciled against the current policy and reconciler.
- An older vulnerability verdict **must not** be presented as current evidence.

## Ranked optimisation targets — with evidence class

Every claimed saving is labelled by how it is known. **Nothing below is
measured at phase level yet**, which is precisely what the next run fixes.

| rank | change | claimed saving | evidence class | risk |
|---|---|---|---|---|
| 1 | Native arm64 runner | large; see note | **extrapolated** | medium |
| 2 | Raise `max-parallel` with a resource model | 30–50% wall | **theoretical upper bound** | medium |
| 3 | Split the matrix across both trusted runners | ~50% wall | **theoretical upper bound** | low–medium |
| 4 | Reuse unchanged children by content key | unknown | **blocked pending phase telemetry** | high |
| 5 | Skip rebuilds when only policy changed | **none available today** | **refuted** — see `VCS_REF` | n/a |
| 6 | Shared BuildKit cache mount across children | 10–20% | **theoretical upper bound** | low |

### What changed in this ranking, and why

**The previous "~9 hours saved by child reuse" claim is withdrawn.** It came
from observing that the whole arm64 run took ~9 hours and assuming reuse would
eliminate all of it. That does not follow. The QEMU cost may sit in
foreign-architecture build execution, in runtime smoke, in scanning, in image
transfer, or across several phases at once — and reuse only addresses some of
those. The number was arithmetic on a total, not a measurement of a mechanism.

**Rank 5 is refuted, not deferred.** A policy-only commit changes `VCS_REF`,
which changes the revision label, the config digest and therefore the child
manifest digest. There is no unchanged child to skip rebuilding. That is a
finding, not a scheduling problem.

**Rank 1 remains the probable largest saving and is still required for #111**,
but its precise value stays **extrapolated** until phase-equivalent
measurements exist. "arm64 children take ~53 min against ~5 native" is a
measured ratio of totals; which phases carry that ratio is not yet known, and a
native runner only removes emulation cost from the phases that actually contain
it.

### What the next run will settle

The phase timer records: `db_acquire`, `build_and_push`, `digest_resolve`,
`pull_by_digest`, `smoke`, `metadata_contract`, `vulnerability_scan`,
`package_inventory`, `reconciliation`, `evidence_emit` — plus explicit
`uninstrumented_overhead_seconds` and an unmeasurable, honestly-null
`queue_seconds`.

With one 20-child run, ranks 1, 2, 4 and 6 become measurable instead of argued.

## What the run summary now reports

```text
children with timing, total child wall time,
native children (count, mean), emulated children (count, mean),
slowest child, runners used
```

Derived from the children's own clocks, so it survives artifact retention and
does not depend on scraping the API after the fact. Records written before this
change report `0 / N` timing and `n/a` — degraded, not crashed, and verified
against the committed 2026-08-14 acceptance record.
