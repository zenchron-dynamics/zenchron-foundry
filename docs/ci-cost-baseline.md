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

## Reuse key contract (defined now, reuse deferred)

Any future reuse of **vulnerability evidence** must key on *all* of:

```
source SHA
build inputs (Dockerfile + context digest)
base image digests
immutable child manifest digest
platform
scanner version and configuration
frozen vulnerability database identity
policy/ledger digest
reconciliation implementation version
```

Three rules that follow, and why each exists:

- **A build-cache hit must never imply a vulnerability-evidence hit.** The same
  bytes scanned against a newer database can legitimately produce a different
  verdict. Run 31792482449's caddy child passed with 10 CRITICAL/HIGH; the same
  digest rescanned three days later reported 19.
- **A previous database snapshot must never be presented as current evidence.**
  The identity is part of the claim, not metadata about it.
- **amd64 evidence must never authorize arm64, or vice versa.** Enforced today by
  `verified_architectures` on every ledger record.

Reuse is deferred because none of these can yet be proven cheaply, and
speculative caching in the acceptance path would weaken the evidence it is meant
to make cheaper. Telemetry first; reuse only once a hit can be shown to be sound.

## Ranked optimisation targets

| rank | change | est. saving | risk | why not now |
|---|---|---|---|---|
| 1 | Native arm64 runner | ~8 h/run | medium | control-plane change; also required by #111 |
| 2 | Reuse unchanged children across runs by content key | up to ~9 h when few images change | **high** | needs the full key above proven; must never let a build hit imply a scan hit |
| 3 | Raise `max-parallel` with a resource model | 30–50% wall time | medium | 2 vCPU / 4 GB; OOM risk raises failure cost |
| 4 | Split the matrix across both trusted runners | ~50% wall time | low–medium | halves capacity for everything else; needs contention policy |
| 5 | Skip rebuilds when only policy changed | ~9 h on ledger-only changes | medium | needs child-digest-bound evidence reuse (rank 2) |
| 6 | Shared BuildKit cache mount across children | 10–20% | low | measure first; disk is the constrained resource on this host |

Ranks 2 and 5 depend on rank 2's key being proven. Rank 1 is the only one that
also advances an open issue.

## What the run summary now reports

```
children with timing, total child wall time,
native children (count, mean), emulated children (count, mean),
slowest child, runners used
```

Derived from the children's own clocks, so it survives artifact retention and
does not depend on scraping the API after the fact. Records written before this
change report `0 / N` timing and `n/a` — degraded, not crashed, and verified
against the committed 2026-08-14 acceptance record.
