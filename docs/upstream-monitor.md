# Buildless upstream monitor and expiry operating controls

The exception ledger's 2026-09-30 cohort is 32 records whose exit conditions are
written in prose. Prose cannot be evaluated on a schedule, and the two questions
that decide those records — *has a consumable official artifact appeared?* and
*is the maintainer being asked to decide in time?* — were being answered by
somebody remembering to look.

This is what looks instead. It **observes and reports**. It builds nothing,
moves no pin, dispatches no acceptance, publishes nothing, signs nothing,
renews no exception and removes none. `policies/vulnerability-exceptions.yaml`
has no write path from any of it.

| piece | what it is |
|---|---|
| `policies/upstream-watch.yaml` | observation-only config: watched artifacts, clearing floors, group→record binding, checkpoints |
| `scripts/upstream-monitor.py` | `observe` / `evaluate` / `checkpoints` / `--self-test` |
| `scripts/upstream-monitor.sh` | entry point: checkpoints, then observe, then evaluate |
| `.github/workflows/upstream-monitor.yml` | daily; `issues: write` is its only write permission |
| `tests/vulnerability-policy/test_upstream_monitor.sh` | 62 assertions, offline, dates pinned with `--today` |

## 1. A moved tag is not remediation

This is the property everything else is arranged around, and it is not
hypothetical. Twice, upstream movement in this repository looked like
remediation and was not:

* the FrankenPHP 8.3 **index** digest moved while both Foundry platform
  manifests stayed byte-identical — the Linux artifact had not changed at all;
* the 8.4 tag later moved on **both** platforms, and the embedded modules were
  unchanged at `kin-openapi v0.140.0` and `grpc v1.81.1`.

So three observations are kept apart and never conflated:

| classification | what changed | can it alert? |
|---|---|---|
| `index-movement-only` | the manifest-list digest, with every required platform manifest byte-identical | **never** |
| `platform-manifest-movement` | a `linux/amd64` or `linux/arm64` manifest digest, with every watched component at its baseline version | **never** |
| `content-change` | a watched component's version inside the artifact | only if it reaches the clearing floor |

Index digests are never compared against platform digests. The index digest is
recomputed locally as the SHA-256 of the raw manifest-list bytes, so the value
reported is the object actually read; each platform manifest is resolved
separately and the inventory is read **against the immutable platform digest**,
never against the tag.

Even a `content-change` is not enough. It must reach the declared clearing floor
on **every** required platform, because the governed cohort is both children. A
component fixed on `linux/amd64` alone clears nothing and stays silent.

## 2. What is bound for every observed artifact

Each bind carries: tag; immutable index (manifest-list) digest and the baseline
it is compared against; per-platform manifest digest and its baseline;
retrieval time in UTC; the package/module inventory and where it came from; the
clearing version; and the governance groups and exact ledger records the
component would bear on. Ledger records are named by their canonical identity
`cve|image|package|installed_version`, computed by `scripts/lib/exception_id.py`
— the same identity the validator, the reconciler and the stale-exception
aggregate use.

Reads, all of them GETs:

| source | what it establishes |
|---|---|
| `docker buildx imagetools inspect --raw` | index digest and each platform manifest digest |
| `syft --from registry <repo>@<platform-digest>` | the package/module inventory of one immutable platform manifest |
| `api.osv.dev` (`Debian:12`) | whether bookworm/bookworm-security publishes a fix for a governed advisory |
| Alpine `APKINDEX` for the branch | whether a fixed aport is available |

Evidence class is `upstream-base`, and it is used only to establish upstream
ownership and patched-artifact availability. It is never read as a Foundry
child's inventory: the child Dockerfiles purge build tooling, so the two
inventories differ by design. Children are scanned by
`scripts/rescan-retained-cohort.sh` and `scripts/reconcile-vulnerabilities.sh`;
this monitor does not scan children and does not pretend to.

A read that fails is a **gap**, never a clean result. The report says so in
those words, and a gap produces no alert in either direction — a monitor that
reports "quiet" because it could not look is worse than one that says nothing.

## 3. The two alert conditions, and why tag movement cannot reach them

`exit-condition-met`
: A watched component's observed version is provably at or above the clearing
  floor on every required platform. Reached only through a content comparison;
  no digest comparison contributes to it.

`ledger-contradicted`
: Upstream evidence contradicts something the ledger asserts about upstream:
  Debian publishes a fix for an advisory a record carries `fix_available: false`
  for; a package a group's records attribute to a base appears in a base
  measured not to ship it; or the watch config no longer binds to the ledger.

Nothing else alerts. Movement, availability of a fixed Alpine aport, and a
content change that stops short of the floor are all **notes** — printed in the
run log, never opening an issue.

Version ordering is deliberately conservative and refuses when unsure, and a
refusal never satisfies a floor:

* Go modules compare numerically, with `go1.26.3` and `v1.26.3` normalised to
  the same value so two tools' spellings are not read as a change; a
  pre-release is refused rather than guessed, because guessing high would fake a
  cleared exit condition.
* Alpine versions compare `<upstream>` then `-r<pkgrel>`, so `3.5.7-r1` does not
  satisfy a `3.5.8-r0` floor.
* Debian versions are **never** ordered here — epochs, tildes and `+debNuM`
  revisions are dpkg's business. The Debian watch is a fix-*existence*
  observation, which needs no ordering.

### The floor that matters most

`kin-openapi` clears at **`0.144.0`**, not `0.141.0` and not `0.142.0`. Trivy
reports per-CVE `FixedVersion`s of 0.141.0 (CVE-2026-76905) and 0.142.0
(CVE-2026-77354), but the same binary carries `GHSA-r277-6w6q-xmqw`, which is
CRITICAL and fixed at 0.144.0. An upstream move to 0.142.x would clear two HIGHs
and leave the CRITICAL in place. The monitor stays silent at 0.142.0 and the
test suite asserts that it does.

## 4. Expiry operating controls

Four dates. The last one does not move.

| date | what it is |
|---|---|
| 2026-09-15 | first review |
| 2026-09-23 | final evidence refresh |
| 2026-09-27 | maintainer decision deadline |
| **2026-09-30** | **fail-closed expiry — unchanged** |

A reminder that says only a date is not actionable, so the checkpoint never
says only a date. It names the record count, every group, each group's exit
condition, and every individual record by advisory, selector, package and
installed version — 32 of them. It states what happens on 2026-09-30:
`reconcile-vulnerabilities.sh` refuses the matching findings as ungoverned and
`caddy/prod`, `nginx/prod` and the FrankenPHP children fail the release gate.

And it is explicit about what it is not:

> This is a PROMPT TO DECIDE. It schedules nothing, renews nothing and extends
> nothing. […] NOTHING IN THIS REPOSITORY RENEWS AN EXCEPTION. There is no
> automatic extension, no default roll-forward and no tool that may write
> `policies/vulnerability-exceptions.yaml`. Continuing a record is a fresh risk
> acceptance the maintainer role records by hand, with its own justification.

Lapsing is stated as the default outcome rather than as a failure of the
process. The test suite asserts the presence of that wording and the **absence**
of any sentence promising a renewal, an extension or a roll-forward.

Outside the reporting window the checkpoint reporter prints one line and lists
nothing, and the workflow closes its tracking issue — noting, when it does, that
closing the issue changes no expiry date and renews nothing.

## 5. The config must keep describing the ledger

`policies/upstream-watch.yaml` binds groups to records in both directions, and
both are enforced:

* every record a group names must exist in the ledger;
* every ledger record expiring on the fail-closed date must be named by exactly
  one group.

The second is the one that matters. A record added to the fail-closed cohort
that no group names is a record no checkpoint would ever report — a maintainer
silently not reminded about a live risk decision. That fails closed: the
checkpoint command exits 5, the workflow's first step stops the run, and the
test suite proves it by deleting a group and requiring the refusal to name the
orphaned record.

## 6. Running it

```bash
scripts/upstream-monitor.sh                      # checkpoints, observe, evaluate
scripts/upstream-monitor.sh --manifests-only     # digests only; no inventory, no feeds
scripts/upstream-monitor.sh --checkpoints-only --today 2026-09-15
python3 scripts/upstream-monitor.py --self-test  # offline unit checks
bash tests/vulnerability-policy/test_upstream_monitor.sh
```

Exit codes: `0` quiet, `2` usage or observation failure, `3` an alert fired
(with `--fail-on-alert`), `4` a checkpoint is due (with `--fail-on-checkpoint`),
`5` the watch config no longer binds to the ledger.

## 7. What acting on an alert still requires

An alert is evidence that an exit condition *appears* satisfiable. It is not a
clearance. Removing a record requires the finding to have actually gone from the
**child**, which means: verify the artifact, move the pin in a reviewed pull
request, rebuild, rescan the children, reconcile per platform, and only then
remove the records the evidence clears. All of that is a maintainer decision.
The monitor's job ends at telling somebody it is worth looking.
