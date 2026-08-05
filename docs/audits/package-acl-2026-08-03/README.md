# GHCR package access boundary — enforced state, 2026-08-03

This directory records that the repository's default `GITHUB_TOKEN` cannot write
any production container package, and can write only the private
`foundry-staging` quarantine package.

The record separates three kinds of claim, because they carry very different
weight. Operator attestation is someone's word. Behavioural proof is a
measurement. Cleanup is housekeeping that happened afterwards and proves nothing
about the boundary. Presenting them as one list would let the weakest claim
borrow credibility from the strongest.

## 1. Operator-attested configuration

Applied by an organization owner through the GitHub web UI on 2026-08-02 and
2026-08-03:

- organization package access inheritance default **disabled** for newly
  published packages;
- `foundry-staging` — **Private**, independent permissions, *Manage Actions
  access* → `zenchron-dynamics/zenchron-foundry` = **Write**;
- `php-fpm`, `php-cli`, `php-worker`, `php-frankenphp`, `caddy`, `nginx` —
  independent permissions, *Manage Actions access* →
  `zenchron-dynamics/zenchron-foundry` = **Read**.

**These are attestations, not verified facts.** None of them is readable through
the documented public GitHub API. `GET /orgs/{org}/settings/packages` returns
404, no documented per-package access endpoint exists, and the package object
exposes only `created_at, html_url, id, name, owner, package_type, repository,
updated_at, url, version_count, visibility` — no access role. Both controls are
UI procedures, in read as well as in write. Undocumented or internal endpoints
may exist; they are not something a control can be built on.

Nothing in this section should be described as API-verified, and no gate in this
repository reads it.

Note also that **linkage is not inheritance**. All six production packages remain
linked to `zenchron-foundry` via `org.opencontainers.image.source`. A link shows
a potential inheritance path, not that inheritance is enabled — GitHub permits a
package to stay linked while using independent granular permissions. Reading the
link proves nothing in either direction, which is exactly why the write is
attempted instead.

## 2. Behaviourally proven properties

Established by workflow run
[30837370041](https://github.com/zenchron-dynamics/zenchron-foundry/actions/runs/30837370041),
a `workflow_dispatch` from `master@b48ae24527495ccb402be0f94cc6e65a6f6bc694`
triggered by `bogdaniel`, started 2026-08-03T17:34:35Z, evidence generated
2026-08-03T17:35:11Z, conclusion `success`, verdict **PASS**:

- the repository `GITHUB_TOKEN` **can** write `foundry-staging`;
- the pushed staging tag **resolves independently through the registry** to the
  same digest that was pushed
  (`sha256:e93f888e5fcf1c5b3bb3bd366a45a9b7d269fd596b79480948f3a13214ccaec7`),
  so the write is confirmed by the registry rather than by the local daemon's
  own record;
- the repository `GITHUB_TOKEN` **cannot** write any of the six production
  packages — each returned an explicit
  `denied: permission_denied: write_package`;
- all seven packages were **private** at probe time, read with a separate
  read-only credential;
- **zero** results were indeterminate, so this is a clean measurement rather
  than an inconclusive one.

A non-zero exit is never accepted as proof of denial. Timeouts, 5xx responses,
connection failures, EOF and unrecognised output classify as `indeterminate`, and
any indeterminate result fails the verdict. A network failure therefore cannot
manufacture a passing boundary.

Independently corroborated outside the workflow's own reporting: after the run,
zero `acl-probe-deny-r30837370041-a1` versions existed in any production package,
and exactly one `acl-probe-r30837370041-a1` version existed in `foundry-staging`.

### Consequence

`.github/workflows/publish-ghcr.yml` is now **structurally non-functional** for
production publication. That is intended. Publication was already blocked by
issue #139; retaining production Write would have preserved the bypass that the
post-build authorization work exists to eliminate. Reopening publication requires
a separate publishing identity and a protected exposure job, not a restoration of
this access.

## 3. Post-run cleanup attestation

Performed 2026-08-04, **after** the PASS verdict, using an administrator
credential separate from the probe — never by the workflow itself.

Two earlier runs (`30769529023` and `30770068008`) predated the boundary and left
canary objects in the production packages. Eleven versions were deleted:

| package | deleted versions |
|---|---|
| `php-fpm` | 1 |
| `php-cli` | 2 |
| `php-worker` | 2 |
| `php-frankenphp` | 2 |
| `caddy` | 2 |
| `nginx` | 2 |

Method and result:

- each version was **re-read immediately before deletion**, so nothing was
  removed on the strength of a stale listing;
- deletion proceeded only where **every** tag attached to the version matched
  `^acl-probe-deny-r(30769529023|30770068008)-a1$`;
- 11 deleted, 0 skipped, 0 errors;
- 0 `acl-probe` versions remain in any production package;
- staging canaries **intentionally retained** — that package is the quarantine
  and accumulation there is expected.

**Cleanup contributed nothing to the PASS verdict.** The boundary was established
by run 30837370041, which completed before any deletion took place. This section
records tidiness, not evidence.

## Contents

| file | what it is |
|---|---|
| `package-acl-probe.json` | the evidence document produced by the run |
| `package-acl-probe-30837370041-1.zip` | the uploaded artifact, byte-identical to what GitHub stored |
| `artifact-metadata.json` | run and artifact identifiers, retrieved from the REST API |
| `SHA256SUMS` | checksums for the three files above |

The ZIP's SHA-256 equals the digest GitHub recorded for artifact `8865384046`, so
the committed copy is provably the exact object the run uploaded — it does not
depend on this repository being trusted, and it survives the artifact's eventual
expiry.

Verify with:

```sh
shasum -a 256 -c SHA256SUMS
```

## How this record was produced

The probe measures the boundary; it does not configure it. It is dispatch-only,
refuses any ref but the default branch, never checks out repository or
pull-request code while holding `packages: write`, holds no `id-token` and no
environment, names packages as fixed literals, and pins every action by commit
SHA.

Its own history is worth recording. Run `30769691840` failed with no artifact:
GitHub invokes `run:` blocks as `bash -e {0}`, and the probe's `set -uo pipefail`
never cleared errexit despite a comment claiming otherwise, so the first
denial — the *successful* outcome — aborted the step. The probe was structurally
incapable of returning PASS. Fixed in #150 with `set +e` and, more importantly,
with a harness that extracts the real `run:` block and executes it under `bash -e`
with stubbed tooling, because the prior tests asserted arrangement and
arrangement is not behaviour.

A control that has never been executed in its success path has not been tested,
however carefully its structure was reviewed.
