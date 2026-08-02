# Fork-boundary test — 2026-07-29

Evidence that the self-hosted runner boundary is enforced by GitHub's control
plane and **not** by repository code. Recorded because the previous design
claimed a boundary it could not provide.

## Why the old design failed

A `pull_request` workflow runs the workflow file from the **merge ref**, which
includes the pull request's own edits to `.github/workflows/`. A fork could
therefore rewrite `runs-on` to `[self-hosted, linux, x64, zenchron]`, delete
`assert-runner-trust.sh`, and GitHub would pick the runner **before any
repository code executed**. An in-workflow assertion cannot govern runner
assignment. It only ever protected against maintainer drift.

## Control-plane configuration

```console
$ gh api orgs/zenchron-dynamics/actions/runner-groups
  1 Default:                  visibility=all      public=false restricted_to_workflows=false  (0 runners)
  3 zenchron-foundry-trusted: visibility=selected public=true  restricted_to_workflows=true   (2 runners)

$ gh api orgs/zenchron-dynamics/actions/runner-groups/3/repositories
  selected repositories: 1 -> zenchron-dynamics/zenchron-foundry

$ gh api orgs/zenchron-dynamics/actions/runner-groups/3 --jq '.selected_workflows[]'
  …/ci.yml@refs/heads/master
  …/scan-images.yml@refs/heads/master
  …/publish-rc.yml@refs/heads/master        (+ publish-ghcr, promote-stable, release,
  …/verify-rc.yml@refs/heads/master           verify-signatures, build-images,
  …/scheduled-rebuild.yml@refs/heads/master   scheduled-rebuild)
```

Every entry is pinned to `refs/heads/master`. A pull-request run's workflow ref
is `refs/pull/N/merge`, so it matches none of them.

## Test: a PR-triggered job that explicitly names the privileged labels

`scan-images.yml` on branch `fix/issue-119-dependabot-manifest-guard` still
declared `runs-on: [self-hosted, linux, x64, zenchron]` (that branch predates the
redesign). A fresh `pull_request` run was triggered **after** the runners moved
into the restricted group.

```console
$ gh api …/actions/runs/30455448845 --jq '.event, .status'
  pull_request
  queued

$ gh api …/actions/runs/30455448845/jobs
  scan php-cli 8.3   status=queued runner=UNASSIGNED
  scan php-cli 8.4   status=queued runner=UNASSIGNED
  scan php-fpm 8.4   status=queued runner=UNASSIGNED
  scan caddy prod    status=queued runner=UNASSIGNED
  …10 jobs, none assigned, 200+ seconds

$ gh api orgs/zenchron-dynamics/actions/runner-groups/3/runners
  runner-prod-fsn1-org-zenchron-dynamics-1 status=online busy=false
  runner-prod-fsn1-org-zenchron-dynamics-2 status=online busy=false
```

**Both runners idle, nothing executing anywhere, jobs unassigned.** The jobs are
not waiting for capacity — they are refused.

## Attack coverage

| Attack | Outcome | Enforced by |
|---|---|---|
| Fork sets `runs-on: [self-hosted, …]` statically | **Refused** — proven above | group `restricted_to_workflows` + `@refs/heads/master` pin |
| Fork deletes every repository assertion | **Irrelevant** | assertions are not the boundary |
| Fork rewrites the trust predicate / inverts the ternary | **Irrelevant** | no expression is consulted; PR jobs are statically GitHub-hosted |
| Another org repository (10+ are public) uses the pool | **Refused** | `visibility: selected`, one repository |
| Fork invokes `trusted-validation.yml` directly | **Refused** | `workflow_dispatch` requires write access |

## Limits of this test

- It uses a **same-repo** pull request, not a real fork. The mechanism is
  identical — a PR run's workflow ref is `refs/pull/N/merge` either way — but a
  true fork test with an external account has **not** been performed.
- It proves refusal for `scan-images.yml`. Other workflow paths share the same
  group configuration; they were not individually exercised.
- `Default` retains `visibility: all`; it now holds **no runners**, so it grants
  nothing, but a runner added to it later would be org-wide again.
