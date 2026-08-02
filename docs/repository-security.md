# Repository Security Configuration

> **Status: `ACCEPTED RISK — FREE PLAN LIMITATION`.** The repo is on **GitHub
> Free** and **must remain private**. Classic branch protection, required
> reviewers, repository rulesets, and tag protection are **unavailable on this
> plan for private repos** (verified: the API rejects them with 422
> "Upgrade … or make this repository public"). The settings below are therefore
> the **target** once protection becomes available; today they are compensated
> by deployment branch/tag policies on the `foundry-rc` (branch `master`) and
> `foundry-production` (tags `v*.*.*`) environments, typed-confirmation
> workflow inputs, the exact-commit CI gate, local hooks + policy, and the
> documented `ALLOW_FREE_TIER_NO_REVIEWERS=1` waiver — which are **not
> equivalent to enforced GitHub branch protection**. See
> [audits/free-tier-governance-accepted-risk.md](audits/free-tier-governance-accepted-risk.md),
> [manual-pr-policy.md](manual-pr-policy.md), and
> [ci-failure-policy.md](ci-failure-policy.md).
>
> **Correction, verified 2026-07-28** (`gh repo view --json visibility` →
> `PUBLIC`, `isPrivate: false`): the repository is **public today**, contradicting
> the "must remain private" statement above. Reconciling the intended visibility
> with branch/tag/release protection is tracked in **issue #97** and is not
> settled here. What follows from the verified fact, and is already enforced in
> code, is that **anyone can open a fork pull request** — see
> [CI trust boundary](#ci-trust-boundary).

Exact GitHub settings for `zenchron-dynamics/zenchron-foundry`. This file is the
source of truth; apply via the GitHub UI or `gh`/Terraform **when the plan allows
it**.

> **These are admin/UI actions.** They cannot be enforced from repository code.
> A reviewer must confirm them in *Settings → Branches/Rules*. Status below is
> "required", not "verified-applied" — applying them needs org/repo admin rights.

## Branch protection / ruleset — `master`

> **Requires GitHub Team plan or a public repository.** On the current Free
> private plan the API rejects every setting below with 422 — this checklist is
> the target state, not the applied state.

Target branch: `master` (the project's primary branch).

- [ ] **Require a pull request before merging.**
- [ ] **Require ≥ 1 approving review** (raise to 2 once the security team exists).
- [ ] **Require review from Code Owners** (`CODEOWNERS`). *Note:* effective only
      once real org teams/owners exist — see
      [github-org-setup.md](github-org-setup.md). Until then CODEOWNERS routes to
      the repo admin handle.
- [ ] **Dismiss stale approvals** when new commits are pushed.
- [ ] **Require conversation resolution** before merging.
- [ ] **Require status checks to pass** (exact CI job/context names):
      - `repo structure`
      - `lint (shell / yaml / md / dockerfile)`
      - `secret scan (gitleaks)`
      - `semgrep docker security`
      - `validate compose profiles`
      - `build representative images (php-fpm, 8.3)`
      - `build representative images (php-cli, 8.3)`
      - `build representative images (php-worker, 8.3)`
      - `build representative images (nginx)`
      - `build representative images (caddy)`
- [ ] **Require branches up to date** before merging.
- [ ] **Require linear history.**
- [ ] **Block force pushes.**
- [ ] **Block deletions.**
- [ ] **Restrict who can push to `master`** (include administrators — no direct
      pushes; everything via PR).
- [ ] **Require signed commits** — enable **only** once the org is ready (see
      [signed-commits.md](signed-commits.md)); do not enable before contributors
      have signing configured, or it will block all merges.

## Tag & release protection

> **Requires GitHub Team plan or a public repository.** Tag rulesets are
> unavailable on the current Free private plan (API 422). Until then, the
> enforced control is the `foundry-production` environment's deployment tag
> policy (`v*.*.*`) plus the fact that `release.yml` has no tag-push trigger.

- [ ] **Tag ruleset** for `v*`: restrict **tag creation** to maintainers
      (publishing triggers off `v*` tags — see
      [release-governance.md](release-governance.md)).
- [ ] **Restrict who can create releases** to maintainers.
- [ ] Block deletion/force-update of existing `v*` tags (immutable releases).

## Signed commits

Contributors sign with SSH or GPG; GitHub vigilant mode flags unsigned commits.
Full setup + the decision on *when* to enforce: [signed-commits.md](signed-commits.md).
Do not turn on the branch-protection "require signed commits" box until signing
is configured and tested for all contributors.

## Required reviews & ownership

`CODEOWNERS` routes Dockerfiles/images, workflows, policies, profiles, and docs
to owners. **No org teams exist yet**, so `CODEOWNERS` currently points at the
repo admin handle as a working fallback. Create `platform` and `security` teams
and migrate per [github-org-setup.md](github-org-setup.md), then raise the review
count for security-sensitive paths.

## Dependabot

`.github/dependabot.yml` covers GitHub Actions, Docker bases (supported weekly /
legacy monthly), and Composer (examples). Enable Dependabot **security updates**
and **version updates** in repo settings. Base images are digest-pinned so
Dependabot opens PRs to bump the digests.

## Secret scanning & push protection

- [ ] Enable GitHub **secret scanning** + **push protection**.
- [ ] Gitleaks (CLI) runs in `ci.yml` and pre-commit as defense in depth.

## Code scanning

- [ ] Enable **Private Vulnerability Reporting**.
- [ ] Trivy/Grype/Semgrep SARIF surfaces in the **Security** tab
      (`security-events: write`).

## Actions hardening

- [ ] Restrict Actions to verified + selected actions; pin third-party actions to
      a commit SHA (Dependabot updates them).
- [ ] Default `GITHUB_TOKEN` permissions = **read**; workflows opt into more.
- [ ] Require approval for workflows from fork PRs. **Not verified applied** —
      an admin must confirm *Settings → Actions → General → Fork pull request
      workflows*. The CI trust boundary below does **not** depend on it.

## CI trust boundary

**Status: ENFORCED IN CODE** (unlike the admin/UI items above). Gate:
[`scripts/assert-runner-trust.sh`](../scripts/assert-runner-trust.sh), wired into
`make validate` and the `repo structure` CI job; regression test:
[`tests/runner/test_workflow_trust.sh`](../tests/runner/test_workflow_trust.sh).

The `[self-hosted, linux, x64, zenchron]` runners are **persistent, shared,
Docker-capable and sudo-capable** hosts that also execute release-adjacent jobs
(see [runner-capacity.md](runner-capacity.md)). A fork pull request's head commit
is attacker-controlled code — Dockerfiles, the `scripts/*.sh` CI invokes, compose
files, linter configs — so executing it there would compromise the runner host,
its Docker daemon, the workspaces reused by later trusted jobs, and therefore the
release supply chain.

Every job therefore derives its runner from the trust of the triggering event:

| Trigger | Runner | Rationale |
|---|---|---|
| `push` to `master`, tag, `schedule`, `workflow_dispatch` | `[self-hosted, linux, x64, zenchron]` | Code already merged/authorized by a maintainer |
| `pull_request` from a branch **in this repository** | `[self-hosted, linux, x64, zenchron]` | Push access to this repo is already required |
| `pull_request` from a **fork** | `ubuntu-latest` (GitHub-hosted, ephemeral, destroyed after the job) | Untrusted code; blast radius is one throwaway VM |

The decision is spelled with one unspoofable predicate,
`github.event.pull_request.head.repo.full_name == github.repository` — GitHub
populates `head.repo` from the head ref itself, so a PR branch cannot forge it.
It appears either inside a job's `runs-on` expression (`ci.yml`) or as a job-level
`if:` that skips the job entirely for forks (`scan-images.yml`).

Enforced invariants (each fails the build):

- **R1** — no workflow may use `pull_request_target` (base-repo token in the
  context of PR-authored content).
- **R2** — every `pull_request`-reachable job on a privileged label carries the
  predicate in job-level configuration. A *step*-level `if:` or a comment
  mentioning the predicate does **not** satisfy the gate.
- **R3** — a `pull_request`-reachable job may not delegate to another workflow
  (`uses:` at job level): the callee's runner labels are unprovable from the
  caller, so the gate fails closed pending review.
- **R4** — empty discovery (no workflow files, no `runs-on`) fails; the gate is
  never vacuously green.

Consequences for fork contributors:

- Structure, lint, secret-scan, SAST and compose validation **do** run on a fork
  PR, on GitHub-hosted runners.
- `build+smoke *` and `aggregate build+smoke results` **skip** on fork PRs (they
  build fork-authored Dockerfiles). Those checks are required for merge, so a
  maintainer must re-run them from a same-repo branch before merging a fork PR —
  see [manual-pr-policy.md](manual-pr-policy.md).
- `ci.yml` references no secrets and keeps `permissions: contents: read`, so an
  untrusted job has nothing to exfiltrate even on its own ephemeral VM.

## Vulnerability reports

Routed via [`SECURITY.md`](../SECURITY.md) to `security@zenchron.com` / private
reporting; SLAs there.

## Apply via `gh` (example — requires admin)

> **Requires GitHub Team plan or a public repository.** Both commands below
> fail with 422 on the current Free private plan. Keep them for the day the
> plan changes; do not treat them as applied.

```bash
# Branch protection (encode the checklist as JSON):
gh api -X PUT repos/zenchron-dynamics/zenchron-foundry/branches/master/protection \
  --input branch-protection.json

# Minimal branch-protection.json:
# {
#   "required_status_checks": {
#     "strict": true,
#     "contexts": [
#       "repo structure",
#       "lint (shell / yaml / md / dockerfile)",
#       "secret scan (gitleaks)",
#       "semgrep docker security",
#       "validate compose profiles",
#       "build representative images (php-fpm, 8.3)"
#     ]
#   },
#   "enforce_admins": true,
#   "required_pull_request_reviews": {
#     "required_approving_review_count": 1,
#     "require_code_owner_reviews": true,
#     "dismiss_stale_reviews": true
#   },
#   "required_conversation_resolution": true,
#   "required_linear_history": true,
#   "allow_force_pushes": false,
#   "allow_deletions": false,
#   "restrictions": null
# }

# Tag protection for v*:
gh api -X POST repos/zenchron-dynamics/zenchron-foundry/rulesets --input tag-ruleset.json
```

> `required_signed_commits` is intentionally omitted above — add it only after
> [signed-commits.md](signed-commits.md) is in effect for all contributors.
