# Repository Security Configuration

> **Status: ENFORCED AND MACHINE-VERIFIED** (applied 2026-07-28, issue #97).
> `zenchron-dynamics/zenchron-foundry` is **public** on **GitHub Free**, where
> branch protection, rulesets and tag protection are available. Both rulesets are
> live with **no bypass actors — administrators included**.
>
> The declared configuration lives in
> [`../policies/repository-governance.yaml`](../policies/repository-governance.yaml);
> [`../scripts/verify-repo-governance.sh`](../scripts/verify-repo-governance.sh)
> (`make verify-governance`) compares it against the live GitHub API and **fails
> closed in both directions** — a control claimed here but missing live, *and*
> live configuration not declared here. Dated evidence:
> [`audits/governance-verification-2026-07-28.json`](audits/governance-verification-2026-07-28.json).
>
> **What this file used to say, and why that mattered.** Until 2026-07-28 it
> opened with an accepted-risk banner asserting the repo "must remain private"
> and that protections were rejected with HTTP 422 on the Free plan. The repo was
> **public**, so the premise was false — and the live configuration had *zero*
> protections (`GET /rulesets` → `[]`, `GET /branches/master/protection` → 404).
> A checklist of unchecked boxes read as governance. The verifier exists so that
> can never silently recur: every claim below is now checked against reality.
> Superseded record:
> [audits/free-tier-governance-accepted-risk.md](audits/free-tier-governance-accepted-risk.md).

Sections marked **ENFORCED** are verified against the API by
`make verify-governance`. Sections marked **NOT ENFORCED** are gaps, deliberately
stated as gaps — not as controls-in-waiting.

## Branch ruleset — `master` (ENFORCED)

`master-protection`, target `refs/heads/master`, enforcement `active`,
`bypass_actors: []` (live: `current_user_can_bypass: never`).

- [x] **Pull request required before merging** — no direct push, for anyone.
- [x] **Dismiss stale approvals** when new commits are pushed.
- [x] **Conversation resolution required** before merging.
- [x] **All required status checks must pass.** The exact names are **not copied
      here**: they come from
      [`../policies/required-release-checks.yaml`](../policies/required-release-checks.yaml)
      (26 checks), the same file the exact-commit release gate reads, and
      `scripts/assert-required-checks.sh` keeps that file in lockstep with the
      real workflow job names. One list, three consumers, no drift. (The
      hand-copied list that used to sit here had rotted to job names — `build
      representative images (…)` — that no longer exist.)
- [x] **Linear history required.**
- [x] **Force pushes blocked** (`non_fast_forward`).
- [x] **Deletions blocked.**
- [ ] **Require branches up to date before merging** — deliberately **off**.
      A full CI pass is measured in hours (see [runner-capacity.md](runner-capacity.md)),
      so strict mode would force a rebase and full re-run on every `master`
      update and can livelock a merge. Compensating control: the release gate
      re-verifies every required check against the **exact tagged commit**
      (`scripts/check-exact-commit-ci.sh`), so a merge on a slightly stale base
      cannot produce an unverified release. Merge-time staleness is a correctness
      risk; release-time staleness is the security risk, and that one is closed.
- [ ] **Require signed commits** — still off by choice; enabling it before every
      contributor has signing configured blocks all merges. See
      [signed-commits.md](signed-commits.md).

## Tag ruleset — `v*` (ENFORCED)

`release-tags-immutable`, target `refs/tags/v*`, enforcement `active`,
`bypass_actors: []`.

- [x] **Deletion blocked** — a published release tag cannot be removed.
- [x] **Force-move blocked** (`non_fast_forward`).
- [x] **Repointing blocked** (`update`) — together with the two above, `v*` tags
      are immutable for **everyone**, including the owner. Repairing a mis-tagged
      release means disabling the ruleset, which is a visible, auditable admin
      action rather than a quiet force-push.
- [ ] **Tag creation is intentionally NOT restricted.** `scripts/prepare-release.sh`
      pushes new `v*` tags as the normal release path, and a *new* tag mutates no
      existing release. Restricting creation would break the release path and buy
      nothing.
- [ ] **Restrict who can create releases** — not applied. This is a role/settings
      action with no ruleset equivalent and is not API-verifiable from repository
      code; declared `pending` in the policy.

## What is NOT enforced, and why

These are **gaps**, not pending controls. The verifier requires each to be
*absent* live while the policy declares it `pending`, so none can be quietly
mistaken for protection.

- **A second reviewer.** `required_approving_review_count` is **0**, and
  `require_code_owner_review` is **off**. This is a single-maintainer repository
  and GitHub forbids self-approval: requiring an approval with no bypass actor
  would make every merge impossible, and adding a bypass actor to compensate
  would reduce the entire ruleset to theatre. A PR is still mandatory; what is
  missing is a second pair of eyes — a people problem, tracked in **issue #112**,
  not a settings problem. Raise both in the same change that onboards a second
  maintainer.
- **Environment approval gates.** `foundry-rc` and `foundry-production` carry
  deployment branch/tag policies but **no required reviewers** (verified
  2026-07-28). Previously documented as impossible on the plan — true for Free +
  *private*, false now that the repo is public. Same single-maintainer blocker.
- **Fork pull request workflow approval** (*Settings → Actions → General*) — not
  API-verifiable on this repo/token (`/actions/permissions/fork-pr-workflows` →
  404), so it must be confirmed by hand. It is defense in depth only: the
  [CI trust boundary](#ci-trust-boundary) does not depend on it.
- **Organization-level rulesets** — reading them needs the `admin:org` scope,
  which the maintainer's working token does not carry.

## Organization runner group (ENFORCED)

The self-hosted runners belong to the org-level **Default** group, and
`allows_public_repositories` must be **true**. GitHub disables it by default and
this repository is public, so the flag decides whether CI can run at all: with it
false, jobs are created and then **never dispatched** — they queue until the
24-hour timeout and are cancelled with no runner assigned. That is exactly what
happened between 2026-07-27T07:40 and 2026-07-29, and diagnosing it from outside
took hours because the endpoint requires `admin:org`.

It is verified by `make verify-governance`, and an **unreadable** endpoint is a
failure, not a skip — a control that cannot be read cannot be claimed.

**This flag is only safe because of the [CI trust boundary](#ci-trust-boundary).**
Allowing self-hosted runners on a public repository is precisely the exposure
that fork-PR isolation contains: fork pull requests run on ephemeral
GitHub-hosted runners, and the privileged pool only ever sees push and same-repo
events. The verifier therefore checks both the flag *and* that
`scripts/assert-runner-trust.sh` exists and is wired into `make validate`. Do not
enable the flag in a repository that lacks that gate.

## Emergency bypass

There is no bypass actor, so an emergency means **disabling the ruleset via the
API** — deliberately visible, and far better than a silent local hook override.
Record every use in the bypass log at the end of
[audits/free-tier-governance-accepted-risk.md](audits/free-tier-governance-accepted-risk.md),
then re-run `make verify-governance` to confirm the ruleset is back.

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

**Status: ENFORCED IN CODE.** Gate:
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

## Verify, re-apply, inspect

**Verify (do this first, and after any settings change):**

```bash
make verify-governance                                   # live API vs the policy
make verify-governance EVIDENCE=docs/audits/governance-verification-$(date -u +%F).json
```

It exits non-zero on any divergence and prints which side is wrong. `LOCAL=1`
skips only when `gh`/`jq`/`python3` are missing; a failed API call is a failure,
never a silent pass.

**Inspect what is live:**

```bash
gh api repos/zenchron-dynamics/zenchron-foundry/rulesets \
  --jq '.[] | "\(.id) \(.name) \(.target) \(.enforcement)"'
gh api repos/zenchron-dynamics/zenchron-foundry/rules/branches/master --jq '[.[].type]'
```

**Re-apply after an emergency disable** — reconstruct the payload from the policy
so the two cannot drift, then re-verify:

```bash
python3 - <<'PY' > master-ruleset.json
import yaml, json
names = yaml.safe_load(open("policies/required-release-checks.yaml"))["required_checks"]
p = yaml.safe_load(open("policies/repository-governance.yaml"))["branch_ruleset"]
print(json.dumps({
  "name": p["name"], "target": "branch", "enforcement": p["enforcement"],
  "bypass_actors": [],
  "conditions": {"ref_name": {"include": p["include_refs"], "exclude": []}},
  "rules": [
    {"type": "deletion"}, {"type": "non_fast_forward"}, {"type": "required_linear_history"},
    {"type": "pull_request", "parameters": p["pull_request"]},
    {"type": "required_status_checks", "parameters": {
        "strict_required_status_checks_policy": p["required_status_checks"]["strict"],
        "required_status_checks": [{"context": n} for n in names]}},
  ]}, indent=2))
PY
gh api -X POST repos/zenchron-dynamics/zenchron-foundry/rulesets --input master-ruleset.json

cat > tag-ruleset.json <<'EOF'
{ "name": "release-tags-immutable", "target": "tag", "enforcement": "active",
  "bypass_actors": [],
  "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
  "rules": [{"type": "deletion"}, {"type": "non_fast_forward"}, {"type": "update"}] }
EOF
gh api -X POST repos/zenchron-dynamics/zenchron-foundry/rulesets --input tag-ruleset.json

make verify-governance
```

> Use **rulesets**, not the classic `branches/master/protection` API — this file
> previously carried a classic-protection payload whose `contexts` had rotted to
> job names that no longer exist (`build representative images (…)`) and whose
> `required_approving_review_count: 1` would block **every** merge in a
> single-maintainer repo. Anything applied by hand is invisible to the verifier
> until it is declared in `policies/repository-governance.yaml`; declare first,
> apply second.
>
> `required_signed_commits` stays omitted — add it only once
> [signed-commits.md](signed-commits.md) is in effect for all contributors.
