# PR Policy

**Updated 2026-07-28 (issue #97).** The platform now enforces the core of this
policy: `master` requires a pull request with the 5 PR-required checks green, linear
history, resolved conversations, and blocks direct push, force-push and deletion
— with no bypass actors, administrators included
([repository-security.md](repository-security.md)). The previous version stated
that GitHub Free could not enforce branch protection on a private repo; the repo
is public, so that was false and this policy was carrying the whole load alone.

What still rests on discipline, because GitHub cannot enforce it here: the
**review itself** (single maintainer, approvals set to 0 — issue #112), treating
a **skipped** check as a failure, and the release-time rules below.

## Workflow

```text
feature branch  ->  PR  ->  wait for CI  ->  manual review  ->  squash/merge  ->  release script
```

1. Branch from `master`: `git switch -c feat/<short-name>`.
2. Push the branch and open a PR (the `pre-push` hook blocks pushing to `master`
   directly).
3. Wait for **CI to go green** on the PR.
4. Manual review — CODEOWNERS (`@zenchron-dynamics/platform` / `security`) are
   requested automatically but are **advisory**; a human must actually review.
5. **Squash & merge** the PR (keeps `master` linear).
6. Cut releases only via `scripts/prepare-release.sh`.

## Rules

- **No direct push to `master`.** Enforced by the `master-protection` ruleset for
  everyone, administrators included; the local `pre-push` hook now just fails
  faster and offline.
- **Every change uses a PR** — including docs and config.
- **CODEOWNERS teams are advisory.** `require_code_owner_review` is off: the sole
  code owner cannot approve their own PR, so enabling it would block every merge
  (issue #112). The review request is informational — a human must actually read
  the diff.
- **CI must be green before merge.** Red CI = do not merge
  (see [ci-failure-policy.md](ci-failure-policy.md)).
- **Fork PRs are never merged on their own CI.** A fork PR runs only the
  untrusted-safe checks, on ephemeral GitHub-hosted runners; `build+smoke *` and
  `aggregate build+smoke results` deliberately **skip**, because they would build
  fork-authored Dockerfiles on the privileged self-hosted pool (see
  [repository-security.md § CI trust boundary](repository-security.md#ci-trust-boundary)).
  Before merging a fork PR a maintainer must **review the diff first**, then
  re-run the full matrix from a same-repo branch carrying those commits, and
  merge only when that branch is green. A skipped required check is **not** a
  pass.
- **Release tags only through the release script** (`scripts/prepare-release.sh`),
  which gates the `v*` tag push.
- **Emergency direct push** (using `ZENCHRON_ALLOW_PROTECTED_PUSH=1`) requires an
  appended entry in
  [audits/free-tier-governance-accepted-risk.md](audits/free-tier-governance-accepted-risk.md)
  (date, actor, reason).
- **All production image tags must be immutable or digest-pinned** — never deploy
  `latest`; pin `@sha256:` in production (see
  [image-versioning.md](image-versioning.md)).

## Why bother with PRs GitHub won't enforce

- A PR gives a diff, a CI run, and a review surface even without enforcement.
- It keeps history clean and auditable.
- It makes the eventual switch to enforced rules a no-op (the habit is already in
  place).
- The local hook turns "I forgot" into "I was stopped", which is most of the
  value for a small team.

## Setup

```bash
scripts/install-hooks.sh    # installs the pre-push + pre-commit hooks locally
```

Each maintainer must run this on their clone — local hooks are per-clone and are
**not** distributed by GitHub.
