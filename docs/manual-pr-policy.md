# Manual PR Policy (Free-Tier)

GitHub Free cannot enforce branch protection on a private repo, so this policy is
enforced by **discipline + local tooling**, not by the platform.

> This is a compensating control, not equivalent to enforced GitHub branch
> protection. See
> [audits/free-tier-governance-accepted-risk.md](audits/free-tier-governance-accepted-risk.md).

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

- **No direct push to `master`.** Everything goes through a PR, even though
  GitHub does not enforce it. The local `pre-push` hook blocks accidental direct
  pushes.
- **Every change uses a PR** — including docs and config.
- **CODEOWNERS teams are advisory.** Their review request is informational; merge
  is not blocked by GitHub. Reviewers must self-discipline to actually review.
- **CI must be green before merge.** Red CI = do not merge
  (see [ci-failure-policy.md](ci-failure-policy.md)).
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
