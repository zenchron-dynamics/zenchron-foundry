# Repository Security Configuration

Exact GitHub settings for `zenchron-dynamics/zenchron-foundry`. This file is the
source of truth; apply via the GitHub UI or `gh`/Terraform.

> **These are admin/UI actions.** They cannot be enforced from repository code.
> A reviewer must confirm them in *Settings → Branches/Rules*. Status below is
> "required", not "verified-applied" — applying them needs org/repo admin rights.

## Branch protection / ruleset — `master`

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
- [ ] Require approval for workflows from fork PRs.

## Vulnerability reports

Routed via [`SECURITY.md`](../SECURITY.md) to `security@zenchron.com` / private
reporting; SLAs there.

## Apply via `gh` (example — requires admin)

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
