# Repository Security Configuration

Settings to apply in GitHub (org/repo admin). This file is the source of truth;
apply it manually or via Terraform/`gh` until codified.

## Branch protection — `master`

- [ ] Require a pull request before merging.
- [ ] Require **≥ 1 approving review** (2 for security-sensitive paths via
      CODEOWNERS).
- [ ] Require **review from Code Owners** (`CODEOWNERS`).
- [ ] Dismiss stale approvals on new commits.
- [ ] Require **status checks to pass**:
      `ci / structure`, `ci / lint`, `ci / secrets`, `ci / sast`,
      `ci / build-test`, `ci / compose-validate`.
- [ ] Require branches up to date before merge.
- [ ] Require **signed commits**.
- [ ] Require linear history.
- [ ] **No direct pushes** (include admins).
- [ ] **No force-push**, no branch deletion.

## Signed commits

Contributors sign with GPG/SSH/`gitsign`. Branch protection enforces it.
`git config commit.gpgsign true`.

## Required reviews & ownership

`CODEOWNERS` routes workflows, policies, profiles, and legacy images to the
platform and security teams. Replace the placeholder teams before enabling
enforcement.

## Dependabot

`.github/dependabot.yml` covers GitHub Actions, Docker bases (supported weekly /
legacy monthly), and Composer (examples). Enable Dependabot **security updates**
and **version updates** in repo settings.

## Secret scanning & push protection

- [ ] Enable GitHub **secret scanning**.
- [ ] Enable **push protection**.
- [ ] Gitleaks runs in pre-commit and `ci.yml` as defense in depth.

## Code scanning

- [ ] Enable **Private Vulnerability Reporting**.
- [ ] SARIF from Trivy/Grype/Semgrep surfaces in the **Security** tab
      (`security-events: write`).

## Actions hardening

- [ ] Restrict Actions to verified + selected actions; pin third-party actions
      to a commit SHA (Dependabot updates them).
- [ ] Default `GITHUB_TOKEN` permissions = **read**; workflows opt into more.
- [ ] Require approval for workflows from fork PRs.

## Vulnerability reports

Routed via [`SECURITY.md`](../SECURITY.md) to `security@zenchron.com` / private
reporting. SLAs defined there.

## Apply via `gh` (example)

```bash
gh api -X PUT repos/zenchron-dynamics/docker-platform/branches/master/protection \
  --input branch-protection.json   # encode the checklist above
```
