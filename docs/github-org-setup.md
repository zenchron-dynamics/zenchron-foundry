# GitHub Org Setup — Teams & Ownership

`CODEOWNERS` currently falls back to the repo admin handle because the
`zenchron-dynamics` org has **no teams yet** (verified: `gh api
orgs/zenchron-dynamics/teams` returns `[]`). Create the teams below, then migrate
`CODEOWNERS` to real teams.

> All steps require **org owner / admin** rights and are GitHub UI / API actions —
> they cannot be enforced from this repository's code.

## 1. Create teams

```bash
gh api -X POST orgs/zenchron-dynamics/teams -f name='platform' \
  -f description='Platform engineering — images, CI/CD, runtime' -f privacy='closed'
gh api -X POST orgs/zenchron-dynamics/teams -f name='security' \
  -f description='Security — policies, threat model, vuln management' -f privacy='closed'
```

Resulting slugs: `@zenchron-dynamics/platform`, `@zenchron-dynamics/security`.

## 2. Add members

```bash
gh api -X PUT orgs/zenchron-dynamics/teams/platform/memberships/<user>  -f role='maintainer'
gh api -X PUT orgs/zenchron-dynamics/teams/security/memberships/<user>  -f role='maintainer'
```

## 3. Grant the teams access to the repo

```bash
gh api -X PUT orgs/zenchron-dynamics/teams/platform/repos/zenchron-dynamics/zenchron-foundry -f permission='push'
gh api -X PUT orgs/zenchron-dynamics/teams/security/repos/zenchron-dynamics/zenchron-foundry -f permission='push'
```

A team must have at least write/push access for its CODEOWNERS entries to be
honored.

## 4. Ownership mapping (apply in CODEOWNERS after teams exist)

| Path | Owners |
|------|--------|
| `/images/**`, Dockerfiles | `@zenchron-dynamics/platform` `@zenchron-dynamics/security` |
| `/.github/workflows/**` | `@zenchron-dynamics/platform` `@zenchron-dynamics/security` |
| `/policies/**` | `@zenchron-dynamics/security` |
| `/profiles/**` | `@zenchron-dynamics/platform` `@zenchron-dynamics/security` |
| `/docs/**` | `@zenchron-dynamics/platform` |
| `/examples/**` | `@zenchron-dynamics/platform` |
| `SECURITY.md`, threat-model, vuln-management, release-governance, repository-security | `@zenchron-dynamics/security` |

Then update `docs/repository-security.md` to require **2** approvals on
security-sensitive paths.

## 5. Verify

```bash
gh api orgs/zenchron-dynamics/teams --jq '.[].slug'          # platform, security
# Open a test PR touching images/ and confirm both teams are requested as reviewers.
```

## 6. Migrate CODEOWNERS

Replace `@bogdaniel` per the table above and commit. Re-open a test PR to confirm
team review requests fire. Until this is done, leave the working `@bogdaniel`
fallback in place — do **not** point CODEOWNERS at nonexistent teams.
