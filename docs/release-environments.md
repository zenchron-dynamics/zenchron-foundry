# Release environments

The protected release chain deploys through **exactly two** GitHub Environments.
Their names are fixed and enforced by CI (`scripts/assert-environment-names.sh`):

| Environment | Used by | Purpose |
|-------------|---------|---------|
| `foundry-rc` | `publish-rc.yml` (`gate` job) | Approve + gate RC publication. Cannot mutate canonical `*-prod` aliases. |
| `foundry-production` | `promote-stable.yml` (`gate`), `release.yml` (`guard`) | Approve + gate stable promotion and the GitHub Release seal. |

No other workflow may use these environments. Generic CI, scheduled rebuilds,
and dispatchable helpers run with `contents: read` and no environment.

## Non-human protections (configured)

These are set and verifiable via the API today — no reviewer identity required.

### `foundry-rc`

- Deployment restricted to a **custom branch policy: `master`** (the protected
  default branch). No arbitrary feature branch, no PR branch, no fork.
- The RC workflow independently re-validates the RC identifier (`rc<N>`), and the
  release convention is further enforced by the `guard`/`gate` jobs
  (`expected_revision == github.sha`, reachable from `origin/master`, valid CalVer).

### `foundry-production`

- Deployment restricted to a **custom tag policy: `v*.*.*`** — tags only, no
  branches, no PR refs, no fork.
- `v*.*.*` is a coarse net. The authoritative CalVer/RC filter is `release.yml`'s
  `guard` regex `^v[0-9]{4}\.[0-9]{2}\.[0-9]{2}(\.[0-9]+)?$`, which rejects RC and
  malformed tags before anything publishes.
- No environment secrets (registry access is OIDC + `GITHUB_TOKEN`). Verified: 0
  secrets in each environment.
- No bypass actors.

## Preflight

Every release job runs, before any publish/promote/seal:

```sh
scripts/check-release-environments.sh --release-ready
```

It **fails closed**: any check the GitHub API cannot positively prove (auth,
existence, deployment policy, required reviewers, production self-review) blocks
the release. `--structure` verifies everything except reviewers, for local scaffolding
checks. See the script header for the token it needs.

**Compensating-control mode.** Because no reviewers are attached (see the warning
below), the release workflows set `ALLOW_FREE_TIER_NO_REVIEWERS=1`. In that mode
`--release-ready` still hard-fails on auth / existence / deployment-policy checks,
but the reviewer + self-review checks are **WAIVED** and logged, and the banner
reads `PASS (COMPENSATING-CONTROL MODE)`. Enforcement then rests on the deployment
branch/tag policies, the active `master` / `v*` rulesets
([repository-security.md](repository-security.md)), and the workflow guards
(CalVer, master-ancestry, exact-digest equality, signature/SBOM verification).
Locally, without the env var, the script stays **strict** and fails on missing
reviewers — remove the workflow env var and assign real reviewers once a second
maintainer exists (issue #112).

## BLOCKING — human reviewers required

> ⚠️ **Corrected 2026-07-28 (issue #97): this is a single-maintainer limit, not a
> plan limit.** The previous text said environment *required reviewers* were
> billing-gated (HTTP 422) on "GitHub Free, private repo". The repository is
> **public**, where environment protection rules are available for free — so the
> approval gate *can* now be attached. It is not, because with one maintainer a
> required reviewer blocks every release instead of adding oversight (GitHub
> forbids self-approval, and `prevent_self_review` cannot be set until a reviewer
> exists). Verified 2026-07-28: both environments carry `branch_policy` only, no
> `required_reviewers` — recorded as `pending` in
> [`../policies/repository-governance.yaml`](../policies/repository-governance.yaml)
> so `make verify-governance` keeps it visible as a **gap, not a control**.
> Closing it means onboarding a second approver (issue #112), after which
> `--release-ready` can drop the waiver.

The environments are scaffolded but **not release-ready**. GitHub will not let
`prevent_self_review` be set until at least one reviewer exists, so both the
reviewers and self-review hardening are a single owner action.

```text
foundry-rc required reviewers:
- [OWNER TO ASSIGN]

foundry-production required reviewers:
- [OWNER TO ASSIGN]
- [SECURITY/PLATFORM REVIEWER TO ASSIGN]
```

Recommended policy:

```text
foundry-rc:
  at least 1 required reviewer

foundry-production:
  at least 1 required reviewer
  preferably 2 distinct reviewers
  prevent self-review enabled
```

Until real reviewers are assigned, `check-release-environments.sh --release-ready`
fails and the release workflows stay blocked. Do **not** assign the workflow
author as the only production reviewer.

## Owner action checklist

- [ ] Assign `foundry-rc` required reviewer(s) (≥1).
- [ ] Assign `foundry-production` required reviewers (≥1, preferably 2 distinct;
      not the workflow author alone).
- [ ] Enable **Prevent self-review** on `foundry-production` (Settings →
      Environments → foundry-production). This can only be enabled once reviewers
      exist. Recommended on `foundry-rc` too.
- [ ] (Recommended) Add branch protection to `master` so the default branch is
      protected in its own right — the deployment policy already restricts `foundry-rc`
      to `master`, but branch protection hardens the source of truth.
- [ ] Provide a repo/org secret `RELEASE_ENV_CHECK_TOKEN` — a fine-grained PAT with
      **Environments: read** + **Administration: read** — so the in-workflow preflight
      can prove reviewer protection. Without it the preflight fails closed (safe, but
      blocks release).
- [x] ~~Ratify CVE-2026-34986 (Caddy)~~ **RESOLVED** — the pinned Caddy base
      already ships the fixed `go-jose/v3 v3.0.5`; exception removed, no ratification
      needed. See [security/cve-2026-34986-review.md](security/cve-2026-34986-review.md).

Reviewer assignment is not scriptable here without inventing identities; it is
left to the repository owner.
