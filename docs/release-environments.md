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

## BLOCKING — human reviewers required

The environments are scaffolded but **not release-ready**. GitHub will not let
`prevent_self_review` be set until at least one reviewer exists, so both the
reviewers and self-review hardening are a single owner action.

```
foundry-rc required reviewers:
- [OWNER TO ASSIGN]

foundry-production required reviewers:
- [OWNER TO ASSIGN]
- [SECURITY/PLATFORM REVIEWER TO ASSIGN]
```

Recommended policy:

```
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
- [ ] Ratify CVE-2026-34986 (Caddy) separately — see
      [security/cve-2026-34986-review.md](security/cve-2026-34986-review.md). The
      environment work does **not** unblock stable promotion by itself.

Reviewer assignment is not scriptable here without inventing identities; it is
left to the repository owner.
