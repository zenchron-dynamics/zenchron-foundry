# Security model: who can publish what

This describes the publish authority and least-privilege controls of the CI/CD
pipeline as implemented. It is the operational companion to
[threat-model.md](threat-model.md) (the full STRIDE enumeration) and
[release-governance.md](release-governance.md).

## Trust boundary

```text
[committer] -> [PR review on master] -> [GitHub Actions] -> [GHCR] -> [prod host] -> [container]
```

Nothing reaches the canonical `*-prod` tags without crossing a reviewed merge to
`master` and a gated, environment-approved release.

## Who can publish what

The workflows are deliberately separated so that each entry point can only do one
thing:

| Workflow | Trigger | Can push? | Tags it may write |
|----------|---------|-----------|-------------------|
| `ci.yml` | push/PR to `master` | No | none (build + smoke only) |
| `build-images.yml` | dispatch / call | No (`contents: read` only) | none — cannot publish |
| `scan-images.yml` | PR(images) / weekly | No | none |
| `scheduled-rebuild.yml` | weekly cron | Yes | dated candidate `rebuild-*` only |
| `publish-rc.yml` | dispatch (`rc` required) | Yes (via reusable) | immutable RC tags only |
| `publish-ghcr.yml` | `workflow_call` only (sole caller: `publish-rc.yml`) | Yes | immutable RC tags only |
| `promote-stable.yml` | dispatch from `refs/tags/<version>` | Retag only (no build) | `*-prod` + dated + `-debian` aliases |
| `release.yml` | dispatch from `refs/tags/<version>` | No | seals the GitHub Release only |

Key invariants:

- `build-images.yml` has **no `packages: write`**, so it physically cannot push a
  canonical tag even if a step tried.
- `publish-ghcr.yml` is **reusable only** (no `workflow_dispatch`), and its
  **sole caller is `publish-rc.yml`**. It emits **only** immutable, SHA-bound RC
  tags (e.g. `php-*:<ver>-vYYYY.MM.DD-rc<N>-sha-<12>` plus mutable convenience
  aliases) and never `*-prod`. Stable `*-prod` tags are **never built by any
  workflow** — they exist only as digest-only retags of verified RC digests,
  performed by `promote-stable.yml`.
- `scheduled-rebuild.yml` writes only dated candidate tags
  (`<fam>:rebuild-<date>` / `<ver>-rebuild-<date>`) and **never** mutates
  `*-prod`. Promotion stays manual via `release.yml`.

## Release controls (stable path)

`release.yml`'s `guard` job runs in the `foundry-production` GitHub Environment
(deployment tag policy `v*.*.*`; environment *required reviewers* are
billing-gated on the GitHub Free private plan and explicitly waived via
`ALLOW_FREE_TIER_NO_REVIEWERS=1` — see
[audits/free-tier-governance-accepted-risk.md](audits/free-tier-governance-accepted-risk.md))
and refuses to seal unless all hold:

1. **Tag format** — `vYYYY.MM.DD[.N]`, and the dispatch ref **is** that tag.
2. **Ancestry** — the tagged commit is an ancestor of `origin/master`
   (`git merge-base --is-ancestor`), so an unmerged commit cannot be released.
3. **Repo invariants** — `assert-pinned-actions.sh`, `assert-no-wolfi.sh`, and
   `assert-image-matrix.sh` pass.
4. **Exact-commit CI gate** — the required CI checks concluded successfully on
   the tagged commit itself.

`release.yml` **builds and pushes nothing**: it downloads the signed RC
manifest from the `publish-rc` workflow **artifact** (never committed, never
regenerated), verifies the promoted `*-prod` digests against it (see
[sbom-signing-provenance.md](sbom-signing-provenance.md)), and seals the GitHub
Release. The `foundry-rc` environment gates `publish-rc.yml` the same way
(deployment branch policy `master`) for release candidates.

## Least-privilege permissions

Each workflow requests only the scopes it needs:

- `ci.yml`, `build-images.yml`, `scan-images.yml` preflights: `contents: read`
  (scan-images also `security-events: write` for SARIF).
- `publish-ghcr.yml` (publish job): `contents: read`, `packages: write`,
  `security-events: write`, `id-token: write` (keyless cosign via OIDC).
- `release.yml`: top-level `contents: read`; the `release` job is granted
  `contents: write` only to create the GitHub Release.
- Publish concurrency is per channel (`stable` vs `rc-<rc>`) and never cancels a
  publish mid-flight.

`GITHUB_TOKEN` is ephemeral and repo-scoped; OIDC tokens are request-scoped.
There is no long-lived registry password and no signing private key to leak.
