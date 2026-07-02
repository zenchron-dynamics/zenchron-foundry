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
| `publish-ghcr.yml` | `workflow_call` only | Yes | RC when `rc` set; `*-prod` only when `rc==""` |
| `release.yml` | push tag `v*` | Yes (via reusable) | `*-prod` + dated + build + `-debian` |

Key invariants:

- `build-images.yml` has **no `packages: write`**, so it physically cannot push a
  canonical tag even if a step tried.
- `publish-ghcr.yml` is **reusable only** (no `workflow_dispatch`): the only ways
  to reach it are `release.yml` (stable) and `publish-rc.yml` (RC). When its `rc`
  input is non-empty it emits **only** immutable RC tags (`php-*:<ver>-debian-rc<N>`,
  edges `prod-rc<N>`) and never `*-prod`. Stable (`rc==""`) additionally requires
  a tag ref matching `vYYYY.MM.DD[.N]` — a defensive check beyond `release.yml`.
- `scheduled-rebuild.yml` writes only dated candidate tags
  (`<fam>:rebuild-<date>` / `<ver>-rebuild-<date>`) and **never** mutates
  `*-prod`. Promotion stays manual via `release.yml`.

## Release controls (stable path)

`release.yml`'s `guard` job runs in the protected `foundry-production` GitHub Environment
(required reviewers) and refuses to publish unless all hold:

1. **Tag format** — `vYYYY.MM.DD[.N]`.
2. **Ancestry** — the tagged commit is an ancestor of `origin/master`
   (`git merge-base --is-ancestor`), so an unmerged commit cannot be released.
3. **Repo invariants** — `assert-pinned-actions.sh`, `assert-no-wolfi.sh`, and
   `assert-image-matrix.sh` pass.

Only then does `images` call `publish-ghcr.yml` multi-arch, followed by the
post-publish `verify-release-artifacts.sh` proof (see
[sbom-signing-provenance.md](sbom-signing-provenance.md)). The `foundry-rc` environment
gates `publish-rc.yml` the same way for release candidates.

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
