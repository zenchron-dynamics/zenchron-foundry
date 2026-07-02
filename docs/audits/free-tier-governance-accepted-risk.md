# ACCEPTED RISK — FREE PLAN LIMITATION

**Status:** `ACCEPTED RISK — FREE PLAN LIMITATION`
**Owner:** Bogdan Olteanu / Zenchron Dynamics
**Decision date:** 2026-06-01
**Review date:** 2026-07-01 (30 days)

> This is a compensating control, not equivalent to enforced GitHub branch
> protection.

## Decision

Keep `zenchron-dynamics/zenchron-foundry` on **GitHub Free** for now. The
repository **must remain private**.

## Reason

Avoid extra cost while the platform is internal / pre-production. The runtime
images, CI, signing, and SBOM supply chain are already in place; the only gap is
GitHub-enforced repository governance.

## Limitation

On the GitHub Free plan, **private** repositories cannot use:

- Classic **branch protection** (`PUT …/branches/master/protection` → HTTP 403
  "Upgrade to GitHub Pro or make this repository public").
- **Repository rulesets** (`POST …/rulesets` → same 403).
- **Tag protection** (rulesets gated; the legacy `tags/protection` API is
  removed → 404).

- **Environment required reviewers** (`PUT …/environments/{env}` with
  `reviewers` → HTTP 422 "ensure the billing plan supports the required
  reviewers protection rule"). The `foundry-rc` / `foundry-production`
  environments exist and their **deployment branch/tag policies work** (those
  are free), but the human **approval gate cannot be attached** on Free+private.

This is a **plan** limitation, not a permissions one — the maintainer is org
admin and repo admin; the API rejects the feature on this plan.

## Impact (what GitHub cannot enforce)

- Required pull requests before merge to `master`.
- Required CODEOWNERS review.
- Required passing status checks before merge.
- Force-push / branch-deletion blocking on `master`.
- Protected / restricted release tags (`v*`).

CODEOWNERS resolves to real teams but is **advisory** — it requests reviewers, it
cannot block a merge.

## Compensating controls (implemented)

| Control | Where | Note |
|---------|-------|------|
| Local `pre-push` hook: block direct/force push to master, gate `v*` tags | `scripts/git-hooks/pre-push` | local + bypassable |
| Hook installer | `scripts/install-hooks.sh` | copies into `.git/hooks` |
| Release safety script (clean tree, branch, tag format, CI status, checks, confirm) | `scripts/prepare-release.sh` | refuses red CI / bad tag |
| Manual PR policy | `docs/manual-pr-policy.md` | branch → PR → CI → review → merge |
| CI failure policy | `docs/ci-failure-policy.md` | red master CI = release blocker |
| Read-only GHCR deploy tokens | `docs/ghcr-consuming-private-images.md` | `read:packages` only |
| Digest pinning + Dependabot | Dockerfiles, `dependabot.yml` | immutable bases |
| Cosign signing + SBOM attest | `publish-ghcr.yml` | tamper-evidence |
| Release-env deployment branch/tag policies | `foundry-rc`→`master`, `foundry-production`→`v*.*.*` | free; restricts refs even without reviewer gate |
| Release-env preflight (fail-closed) | `scripts/check-release-environments.sh` | proves existence + policies live; still demands reviewers (unattainable on this plan) |
| Signed commits (when key available) | `docs/signed-commits.md` | armed, opt-in |

**None of these enforce policy the way paid branch protection would.** They
reduce accidents and add visibility; a determined actor with push access can
bypass the local hook (`ZENCHRON_ALLOW_PROTECTED_PUSH=1`).

## Exit criteria

Re-evaluate this accepted risk (and the plan) when **either**:

- this platform is consumed by production, revenue-generating systems; **or**
- more than one maintainer can push to the repository.

At that point, enforced governance becomes worth its cost.

## Emergency direct-push / bypass log

Any use of `ZENCHRON_ALLOW_PROTECTED_PUSH=1` or a direct push to `master` outside
the PR flow must be appended here with date, actor, and reason.

| Date | Actor | Action | Reason |
|------|-------|--------|--------|
| 2026-06-01 | automation (this pass) | direct push to master via bypass | bootstrap the compensation controls themselves; no PR flow existed yet |
