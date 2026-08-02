# Accepted risks

Formal record of risks accepted because the current GitHub plan cannot enforce
the ideal control. Each names the gap, why it is accepted, and the compensating
controls. Re-review when the org moves to Team or the repo goes public.

## AR-1 — No independent human reviewer on release

- **Gap:** GitHub Free (private repo) cannot attach required reviewers or
  `prevent_self_review` to the `foundry-rc` / `foundry-production` environments,
  so a single maintainer both authors and approves a release.
- **Why accepted:** it is a real platform limit, not a choice; faking a second
  reviewer would be security theatre. `ALLOW_FREE_TIER_NO_REVIEWERS=1` in the
  release workflows records this explicitly (fail-closed on everything else).
- **Compensating controls:** the full technical stack in
  [solo-maintainer-release-model](solo-maintainer-release-model.md) — immutable
  SHA-bound RC artifacts, exact-revision binding, mandatory exact-commit CI,
  cryptographic attestations under explicit identities, build-free promotion with
  tested rollback, typed confirmations, and immutable evidence.
- **Detection/limit:** `scripts/check-release-environments.sh` still enforces the
  non-human protections (tags-only production, deployment branch/tag policies) and
  fails closed if it cannot read them.
- **Removal condition:** move to a plan with environment reviewers, then drop the
  `ALLOW_FREE_TIER_NO_REVIEWERS` waiver and require reviewers.

## AR-2 — Self-hosted runners are persistent, shared, sudo-capable

- **Gap:** the runner instances are **non-root but sudo-capable**, live on one
  2 vCPU / 4 GB / 40 GB host, share a single `$HOME`, and keep their workspaces
  between jobs (corrected 2026-07-09 from the earlier "root, no sudo, strictly
  serial" note — see [runner-capacity.md](runner-capacity.md)). Heavy matrices
  still run `max-parallel: 1`, for disk, not isolation.
- **Why accepted:** it is the available capacity.
- **Compensating controls:** **untrusted code never runs there** — every job
  picks its pool from the trigger's trust, so fork PRs land on ephemeral
  GitHub-hosted VMs and the privileged pool is reserved for push/tag/schedule/
  dispatch and same-repo PRs (`scripts/assert-runner-trust.sh` fails CI on drift;
  `pull_request_target` is banned repo-wide; see
  [repository-security.md § CI trust boundary](repository-security.md#ci-trust-boundary)).
  Plus: centralized strict workspace reset
  (`scripts/ci/reset-workspace-ownership.sh`, realpath + strict-descendant, no
  `|| true`), job-scoped Docker cleanup (`scripts/ci/cleanup-docker-job.sh`, no
  global prune), publish/OIDC permissions only in dispatch/tag-triggered jobs,
  and a runner job-started hook template (`scripts/ci/install-runner-hook.sh`).
- **Residual:** host-level hardening of the runner user (sudoers scope, Docker
  group membership, per-job isolation) requires **runner-admin access** and
  cannot be enforced from repository code. A maintainer-authored PR is still
  trusted-by-construction on this host.
