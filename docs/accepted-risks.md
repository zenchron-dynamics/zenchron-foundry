# Accepted risks

Formal record of risks accepted because the ideal control cannot currently be
enforced. Each names the gap, why it is accepted, and the compensating controls.

> **Re-scoped 2026-07-28 (issue #97).** These records previously blamed the
> GitHub *plan*. The repository is public, where rulesets, branch protection and
> environment reviewers are all available for free — branch and tag protection
> are now applied and machine-verified
> ([repository-security.md](repository-security.md)). What survives is a
> *single-maintainer* limit, which no plan fixes. Re-review when a second
> maintainer can push (issue #112).

## AR-1 — No independent human reviewer on release

- **Gap:** a single maintainer both authors and approves every release. GitHub
  forbids self-approval, so attaching required reviewers to the `foundry-rc` /
  `foundry-production` environments — or raising the branch ruleset's approval
  count above 0 — would block every release rather than add oversight.
- **Why accepted:** it is a people limit, not a platform one (corrected
  2026-07-28: the reviewer gate is *available* now that the repo is public; it is
  unattachable because there is nobody else to approve). Faking a second reviewer
  would be security theatre. `ALLOW_FREE_TIER_NO_REVIEWERS=1` in the release
  workflows records this explicitly (fail-closed on everything else); the flag
  name is now a misnomer — it is a single-maintainer waiver, not a plan waiver.
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
