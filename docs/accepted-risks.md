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

## AR-2 — Self-hosted runner is root, single-concurrency

- **Gap:** the shared runner executes as root without sudo and runs one job at a
  time (serial matrix).
- **Why accepted:** it is the available capacity.
- **Compensating controls:** centralized strict workspace reset
  (`scripts/ci/reset-workspace-ownership.sh`, realpath + strict-descendant, no
  `|| true`), job-scoped Docker cleanup (`scripts/ci/cleanup-docker-job.sh`, no
  global prune), fork-PR guards on build jobs, publish/OIDC permissions only in
  dispatch/tag-triggered jobs, and a runner job-started hook template for a
  future non-root runner (`scripts/ci/install-runner-hook.sh`).
