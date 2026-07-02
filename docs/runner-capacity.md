# Runner capacity & self-hosted hygiene

Applies to the single self-hosted runner labelled `[self-hosted, linux, x64, zenchron]`.

## Current limitation

- **One runner, single concurrency.** The 10-image build+smoke matrix runs
  **serially**, not in parallel. Expect the full `ci.yml` matrix to take tens of
  minutes wall-clock (observed: run `28597652716` ≈ within a normal CI window on
  GitHub-hosted; the self-hosted path is serial and slower).
- **Root, no sudo.** Jobs run as uid 0 with no `sudo`. This is why workspace
  ownership reset uses the root branch (see below) and why checkout-first is safe.
- A queued release waits behind any in-flight job; there is no parallel lane for
  an emergency CVE rebuild.

## Workspace ownership reset

All workflows call the single hardened helper **`scripts/ci/reset-workspace-ownership.sh`**
(no inline `chown`, no `|| true`). It canonicalizes with `realpath`, refuses to
operate on `/`, outside the `_work` tree, or through a symlink escape, and:

| Context | Action |
|---|---|
| root | `chown` directly |
| non-root + working sudo | `chown` via sudo |
| already correctly owned | no-op |
| non-root, wrong owner, no sudo | fail with explicit diagnosis |

Self-test: `bash scripts/ci/reset-workspace-ownership.sh --self-test` (14 checks).

**Ordering note.** The call now runs **immediately after `actions/checkout`**
(the step cannot live before checkout, because the script lives in the repo which
is not yet present). On this root runner, checkout cleans any stale tree
regardless of prior ownership, so this is safe. For a **non-root** runner, install
the same script as the runner's `ACTIONS_RUNNER_HOOK_JOB_STARTED` hook so the
reclaim happens *before* checkout — that is the only correct place for a
pre-checkout reset, and it keeps the logic single-sourced.

## Disk & cache

- Keep headroom for 10 image builds × 2 architectures plus scanner databases.
  Budget conservatively: several GB of layer cache + Trivy/Grype DBs.
- Cleanup is **targeted** (per run-id/attempt/matrix builders and tags). Do **not**
  run a global `docker system prune` on a shared runner — it would evict other
  jobs' caches and in-flight layers.
- On cancellation, the reset helper + targeted cleanup restore a usable state on
  the next job; there is no partial-ownership residue because the helper is
  fail-loud, not `|| true`.

## Emergency CVE response

With one serial runner, an urgent rebuild competes with normal CI. Options:
1. Cancel the in-flight non-release job, let the rebuild take the lane.
2. Trigger the scheduled-rebuild path (candidate tags only — never mutates
   `*-prod`).
3. If turnaround matters, this is the strongest argument for a second runner.

## Recommendations

- **Add a second / dedicated release runner** so RC publish + promotion do not
  queue behind routine CI, and emergency rebuilds have a lane.
- **Move toward ephemeral runners** when: (a) build isolation between jobs becomes
  a trust requirement, (b) you want a clean FS per job instead of reset-on-reuse,
  or (c) you add fork-PR builds. Ephemeral runners remove the ownership-reset
  problem entirely (fresh workspace each job).
