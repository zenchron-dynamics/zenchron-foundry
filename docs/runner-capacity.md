# Runner capacity & self-hosted hygiene

Applies to the org-level self-hosted runners labelled
`[self-hosted, linux, x64, zenchron]` (observed: `runner-prod-fsn1-org-zenchron-dynamics-1`,
`...-2` — **more than one**, so jobs run in parallel, not strictly serial).

## Ground truth (observed from CI logs, run 28601963xxx)

- **Non-root jobs, with sudo.** Jobs do **not** run as uid 0. Prior container
  steps (Docker, `.act`) leave **root-owned** files in the workspace; a later job
  running as the non-root runner user cannot remove them, so `actions/checkout`
  fails with `Permission denied` on `.git/index.lock` / `EACCES rmdir .../.act`
  **unless** ownership is reclaimed first (via `sudo chown`).
- Working dir: `/opt/actions-runner/org-zenchron-dynamics-N/_work/zenchron-foundry/zenchron-foundry`.
- Disk observed ~11G/38G used post-cleanup — keep headroom for 10 images × 2 arches
  plus Trivy/Grype DBs.

> Correction: earlier notes claimed a single root/no-sudo serial runner. CI proved
> otherwise — multiple runners, non-root, sudo-capable. Plan against these facts.

## Workspace ownership reset — MUST be pre-checkout

Because the failure is root-owned `.git`/`.act` that blocks `actions/checkout`
itself, the reclaim **must run before checkout**. A workflow step placed *after*
checkout cannot help — checkout has already failed. And a pre-checkout step
**cannot** call a script from the repo, because the repo is not checked out yet.

Consequences:

1. **The workflows keep a minimal inline pre-checkout reclaim** (no `|| true`,
   fail-loud, runner-root containment). This is a genuine GitHub Actions
   constraint, not a code smell — do not "dedup" it into a repo script and move
   it after checkout (that reintroduces the permission-denied failure).
2. **The single-sourced, hardened implementation lives in
   `scripts/ci/reset-workspace-ownership.sh`** (realpath canonicalization, strict
   `_work` containment, symlink-escape rejection, root/sudo/no-sudo branches,
   14-case self-test). The correct way to dedup the pre-checkout logic is to
   install this script as the runner's **`ACTIONS_RUNNER_HOOK_JOB_STARTED`** hook
   on each runner host — hooks run before checkout and read from the runner
   filesystem, not the repo. That is the recommended follow-up (requires runner
   admin access; cannot be done from repo code).

| Context | Action |
|---|---|
| root | `chown` directly |
| non-root + working sudo | `chown` via sudo  ← **the path this runner uses** |
| already correctly owned | no-op |
| non-root, wrong owner, no sudo | fail with explicit diagnosis |

## Cache & cleanup

- Cleanup is **targeted** (per run-id/attempt/matrix builders + tags). Never run a
  global `docker system prune` on a shared runner — it evicts other jobs' caches
  and in-flight layers.
- A runner-configured `runner-cleanup.sh` job-completed hook is already present
  (seen in logs). The workspace-reset hook above would complement it on the
  job-**started** side.

## Emergency CVE response

With multiple runners there is some parallel capacity, but an urgent rebuild still
competes with routine CI. Options: cancel a non-release job, use the
scheduled-rebuild path (candidate tags only — never mutates `*-prod`), or add a
dedicated release runner.

## Recommendations

- **Install `reset-workspace-ownership.sh` as the job-started hook** on every
  runner so the pre-checkout reclaim is single-sourced and hardened.
- **Add a dedicated release runner** so RC publish + promotion don't queue behind
  routine CI.
- **Move toward ephemeral runners** when build isolation becomes a trust
  requirement or to eliminate the ownership-reset problem entirely (fresh
  workspace per job — no root-owned leftovers to reclaim).
