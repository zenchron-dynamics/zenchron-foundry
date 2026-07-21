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

## Shared `$HOME`: tool installers are shared mutable state

The runner instances (`...-1`, `...-2`) run on **one host as one user**, so they
share a single `$HOME`. Any action that installs a tool into a fixed home-relative
path is therefore writing to state that a concurrently-running job on the *other*
instance can see and clobber.

This is not theoretical. It broke the `v2026.07.04` RC publish three times.
`sigstore/cosign-installer` defaults to `install-dir: $HOME/.cosign` and installs
by doing `rm <bootstrap>` then `mv <verified> <bootstrap>`. Two jobs interleaving
those four operations produce two *different* symptoms from one cause:

| Symptom | Which job | What happened |
|---|---|---|
| `mv: cannot stat 'cosign_v2.5.2': No such file or directory` | the loser | the other job's `rm` deleted the file between its download and its `mv` |
| `cosign: command not found` → `cosign sign failed after retries` | the winner | install "succeeded", then the other job's `rm` removed the binary before the signing step ran |

The second is the nastier one: it fails late, after a multi-arch build, and looks
like a signing/credential problem rather than an install problem.

**Fix — isolate per job, do not serialize.** Every `sigstore/cosign-installer`
use pins:

```yaml
- uses: sigstore/cosign-installer@<sha> # v4.1.2
  with:
    cosign-release: v2.5.2
    install-dir: ${{ runner.temp }}/cosign
```

`RUNNER_TEMP` is per-runner-instance and a runner executes one job at a time, so
two jobs can never share it. Prefer this over overriding `HOME` wholesale: an
`env: { HOME: ... }` on the step also relocates docker/git config that other
steps in the same job expect to find.

**Applies to any home-relative installer**, not just cosign — syft/grype, Go/Rust
toolchains, `~/.docker`, `~/.cache`. When adding one, ask where it writes and
whether a parallel job could be writing there too.

### Workflow-level concurrency is a complement, not the fix

`publish-rc.yml` and `scheduled-rebuild.yml` share the literal group
`org-cosign-publish` (`cancel-in-progress: false`) so the two signing workflows
are mutually exclusive org-wide, including against the matching pair in
`php-app-template`. The group must be the **same literal string** in every file —
that is what makes them exclusive.

Two constraints when adding it elsewhere:

1. **Both files already had a top-level `concurrency:` key.** A workflow gets
   exactly one; a second is a duplicate YAML mapping key and the workflow will not
   load. Replace the existing block, don't append one.
2. **It does not fix the intra-workflow case.** All three observed `v2026.07.04`
   failures were two legs of the *same* `publish-ghcr` matrix racing each other.
   A workflow-level group cannot prevent that — only per-job `install-dir` can.
   Ship both; they cover different halves.

Replacing the previous groups had two deliberate side effects: `publish-rc` lost
per-`version+rc+revision` keying, so distinct publishes now serialize (one shared
runner host required that anyway), and `scheduled-rebuild` went
`cancel-in-progress: true → false`, so a rebuild now waits for a release instead
of cancelling a wedged predecessor.

### Recovering a stuck publish

`fail-fast: false` on the publish matrix means a race victim does not cancel its
siblings — but `gh run rerun --failed` re-runs **all** failed jobs concurrently
and can reproduce the race. Re-run them **one at a time**:

```bash
gh run rerun --job "$(gh run view <run-id> --json jobs \
  --jq '.jobs[]|select(.name|test("<matrix leg>"))|.databaseId')"
```

Then `gh run rerun --failed <run-id>` once only one failure remains, so the last
job and its dependents run alone. Re-runs stay under the same run ID (a new
*attempt*), so a recorded `rc_manifest_run_id` remains valid. Note reruns replay
the workflow file from the original commit — a fix pushed to `master` mid-flight
does **not** reach an in-flight run.

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
