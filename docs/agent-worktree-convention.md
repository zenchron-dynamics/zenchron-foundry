# Agent worktree convention

How multiple automated agents (and the humans coordinating them) share this
repository without operating in the wrong one, and without operating in each
other's checkouts.

This is a **convention with an enforceable check behind it**, not a style guide.
The check is `scripts/lib/repo-identity.sh`; the expectations it reads are
`policies/repo-identity.yaml`; the proofs are
`tests/lib/test_repo_identity_guard.sh`.

## The two incidents

Both happened here. Neither was a knowledge problem — everyone involved knew the
rules. Both were missing preconditions.

### 1. Wrong-repository operation

A multi-agent workflow used `git worktree` for isolation. A worktree is derived
from **the repository the session is sitting in**, not from the repository the
work targets. The session was attached to `bogdaniel/zenchron-infra`; the work
targeted `zenchron-dynamics/zenchron-foundry`.

Two agents therefore received checkouts of an unrelated repository and believed
they were in this one. They produced nothing usable. A third agent noticed and
built its own clone. A push made from that state was flagged by a security
classifier as possible exfiltration to the wrong repository — a false positive,
but one that could only be established by manually inspecting the remote,
because no tool had ever asserted which repository it was in.

The lesson is not "use worktrees more carefully". It is that **repository
identity was assumed and never checked**, so being wrong about it was
undetectable from inside.

### 2. Shared-worktree collision

A coordinator ran git commands inside a lane agent's live checkout and switched
branches under it. Two **tracked** files the agent had edited were silently
reverted. The agent's own backup covered untracked files only, so the loss was
recovered by luck and manual comparison.

Again: **checkout ownership was assumed and never checked.**

## The convention

1. **A lane owns exactly one checkout.** A lane is a short identifier — `laneA`,
   `laneD`, `docs-fix`. One checkout, one lane, for the life of the task.
2. **A lane registers its checkout before mutating anything.**
3. **Nobody operates in a checkout they have not registered.** That includes the
   coordinator. If the coordinator needs to inspect a lane's work, it reads the
   lane's branch from its **own** checkout — `git fetch` and `git log`, never
   `cd` into the lane's directory and `git checkout`.
4. **Do not derive an agent worktree from an ambient session.** Clone the target
   repository by URL, or create the worktree from a clone you have verified is
   the target. `bash scripts/lib/repo-identity.sh status` answers "which
   repository is this" in one line.
5. **A lane releases its checkout when the task ends.**

## Commands

```sh
# Which repository is this, and who owns this checkout?
bash scripts/lib/repo-identity.sh status

# Verify everything the guard checks and report; refuses with a named code.
bash scripts/lib/repo-identity.sh check

# Claim this checkout for a lane (records lane, branch and worktree path).
bash scripts/lib/repo-identity.sh register-lane laneD

# Give it back.
bash scripts/lib/repo-identity.sh release-lane
```

Set `ZF_LANE` in the agent's environment so `check` and the guarded scripts know
who is asking:

```sh
export ZF_LANE=laneD
```

## What the guard verifies

`require_repo_identity` answers six questions, in this order, and stops at the
first failure so the diagnostic names one cause rather than a list.

| Refusal code | Question | Fails when |
| --- | --- | --- |
| `unexpected-remote` | Is `origin` present, parseable and on an allowed host? | The remote is missing, or points at a host outside `allowed_remote_hosts` — including a look-alike host carrying the correct `owner/name`. |
| `wrong-repository` | Does `origin` resolve to the expected `owner/name`? | Incident 1: the checkout belongs to a different repository. |
| `wrong-worktree` | Does this tooling belong to the checkout it is pointed at? | Incident 2: a script from one checkout is being run against another. |
| `dirty-protected-path` | Are the protected paths committed? | Uncommitted changes under `.github/workflows`, `policies`, `scripts` or `contracts`, without `--allow-dirty` / `ZF_ALLOW_DIRTY=1`. |
| `foreign-lane` | Is this checkout unclaimed, or claimed by you? | The checkout is registered to another lane, or you supplied no lane identity at all. |
| `branch-ownership` | Is the lane's registered branch still checked out? | Incident 2's other half: someone moved `HEAD` under a live lane. |

Identity comes from `git remote` and the repository's own metadata. **No
filesystem path is hardcoded anywhere**, because the same repository lives at a
different path for every contributor, every CI runner and every worktree; a path
is a fact about one machine, not about the repository.

## Where the ownership records live

Both files live inside the git directory, so they are untracked by construction
and can never be committed, shipped, or diffed into a pull request.

```text
<worktree git dir>/zf-lane          who owns THIS checkout
<common git dir>/zf-lanes/<lane>    which checkout a lane owns
```

The marker refuses a stranger walking into a claimed checkout. The registry
refuses a lane claiming a second checkout while its first is still live. Both
names come from `policies/repo-identity.yaml`.

## Scope — who this does *not* affect

**Ordinary contributors are unaffected, and that is a tested property.**

- The guard runs only in the scripts named in `guarded_scripts` in
  `policies/repo-identity.yaml`, plus the commands above. Today that is
  `scripts/prepare-release.sh` (creates and pushes release tags) and
  `scripts/admin/runner-group-patch.sh` (mutates the org control plane). Both
  are maintainer-only operations that are destructive in the wrong repository.
- Building, testing, linting, committing and `make init` never reach it.
  `scripts/install-hooks.sh` is deliberately **not** guarded: it is bootstrap,
  it is run from forks, and guarding it would block exactly the people this
  convention promises not to block.
- The ownership check is a no-op when no lane marker exists, which is the state
  of every ordinary clone.
- `tests/lib/test_repo_identity_guard.sh` enforces the list in **both**
  directions: every guarded script must really call the guard, and no script
  outside the list may call it. That bounds the blast radius to something a
  reader can check, rather than to an intention.

## Break-glass

There is **no bypass for repository identity**. If the guard says you are in the
wrong repository, you are; the fix is to go to the right one. `ZF_ALLOW_DIRTY=1`
relaxes the working-tree cleanliness check only, and is an explicit act recorded
in the shell history of whoever performed it.

If a lane marker is genuinely stale — an agent died without releasing its
checkout — `release-lane` from that checkout clears it. Doing so from a
*different* checkout is refused, on purpose: that is the incident-2 move.
