# Trusted runner-group workflow transition — 2026-08-08

**This directory records an operation that already happened.** The mutation was
performed and independently verified before any of this was written; nothing here
performs or authorises a control-plane change.

| | |
|---|---|
| operation date | 2026-08-08 |
| organization | `zenchron-dynamics` |
| runner group | `3` (`zenchron-foundry-trusted`) |
| helper revision | `a43de134bb2bf77e20d341a274bd4a0a7f9edf3d` |
| API version | `2026-03-10` |
| verdict | **PASS** |
| recovery attempted | **false** |
| repositories before → after | `[1254295268]` → `[1254295268]` |
| runners before → after | `[22,23]` → `[22,23]` |
| workflow count | **10 → 6** |
| availability window | real · fail-closed · **non-atomic** |

## What changed

Removed — five entries naming workflows that no longer build anything
(`publish-ghcr` deleted outright; the rest retained only as fail-closed entry
points that refuse):

```
promote-stable  publish-ghcr  publish-rc  release  scheduled-rebuild
```

Added: `stage-and-authorize.yml@refs/heads/master`, the sole remaining builder
that needs the privileged pool.

Final set, all pinned to `refs/heads/master`:

```
build-images  scan-images  stage-and-authorize
trusted-validation  verify-rc  verify-signatures
```

Everything else was preserved: repository selection, runner membership, name,
visibility, and both restriction flags.

## The availability window

The PATCH and the repository PUT are two REST calls and cannot be made atomic.
Between them the group authorised **no repository**, and both online runners were
unschedulable. That window is real and it is production. It was bounded by
checking that no Actions run was in a non-terminal state immediately beforehand,
and closed by a PUT whose effect was then re-read and verified.

**No duration is claimed here.** The helper does not timestamp the individual
calls, and inventing a figure from the surrounding log would be a guess presented
as a measurement.

## Why the PATCH cannot carry the repository list

Measured separately on a throwaway group —
`docs/audits/runner-group-patch-semantics-2026-08-06/`:

```
PATCH including selected_repository_ids  ->  422 "not a permitted key"
PATCH omitting  selected_repository_ids  ->  200 OK, membership CLEARED
PUT .../repositories                     ->  restored exactly
```

The 200 is the hazard: the call reports success while emptying the selection, so
only a postcondition read distinguishes the outcomes.

## Contents

`before-*` / `recheck-*` are snapshots A and B, taken either side of the drift
check. `patch-request.json` is the exact payload — one key. `after-*` is the
helper's own postcondition read. `live-*-after.json` is an **independent**
re-read performed afterwards, not derived from `result.json`.

Verify with:

```sh
shasum -a 256 -c SHA256SUMS
```
