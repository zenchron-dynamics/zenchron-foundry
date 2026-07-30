# CI Failure Policy

**Updated 2026-07-28 (issue #97).** A red CI now *does* physically stop a merge:
`master` requires the 5 PR-required status checks through the `master-protection` ruleset,
with no bypass actors — see [repository-security.md](repository-security.md).
This file previously opened with "GitHub Free cannot block a merge on a private
repo"; that premise was false, and these rules were standing in for enforcement
that could have been switched on at any time.

They still matter, because GitHub's merge gate covers less than this policy does:

- GitHub counts a **skipped** check as satisfied. This policy does not, and
  neither does the release gate (`scripts/check-exact-commit-ci.sh`).
- GitHub gates the **merge**; this policy also gates the **release**, against the
  exact tagged commit.
- Dispatch-only runs (`scan-images` on a release revision, `verify-rc`) produce
  no PR check at all, so nothing but this rule covers them.

## Rules

- **A failed CI run on `master` is a release blocker.** Do not publish images
  from a commit whose `master` CI is not green.
- **Fix `master` CI before any new image publish.** No "publish now, fix later".
- **The release script checks CI status** (`scripts/prepare-release.sh`): if
  `gh` is available it reads the latest `master` `ci.yml` conclusion and
  **refuses** to proceed unless it is `success`.
- **Publishing from a failed commit is forbidden by policy.** `publish-ghcr.yml`
  only runs from a `v*` tag, and tags should only be created by the release
  script — which won't tag a red `master`.

## How to check CI manually

```bash
gh run list --workflow ci.yml --branch master --limit 1
gh run view --branch master   # detail of the latest run
```

The release script runs the equivalent and stops on a non-`success` conclusion:

```bash
gh run list --workflow ci.yml --branch master --limit 1 \
  --json conclusion -q '.[0].conclusion'   # must print: success
```

## When CI is red

1. Stop. Do not tag or publish.
2. Open a fix on a feature branch → PR → green CI → merge (see
   [manual-pr-policy.md](manual-pr-policy.md)).
3. Confirm `master` CI is green again.
4. Only then run `scripts/prepare-release.sh`.

## Visibility aids (free)

- Watch the **Actions** tab; enable GitHub email notifications for failed
  workflow runs on `master`.
- The release script is the last line of defense — it will not tag a red
  `master` when `gh` is authenticated.

This policy depends on humans honoring it plus the release-script check; it is not
a GitHub-enforced gate.
