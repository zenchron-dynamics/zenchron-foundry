# Running workflows locally with `act`

`act` runs the GitHub Actions workflows in a local container so you can iterate
on workflow logic without pushing. It is a **supplement to**, not a replacement
for, hosted CI.

## Usage

```bash
# Lint / structure / pinning gates (the ci.yml jobs)
act push          -e .act/events/push.json -j structure
act pull_request  -e .act/events/pull-request.json -j lint

# Build + smoke a single image family (matrix job)
act push -e .act/events/push.json -j build-test

# An RC dispatch (will execute steps up to the points that need GitHub)
act workflow_dispatch -e .act/events/workflow-dispatch.json -W .github/workflows/publish-rc.yml
```

Config lives in `../.actrc` (runner image + architecture).

## What `act` CANNOT validate (do not trust a green act run for these)

| Concern | Why act can't | Where it's really enforced |
|---------|---------------|----------------------------|
| Keyless cosign signing | needs GitHub OIDC token | hosted `release.yml` / `publish-ghcr.yml` |
| `release` / `rc` Environment approvals | protected envs are server-side | GitHub Environments + required reviewers |
| SARIF upload to code-scanning | needs GitHub API + Advanced Security | hosted `scan-images.yml` |
| GitHub Release creation | needs `contents: write` against GitHub | hosted `release.yml` |
| Tag ancestry against `origin/master` | needs the real remote | hosted `release.yml` guard job |
| Runner policy / multi-arch QEMU parity | local runner differs | hosted matrix |

Steps that touch these are expected to no-op or fail under `act`; that is **not**
a release signal. Real release validation is the hosted `release.yml` →
`verify-release-artifacts.sh` path and `verify-signatures.yml`.
