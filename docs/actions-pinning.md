# Pinning GitHub Actions and CI container images

Every third-party GitHub Action and every container image used by CI is pinned to
an immutable identity. Two CI guards enforce this on push, PR, and before any
publish: `scripts/assert-pinned-actions.sh` and
`scripts/assert-pinned-containers.sh`.

## Why

A tag like `@v4` or `:latest` is mutable: the owner (or an attacker who
compromises the upstream repo) can repoint it at new code that then runs inside
our build with our `GITHUB_TOKEN` and OIDC identity. Pinning to a full commit SHA
(actions) or a `@sha256:` digest (images) freezes the exact bytes that execute,
so a moved tag cannot silently change our pipeline. Dependabot still proposes
updates through reviewed PRs; pinning only removes the *silent* mutation path.

## Action pinning policy

- Every `uses:` reference resolves to a **full 40-character lowercase commit
  SHA**, with a trailing `# vX` comment recording the human-readable version.
- Accepted forms: `owner/repo@<40-hex>`, `owner/repo/subpath@<40-hex>`, and local
  references (`./.github/...`), which are exempt.
- Rejected: `@vN`, `@vN.N.N`, `@main`, `@master`, branch names, and short SHAs.
- `ludeeus/action-shellcheck` was moved off `@master` onto a pinned release SHA.

`scripts/assert-pinned-actions.sh` scans all workflows and composite/reusable
action definitions under `.github/` and fails listing any unpinned reference. It
runs in `ci.yml` (structure job), in the `publish-ghcr.yml` preflight, in the
`release.yml` guard, and in the `scheduled-rebuild.yml` preflight.

## Container-image pinning policy

CI runs several tools as containers (lint, scan, SAST). Each is digest-pinned
with a readable version tag. Current pins:

| Tool | Reference |
|------|-----------|
| Hadolint | `hadolint/hadolint:2.12.0-debian@sha256:…` |
| ShellCheck | `koalaman/shellcheck:v0.10.0@sha256:…` |
| Gitleaks | `zricethezav/gitleaks:v8.21.2@sha256:…` |
| Trivy | `aquasec/trivy:0.71.0@sha256:…` |
| Semgrep | `semgrep/semgrep:1.86.0@sha256:…` |

`scripts/assert-pinned-containers.sh` fails on any `:latest` in a workflow, any
`container:`/`image:` value that is not `@sha256:`-pinned, and any known tool
image used in a `run` step without a digest. (Dockerfile `FROM` digests are
covered separately by `scripts/check-structure.sh` and
`scripts/verify-base-images.sh`; see [base-image-policy.md](base-image-policy.md).)

## How to update a pinned action

1. Pick the target release tag (e.g. `v7`) and resolve it to a commit SHA:

   ```bash
   gh api repos/<owner>/<repo>/commits/<tag> --jq '.sha'
   ```

2. Replace the SHA in the `uses:` line and update the trailing `# vX` comment to
   the tag you resolved.
3. Run the guard locally before committing:

   ```bash
   bash scripts/assert-pinned-actions.sh
   ```

4. Open a PR. CI re-runs the guard; merge only when it is green.

## How to update a pinned container image

1. Resolve the multi-arch digest for the new tag:

   ```bash
   docker buildx imagetools inspect <image>:<tag>
   ```

   Use the top-level manifest-list digest, not a per-arch digest.
2. Update the `image@sha256:…` reference in the workflow, keeping the readable
   tag.
3. Verify with `bash scripts/assert-pinned-containers.sh`, then open a PR.
