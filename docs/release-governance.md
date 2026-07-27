# Release Governance

Who can publish, from where, and how the pipeline resists tampering.

## Publish triggers (verified against the workflows)

| Workflow | Trigger | Publishes to GHCR? |
|----------|---------|--------------------|
| `ci.yml` | PR, push to `master` | **No** (build/test only, `push: false`) |
| `scan-images.yml` | PR (images), schedule | **No** (builds locally to scan; no registry push) |
| `build-images.yml` | `workflow_dispatch`, `workflow_call` | **No** — no `packages: write`, no push input; local `--load` builds only |
| `publish-ghcr.yml` | `workflow_call` **only** (sole caller: `publish-rc.yml`) | **Yes** — push + cosign sign + SBOM attest, immutable RC tags only |
| `publish-rc.yml` | `workflow_dispatch` (from `master`, `foundry-rc` environment) | **Yes** — via `publish-ghcr.yml`; also signs the RC manifest |
| `scheduled-rebuild.yml` | weekly cron, `workflow_dispatch` | **Yes** — dated candidate tags only, never `*-prod` |
| `promote-stable.yml` | dispatch from `refs/tags/<version>` | **No build** — digest-only retag of validated RC digests onto `*-prod` |
| `release.yml` | dispatch from `refs/tags/<version>`; **no tag-push trigger** | **No build, no push** — verifies the promoted images, then seals the GitHub Release |

**Publishing occurs only from:** `publish-rc.yml` → `publish-ghcr.yml`
(immutable RC tags) and `scheduled-rebuild.yml` (dated candidates). Stable
`*-prod` tags are **never built** — `promote-stable.yml` retags the exact RC
digests. **No workflow publishes from a pull request**, and `publish-ghcr` has
no `workflow_dispatch`, `pull_request`, or `push` trigger — confirmed.

## Least-privilege permissions

Publishing workflows request only what they need:

```yaml
permissions:
  contents: read
  packages: write          # push images
  security-events: write   # SARIF / attestation
  id-token: write          # cosign keyless (OIDC)
```

`GITHUB_TOKEN` is ephemeral and repo-scoped; no long-lived registry password
exists. Signing is keyless (Fulcio/Rekor), so there is no private key to leak.

## Who may publish

- Only maintainers who can dispatch the release workflows and push a `v*`
  **tag** can cut a release.
- **Enforced by GitHub since 2026-07-28 (issue #97):** direct pushes to `master`
  are blocked by the `master-protection` ruleset (PR + 26 required checks +
  linear history, no bypass actors), and `v*` tags are **immutable** — no
  deletion, force-move or repoint, for anyone including the owner. Tag
  *creation* stays open so `scripts/prepare-release.sh` can still cut a release.
  The earlier claim that these were unavailable (API 422) assumed a *private*
  Free repo and was false. Required reviewers and CODEOWNERS enforcement remain
  off — now for a single-maintainer reason, not a plan reason (issue #112). See
  [repository-security.md](repository-security.md); confirm with
  `make verify-governance`.
- The other enforced controls are the **deployment branch/tag policies** on the
  `foundry-rc` (branch `master`) and `foundry-production` (tags `v*.*.*`)
  environments, typed-confirmation workflow inputs, and the exact-commit CI
  gate on the tagged revision.

## Threat model

| Threat | Mitigation |
|--------|-----------|
| **Compromised contributor branch** | Branch is not `master`; CI runs but never publishes; a feature branch cannot push images. The `foundry-rc` environment's deployment branch policy limits `publish-rc` to `master`. PR review + signed commits are policy + local hooks (not GitHub-enforced on the Free plan — accepted risk, waiver documented). |
| **Malicious PR modifying a Dockerfile** | PR builds in `ci.yml` with `push: false` → cannot reach GHCR. Semgrep/hadolint/gitleaks gate the diff. CODEOWNERS routes `images/**` + `.github/**` for review as policy (routing only; approval is not GitHub-enforced on the Free plan). |
| **Leaked GitHub token** | Servers hold only `read:packages` (cannot push). CI uses ephemeral `GITHUB_TOKEN`. No static push token exists. Rotate/revoke per ghcr-consuming-private-images.md. id-token is request-scoped. |
| **Malicious tag** (attacker pushes a `v*` tag) | Tag rulesets are unavailable on the Free plan, so a tag push alone triggers **nothing**: `release.yml` has no tag-push trigger, and sealing requires a manual dispatch **from** the tag through the `foundry-production` environment (deployment tag policy `v*.*.*`) with a typed confirmation. The exact-commit CI gate and the tag==manifest==provenance==OCI equality chain reject a tag that does not match the published RC revision. Cosign signs with the pinned workflow identity, so an out-of-band build cannot forge a valid signature. |
| **Image tampering in the registry** | Cosign keyless signatures + Rekor transparency log; consumers `cosign verify` and pin by digest (immutable). Tampered or unsigned images fail verification. |
| **Dependency/base poisoning** | Bases pinned by digest; Dependabot updates them through reviewed PRs; Trivy+Grype gate supported images; SBOM attached for audit. |

## Release procedure (summary)

1. PR merged to `master` (reviewed, CI green).
2. `publish-rc.yml` → `publish-ghcr.yml`: build, push, **cosign sign**,
   **SBOM attest** all 10 images as immutable RC tags; signs the RC manifest.
3. `verify-rc.yml`: runtime + multi-arch certification of the published RC.
4. Maintainer pushes tag `vYYYY.MM.DD` (e.g. `v2026.07.21`) on the exact RC revision.
5. `promote-stable.yml`, dispatched from that tag: retag the exact RC digests
   onto `*-prod` (no build, no re-sign — stable carries the RC signature via digest).
6. `release.yml`, dispatched from the same tag: verify the promoted images
   against the signed RC manifest (fetched from the `publish-rc` artifact), then
   seal the GitHub Release with manifest, SBOMs, checksums, `VERIFY.md`.
7. Optionally run `verify-signatures.yml` to confirm the published set.

See [image-versioning.md](image-versioning.md) for tag immutability/rollback and
[sbom-and-signing.md](sbom-and-signing.md) for the signing identity.
