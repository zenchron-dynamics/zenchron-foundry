# Release Governance

Who can publish, from where, and how the pipeline resists tampering.

## Publish triggers (verified against the workflows)

| Workflow | Trigger | Publishes to GHCR? |
|----------|---------|--------------------|
| `ci.yml` | PR, push to `master` | **No** (build/test only, `push: false`) |
| `scan-images.yml` | PR (images), schedule | **No** (builds locally to scan; no registry push) |
| `build-images.yml` | `workflow_dispatch`, `workflow_call` | Only if `inputs.push == 'true'` (default `false`) |
| `publish-ghcr.yml` | `workflow_call`, `workflow_dispatch` | **Yes** — push + cosign sign + SBOM attest |
| `release.yml` | push **tag** `v*` | calls `publish-ghcr.yml`, then creates the GitHub Release |

**Publishing occurs only from:** a `v*` tag (via `release.yml` → `publish-ghcr.yml`),
or a deliberate `workflow_dispatch` of `publish-ghcr`/`build-images` with
`push=true`. **No workflow publishes from a pull request**, and `publish-ghcr`
has no `pull_request` or `push: branches` trigger — confirmed.

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

- Only maintainers who can push a `v*` **tag** to the repo can cut a release.
- Restrict tag creation via a tag protection rule / ruleset (see
  [repository-security.md](repository-security.md)).
- Branch protection prevents direct pushes to `master`, so the Dockerfiles that
  get built into a release must pass through a reviewed PR first.

## Threat model

| Threat | Mitigation |
|--------|-----------|
| **Compromised contributor branch** | Branch is not `master`; CI runs but never publishes; merge requires PR review + passing checks + (when enabled) signed commits. A feature branch cannot push images. |
| **Malicious PR modifying a Dockerfile** | PR builds in `ci.yml` with `push: false` → cannot reach GHCR. CODEOWNERS routes `images/**` + `.github/**` to platform+security review. Semgrep/hadolint/gitleaks gate the diff. Merge needs approval. |
| **Leaked GitHub token** | Servers hold only `read:packages` (cannot push). CI uses ephemeral `GITHUB_TOKEN`. No static push token exists. Rotate/revoke per ghcr-consuming-private-images.md. id-token is request-scoped. |
| **Malicious tag** (attacker pushes a `v*` tag) | Tag creation restricted by ruleset to maintainers; `release.yml` runs a `preflight` (`check-structure.sh`) before publishing; cosign signs with the workflow identity so a rogue out-of-band build cannot forge a valid signature. Consumers verify the identity regexp. |
| **Image tampering in the registry** | Cosign keyless signatures + Rekor transparency log; consumers `cosign verify` and pin by digest (immutable). Tampered or unsigned images fail verification. |
| **Dependency/base poisoning** | Bases pinned by digest; Dependabot updates them through reviewed PRs; Trivy+Grype gate supported images; SBOM attached for audit. |

## Release procedure (summary)

1. PR merged to `master` (reviewed, CI green).
2. Maintainer pushes tag `vYYYY.MM.DD` (e.g. `v2026.05.30`).
3. `release.yml` → `preflight` → `publish-ghcr.yml`: build, push, **cosign sign**,
   **SBOM attest** for all 12 images.
4. GitHub Release created with SBOMs, checksums, `VERIFY.md`.
5. Optionally run `verify-signatures.yml` to confirm the published set.

See [image-versioning.md](image-versioning.md) for tag immutability/rollback and
[sbom-and-signing.md](sbom-and-signing.md) for the signing identity.
