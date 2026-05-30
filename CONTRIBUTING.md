# Contributing to docker-platform

Internal Zenchron Dynamics platform repository. Contributions come from
authorized platform/security engineers.

## Ground Rules

- **No application code** in base images. This repo ships runtimes, not apps.
- **No secrets** in any commit, build arg, or ENV. Gitleaks blocks this.
- **No `latest` as a deploy target.** Tagging rules: [docs/image-versioning.md](docs/image-versioning.md).
- New runtime images must be **non-root, read-only-capable, multi-stage,
  scanned, and SBOM'd** before merge.

## Workflow

1. Branch from `master`: `git checkout -b feat/<short-name>`.
2. Install hooks: `make hooks` (or `scripts/install-hooks.sh`).
3. Make changes. Keep one image family / concern per PR where possible.
4. Run locally: `make lint` and, for image changes, `make build` + `make scan`.
5. **Sign your commits**: `git commit -S` (required by branch protection).
6. Open a PR. CI must be green. CODEOWNERS review required.
7. No direct pushes to `master`. No force-push to shared branches.

## Commit Convention

Conventional Commits:

```text
feat(php-fpm): add 8.4 production image
fix(nginx): correct hidden-file deny regex
docs(threat-model): add CI compromise mitigation
chore(ci): pin actions to commit SHA
```

## Definition of Done (image change)

- [ ] Multi-stage; no build tools / package manager in final stage.
- [ ] Non-root runtime (UID/GID 10001), read-only rootfs compatible.
- [ ] OCI labels present.
- [ ] Hadolint clean (or justified `.hadolint.yaml` ignore).
- [ ] Trivy + Grype: no unjustified CRITICAL/HIGH.
- [ ] SBOM generates.
- [ ] Docs updated (taxonomy / consuming-images if user-facing).
- [ ] Legacy versions carry the legacy warning banner.

## Local Tooling

See `docs/` and `policies/`. Tools used: docker buildx, hadolint, trivy, grype,
syft, cosign, gitleaks, semgrep, shellcheck, yamllint, markdownlint, pre-commit.
