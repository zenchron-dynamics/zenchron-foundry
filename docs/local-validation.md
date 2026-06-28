# Local validation

How to run the platform's gates on your own machine before pushing. The Makefile
harness mirrors the hosted CI gates so you can catch failures locally; `act` is a
supplement for exercising workflow logic, not a release signal.

## Makefile harness

| Target | What it runs |
|--------|--------------|
| `make doctor` | Reports local tool availability with install hints (informational) |
| `make validate` | Static gates: structure, no-wolfi, action + container pinning, image matrix, base-image verify |
| `make build-test` | Builds all 10 images locally (`load`, no push) |
| `make smoke-all` | Runtime smoke tests for all 10 images (fails if zero are tested) |
| `make scan-local` | Trivy + Grype scan (SKIPPED if tools absent unless `STRICT=1`) |
| `make sbom-local` | Syft SBOM for the current php-fpm image (SKIPPED if syft absent) |
| `make verify-local` | Verifies base images + release artifacts (signatures/SBOM/provenance) |
| `make ci-local` | Full local CI: `validate` + `build-test` + `smoke-all` + scan + sbom |

`make smoke-all` (via `scripts/smoke-all.sh`) builds and smoke-tests
`php-{cli,fpm,worker,frankenphp}` x `{8.3,8.4}` plus `nginx` and `caddy`,
aggregates the results, and exits nonzero if any check fails or zero images are
tested. Restrict the matrix with `SMOKE_FAMILIES="php-fpm nginx"`.

## STRICT mode

By default the harness is lenient: scripts honor `LOCAL=1`, so a missing tool
(docker, cosign, trivy, syft) is reported as `SKIPPED` and the run continues —
useful offline. Setting `STRICT=1` clears `LOCAL`, turning **every** gate into a
hard requirement (no `SKIPPED`), matching the hosted release behavior:

```bash
make ci-local STRICT=1
make verify-local STRICT=1
```

Use `STRICT=1` as the final check before tagging a release.

## doctor tool list

`make doctor` checks for: docker, docker buildx, hadolint, shellcheck, yamllint,
markdownlint, trivy, grype, syft, cosign, gitleaks, semgrep, pre-commit, docker
compose, act, and gh. Missing (✗) tools only affect local workflows — CI installs
its own — so doctor is informational and never fails the build.

## Running workflows with `act` (supplement only)

`act` runs the GitHub Actions workflows in a local container to iterate on
workflow logic. Config lives in `.actrc`
(`catthehacker/ubuntu:act-latest`, `linux/amd64`); usage examples are in
[../.act/README.md](../.act/README.md), e.g.:

```bash
act push -e .act/events/push.json -j structure
act workflow_dispatch -e .act/events/workflow-dispatch.json -W .github/workflows/publish-rc.yml
```

`act` **cannot** validate, and a green `act` run is **not** a release signal for:

- keyless cosign signing (needs GitHub OIDC);
- `release` / `rc` Environment approvals (server-side protected environments);
- SARIF upload to code-scanning (needs the GitHub API / Advanced Security);
- GitHub Release creation (needs `contents: write` against GitHub);
- tag ancestry against `origin/master` (needs the real remote);
- multi-arch QEMU / runner-policy parity.

Real release validation is the hosted `release.yml` →
`verify-release-artifacts.sh` path plus `verify-signatures.yml`.
