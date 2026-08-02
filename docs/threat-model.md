# Threat Model

Scope: the platform repo, its CI/CD, the images it produces, and their runtime.
Method: lightweight STRIDE-flavored enumeration with mitigations and accepted
risks. Consuming apps own their own application-layer threat models.

## Assets

- Integrity of published base images (most critical — fans out everywhere).
- GHCR registry + signing identity.
- CI/CD pipeline and its tokens.
- Build provenance / SBOM accuracy.

## Trust boundaries

```text
[committer] → [GitHub repo] → [GitHub Actions runner] → [GHCR] → [prod host] → [running container]
```

## Threats & mitigations

| # | Threat | Mitigation | Residual / accepted |
|---|--------|-----------|---------------------|
| T1 | **Vulnerable base image** ships CVEs | Official Debian (bookworm) bases pinned by digest (caddy: Alpine, ADR-0001 exception); Trivy+Grype gates; weekly rebuild; Dependabot | Zero-day window between disclosure and rebuild |
| T2 | **Malicious / compromised dependency** (Debian/dpkg package, PHP ext, action) | Pinned bases; minimal extension set compiled from source; SBOM; actions pinned; Dependabot review | Upstream compromise before detection |
| T3 | **Image tampering** in registry | Cosign keyless signatures + Rekor log; consumers verify; digest pinning | Consumer skipping verification (process control) |
| T4 | **Registry compromise** (GHCR) | Signatures detect tampering; digests immutable; verify-before-run | GHCR availability outage |
| T5 | **CI compromise** (poisoned workflow/runner) | Least-priv `permissions`; OIDC (no static keys); `publish` gated to `v*` tags + preflight; protected branches; CODEOWNERS on workflows | Malicious maintainer with tag rights |
| T5a | **Fork PR executes attacker code on the persistent self-hosted runner** (public repo → anyone can open one; runner is shared, Docker- and sudo-capable, and its workspaces are reused by later trusted jobs → runner-host and release-supply-chain compromise) | Runner selected from trigger trust: forks get an ephemeral GitHub-hosted VM, privileged pool reserved for push/tag/schedule/dispatch and same-repo PRs; `pull_request_target` banned; `ci.yml` carries no secrets and `contents: read`. Enforced by `scripts/assert-runner-trust.sh` (`make validate` + `repo structure` job), regression-tested by `tests/runner/test_workflow_trust.sh`. See [repository-security.md § CI trust boundary](repository-security.md#ci-trust-boundary) | Compromise of a GitHub-hosted VM (blast radius = that VM; no secrets, read-only token). Self-hosted host hardening (runner user privileges, sudoers) is a runner-admin action outside repo code — see [accepted-risks.md § AR-2](accepted-risks.md) |
| T6 | **Leaked deploy token** | Read-only `read:packages` tokens on prod; rotation; no write scope; secret manager | Token misuse window until rotation |
| T7 | **Secret baked into image** | No secrets in ARG/ENV; Gitleaks (pre-commit + CI); Semgrep ARG/ENV rule; runtime secret injection | Human error caught by scanners |
| T8 | **Container escape / privilege** | Non-root 10001; cap_drop ALL; no-new-privileges; read-only rootfs; no privileged; no docker.sock; pids_limit | Kernel 0-day (host patching out of scope) |
| T9 | **Legacy EOL PHP exploitation** (7.4/8.0) | Isolated, labeled high-risk; not internet-exposed; migration mandate; awareness scanning | **Accepted, temporary** — no upstream fixes exist |
| T10 | **Supervisor masking crashes / signal mishandling** in workers | One-process-per-container; tini PID1; graceful SIGTERM; orchestrator restart | — |
| T11 | **Healthcheck tooling as attack surface** | Minimal `cgi-fcgi` only; no curl/wget; prefer orchestrator probes | small busybox surface on FPM |
| T12 | **Privileged port binding** forces root | High ports 8080/8443; NET_BIND_SERVICE only if needed; LB TLS termination | — |

## Accepted risks (explicit)

- **Legacy 7.4/8.0 carry unpatched CVEs** (T9). Mitigated by isolation, no
  public exposure, and a migration deadline. Re-reviewed quarterly.
- **Near-distroless, not fully shell-less FPM** (T11). busybox + cgi-fcgi remain
  for the healthcheck; revisited if a static-binary healthcheck path matures.
- **Single-region GHCR dependency** (T4). Availability, not integrity, risk.

## Out of scope

Host OS/kernel hardening, network segmentation, application business logic,
and orchestrator (Compose/k8s) cluster security — owned by platform-ops and
consuming teams respectively.
