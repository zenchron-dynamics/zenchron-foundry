# Changelog

All notable changes to the Zenchron Dynamics `docker-platform` are documented
here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
image releases follow [docs/image-versioning.md](docs/image-versioning.md).

## [Unreleased]

### Fixed — governance binding could not see residue in its own bound scripts (#97 class)

- **Three bound governance inputs carried committed self-test residue.** A bare
  `# governance-binding self-test mutation` line sat in
  `scripts/verify-repo-governance.sh`, `scripts/assert-pr-workflows-github-hosted.sh`
  and `scripts/governance-content-binding.sh` — written by an earlier self-test
  that mutated the ambient checkout. The binding's own cleanliness check was
  scoped to `$ROOT/policies`, so it *structurally could not* see residue in the
  bound **scripts**: the marker search never looked at them. That scoping was
  introduced to stop the grep matching the checker's own source, and it created
  the blind spot it was meant to avoid.
- The check now iterates **every bound input**, and a non-vacuity probe proves
  the search still matches a planted marker — so a future narrowing cannot make
  it silently pass by looking at nothing.
- The binding aggregate therefore changes from `ead0c28a…` to `bd8ad9dc…`.
  Current-evidence citations move to
  `docs/audits/governance-verification-2026-08-24.json` (verdict PASS, live
  configuration re-verified against the API). The 08-23 record is kept, not
  deleted: it is the true record of what was verified that day, and the
  CHANGELOG entry below still cites it.

### Security — release-result integrity (#96)

- **The exact-commit gate now picks the NEWEST result for each required check.**
  It previously took `tail -1` — whatever the API happened to list last — so a
  stale success could outrank a newer failure and seal a release on a result
  nobody produced last. Normalized records carry `updated_at` and `source`
  (`check_run` / `commit_status`), and the newest wins. Anything that cannot be
  ordered safely REJECTS: a record with a missing or non-UTC timestamp, and two
  or more newest records that disagree.
- **Release-required results are published as commit statuses**, not check runs.
  A check run attaches to the commit of the dispatched ref, never to the commit
  under validation, so a dispatch on `master` could otherwise mark
  `trusted validation result` green on a master commit while validating an
  unrelated SHA. No job in `trusted-validation.yml` is named after a
  release-required check.
- **`statuses: write` is granted to one job.** The workflow-level default is
  read-only; only `publish-status` may write. The job that checks out and
  executes the commit under validation on a privileged runner holds
  `contents: read` and nothing else.

### Security — fail-closed capability removal + final-image inventory (#100)

- `setcap -r … 2>/dev/null || true` in `caddy` and `php-frankenphp` 8.3/8.4 is
  replaced by a fail-closed sequence: the binary must exist, `setcap`/`getcap`
  must be present, the removal must succeed, and **no file anywhere in the image**
  may carry a capability. Any failure REFUSEs the build. The same suppressed
  shape is removed from FrankenPHP's static-archive deletion and from the
  user/group creation (a failed `useradd` would ship an image whose `USER` does
  not exist).
- New `scripts/ci/capability-inventory.sh` verifies the **assembled** image from
  outside, reading capabilities from `docker export` PAX xattr records — so it
  needs no tools inside the image and works for FrankenPHP (which purges
  `libcap2-bin`) and for any future distroless image. Wired into
  `scripts/smoke/lib.sh`, so all **10** images are checked on every smoke run,
  local and CI; CI publishes the JSON as a `capability-inventory-*` artifact on
  success and failure.
- Caddy and FrankenPHP smoke tests now run their containers with
  `--cap-drop ALL --security-opt no-new-privileges`, turning a surviving
  capability into an observable failure instead of an inference.
- Verified on **both architectures** (amd64 + arm64): zero capabilities and a
  clean exec under the hardened profile. The unmodified upstream
  `caddy:2-alpine` base fails the same run with `operation not permitted` —
  confirming the check is meaningful. No image was actually shipping a
  capability; this closes a latent fail-open, not a live exposure.

### Security — repository governance now enforced and verified (#97)

- **`master` and `v*` are protected for the first time.** Two rulesets are live
  with **no bypass actors, administrators included**: `master-protection` (pull
  request required, no direct push, no force-push, no deletion, linear history,
  conversation resolution, the required status checks) and
  <!-- Corrected 2026-07-30: this entry originally said "all 26 required
  status checks". The ruleset gates PULL REQUESTS and requires the 5
  PR-producible checks; the 17-entry release set is verified on the release
  commit. The figure was wrong when written, not changed since. -->
  `release-tags-immutable` (`v*` cannot be deleted, force-moved or repointed).
  Tag *creation* stays open so `scripts/prepare-release.sh` still works.
- **The premise everything rested on was false.** Four documents stated the repo
  "must remain private" on GitHub Free, where protections return 403/422. The
  repo is **public** (verified 2026-07-28), where they are free — and the live
  configuration had **zero** protections (`/rulesets` → `[]`,
  `/branches/master/protection` → 404). Unchecked checkboxes were reading as
  governance.
- `policies/repository-governance.yaml` + `scripts/verify-repo-governance.sh`
  (`make verify-governance`) now declare and machine-check that configuration,
  failing closed on divergence in either direction. Required-check names are
  read from `policies/required-release-checks.yaml` rather than copied. Dated
  evidence: `docs/audits/governance-verification-2026-08-23.json`.
- The stale apply-instructions in `repository-security.md` (classic
  branch-protection payload, rotted `build representative images (…)` contexts,
  `required_approving_review_count: 1`) are replaced — following them would have
  wedged every merge in a single-maintainer repo.
- Truth-synced: `README.md`, `SECURITY.md`, `repository-security.md`,
  `accepted-risks.md` (AR-1), `manual-pr-policy.md`, `ci-failure-policy.md`,
  `release-governance.md`, `release-environments.md`, `security-model.md`,
  `solo-maintainer-release-model.md`, `architecture.md`. The Free-plan
  accepted-risk record is **superseded**, not deleted.
- Re-scoped, not closed: required reviewers, CODEOWNERS enforcement and
  environment approval gates stay off because a single maintainer cannot
  self-approve — a people limit (#112), no longer a plan limit. Visibility
  remains public for external review access, which does **not** resolve the
  proprietary-LICENSE conflict in #98.

### Security — CI trust boundary (#96)

- Fork pull requests can no longer schedule work on the persistent, shared,
  sudo- and Docker-capable `[self-hosted, linux, x64, zenchron]` runners. Every
  `ci.yml` job now derives `runs-on` from the trigger's trust: trusted events
  (push/tag/schedule/dispatch, same-repo PRs) keep the self-hosted pool, fork PRs
  get an ephemeral GitHub-hosted `ubuntu-latest` VM.
- New fail-closed gate `scripts/assert-runner-trust.sh` (wired into
  `make validate` and the `repo structure` job) enforces this across **every**
  workflow: no `pull_request_target` anywhere, no unguarded PR-reachable job on a
  privileged label, no unprovable workflow delegation from a PR job, and no
  vacuous pass on empty discovery. Regression test:
  `tests/runner/test_workflow_trust.sh`.
- Docs truth-synced: new *CI trust boundary* section in `repository-security.md`
  (plus a dated correction — the repo is verifiably **public**, reconciliation
  tracked by #97), trust-boundary preface in `runner-capacity.md`, threat **T5a**
  in the threat model, and a rewritten **AR-2** (its "runner is root without
  sudo" text was already contradicted by the 2026-07-09 runner findings).

### BREAKING — nginx dynamic modules removed (#102/#103)

`ghcr.io/zenchron-dynamics/nginx:prod` no longer ships these upstream dynamic
modules, or the decoder/parser stacks they pulled in:

| Removed module | Also removed with it |
|---|---|
| `ngx_http_image_filter_module` | `libgd3`, `libheif1`, `libaom3`, `libavif15` |
| `ngx_http_xslt_filter_module` | `libxslt1.1`, `libxml2` |
| `ngx_http_js_module` (njs), `ngx_stream_js_module` | `libxml2` |
| `ngx_http_geoip_module`, `ngx_stream_geoip_module` | `libgeoip` |

Also removed: `curl` (and with it `libcurl4`, `libssh2-1`, the krb5 stack),
`libtiff6`, `libexpat1`.

**Why:** none was loaded — no `load_module` directive exists in any shipped
config — and together they accounted for 74 of the image's 87 CRITICAL/HIGH
findings, including the CVSS 9.8 libxml2 use-after-free `CVE-2026-6653`.
Removing dead code beats documenting it as unreachable.

**Who is affected:** only a consumer that added a `load_module` line of their own
for one of the modules above, or invoked `curl` inside the container. Nothing in
Foundry's `nginx.conf`, `conf.d/`, contract or documentation referenced them.

**Migration — pick one:**

1. **Use the official upstream image** — `nginxinc/nginx-unprivileged:1.27-bookworm`
   still ships all four modules (without Foundry's hardening).
2. **Derive and reinstall** the module you need:

   ```dockerfile
   FROM ghcr.io/zenchron-dynamics/nginx@sha256:<digest>
   USER root
   RUN apt-get update && apt-get install -y --no-install-recommends nginx-module-njs \
       && rm -rf /var/lib/apt/lists/*
   USER 101:101
   ```

   Note you re-inherit that module's CVE surface, which is yours to govern.
3. **Stay on the previous Foundry digest temporarily**, with an explicit,
   time-boxed risk acceptance recorded on your side — that digest still carries
   `CVE-2026-6653` and the curl/libssh2/krb5/libaom stack.

Nothing yet.

## [v2026.07.24] - 2026-07-25

First release sealed by the fully automated ceremony: zero manual steps, zero
failed gates, zero reruns. Full run ledger and digests:
[docs/releases/v2026.07.24-war-room.md](docs/releases/v2026.07.24-war-room.md).

### Fixed — images

- Six Debian php-family bases bumped to Debian 12.15: curl/libcurl4
  `7.88.1-10+deb12u15` (CVE-2026-5773) absorbed on php-cli/fpm/worker ×
  8.3/8.4 and frankenphp × 8.3/8.4 (fixes #75). frankenphp's rebuilt base also
  cleared Go-stdlib CVE-2026-39822. nginx/caddy bases unchanged upstream —
  their findings remain governed exceptions.
- frankenphp hardening: security headers aligned with the caddy canon,
  `pcntl_exec` disabled, dead `EXPOSE 8443` dropped (batch 4a, #71).

### Added — release automation (the audit batches, PRs #69–#78, #80)

- `release-preflight.yml`: read-only rehearsal of every seal gate against a
  candidate SHA, dispatched pre-build and again post-RC.
- `rollback-exercise.yml`: automated live rollback round-trip with derived
  `rollback-results.json` — first production run in this ceremony.
- Derived evidence everywhere: verification values in `evidence.json` come
  from verifier output (never literals), `RUNTIME_RESULT` from a bound
  verify-rc run, `release-evidence-summary.json` assembled + validated at
  seal; per-stage results artifacts across ci/scan/publish/verify-rc/promote.
  Schema: [docs/release-evidence.md](docs/release-evidence.md).
- Typed confirmations on all three outward stages (seal gained
  `SEAL-<version>-<sha>`); promote-time exact-commit CI gate; binding
  verification across all 28 aliases with per-arch OCI-label checks.
- Supply-chain: production alias mutation refused outside CI; wildcard cosign
  identity fallback removed; GHSA-only advisories now governable by the
  exception validator; fail-closed environment preflight.
- Runner safety: 26 canonical hardened workspace-reset blocks with a CI drift
  gate; all heavy matrices serialized; SIGPIPE flake in the required-checks
  gate fixed.

### Accepted risk

18 governed exceptions (ledger:
[docs/vulnerability-exceptions.md](docs/vulnerability-exceptions.md)), all
expiring 2026-08-31, incl. the interim kin-openapi CRITICAL in the upstream
FrankenPHP binary (unreachable in shipped config; upstream bump requested,
php/frankenphp#2559, tracked by #79).

## [v2026.07.21] - 2026-07-22

First fully sealed production release: 10 images (php-{cli,fpm,worker,frankenphp}
× {8.3,8.4} + nginx + caddy), linux/amd64 + linux/arm64, promoted by exact digest
from RC `rc1` at revision `29f26c4f1bf7e53d8bc07f99b34708ba32322046`. Image
content is identical to the v2026.07.04 promotion (CI-only changes in between);
this release adds the completed identity chain and the sealed evidence package.

### Release ceremony

- publish-rc run 29845853856 (10/10 images signed + SBOM + SLSA provenance,
  signed RC manifest artifact), verify-rc run 29876269380 (10/10 runtime
  certification, both architectures), promote-stable run 29895243521 (digest-only
  retag, zero builds), stable-alias binding verified 10/10 against the signed
  manifest, rollback exercised live against the registry (priors restored,
  verified, smoked; new release restored, verified, smoked).
- The GitHub Release was created manually with owner approval after the tagged
  seal workflow failed on the ARG_MAX defect fixed in #67 — full justification
  and independently re-proven gate results in the release's `DEVIATION.md`.

### Fixed — release pipeline hardening (#65, #66, #67, #68)

- **#65** — cosign installs are per-job (`install-dir: $RUNNER_TEMP/cosign`),
  eliminating the shared-`$HOME` install race between the two runner instances;
  signing workflows share an `org-cosign-publish` concurrency group; the
  publish matrix runs `max-parallel: 1` (2 vCPU / 4 GB single-host runner).
- **#66** — the seal guard has `checks: read` + `statuses: read`, and
  `check-exact-commit-ci.sh` refuses with the real API response instead of
  producing malformed JSON when it cannot read CI (never passes vacuously).
- **#67** — `check-exact-commit-ci.sh` reads the check-runs payload via files,
  never argv: a busy release commit's checks (~180 KB, growing with every
  verify/promote/seal run) overflowed Linux `MAX_ARG_STRLEN` and killed the
  seal on a frozen tag. Also merges multi-page `--paginate` output.
- **#68** — new dispatch-only `release-preflight.yml`: read-only rehearsal of
  every seal gate against a candidate SHA on the real runner. Each of the four
  historical seal failures would have been caught by it in minutes instead of
  after ~24 h of builds. Dispatch before tagging and again after verify-rc.

### Accepted CVE exceptions (all expire 2026-08-31)

Complete ledger in [docs/vulnerability-exceptions.md](docs/vulnerability-exceptions.md):
php-all zlib1g/perl-base/libsqlite3-0/curl (CVE-2023-45853, CVE-2026-42496,
CVE-2026-8376, CVE-2025-7458, CVE-2026-5773); php-frankenphp libaom3/
linux-libc-dev/Go-stdlib (CVE-2023-6879, CVE-2026-43185, CVE-2026-39822); nginx
krb5 (CVE-2026-40355/40356); caddy Go-stdlib/c-ares/curl (CVE-2026-27145,
CVE-2026-42504, CVE-2026-33630, CVE-2026-6276). caddy go-jose CVE-2026-34986
remains RESOLVED (no standing exception). All are "pinned base lags upstream
fix" or "no fix exists", watched by the weekly enforcing rebuild scan.

### Fixed — stable seal path (first live ceremony blockers)

- **RC manifest is artifact-sourced, never committed.** `release.yml` no longer
  requires `release-evidence/<version>/release-manifest.yaml` in git — committing
  generated RC evidence created a commit *after* the RC images were built and
  broke `tag commit == manifest.revision == provenance revision == OCI revision`.
  New `scripts/fetch-rc-manifest.sh` downloads the signed manifest from the
  `publish-rc` artifact and fails closed on wrong repository, wrong workflow,
  non-success run, `head_sha` != tag commit, missing/incomplete artifact, checksum
  or signature failure, schema/policy failure, or version/rc/revision mismatch.
  No fallback to local evidence.
- **Promotion and sealing run from the stable tag.** New
  `scripts/check-promotion-ref.sh` requires `github.ref == refs/tags/<version>`
  (branch refs and RC tags refused) in both `promote-stable.yml` and
  `release.yml`, matching the `foundry-production` stable-tags-only policy that
  blocked the first attempt. `promote-stable.yml` additionally binds the tag
  commit to `expected_revision`.
- **Ceremony order enforced**: publish-rc → tag → promote-stable (from tag) →
  release (from tag). `release.yml` is dispatch-only (no tag-push auto-seal) and
  its guard fails if the stable aliases do not already hold the RC digests.
- Neither workflow builds images; promotion remains a registry-side retag.
- **Third blocker found while verifying the gate: the exact-commit CI policy could
  never pass.** Every name in `policies/required-release-checks.yaml` was
  unproducible — measured against a real `master` commit, all 18 reported
  `missing:`, so `release.yml`'s guard would refuse every seal. The gate's own
  self-test built its fixture *from the policy*, so the drift was invisible.
  Policy rewritten with the exact rendered check names (15 from `ci.yml`, 10 from
  `scan-images.yml`); the two names no workflow ever emitted
  (`release-manifest-validate`, `image-identity-validate`) are dropped — those
  validations already run inside the release guard itself. New
  `scripts/assert-required-checks.sh` compares the policy against the workflow job
  names (matrices expanded) and runs in both `ci.yml` and the release guard, so
  the drift cannot recur silently.

## [v2026.07.04] - 2026-07-04 (promoted, never sealed — superseded by v2026.07.21)

> The v2026.07.04 stable aliases were promoted and verified, but the GitHub
> Release could never be sealed: the tag-pinned seal workflow lacked
> `checks: read` (fixed in #66 after the tag was frozen). The identical image
> content shipped, sealed, as v2026.07.21.

### Added — release binding & supply-chain macro-increment (v2026.07.04)

- **RC identity binding**: `publish-rc` requires version + rc + 40-hex revision +
  typed confirmation + master ancestry; immutable SHA-bound RC tags; pre-publish
  immutability probe (fails closed on conflict).
- **Signed RC manifest** (`schema_version: 1`) as the sole promotion source of
  truth — generate/validate/sign/verify with a real parser + JSON Schema.
- **Single authoritative image-identity verifier** with explicit per-role cosign
  identities (`policies/cosign-identities.yaml`); scheduled-rebuild candidates can
  no longer satisfy production policy; the two former verifiers are thin wrappers.
- **Exact-commit release gate** (GitHub Checks API) + the tag/manifest/provenance/
  OCI/stable-digest equality chain across all 10 images.
- **Two-phase promotion with automatic compensating rollback** — signed rollback
  manifest, mutation journal, reverse-order restore, emergency incident (exit 99).
- **Runner hardening**: one strict workspace-reset helper across all 9 workflows;
  job-scoped Docker cleanup (no global prune); fork-PR guards; runner-hook template.
- **Vulnerability enforcement**: validator now requires approver / compensating
  controls / created_at format / explicit release_blocking / future expiry; Caddy
  enforcing; scheduled-rebuild isolated with immutable candidate tags + least-priv
  issue reporting.
- **Runtime + multi-arch certification** (`verify-rc.yml`): cold build + smoke +
  data-driven contract check (10/10) + amd64/arm64 verification per RC digest.
- **Solo-maintainer governance + immutable evidence package**; typed production
  confirmation; accepted-risk record. No artificial two-reviewer requirement.
- **Offline macro-validation + release dry-run** (`scripts/macro-validate.sh`,
  `scripts/release-dry-run.sh`) — full pipeline rehearsal with no live actions.

### Changed

- **Stable release now promotes exact RC digests instead of rebuilding** (rule
  #14 / Sprint 6). New `promote-stable.yml` + `scripts/promote-stable.sh` copy the
  already-signed RC image digests onto the `*-prod` aliases via registry retag
  (`docker buildx imagetools create`) — two-phase, atomic-at-the-alias, with
  digest-equality verification and rollback metadata. `release.yml` no longer
  builds: it only verifies + seals the GitHub Release over the promoted images.
- **Hardened self-hosted workspace-ownership reset** across all workflows: the
  `sudo chown … || true` pattern is replaced with a path-validated, fail-loud
  block (refuses to `chown` outside `$RUNNER_WORKSPACE`; errors if the tree is not
  ours and `sudo` is unavailable) (Sprint 7).

## [2026.06.21] — Debian-first STABLE promotion

This release **flips the generic production tags to the Debian line.**
`php-{cli,fpm,worker,frankenphp}:{8.3,8.4}-prod`, `nginx:prod`, and `caddy:prod`
now resolve to the Debian-backed images (provider-explicit `8.x-debian` tags also
published). Built multi-arch (linux/amd64 + linux/arm64), Cosign-signed, with
SPDX SBOM + provenance attestations. Promotes the validated RC1 source state
(commit `4425011`, image contents unchanged from `8.x-debian-rc1`).

Consumer validation: full Laravel + Symfony matrix (php-fpm+nginx, php-fpm+Caddy,
FrankenPHP, worker, CLI, scheduler) passed via `php-app-template` (master
`75a3d2b`) against the RC images — Postgres + Redis, migrations, queued job,
heartbeat, clean SIGTERM, non-root (10001), read-only rootfs.

### Rollback (previous Wolfi `*-prod` digests — retained, never deleted)

Emergency rollback = re-pin consumers to these digests (no tag mutation needed):

```text
php-cli:8.4-prod        sha256:bdc99337029787dc9ab63bdbad3e386f1ea1c5e6c74f9d3e1cf210e380a0e359
php-fpm:8.4-prod        sha256:4699b1bed89d115cd4ec1512513da2778bb149ad9d4eb19794e5b0a0e28fb3fb
php-worker:8.4-prod     sha256:bfd83613de911aeb43eb17c953ba531ec938a833b69cd239deb9979bc4d89b61
php-frankenphp:8.4-prod sha256:926d9b1db3ff4e15d2fb7b85c4112a16bbb8f4deb138be8ef8c4c8cef25e8011
php-cli:8.3-prod        sha256:433a73539d88e6e2f9028ae8d04429f91104b5be737b216808bfc996fd4060a5
php-fpm:8.3-prod        sha256:89838f2e1f1a9d641f8dba3c927d02043876280f55804ffbf7919cae71de7214
php-worker:8.3-prod     sha256:5188724af284b272ba17a728fce6ecf944af7e32b0235893e5fed5b62f5d6694
php-frankenphp:8.3-prod sha256:83021a9d56c0d17e866495e97e65ed8f29119e0f9bdc7fef73654b027a5d5043
nginx:prod              sha256:a0b1ade4583e64c00bc013f16b3ad95ff1de42cc358b6ed128063f533af65953
caddy:prod              sha256:3c02c618980d01f3d008801e0d5e429b4c515a0dcee07262efceb54b74bb04af
```

### Accepted CVE exceptions (review by 2026-07-20; see vulnerability-management.md)

Unfixed Debian distro CRITICALs, excluded by `--ignore-unfixed` + recorded in
`policies/.trivyignore`: `zlib1g` (CVE-2023-45853, will_not_fix), `perl-base`
(CVE-2026-42496/8376), `libsqlite3-0` (CVE-2025-7458), FrankenPHP base `libaom3`
(CVE-2023-6879), `linux-libc-dev` (CVE-2026-43185); caddy go-jose (CVE-2026-34986,
review 2026-07-02). PHP/nginx images: **0 fixable CRITICAL/HIGH**.

### Notes

- PHP 7.4 / 8.0 remain **frozen legacy** (Wolfi images retained, never rebuilt).
- Internal config path: old `/etc/php` → new `/usr/local/etc/php`.
- FrankenPHP serves HTTP `:8080` + readiness `:8081`; state under `/tmp`.

### Changed — Debian-first base image platform (BREAKING for base provider)

- **Removed all Wolfi/Chainguard dependencies.** `php-cli`, `php-fpm`,
  `php-worker` now build on official **`php:8.x-{cli,fpm}-bookworm`** (Debian 12);
  `php-frankenphp` on **`dunglas/frankenphp:1-php8.x-bookworm`**; `nginx` on
  **`nginxinc/nginx-unprivileged:1.27-bookworm`**. No more `cgr.dev`, `apk`, or
  Wolfi package feeds. `caddy` stays on the official Alpine image (no upstream
  Debian variant; documented exception). See
  [ADR-0001](docs/adr/ADR-0001-remove-wolfi-chainguard.md).
- PHP extensions are now **compiled from official source** (multi-stage; the
  compiler toolchain is stripped from the final image). `redis` is a pinned pecl
  build. Added `pgsql`, `sockets`, `sqlite3`/`pdo_sqlite` (parity + additions —
  see [php-extension-matrix.md](docs/php-extension-matrix.md)).
- FrankenPHP writable state moved to `/tmp/caddy-data` + `/tmp/caddy-config`
  (single `tmpfs /tmp` covers read-only rootfs); php-based healthcheck (Debian
  ships no wget).
- Trivy gate now blocks on **fixable** CRITICAL/HIGH (`--ignore-unfixed`); edge
  images (nginx/caddy) are scan-and-report. PHP images: **0 fixable CRITICAL/HIGH**.
- Internal PHP config paths moved `/etc/php/*` → `/usr/local/etc/php/*`.

### Removed

- **PHP 7.4 and 8.0 source Dockerfiles** (cli/fpm/worker). These are now frozen
  legacy: previously-published Wolfi images remain in GHCR, but they are not
  rebuilt. See [legacy-php-policy.md](docs/legacy-php-policy.md).

### Added

- Migration docs: [base-image-strategy](docs/base-image-strategy.md),
  [base-image-patching](docs/security/base-image-patching.md),
  [wolfi-to-debian migration guide](docs/migration/wolfi-to-debian.md),
  [php-extension-matrix](docs/php-extension-matrix.md),
  [release-process](docs/release-process.md), and [ADR-0001](docs/adr/ADR-0001-remove-wolfi-chainguard.md).
- `scripts/assert-no-wolfi.sh` CI guard (forbids cgr.dev/chainguard/wolfi/apk in
  active code); base digest-pin + no-`latest` enforcement in `check-structure.sh`.
- Provider-explicit `8.x-debian` image tag.

- Initial platform bootstrap: repository structure, security tooling, CI/CD
  workflows, shared Compose profiles, and core documentation.
- Production Dockerfiles for the PHP 8.3 and 8.4 image families (php-fpm,
  php-cli, php-worker, php-frankenphp) plus hardened Caddy and nginx images.
- Pre-commit hooks: gitleaks, hadolint, shellcheck, yamllint, markdownlint,
  trailing-whitespace / end-of-file / large-file checks.
- GitHub Actions: ci, build-images, scan-images, publish-ghcr, release.
- Cosign signing, Syft SBOM, Trivy + Grype scanning policies.
- Free-tier governance compensating controls: local pre-push hook, release
  safety script, manual PR + CI-failure policies, and accepted-risk record.

### Changed (P2 hardening)

- Caddy and FrankenPHP now use **real HTTP readiness** healthchecks
  (always-on `:8081/healthz` via `wget`) instead of `<binary> version`.
- CI shellchecks the worker scripts under `images/php-worker/`.
- `build-images` / `publish-ghcr` accept a `platforms` input for optional
  `linux/arm64` multi-arch (default `linux/amd64`; arm64 verified to build).
- `make doctor` reports local tool availability with install hints.
- `make build-frankenphp` / `build-php-worker` guard against invalid versions.

### Verified

- GHCR private consumption proven end-to-end: read-only `read:packages` token
  pulls all six images; push is denied (`permission_denied`).
- OPcache JIT disabled by default; worker heartbeat liveness implemented.

### Fixed (post-v2026.06.02 verification)

- Hardened-runtime defects found while verifying v2026.06.02 under the documented
  `cap_drop: ALL` + read-only profile (all fixed; **v2026.06.02 images are
  superseded — do not deploy them, use the next tag**):
  - **php-fpm** exited (code 78, "Unable to create the PID file") under a
    read-only rootfs. Removed the pid directive (FPM is foreground PID 1); now
    needs only tmpfs `/tmp`.
  - **caddy / frankenphp** failed to exec under `cap_drop: ALL` ("operation not
    permitted") because their binaries carry a `cap_net_bind_service` file cap.
    Stripped it at build (`setcap -r`); they now run with zero capabilities on
    high ports (bind :80/:443 only via an upstream LB).

### Security

- Repaired `scan-images` (the `trivy-action`/`setup-trivy` tags were yanked):
  Trivy now runs from the official `aquasec/trivy` image and is the enforcing
  gate; Grype is a non-gating second opinion. First real scan surfaced and fixed
  CVEs the upstream bases hadn't republished: nginx `apk upgrade libssl3
  libcrypto3` (2 CRITICAL + 28 HIGH → 0), frankenphp `apk upgrade libxml2`
  (1 HIGH → 0). Caddy's go-jose CVE (compiled into the binary, not reachable with
  upstream TLS termination) is a justified, dated exception.
- All runtime images: non-root (10001:10001), read-only rootfs default,
  cap_drop ALL, no-new-privileges.
- PHP 7.4 / 8.0 marked high-risk legacy (EOL); isolated and documented.

[v2026.07.24]: https://github.com/zenchron-dynamics/zenchron-foundry/releases/tag/v2026.07.24
[v2026.07.21]: https://github.com/zenchron-dynamics/zenchron-foundry/releases/tag/v2026.07.21
[v2026.07.04]: https://github.com/zenchron-dynamics/zenchron-foundry/compare/2026.06.21...v2026.07.04
