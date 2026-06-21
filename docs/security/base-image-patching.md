# Base-image patching policy

How Zenchron Foundry keeps its Debian-first images current. Companion to
`docs/vulnerability-management.md` and `docs/base-image-strategy.md`.

## Core rule

**Patch by bumping the pinned base digest and rebuilding — not by running broad
package upgrades inside the image.** In-image `apt-get upgrade` / `dist-upgrade`
hides uncontrolled package drift and is forbidden (`policies/semgrep`, ADR-0001).
A fixable CVE means a fresher upstream base exists: bump the digest.

## Digest refresh cadence

- **Weekly (automated):** Dependabot (`docker` ecosystem) proposes base digest
  bumps for every image directory; `scan-images.yml` cron rebuilds and rescans
  every Monday 03:00 UTC.
- **On Dependabot PR:** CI builds + scans the bumped base. Merge if green.
- **Emergency (named CVE):** see below.

## CVE triage classes

When Trivy/Grype report a CRITICAL/HIGH, classify it:

| Class | Action |
|-------|--------|
| Fixable, fix in a newer base digest | Bump the digest, rebuild, publish. |
| Fixable, but upstream image hasn't rebuilt (e.g. `nginx`/`caddy` lag) | Track; the weekly cron picks up the upstream rebuild. Compensating controls below. Time-box an exception if it lingers. |
| Unfixed distro CVE (no Debian fix; `perl-base`, `zlib1g`, `libsqlite3-0`, …) | Not actionable — document in `vulnerability-management.md`; the gate ignores unfixed. |
| Build-only dependency | Verify it is absent from the final image (toolchain is stripped). |
| False positive | Document evidence; add to `policies/.trivyignore` with rationale + review date. |

## Enforcing gate

`scan-images.yml` fails the build on **fixable** CRITICAL/HIGH
(`--ignore-unfixed`) for the PHP images. The edge images (`nginx`, `caddy`) are
scan-and-report because we do not rebuild their binaries; their fixable findings
are governed by upstream rebuild cadence.

## Base rebuild cadence

- PHP images: rebuilt weekly (cron) and whenever a base digest bump merges.
- A new immutable Foundry release is cut when a base bump changes published tags
  (see `docs/release-process.md`).

## Emergency rebuild (named critical CVE)

1. Confirm the CVE is **fixable** and reachable in our final image.
2. Find the patched upstream base digest (`docker buildx imagetools inspect`).
3. Bump the `*_BASE` ARG digest in the affected Dockerfile(s).
4. Open a PR; CI builds + scans.
5. On green, tag a release; `publish-ghcr.yml` builds, signs, attests, pushes
   immutable tags.
6. Roll consumers forward to the new digest.

## Exception process

Record accepted exceptions in `docs/vulnerability-management.md` /
`policies/.trivyignore` with: CVE ID, affected package, rationale, owner,
review/expiry date, and compensating control. Review on every weekly scan.

## Rollback

Every release records the previous digest (`docs/migration/wolfi-to-debian.md`).
To roll back, re-pin the prior digest and rebuild, or point consumers at the
previous immutable tag. No DB migration is tied to an image bump.

## Compensating controls (apply to all images, esp. edge upstream-lag)

- Non-root (10001 / nginx 101), `cap_drop: ALL`, `no-new-privileges`,
  read-only rootfs, tmpfs `/tmp`, process limits.
- Edge TLS terminated upstream (LB/ingress); edge images are not the TLS
  endpoint, reducing reachability of openssl/gnutls CVEs.
- Weekly automated rebuild + rescan surfaces upstream patches promptly.
