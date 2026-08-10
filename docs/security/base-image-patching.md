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
| Unfixed distro CVE (no Debian fix; `perl-base`, `zlib1g`, `libsqlite3-0`, …) | Not remediable here, but **not ignored**: write a scoped, dated record in `policies/vulnerability-exceptions.yaml`, or the build fails. |
| Build-only dependency | Verify it is absent from the final image (toolchain is stripped). |
| False positive | Add a `not_affected:` record with a version binding, so the determination self-invalidates when the package moves. `policies/.trivyignore` is gone — one global ignore file suppressed a CVE on all ten images (#102/#103). |

## Enforcing gate

`scan-images.yml` reports the **complete** CRITICAL/HIGH finding set and fails
the build on any finding that is not governed by a record in
`policies/vulnerability-exceptions.yaml`. Fixed or unfixed makes no difference to
whether a finding must be governed — only to what the record says.

This applies to **all ten images on identical terms**, edge images included.
There is no per-image gate flag and a report-only image cannot be expressed. The
edge images were scan-and-report until #136; that is no longer true, and "we do
not rebuild their binaries" is now the *content* of their exception records
rather than a reason to skip the gate.

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
