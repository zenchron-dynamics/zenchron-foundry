# Production readiness report — v2026.07.04 macro-increment

**Verdict: `READY FOR RC` — since LIVE-PROVEN by the sealed v2026.07.21 release**

At the time of writing, everything below had been validated **offline only**
(mock registry, local crypto). That caveat no longer applies: the controls this
increment introduced were exercised end-to-end by the sealed **v2026.07.21**
release (sealed 2026-07-22) —
<https://github.com/zenchron-dynamics/zenchron-foundry/releases/tag/v2026.07.21>,
ceremony log in
[releases/v2026.07.21-war-room.md](releases/v2026.07.21-war-room.md):

- **Equality chain live-proven, 10/10**: release tag commit == manifest
  revision == provenance revision == OCI revision, and each stable `*-prod`
  digest == its RC digest.
- **Evidence package live-proven**: the GitHub Release ships `evidence.json`,
  `rollback-results.json`, and `DEVIATION.md` (manual seal, owner-approved,
  after the ARG_MAX defect fixed in #67).
- **Rollback exercised live** during the ceremony (`rollback-results.json`).

Honest remaining gaps: the read-only `release-preflight.yml` workflow now
exists (#68), but there is still **no automated rollback-exercise workflow** —
the v2026.07.21 rollback exercise was performed manually as part of the
ceremony.

## What this increment delivers

Binding + formalization layer on top of the existing platform:

- **RC identity binding** — `publish-rc` requires version, rc, 40-hex revision,
  a typed confirmation and master ancestry; RC tags are immutable and SHA-bound;
  a pre-publish probe fails closed on conflict.
- **Signed RC manifest** — schema_version-1 manifest (10 images, digests, real
  platforms, revision), cosign-blob signed + checksummed; the sole promotion input.
- **One authoritative verifier** — `verify-image-release-identity.sh` with
  explicit per-role cosign identities; the two former duplicate verifiers are
  thin orchestrators; scheduled-rebuild can never pass production policy.
- **Exact-commit release binding** — Checks API gate on the tagged commit +
  the tag==manifest==provenance==OCI==stable-digest equality chain (10/10).
- **Two-phase promotion + automatic compensating rollback** — full alias
  inventory, signed rollback manifest, journal, reverse-order restore, emergency
  incident (exit 99).
- **Runner + Docker + trust hardening** — one strict workspace-reset helper
  wired into every workflow (11 files under `.github/workflows/` as of
  v2026.07.21); job-scoped Docker cleanup (no global prune);
  fork-PR guards; publish/OIDC scoped to non-PR jobs.
- **Vulnerability enforcement** — validator now requires approver /
  compensating_controls / created_at format / explicit release_blocking /
  expiry-today; Caddy enforcing; scheduled-rebuild isolated (immutable candidate
  tags, least-priv issue reporting, distinct identity).
- **Runtime + multi-arch certification** — `verify-rc.yml` cold-builds + smokes +
  contract-checks 10/10, and verifies amd64+arm64 per published RC digest.
- **Solo-maintainer governance + evidence** — typed production confirmation, no
  fake reviewer, immutable signed evidence package, accepted-risk record.

## Offline validation results (`scripts/macro-validate.sh`)

```text
repo structure ......... PASS      actionlint ............. PASS
action pinning ......... PASS      shellcheck (scripts) ... PASS
container pinning ...... PASS      vulnerability policy ... PASS
no-wolfi guard ......... PASS      self-test + unit suite . PASS  (9 suites)
image matrix (10/10) ... PASS      release dry-run ........ PASS
environment names ...... PASS
```

Unit/self-test coverage (offline, assert-based): matrix drift-guard; RC input
gate (9 negative cases); immutability probe; manifest validator (8 reject
cases); cosign identity separation; exact-commit CI gate (7 cases); release
binding; promotion + reverse rollback + emergency-99; runner + Docker helpers;
vuln policy (12 cases); platforms + contract; evidence build/validate.

## NOT executed (require explicit owner authorization)

- Building/pushing RC images to GHCR
- Publishing/mutating any stable alias
- Creating any git tag or GitHub release
- Live cosign signing / attestation / Rekor

## Remaining live steps to reach production

> **Status: all five steps were executed live for v2026.07.21** (with a
> documented, owner-approved manual seal deviation — see `DEVIATION.md` in the
> release assets and the war-room log). Kept for reference as the canonical
> sequence.

1. `publish-rc.yml` → build+sign immutable RC images + signed RC manifest.
2. `verify-rc.yml` → runtime + multi-arch certification of the published RC.
3. push the `v*` tag on the exact revision the RC was built from.
4. `promote-stable.yml`, dispatched **from that tag** (typed `PROMOTE-…` +
   `ACCEPT-RISK`) → retag to stable.
5. `release.yml`, dispatched **from the same tag** with `rc_manifest_run_id` →
   seals the release with the evidence package. The signed RC manifest is fetched
   from the `publish-rc` artifact; it is never committed to the source tree.
