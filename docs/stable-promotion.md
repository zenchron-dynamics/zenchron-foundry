# Stable promotion — two-phase with compensating rollback

Implemented by **`scripts/promote-stable.sh`** (invoked by
`.github/workflows/promote-stable.yml`). Stable promotion **never rebuilds
images** — it retags exact RC digests. Cross-repository atomicity is not
available, so this is *two-phase promotion with compensating rollback*, **not**
truly atomic. Do not describe it as atomic.

## Inputs it consumes

- The signed RC manifest (exact per-image digests + revision).
- The 10 published RC images (signed + attested) in GHCR.

## Phase 1 — preflight (mutates nothing)

For all 10 images: resolve the RC digest, verify it is signed + attested, and
**record the current canonical alias digest for rollback**. Any failure here
aborts before a single alias is touched. The prior digests are written to a
rollback manifest and uploaded *before* any mutation.

## Phase 2 — promote (retag exact digests)

Registry-side copy of each exact RC digest onto its stable aliases (no pull, no
build — signatures ride the digest). Promotion order minimizes canonical
mixed-release exposure:

1. immutable version-specific aliases
2. provider-explicit aliases (`*-debian`)
3. compatibility aliases
4. canonical `*-prod` aliases **last**

## Alias inventory

From `aliases_for` in `promote-stable.sh`, with `REL = <release-version>`:

| Image class | Aliases mutated |
|---|---|
| PHP family (8.3/8.4 × cli/fpm/worker/frankenphp) | `<ver>-prod`, `<ver>-prod-<REL>`, `<ver>-debian` |
| Edges (caddy, nginx) | `prod`, `prod-<REL>` |

Record **every** alias above for rollback — not just the primary.

## Phase 3 — verify

After promotion, verify every alias resolves to the **exact** RC digest. Any
mismatch is a failure.

## Failure handling (compensating rollback)

On any mutation/verification failure: stop, restore every alias already changed
to its recorded prior digest, verify the restored digest, record the rollback
result, upload failure evidence, and fail the workflow. If **rollback itself
fails**, raise a critical release incident, block release sealing, and list every
alias needing manual repair — do not continue.

## Open items (not yet proven live)

- Revision-equality / OCI-label binding (`stable provenance revision == release
  tag SHA`, `stable OCI label == release tag SHA`) is **not** yet enforced by the
  existing verifier (`verify-release-artifacts.sh` checks signature/SBOM/
  provenance/multiarch only). See `docs/release-security.md`.
- Rollback has **not** been exercised end-to-end against the live registry.
