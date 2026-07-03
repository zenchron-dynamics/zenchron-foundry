#!/usr/bin/env bash
# =============================================================================
# scripts/verify-release-artifacts.sh
# -----------------------------------------------------------------------------
# THIN ORCHESTRATOR. Verifies the 10 canonical stable (-prod) images by
# delegating every per-image trust check to the single authoritative verifier
# scripts/verify-image-release-identity.sh (signature, exact per-role identity,
# issuer, SBOM, SLSA provenance, provenance repo+revision, OCI revision label,
# amd64+arm64). No verification logic is reimplemented here — this file only
# fans out over the matrix, pins each tag to its digest, and enforces 10/10.
#
# Env:
#   EXPECTED_REVISION  40-hex release revision (required unless LOCAL=1)
#   EXPECTED_REPO      default zenchron-dynamics/zenchron-foundry
#   EXPECTED_ROLE      default rc-publisher (stable digests are promoted RC digests)
#   REGISTRY/NAMESPACE default ghcr.io / zenchron-dynamics
#   LOCAL=1            cosign/registry absent -> SKIP, exit 0
# =============================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
# shellcheck source=lib/common.sh
. "$ROOT/scripts/lib/common.sh"

REGISTRY="${REGISTRY:-ghcr.io}"; NAMESPACE="${NAMESPACE:-zenchron-dynamics}"
NS="${REGISTRY}/${NAMESPACE}"
export EXPECTED_REPO="${EXPECTED_REPO:-zenchron-dynamics/zenchron-foundry}"
export EXPECTED_ROLE="${EXPECTED_ROLE:-rc-publisher}"
VERIFIER="$ROOT/scripts/verify-image-release-identity.sh"

if [ "${LOCAL:-0}" = 1 ] || ! command -v cosign >/dev/null 2>&1; then
  [ "${LOCAL:-0}" = 1 ] || die "cosign not installed (set LOCAL=1 to skip for non-release use)"
  echo "SKIPPED: LOCAL=1 — release artifact verification not run"; exit 0
fi
[ -n "${EXPECTED_REVISION:-}" ] || die "EXPECTED_REVISION required (40-hex release revision)"
export EXPECTED_REVISION

# Stable -prod ref per matrix image.
stable_ref() { # <fam> <sel>
  case "$2" in prod) printf '%s/%s:prod' "$NS" "$1" ;; *) printf '%s/%s:%s-prod' "$NS" "$1" "$2" ;; esac
}
digest_of() { docker buildx imagetools inspect "$1" --format '{{.Manifest.Digest}}' 2>/dev/null; }

n=0 ok=0
for t in $MATRIX_IMAGES; do
  n=$((n+1)); fam="${t%:*}"; sel="${t#*:}"
  ref="$(stable_ref "$fam" "$sel")"
  dg="$(digest_of "$ref" || true)"
  [ -n "$dg" ] || { echo "FAIL $ref: digest unresolved"; continue; }
  if "$VERIFIER" "${NS}/${fam}@${dg}" >/dev/null 2>&1; then
    echo "PASS $ref @ $dg"; ok=$((ok+1))
  else
    echo "FAIL $ref @ $dg (identity verification failed)"
  fi
done

echo "RELEASE VERIFY: ${ok}/${n} images fully verified"
assert_full_matrix "$n"
[ "$ok" -eq "$MATRIX_COUNT" ] || die "not all images passed (${ok}/${MATRIX_COUNT})"
echo "ALL CHECKS PASSED (${MATRIX_COUNT}/${MATRIX_COUNT})"
