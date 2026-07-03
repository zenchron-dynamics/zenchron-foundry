#!/usr/bin/env bash
# =============================================================================
# scripts/verify-signatures.sh <image-ref> [<image-ref> ...]
# -----------------------------------------------------------------------------
# THIN ORCHESTRATOR. Delegates each image ref to the single authoritative
# verifier scripts/verify-image-release-identity.sh. This replaces the previous
# weaker path (bare signature + best-effort SBOM warning) so every caller gets
# the full trust check: signature, exact per-role identity, issuer, SBOM,
# provenance repo+revision, OCI revision label, and amd64+arm64.
#
# Env: EXPECTED_REVISION (40-hex, required unless LOCAL=1), EXPECTED_REPO
#      (default zenchron-dynamics/zenchron-foundry), EXPECTED_ROLE
#      (default rc-publisher), LOCAL=1 to skip when cosign is absent.
# =============================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/common.sh
. "$ROOT/scripts/lib/common.sh"

[ "$#" -ge 1 ] || { echo "usage: verify-signatures.sh <image-ref> [...]" >&2; exit 2; }
export EXPECTED_REPO="${EXPECTED_REPO:-zenchron-dynamics/zenchron-foundry}"
export EXPECTED_ROLE="${EXPECTED_ROLE:-rc-publisher}"
VERIFIER="$ROOT/scripts/verify-image-release-identity.sh"

if [ "${LOCAL:-0}" = 1 ] || ! command -v cosign >/dev/null 2>&1; then
  [ "${LOCAL:-0}" = 1 ] || die "cosign not installed (set LOCAL=1 to skip)"
  echo "SKIPPED: LOCAL=1 — signature verification not run"; exit 0
fi
[ -n "${EXPECTED_REVISION:-}" ] || die "EXPECTED_REVISION required"
export EXPECTED_REVISION

rc=0
for image in "$@"; do
  echo "==> verify identity: $image"
  "$VERIFIER" "$image" || rc=1
done
[ "$rc" -eq 0 ] || die "one or more images failed identity verification"
echo "==> Verification complete."
