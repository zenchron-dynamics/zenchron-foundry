#!/usr/bin/env bash
# =============================================================================
# scripts/sign-release-manifest.sh <manifest.yaml>
# -----------------------------------------------------------------------------
# Checksums and cosign-blob-signs the RC manifest, producing the immutable
# evidence trio consumed by promotion:
#     <manifest>.sha256   sha256 checksum
#     <manifest>.sig      cosign blob signature (keyless)
#     <manifest>.pem      signing certificate
#
# LOCAL=1 (or cosign absent) writes the checksum only and SKIPS signing — for
# offline dry-runs. A real RC publish must sign (cosign present, LOCAL unset).
# =============================================================================
set -euo pipefail
_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/release-manifest.sh
. "$_d/lib/release-manifest.sh"

MANIFEST="${1:?usage: sign-release-manifest.sh <manifest.yaml>}"
[ -f "$MANIFEST" ] || die "manifest not found: $MANIFEST"

checksum_file "$MANIFEST" > "${MANIFEST}.sha256"
log "wrote ${MANIFEST}.sha256"

if ! command -v cosign >/dev/null 2>&1; then
  [ "${LOCAL:-0}" = 1 ] || die "cosign not installed (set LOCAL=1 for an unsigned offline manifest)"
  warn "LOCAL: cosign absent — manifest checksummed but NOT signed"
  exit 0
fi

cosign sign-blob --yes \
  --output-signature "${MANIFEST}.sig" \
  --output-certificate "${MANIFEST}.pem" \
  "$MANIFEST"
log "signed: ${MANIFEST}.sig + ${MANIFEST}.pem"
