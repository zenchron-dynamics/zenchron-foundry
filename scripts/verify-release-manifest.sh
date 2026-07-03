#!/usr/bin/env bash
# =============================================================================
# scripts/verify-release-manifest.sh <manifest.yaml> [<sig> <cert>]
# -----------------------------------------------------------------------------
# Verifies the RC manifest before promotion trusts it:
#   1. checksum matches <manifest>.sha256 (if present)
#   2. cosign blob signature verifies against the pinned role identity
#   3. schema + policy validation (delegates to validate-release-manifest.sh)
#
# EXPECTED_ROLE (default rc-publisher) selects the cosign identity from
# policies/cosign-identities.yaml. LOCAL=1 (or cosign absent) skips step 2 only.
# =============================================================================
set -euo pipefail
_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/release-manifest.sh
. "$_d/lib/release-manifest.sh"
# shellcheck source=lib/cosign-identity.sh
. "$_d/lib/cosign-identity.sh"

MANIFEST="${1:?usage: verify-release-manifest.sh <manifest.yaml> [<sig> <cert>]}"
SIG="${2:-${MANIFEST}.sig}"
CERT="${3:-${MANIFEST}.pem}"
ROLE="${EXPECTED_ROLE:-rc-publisher}"

[ -f "$MANIFEST" ] || die "manifest not found: $MANIFEST"

# 1. checksum
if [ -f "${MANIFEST}.sha256" ]; then
  want="$(awk '{print $1}' "${MANIFEST}.sha256")"
  got="$(checksum_file "$MANIFEST")"
  [ "$want" = "$got" ] || die "checksum mismatch: $got != $want"
  log "checksum OK"
fi

# 2. signature
if command -v cosign >/dev/null 2>&1 && [ "${LOCAL:-0}" != 1 ]; then
  [ -f "$SIG" ]  || die "signature not found: $SIG"
  [ -f "$CERT" ] || die "certificate not found: $CERT"
  cosign verify-blob \
    --certificate "$CERT" --signature "$SIG" \
    --certificate-identity-regexp "$(identity_re_for_role "$ROLE")" \
    --certificate-oidc-issuer "$(issuer_from_policy)" \
    "$MANIFEST" >/dev/null || die "manifest signature verification failed"
  log "signature OK (role $ROLE)"
else
  warn "LOCAL/cosign-absent: skipping signature verification"
fi

# 3. schema + policy
bash "$_d/validate-release-manifest.sh" "$MANIFEST"
log "manifest verified: $MANIFEST"
