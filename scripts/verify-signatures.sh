#!/usr/bin/env bash
# Verify Cosign keyless signatures + SBOM attestations for platform images.
# Usage: scripts/verify-signatures.sh ghcr.io/zenchron-dynamics/php-fpm:8.3-prod
set -euo pipefail

IDENTITY_RE="${IDENTITY_RE:-https://github.com/zenchron-dynamics/docker-platform/.*}"
ISSUER="${ISSUER:-https://token.actions.githubusercontent.com}"

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <image-ref> [<image-ref> ...]"
    exit 2
fi

for image in "$@"; do
    echo "==> verify signature: $image"
    cosign verify \
        --certificate-identity-regexp "$IDENTITY_RE" \
        --certificate-oidc-issuer "$ISSUER" \
        "$image" >/dev/null
    echo "    signature OK"

    echo "==> verify SBOM attestation: $image"
    if cosign verify-attestation --type spdxjson \
        --certificate-identity-regexp "$IDENTITY_RE" \
        --certificate-oidc-issuer "$ISSUER" \
        "$image" >/dev/null 2>&1; then
        echo "    attestation OK"
    else
        echo "    WARNING: no SBOM attestation found"
    fi
done
echo "==> Verification complete."
