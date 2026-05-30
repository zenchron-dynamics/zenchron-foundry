#!/usr/bin/env bash
# Scan one or all images with Trivy + Grype. Fails on CRITICAL/HIGH (supported).
# Usage: IMAGE=ghcr.io/.../php-fpm:8.3-prod scripts/scan-all.sh
#        scripts/scan-all.sh   # scans the default supported set
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
OUT="${OUT:-artifacts/scan}"; mkdir -p "$OUT"

scan_one() {
    local image="$1" name
    name="$(echo "$image" | tr '/:@' '___')"
    echo "==> Trivy: $image"
    trivy image \
        --severity CRITICAL,HIGH \
        --exit-code 1 \
        --ignorefile policies/.trivyignore \
        --format json --output "${OUT}/${name}.trivy.json" \
        "$image" || { echo "Trivy gate FAILED for $image"; return 1; }

    echo "==> Grype: $image"
    grype "$image" \
        --config policies/grype.yaml \
        --fail-on high \
        -o json --file "${OUT}/${name}.grype.json" || { echo "Grype gate FAILED for $image"; return 1; }
}

if [ -n "${IMAGE:-}" ]; then
    scan_one "$IMAGE"
else
    NS="${REGISTRY:-ghcr.io}/${NAMESPACE:-zenchron-dynamics}"
    for ref in php-fpm:8.3-prod php-cli:8.3-prod php-worker:8.3-prod \
               php-frankenphp:8.3-prod caddy:prod nginx:prod; do
        scan_one "${NS}/${ref}"
    done
fi
echo "==> Scans complete. Reports in ${OUT}/"
