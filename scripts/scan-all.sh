#!/usr/bin/env bash
# self-test: waived (thin wrapper; exercised by make scan / scan-local and scan-images.yml)
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
    # The global ignore file is retired (#102): it suppressed by advisory id
    # across every image. Trivy therefore reports the FULL CRITICAL/HIGH set
    # (--exit-code 0 so the scan is not the gate) and
    # scripts/reconcile-vulnerabilities.sh decides per image whether each
    # finding is governed — the same gate CI runs.
    echo "==> Trivy: $image"
    trivy image \
        --severity CRITICAL,HIGH \
        --exit-code 0 \
        --format json --output "${OUT}/${name}.trivy.json" \
        "$image" || { echo "Trivy scan FAILED for $image"; return 1; }
    if [ -n "${RECONCILE_FAMILY:-}" ]; then
        bash "$(dirname "$0")/reconcile-vulnerabilities.sh" \
            "${OUT}/${name}.trivy.json" "$RECONCILE_FAMILY" "${RECONCILE_VERSION:-}" \
            || { echo "Vulnerability gate FAILED for $image"; return 1; }
    else
        echo "    (set RECONCILE_FAMILY=<image-family> [RECONCILE_VERSION=<ver>] to apply the gate)"
    fi

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
