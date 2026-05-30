#!/usr/bin/env bash
# Generate SBOMs (SPDX + CycloneDX) for an image using Syft.
# Usage: IMAGE=ghcr.io/.../php-fpm:8.3-prod scripts/generate-sbom.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
OUT="${OUT:-artifacts/sbom}"; mkdir -p "$OUT"

: "${IMAGE:?Set IMAGE=ghcr.io/.../name:tag}"
NAME="$(echo "$IMAGE" | tr '/:@' '___')"

echo "==> Syft SBOM (SPDX): $IMAGE"
syft "$IMAGE" -c policies/syft.yaml -o "spdx-json=${OUT}/${NAME}.spdx.json"
echo "==> Syft SBOM (CycloneDX): $IMAGE"
syft "$IMAGE" -c policies/syft.yaml -o "cyclonedx-json=${OUT}/${NAME}.cdx.json"

( cd "$OUT" && sha256sum "${NAME}".*.json >> checksums.txt )
echo "==> SBOMs written to ${OUT}/"
