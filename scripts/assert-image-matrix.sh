#!/usr/bin/env bash
# =============================================================================
# assert-image-matrix.sh
# -----------------------------------------------------------------------------
# Asserts the production image matrix is exactly the expected 10 images, each
# backed by a Dockerfile on disk:
#
#   php-cli/8.3        php-cli/8.4
#   php-fpm/8.3        php-fpm/8.4
#   php-worker/8.3     php-worker/8.4
#   php-frankenphp/8.3 php-frankenphp/8.4
#   nginx              caddy
#
# Also fails if any forbidden legacy PHP line is present (php-*/7.4, php-*/8.0).
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGES="${ROOT}/images"

EXPECTED=(
  "php-cli/8.3/Dockerfile"
  "php-cli/8.4/Dockerfile"
  "php-fpm/8.3/Dockerfile"
  "php-fpm/8.4/Dockerfile"
  "php-worker/8.3/Dockerfile"
  "php-worker/8.4/Dockerfile"
  "php-frankenphp/8.3/Dockerfile"
  "php-frankenphp/8.4/Dockerfile"
  "nginx/Dockerfile"
  "caddy/Dockerfile"
)

missing=0
found=0

echo "=== Required image matrix ==="
for rel in "${EXPECTED[@]}"; do
  if [[ -f "${IMAGES}/${rel}" ]]; then
    echo "OK:      images/${rel}"
    found=$((found + 1))
  else
    echo "MISSING: images/${rel}"
    missing=$((missing + 1))
  fi
done

echo
echo "=== Forbidden legacy lines ==="
forbidden=0
for legacy in 7.4 8.0; do
  while IFS= read -r dir; do
    echo "FORBIDDEN: ${dir#"${ROOT}/"}"
    forbidden=$((forbidden + 1))
  done < <(find "${IMAGES}" -type d -path "*/php-*/${legacy}" 2>/dev/null || true)
done
if [[ "${forbidden}" -eq 0 ]]; then
  echo "none"
fi

echo
echo "=== Summary ==="
printf 'FOUND=%d/10 MISSING=%d FORBIDDEN=%d\n' "${found}" "${missing}" "${forbidden}"

if [[ "${missing}" -gt 0 || "${forbidden}" -gt 0 ]]; then
  echo "RESULT: FAIL"
  exit 1
fi

echo "MATRIX OK: 10/10"
