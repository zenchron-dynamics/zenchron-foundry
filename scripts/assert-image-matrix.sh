#!/usr/bin/env bash
# =============================================================================
# assert-image-matrix.sh
# -----------------------------------------------------------------------------
# self-test: waived (thin wrapper; exercised by the "image matrix (14/14)" gate
# in scripts/macro-validate.sh, ci.yml, and tests/lib/test_foundations.sh's
# matrix drift-guard)
#
# Asserts the production image matrix — derived from MATRIX_IMAGES in
# scripts/lib/common.sh, the ONE authoritative definition — is exactly the
# expected images, each backed by a Dockerfile on disk:
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
# shellcheck source=lib/common.sh
. "$ROOT/scripts/lib/common.sh"

IMAGES="${ROOT}/images"

# Expected Dockerfile list, derived from the authoritative matrix:
# <family>:<selector> -> family/selector/Dockerfile (family/Dockerfile for the
# versionless "prod" edge images). No local copy of the matrix (SC-07).
EXPECTED=()
while IFS= read -r token; do
  [ -n "$token" ] || continue
  fam="${token%:*}"; sel="${token#*:}"
  case "$sel" in
    prod) EXPECTED+=("${fam}/Dockerfile") ;;
    *)    EXPECTED+=("${fam}/${sel}/Dockerfile") ;;
  esac
done < <(matrix_images)

# INTENTIONAL independent count assertion: the literal 14 is NOT taken from
# MATRIX_COUNT, so an accidental edit shrinking/growing MATRIX_IMAGES is caught
# here instead of silently re-baselining the gate.
if [[ "${#EXPECTED[@]}" -ne 14 ]]; then
  die "matrix derived ${#EXPECTED[@]} images, expected exactly 14 — MATRIX_IMAGES drifted"
fi

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
printf 'FOUND=%d/%d MISSING=%d FORBIDDEN=%d\n' "${found}" "${MATRIX_COUNT}" "${missing}" "${forbidden}"

if [[ "${missing}" -gt 0 || "${forbidden}" -gt 0 ]]; then
  echo "RESULT: FAIL"
  exit 1
fi

echo "MATRIX OK: ${found}/${MATRIX_COUNT}"
