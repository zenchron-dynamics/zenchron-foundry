#!/usr/bin/env bash
# =============================================================================
# verify-base-images.sh
# -----------------------------------------------------------------------------
# Verifies the approved base-image inventory (config/base-images.env) against:
#   1. The live registry: every <FAMILY>_VERSION (ref@digest) must resolve.
#   2. Multi-arch: linux/amd64 AND linux/arm64 manifests must both exist for
#      every family (caddy/alpine included). Fails if an arch silently vanishes.
#   3. The Dockerfiles: no active `ARG *_BASE=` under images/ may point at a
#      digest that differs from the approved one in the inventory.
#
# Docker handling:
#   - If docker is unavailable, exit 0 with "SKIPPED" ONLY when LOCAL=1.
#     Otherwise (CI/release context) this is a hard failure (exit nonzero).
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ROOT}/config/base-images.env"
LOCAL="${LOCAL:-0}"

pass_count=0
fail_count=0

pass() { printf 'PASS: %s\n' "$1"; pass_count=$((pass_count + 1)); }
fail() { printf 'FAIL: %s\n' "$1"; fail_count=$((fail_count + 1)); }

if [[ ! -f "${ENV_FILE}" ]]; then
  printf 'FAIL: inventory not found: %s\n' "${ENV_FILE}" >&2
  exit 1
fi

# --- docker availability gate -------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
  if [[ "${LOCAL}" == "1" ]]; then
    echo "SKIPPED: docker not available"
    exit 0
  fi
  echo "FAIL: docker not available (set LOCAL=1 to skip outside CI/release)" >&2
  exit 1
fi

# --- load inventory -----------------------------------------------------------
set -a
# shellcheck source=/dev/null
. "${ENV_FILE}"
set +a

# Logical families. *_VERSION holds ref@digest; *_ARCHES the expected platforms.
FAMILIES=(
  PHP_CLI_83 PHP_CLI_84
  PHP_FPM_83 PHP_FPM_84
  PHP_WORKER_83 PHP_WORKER_84
  FRANKENPHP_83 FRANKENPHP_84
  NGINX CADDY
)

# Choose an inspection backend that emits the platform list, normalised to
# "os/arch" lines (the optional /vN variant suffix is dropped so e.g.
# linux/arm/v7 does not masquerade as a missing arch match target).
inspect_platforms() {
  local ref="$1"
  if command -v docker >/dev/null 2>&1 \
     && docker buildx imagetools inspect "${ref}" >/dev/null 2>&1; then
    # Human-readable output lists "Platform:    linux/amd64" per manifest.
    docker buildx imagetools inspect "${ref}" 2>/dev/null \
      | sed -nE 's/.*Platform:[[:space:]]*([a-z0-9]+\/[a-z0-9]+).*/\1/p'
  else
    # Fallback: manifest list JSON -> os + architecture pairs.
    docker manifest inspect "${ref}" 2>/dev/null \
      | tr -d ' \n' \
      | grep -oE '"architecture":"[^"]+","os":"[^"]+"' \
      | sed -E 's/"architecture":"([^"]+)","os":"([^"]+)"/\2\/\1/'
  fi
}

echo "=== Registry + multi-arch verification ==="
for fam in "${FAMILIES[@]}"; do
  ref_var="${fam}_VERSION"
  arch_var="${fam}_ARCHES"
  ref="${!ref_var:-}"
  arches="${!arch_var:-}"

  if [[ -z "${ref}" ]]; then
    fail "${fam}: missing ${ref_var} in inventory"
    continue
  fi

  if ! docker buildx imagetools inspect "${ref}" >/dev/null 2>&1 \
     && ! docker manifest inspect "${ref}" >/dev/null 2>&1; then
    fail "${fam}: digest ref does not resolve: ${ref}"
    continue
  fi

  platforms="$(inspect_platforms "${ref}" || true)"
  missing=""
  for want in ${arches}; do
    if ! grep -qx "${want}" <<<"${platforms}"; then
      missing="${missing} ${want}"
    fi
  done

  if [[ -n "${missing}" ]]; then
    fail "${fam}: missing arch(es):${missing} (resolved: $(tr '\n' ' ' <<<"${platforms}"))"
  else
    pass "${fam}: resolves with arches [${arches}]"
  fi
done

# --- Dockerfile digest drift check -------------------------------------------
echo
echo "=== Dockerfile digest drift check ==="
while IFS= read -r line; do
  file="${line%%:*}"
  rest="${line#*:}"
  lineno="${rest%%:*}"
  content="${rest#*:}"

  # Extract ref@digest from: ARG NAME="ref@sha256:..."  (quotes optional)
  df_ref="$(sed -E 's/.*ARG[[:space:]]+[A-Z0-9_]+=//; s/^"//; s/"$//' <<<"${content}")"
  df_digest="${df_ref##*@}"

  if [[ "${df_digest}" != sha256:* ]]; then
    fail "${file}:${lineno}: base is not digest-pinned: ${df_ref}"
    continue
  fi

  # Match this digest against any approved family digest.
  approved=0
  for fam in "${FAMILIES[@]}"; do
    dig_var="${fam}_DIGEST"
    if [[ "${df_digest}" == "${!dig_var:-}" ]]; then
      approved=1
      break
    fi
  done

  if [[ "${approved}" == "1" ]]; then
    pass "${file}:${lineno}: digest approved (${df_digest})"
  else
    fail "${file}:${lineno}: digest NOT in inventory: ${df_ref}"
  fi
done < <(grep -rnE 'ARG[[:space:]]+[A-Z0-9_]+_BASE=' "${ROOT}/images")

# --- summary -----------------------------------------------------------------
echo
echo "=== Summary ==="
printf 'PASS=%d FAIL=%d\n' "${pass_count}" "${fail_count}"
if [[ "${fail_count}" -gt 0 ]]; then
  echo "RESULT: FAIL"
  exit 1
fi
echo "RESULT: PASS"
