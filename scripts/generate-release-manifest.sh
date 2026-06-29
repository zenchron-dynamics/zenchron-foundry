#!/usr/bin/env bash
# =============================================================================
# Zenchron Dynamics — release manifest generator.
#
# Emits a YAML release manifest (to stdout, and to
# release-artifacts/release-manifest.yaml when that directory exists) that
# records, for each of the 10 canonical images, its registry index digest and
# whether it is signed / has an SBOM attestation / has a SLSA provenance
# attestation.
#
# Usage:
#   scripts/generate-release-manifest.sh <release-version> [--created-at <ts>]
#
# Env overrides:
#   REGISTRY          (default: ghcr.io)
#   NAMESPACE         (default: zenchron-dynamics)
#   IDENTITY_RE       (default: https://github.com/zenchron-dynamics/zenchron-foundry/.*)
#   ISSUER            (default: https://token.actions.githubusercontent.com)
#   GITHUB_REF_NAME   used as source_ref when no positional release tag arg
#   SOURCE_DATE_EPOCH used for created_at (deterministic) if set
#   LOCAL=1           tolerate an unreachable registry: emit digest "UNRESOLVED",
#                     booleans false, warn on stderr (default/strict: hard fail
#                     if any digest cannot be resolved)
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

REGISTRY="${REGISTRY:-ghcr.io}"
NAMESPACE="${NAMESPACE:-zenchron-dynamics}"
IDENTITY_RE="${IDENTITY_RE:-https://github.com/zenchron-dynamics/zenchron-foundry/.*}"
ISSUER="${ISSUER:-https://token.actions.githubusercontent.com}"
LOCAL="${LOCAL:-0}"

# --- Args --------------------------------------------------------------------
RELEASE=""
CREATED_AT_ARG=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --created-at)
            shift
            [ "$#" -gt 0 ] || { echo "ERROR: --created-at needs a value" >&2; exit 2; }
            CREATED_AT_ARG="$1"
            ;;
        -h|--help)
            sed -n '2,28p' "$0"
            exit 0
            ;;
        *)
            [ -z "$RELEASE" ] && RELEASE="$1" || { echo "ERROR: unexpected arg: $1" >&2; exit 2; }
            ;;
    esac
    shift
done

[ -n "$RELEASE" ] || { echo "ERROR: <release-version> is required" >&2; exit 2; }

REVISION="$(git rev-parse HEAD)"
SOURCE_REF="${RELEASE:-}"
[ -n "${GITHUB_REF_NAME:-}" ] && SOURCE_REF="${GITHUB_REF_NAME}"
[ -n "$SOURCE_REF" ] || SOURCE_REF="$RELEASE"

# --- created_at (prefer deterministic sources) -------------------------------
if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
    # date -u accepts epoch via -r on BSD/macOS and -d @ on GNU.
    if date -u -r "$SOURCE_DATE_EPOCH" +%FT%TZ >/dev/null 2>&1; then
        CREATED_AT="$(date -u -r "$SOURCE_DATE_EPOCH" +%FT%TZ)"
    else
        CREATED_AT="$(date -u -d "@$SOURCE_DATE_EPOCH" +%FT%TZ)"
    fi
elif [ -n "$CREATED_AT_ARG" ]; then
    CREATED_AT="$CREATED_AT_ARG"
else
    CREATED_AT="$(date -u +%FT%TZ)"
fi

# --- Tooling -----------------------------------------------------------------
HAVE_COSIGN=0
HAVE_BUILDX=0
HAVE_CRANE=0
command -v cosign >/dev/null 2>&1 && HAVE_COSIGN=1
docker buildx version >/dev/null 2>&1 && HAVE_BUILDX=1
command -v crane >/dev/null 2>&1 && HAVE_CRANE=1

# Canonical images: "manifest-key|image:tag"
IMAGES=(
    "php-cli-8.3|php-cli:8.3-prod"
    "php-cli-8.4|php-cli:8.4-prod"
    "php-fpm-8.3|php-fpm:8.3-prod"
    "php-fpm-8.4|php-fpm:8.4-prod"
    "php-worker-8.3|php-worker:8.3-prod"
    "php-worker-8.4|php-worker:8.4-prod"
    "php-frankenphp-8.3|php-frankenphp:8.3-prod"
    "php-frankenphp-8.4|php-frankenphp:8.4-prod"
    "caddy|caddy:prod"
    "nginx|nginx:prod"
)

# --- Helpers -----------------------------------------------------------------
resolve_digest() {
    ref="$1"
    if [ "$HAVE_CRANE" -eq 1 ]; then
        crane digest "$ref" 2>/dev/null && return 0
    fi
    if [ "$HAVE_BUILDX" -eq 1 ]; then
        docker buildx imagetools inspect "$ref" --format '{{json .Manifest}}' 2>/dev/null \
            | grep -Eo '"digest"[[:space:]]*:[[:space:]]*"sha256:[0-9a-f]+"' \
            | head -1 \
            | grep -Eo 'sha256:[0-9a-f]+' && return 0
    fi
    return 1
}

verify_signature() {
    [ "$HAVE_COSIGN" -eq 1 ] || return 1
    cosign verify \
        --certificate-identity-regexp "$IDENTITY_RE" \
        --certificate-oidc-issuer "$ISSUER" \
        "$1" >/dev/null 2>&1
}

verify_attestation() {
    [ "$HAVE_COSIGN" -eq 1 ] || return 1
    cosign verify-attestation --type "$2" \
        --certificate-identity-regexp "$IDENTITY_RE" \
        --certificate-oidc-issuer "$ISSUER" \
        "$1" >/dev/null 2>&1
}

# --- Build manifest ----------------------------------------------------------
unresolved=0
manifest=""

manifest="${manifest}release: ${RELEASE}
revision: ${REVISION}
source_ref: ${SOURCE_REF}
created_at: ${CREATED_AT}
images:
"

for entry in "${IMAGES[@]}"; do
    key="${entry%%|*}"
    imgtag="${entry##*|}"
    ref="${REGISTRY}/${NAMESPACE}/${imgtag}"

    digest="$(resolve_digest "$ref" || true)"
    signed="false"
    sbom="false"
    provenance="false"

    if [ -z "$digest" ]; then
        unresolved=$((unresolved + 1))
        if [ "$LOCAL" = "1" ]; then
            echo "WARNING: could not resolve digest for ${ref} (LOCAL=1) — marking UNRESOLVED" >&2
            digest="UNRESOLVED"
        else
            echo "ERROR: could not resolve index digest for ${ref} (strict mode)." >&2
            echo "       Ensure the registry is reachable and you are authenticated," >&2
            echo "       or set LOCAL=1 for offline manifest generation." >&2
            exit 1
        fi
    else
        vref="${ref}@${digest}"
        verify_signature "$vref" && signed="true"
        verify_attestation "$vref" "spdxjson" && sbom="true"
        if verify_attestation "$vref" "slsaprovenance" \
            || verify_attestation "$vref" "slsaprovenance1"; then
            provenance="true"
        fi
    fi

    manifest="${manifest}  ${key}:
    ref: ${ref}@${digest}
    platforms: [linux/amd64, linux/arm64]
    signed: ${signed}
    sbom: ${sbom}
    provenance: ${provenance}
"
done

# --- Emit --------------------------------------------------------------------
printf '%s' "$manifest"

if [ -d "release-artifacts" ]; then
    printf '%s' "$manifest" > "release-artifacts/release-manifest.yaml"
    echo "Wrote release-artifacts/release-manifest.yaml" >&2
fi

if [ "$unresolved" -gt 0 ] && [ "$LOCAL" = "1" ]; then
    echo "WARNING: ${unresolved} image digest(s) UNRESOLVED (LOCAL mode)." >&2
fi
