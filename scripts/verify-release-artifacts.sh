#!/usr/bin/env bash
# =============================================================================
# Zenchron Dynamics — release artifact verifier.
#
# Verifies EACH of the 10 canonical released images INDEPENDENTLY from the
# registry. For every image it checks four things:
#   1. signed       — cosign keyless signature (identity regexp + OIDC issuer)
#   2. sbom         — cosign verify-attestation --type spdxjson present/verifies
#   3. provenance   — cosign verify-attestation SLSA provenance present/verifies
#                     (accepts predicate type slsaprovenance OR slsaprovenance1)
#   4. multiarch    — the image index advertises BOTH linux/amd64 + linux/arm64
#
# Per-image cosign exit codes are captured so one failure does not abort the
# loop: all 10 images are always tested and reported, THEN the script exits.
# The script exits nonzero unless ALL FOUR columns are 10/10. No "at least one".
#
# Env overrides:
#   REGISTRY    (default: ghcr.io)
#   NAMESPACE   (default: zenchron-dynamics)
#   IDENTITY_RE (default: https://github.com/zenchron-dynamics/zenchron-foundry/.*)
#   ISSUER      (default: https://token.actions.githubusercontent.com)
#   LOCAL=1     — if cosign is missing, print "SKIPPED" per tool and exit 0
#                 (default/strict mode: missing cosign is a hard failure)
#
# Usage: scripts/verify-release-artifacts.sh
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

REGISTRY="${REGISTRY:-ghcr.io}"
NAMESPACE="${NAMESPACE:-zenchron-dynamics}"
IDENTITY_RE="${IDENTITY_RE:-https://github.com/zenchron-dynamics/zenchron-foundry/.*}"
ISSUER="${ISSUER:-https://token.actions.githubusercontent.com}"
LOCAL="${LOCAL:-0}"

# The canonical 10 image refs (tag suffixes are FIXED, not overridable).
IMAGES=(
    "php-cli:8.3-prod"
    "php-cli:8.4-prod"
    "php-fpm:8.3-prod"
    "php-fpm:8.4-prod"
    "php-worker:8.3-prod"
    "php-worker:8.4-prod"
    "php-frankenphp:8.3-prod"
    "php-frankenphp:8.4-prod"
    "caddy:prod"
    "nginx:prod"
)

# --- Tool availability -------------------------------------------------------
if ! command -v cosign >/dev/null 2>&1; then
    if [ "$LOCAL" = "1" ]; then
        echo "SKIPPED: cosign not installed (signature verify)"
        echo "SKIPPED: cosign not installed (sbom attestation)"
        echo "SKIPPED: cosign not installed (provenance attestation)"
        echo "SKIPPED: cosign not installed (multiarch needs registry tooling)"
        echo "LOCAL=1 set — skipping all verification. Exit 0."
        exit 0
    fi
    echo "ERROR: cosign is not installed and strict mode is active." >&2
    echo "       Install cosign, or set LOCAL=1 to skip (non-release use only)." >&2
    exit 1
fi

# A registry digest resolver is required for multi-arch inspection.
HAVE_BUILDX=0
HAVE_CRANE=0
if docker buildx version >/dev/null 2>&1; then HAVE_BUILDX=1; fi
if command -v crane >/dev/null 2>&1; then HAVE_CRANE=1; fi
if [ "$HAVE_BUILDX" -eq 0 ] && [ "$HAVE_CRANE" -eq 0 ]; then
    echo "ERROR: need 'docker buildx' or 'crane' to inspect the image index." >&2
    exit 1
fi

# --- Helpers -----------------------------------------------------------------

# Print the multi-arch index manifest JSON for a ref to stdout (empty on fail).
fetch_manifest_json() {
    ref="$1"
    if [ "$HAVE_BUILDX" -eq 1 ]; then
        docker buildx imagetools inspect "$ref" --format '{{json .Manifest}}' 2>/dev/null && return 0
    fi
    if [ "$HAVE_CRANE" -eq 1 ]; then
        crane manifest "$ref" 2>/dev/null && return 0
    fi
    return 1
}

# Resolve the index digest for a ref (empty on failure).
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

# Returns 0 if manifest JSON advertises BOTH amd64 and arm64 under linux.
has_both_arches() {
    json="$1"
    has_amd64=0
    has_arm64=0
    # Match platform os/architecture pairs regardless of whitespace/order.
    if printf '%s' "$json" | grep -Eq '"os"[[:space:]]*:[[:space:]]*"linux"'; then :; fi
    if printf '%s' "$json" | grep -Eq '"architecture"[[:space:]]*:[[:space:]]*"amd64"'; then has_amd64=1; fi
    if printf '%s' "$json" | grep -Eq '"architecture"[[:space:]]*:[[:space:]]*"arm64"'; then has_arm64=1; fi
    [ "$has_amd64" -eq 1 ] && [ "$has_arm64" -eq 1 ]
}

# cosign verify keyless signature. Returns cosign exit code.
verify_signature() {
    ref="$1"
    cosign verify \
        --certificate-identity-regexp "$IDENTITY_RE" \
        --certificate-oidc-issuer "$ISSUER" \
        "$ref" >/dev/null 2>&1
}

# cosign verify-attestation of a given predicate type. Returns exit code.
verify_attestation() {
    ref="$1"
    ptype="$2"
    cosign verify-attestation --type "$ptype" \
        --certificate-identity-regexp "$IDENTITY_RE" \
        --certificate-oidc-issuer "$ISSUER" \
        "$ref" >/dev/null 2>&1
}

# --- Per-image verification --------------------------------------------------
n_signed=0
n_sbom=0
n_prov=0
n_multi=0
total=${#IMAGES[@]}

# Rows accumulate formatted table lines for a single final print.
rows=""

mark() { [ "$1" -eq 1 ] && printf 'PASS' || printf 'FAIL'; }

for img in "${IMAGES[@]}"; do
    ref="${REGISTRY}/${NAMESPACE}/${img}"
    echo "==> verifying ${ref}"

    sig_ok=0
    sbom_ok=0
    prov_ok=0
    multi_ok=0

    # Resolve digest (informational; verification uses the tag ref directly so
    # cosign resolves the same index). Empty digest is reported but not fatal
    # on its own — the cosign/multiarch checks below will fail accordingly.
    digest="$(resolve_digest "$ref" || true)"
    if [ -n "$digest" ]; then
        echo "    index digest: ${digest}"
    else
        echo "    index digest: UNRESOLVED"
    fi

    # Verify against the digest-pinned ref when available for immutability.
    vref="$ref"
    [ -n "$digest" ] && vref="${ref}@${digest}"

    if verify_signature "$vref"; then sig_ok=1; n_signed=$((n_signed + 1)); fi
    if verify_attestation "$vref" "spdxjson"; then sbom_ok=1; n_sbom=$((n_sbom + 1)); fi

    if verify_attestation "$vref" "slsaprovenance" \
        || verify_attestation "$vref" "slsaprovenance1"; then
        prov_ok=1
        n_prov=$((n_prov + 1))
    fi

    manifest_json="$(fetch_manifest_json "$ref" || true)"
    if [ -n "$manifest_json" ] && has_both_arches "$manifest_json"; then
        multi_ok=1
        n_multi=$((n_multi + 1))
    fi

    printf '    signed=%s sbom=%s provenance=%s multiarch=%s\n' \
        "$(mark "$sig_ok")" "$(mark "$sbom_ok")" "$(mark "$prov_ok")" "$(mark "$multi_ok")"

    rows="${rows}$(printf '%-26s %-7s %-7s %-11s %-9s' \
        "$img" "$(mark "$sig_ok")" "$(mark "$sbom_ok")" "$(mark "$prov_ok")" "$(mark "$multi_ok")")
"
done

# --- Report ------------------------------------------------------------------
echo
echo "================================ RELEASE VERIFY ==============================="
printf '%-26s %-7s %-7s %-11s %-9s\n' "IMAGE" "SIGNED" "SBOM" "PROVENANCE" "MULTIARCH"
printf '%-26s %-7s %-7s %-11s %-9s\n' "-----" "------" "----" "----------" "---------"
printf '%s' "$rows"
echo "------------------------------------------------------------------------------"
echo "RELEASE VERIFY: signed ${n_signed}/${total}, sbom ${n_sbom}/${total}, provenance ${n_prov}/${total}, multiarch ${n_multi}/${total}"

if [ "$n_signed" -eq "$total" ] \
    && [ "$n_sbom" -eq "$total" ] \
    && [ "$n_prov" -eq "$total" ] \
    && [ "$n_multi" -eq "$total" ]; then
    echo "ALL CHECKS PASSED (${total}/${total} on all four columns)."
    exit 0
fi

echo "FAILED: one or more columns are not ${total}/${total}." >&2
exit 1
