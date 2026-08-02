#!/usr/bin/env bash
# self-test: waived (thin wrapper; exercised by make scan / scan-local and scan-images.yml)
# Scan one or all images with Trivy + Grype. Fails on CRITICAL/HIGH (supported).
# Usage: IMAGE=ghcr.io/.../php-fpm:8.3-prod scripts/scan-all.sh
#        scripts/scan-all.sh   # scans the default supported set
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
OUT="${OUT:-artifacts/scan}"; mkdir -p "$OUT"

# _family_of / _version_of — derive the image family and version from a
# canonical reference, so every scanned image is reconciled against ITS OWN
# scope. A single global RECONCILE_FAMILY cannot be correct for a mixed loop.
_family_of() {
    case "$1" in
        *php-frankenphp*) printf 'php-frankenphp' ;;
        *php-worker*)     printf 'php-worker' ;;
        *php-fpm*)        printf 'php-fpm' ;;
        *php-cli*)        printf 'php-cli' ;;
        *nginx*)          printf 'nginx' ;;
        *caddy*)          printf 'caddy' ;;
        *)                printf '%s' "${RECONCILE_FAMILY:-}" ;;
    esac
}
_version_of() {
    case "$1" in
        *:8.3-*|*:8.3)  printf '8.3' ;;
        *:8.4-*|*:8.4)  printf '8.4' ;;
        *nginx*|*caddy*) printf 'prod' ;;
        *)              printf '%s' "${RECONCILE_VERSION:-}" ;;
    esac
}

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
    # ALWAYS reconcile. Making this conditional turned `make scan`, `make
    # scan-local` and `make ci-local STRICT=1` into report-only despite their
    # names — the Trivy step no longer gated and the script still exited 0.
    local fam ver
    fam="$(_family_of "$image")"; ver="$(_version_of "$image")"
    if [ -z "$fam" ]; then
        echo "REFUSE: cannot derive the image family from '$image'." >&2
        echo "        Pass IMAGE=<ref> with RECONCILE_FAMILY=<family> [RECONCILE_VERSION=<ver>]," >&2
        echo "        or use a canonical ghcr.io/zenchron-dynamics/<family>:<ver>-prod reference." >&2
        return 1
    fi
    # The architecture is DERIVED from the image, never assumed. Defaulting to
    # linux/amd64 labelled an arm64 scan as amd64 whenever this ran on an arm64
    # machine — the reconciliation would then be judged against, and recorded
    # as, evidence for an architecture that was not scanned. An exception
    # authorises only the architectures it was reconciled on, so a mislabelled
    # scan is how amd64-only evidence silently comes to "cover" arm64.
    local arch
    if [ -n "${SCAN_ARCH:-}" ]; then
        arch="$SCAN_ARCH"
    else
        local _os _a
        _os="$(docker image inspect --format '{{.Os}}' "$image" 2>/dev/null || true)"
        _a="$(docker image inspect --format '{{.Architecture}}' "$image" 2>/dev/null || true)"
        [ -n "$_os" ] && [ -n "$_a" ] || {
            echo "REFUSE: cannot read the architecture of '$image' from the local" >&2
            echo "        daemon, and refusing to guess. Pull the image, or set" >&2
            echo "        SCAN_ARCH=linux/<arch> explicitly." >&2
            return 1
        }
        arch="${_os}/${_a}"
    fi
    case "$arch" in
        */*) : ;;
        *) echo "REFUSE: SCAN_ARCH must be os/arch, got '$arch'" >&2; return 1 ;;
    esac
    echo "reconciling $image as $arch"
    bash "$(dirname "$0")/reconcile-vulnerabilities.sh" \
        "${OUT}/${name}.trivy.json" "$fam" "$ver" \
        --arch "$arch" \
        || { echo "Vulnerability gate FAILED for $image"; return 1; }

    # Grype is REPORT-ONLY and carries NO suppressions (#102). policies/grype.yaml
    # was an advisory-id-wide ignore list — the same global cross-image
    # suppression class this work removed for Trivy — and the validator only
    # proved an ignored id existed somewhere in the ledger, never that it was in
    # scope for THIS image. Running it without --config means nothing is
    # suppressed; Trivy plus per-image reconciliation is the sole enforcing gate.
    echo "==> Grype (report-only, no suppressions): $image"
    grype "$image" -o json --file "${OUT}/${name}.grype.json" \
        || { echo "Grype scan FAILED for $image"; return 1; }
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
