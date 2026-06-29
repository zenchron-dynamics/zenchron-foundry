#!/usr/bin/env bash
# =============================================================================
# Zenchron Dynamics — smoke-test dispatcher.
# Usage: scripts/smoke-test.sh <family> <version>
#   family  : php-cli | php-fpm | php-worker | php-frankenphp | nginx | caddy
#   version : 8.3 | 8.4   (required for php-* families; ignored for nginx/caddy)
#
# Maps (family,version) to a build context and a per-family smoke script, builds
# the image on demand if it is not already present, then runs the smoke script
# against the built reference.
#
# Image ref convention: zenchron/<family>:smoke for the version-less families and
# zenchron/<family>:<version>-smoke for the PHP families (so 8.3 and 8.4 do not
# collide when both are tested).
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

FAMILY="${1:-}"
VERSION="${2:-}"

if [ -z "$FAMILY" ]; then
    printf 'usage: %s <family> <version>\n' "$(basename "$0")" >&2
    printf '  family: php-cli|php-fpm|php-worker|php-frankenphp|nginx|caddy\n' >&2
    exit 2
fi

case "$FAMILY" in
    php-cli|php-fpm|php-worker|php-frankenphp)
        if [ -z "$VERSION" ]; then
            printf 'error: family %s requires a version (8.3|8.4)\n' "$FAMILY" >&2
            exit 2
        fi
        CONTEXT="images/${FAMILY}/${VERSION}"
        REF="zenchron/${FAMILY}:${VERSION}-smoke"
        ;;
    nginx|caddy)
        CONTEXT="images/${FAMILY}"
        REF="zenchron/${FAMILY}:smoke"
        ;;
    *)
        printf 'error: unknown family %s\n' "$FAMILY" >&2
        exit 2
        ;;
esac

# Script basename matches the family uniformly: smoke-<family>.sh
SCRIPT_NAME="smoke-${FAMILY}.sh"

SCRIPT="${ROOT}/scripts/smoke/${SCRIPT_NAME}"

if [ ! -f "$SCRIPT" ]; then
    printf 'error: smoke script not found: %s\n' "$SCRIPT" >&2
    exit 2
fi
if [ ! -d "$CONTEXT" ]; then
    printf 'error: build context not found: %s\n' "$CONTEXT" >&2
    exit 2
fi

# Build on demand if the image is not already present locally.
if docker image inspect "$REF" >/dev/null 2>&1; then
    printf '==> using existing image %s\n' "$REF"
else
    VCS_REF="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
    BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '==> building %s from %s\n' "$REF" "$CONTEXT"
    docker build \
        --build-arg "BUILD_DATE=${BUILD_DATE}" \
        --build-arg "VCS_REF=${VCS_REF}" \
        -t "$REF" "$CONTEXT"
fi

printf '==> running %s %s\n' "$SCRIPT" "$REF"
exec "$SCRIPT" "$REF"
