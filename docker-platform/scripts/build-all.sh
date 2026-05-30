#!/usr/bin/env bash
# Build all platform images locally with Buildx.
# Usage: scripts/build-all.sh [PHP_VERSIONS...]   (default: 8.3 8.4)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

REGISTRY="${REGISTRY:-ghcr.io}"
NAMESPACE="${NAMESPACE:-zenchron-dynamics}"
PLATFORMS="${PLATFORMS:-linux/amd64}"
VCS_REF="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
PHP_VERSIONS=("${@:-}")
[ -z "${PHP_VERSIONS[0]:-}" ] && PHP_VERSIONS=(8.3 8.4)

build() {  # build <context> <image:tag>
    local ctx="$1" ref="$2"
    echo "==> build ${ref}  (${ctx})"
    docker buildx build \
        --platform "${PLATFORMS}" \
        --build-arg "BUILD_DATE=${BUILD_DATE}" \
        --build-arg "VCS_REF=${VCS_REF}" \
        --label "org.opencontainers.image.created=${BUILD_DATE}" \
        --label "org.opencontainers.image.revision=${VCS_REF}" \
        -t "${ref}" --load "${ctx}"
}

for v in "${PHP_VERSIONS[@]}"; do
    for fam in php-fpm php-cli php-worker; do
        build "images/${fam}/${v}" "${REGISTRY}/${NAMESPACE}/${fam}:${v}-prod"
    done
    if [ -d "images/php-frankenphp/${v}" ]; then
        build "images/php-frankenphp/${v}" "${REGISTRY}/${NAMESPACE}/php-frankenphp:${v}-prod"
    fi
done

build "images/caddy" "${REGISTRY}/${NAMESPACE}/caddy:prod"
build "images/nginx" "${REGISTRY}/${NAMESPACE}/nginx:prod"

echo "==> All builds complete."
