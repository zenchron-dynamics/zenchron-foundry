#!/usr/bin/env bash
# Push platform images to GHCR. Normally CI-only (publish-ghcr.yml).
# Requires an existing `docker login ghcr.io`. Refuses to run without confirmation.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
REGISTRY="${REGISTRY:-ghcr.io}"
NAMESPACE="${NAMESPACE:-zenchron-dynamics}"
PHP_VERSIONS=("${@:-}")
[ -z "${PHP_VERSIONS[0]:-}" ] && PHP_VERSIONS=(8.3 8.4)

if [ "${I_UNDERSTAND_THIS_PUSHES:-no}" != "yes" ]; then
    echo "Refusing to push. Re-run with I_UNDERSTAND_THIS_PUSHES=yes"
    echo "Production publishing should go through CI (.github/workflows/publish-ghcr.yml)."
    exit 1
fi

push() { echo "==> push $1"; docker push "$1"; }

for v in "${PHP_VERSIONS[@]}"; do
    for fam in php-fpm php-cli php-worker; do
        push "${REGISTRY}/${NAMESPACE}/${fam}:${v}-prod"
    done
    docker image inspect "${REGISTRY}/${NAMESPACE}/php-frankenphp:${v}-prod" >/dev/null 2>&1 \
        && push "${REGISTRY}/${NAMESPACE}/php-frankenphp:${v}-prod" || true
done
push "${REGISTRY}/${NAMESPACE}/caddy:prod"
push "${REGISTRY}/${NAMESPACE}/nginx:prod"
echo "==> Push complete. Remember: signatures + SBOM attestations happen in CI."
