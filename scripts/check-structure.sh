#!/usr/bin/env bash
# Verify the required repository layout exists. Used by ci.yml and `make check-structure`.
# Debian-first layout (ADR-0001): supported PHP lines are 8.3 and 8.4 only.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

required_dirs=(
    images/php-fpm/8.3 images/php-fpm/8.4
    images/php-cli/8.3 images/php-cli/8.4
    images/php-worker/8.3 images/php-worker/8.4
    images/php-frankenphp/8.3 images/php-frankenphp/8.4
    images/caddy/conf.d images/nginx/conf.d
    profiles policies/semgrep scripts docs examples
    .github/workflows
)
required_files=(
    README.md SECURITY.md CONTRIBUTING.md CHANGELOG.md LICENSE CODEOWNERS
    Makefile .pre-commit-config.yaml .gitignore .gitattributes .editorconfig
    .github/dependabot.yml
    images/php-fpm/8.4/Dockerfile images/php-fpm/8.4/php.ini
    images/php-fpm/8.4/php-fpm.conf images/php-fpm/8.4/www.conf
    images/php-cli/8.4/Dockerfile images/php-worker/8.4/Dockerfile
    images/php-frankenphp/8.4/Dockerfile images/php-frankenphp/8.4/Caddyfile
    images/caddy/Dockerfile images/caddy/Caddyfile
    images/nginx/Dockerfile images/nginx/nginx.conf
    profiles/compose.security.yml profiles/compose.readonly.yml
    policies/trivy.yaml policies/grype.yaml policies/syft.yaml
    policies/hadolint.yaml policies/gitleaks.toml
    policies/semgrep/docker-security.yml policies/cosign-policy.md
    scripts/assert-no-wolfi.sh
)

rc=0
for d in "${required_dirs[@]}";  do [ -d "$d" ] || { echo "MISSING dir:  $d"; rc=1; }; done
for f in "${required_files[@]}"; do [ -f "$f" ] || { echo "MISSING file: $f"; rc=1; }; done

# Guardrail: no final-stage root user in any image Dockerfile.
while IFS= read -r -d '' df; do
    grep -q '^USER ' "$df" || { echo "NO USER directive: $df"; rc=1; }
done < <(find images -name Dockerfile -print0)

# Guardrail: every base reference must be digest-pinned (@sha256:) and must not
# rely on a moving tag. We look at base-image ARG declarations (the single source
# of truth each Dockerfile FROMs). See docs/base-image-strategy.md.
while IFS= read -r -d '' df; do
    while IFS= read -r line; do
        case "$line" in
            *_BASE=*)
                printf '%s' "$line" | grep -q '@sha256:' || { echo "UNPINNED base (no @sha256): $df -> $line"; rc=1; }
                printf '%s' "$line" | grep -Eq ':latest@|:latest"' && { echo "MOVING 'latest' base: $df -> $line"; rc=1; }
                ;;
        esac
    done < <(grep -E '^ARG[[:space:]]+[A-Z_]*BASE=' "$df" || true)
done < <(find images -name Dockerfile -print0)

[ "$rc" -eq 0 ] && echo "==> Structure OK." || echo "==> Structure check FAILED."
exit "$rc"
