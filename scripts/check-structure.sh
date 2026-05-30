#!/usr/bin/env bash
# Verify the required repository layout exists. Used by ci.yml and `make check-structure`.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

required_dirs=(
    images/php-fpm/7.4 images/php-fpm/8.0 images/php-fpm/8.3 images/php-fpm/8.4
    images/php-cli/8.3 images/php-worker/8.3
    images/php-frankenphp/8.3 images/php-frankenphp/8.4
    images/caddy/conf.d images/nginx/conf.d
    profiles policies/semgrep scripts docs examples
    .github/workflows
)
required_files=(
    README.md SECURITY.md CONTRIBUTING.md CHANGELOG.md LICENSE CODEOWNERS
    Makefile .pre-commit-config.yaml .gitignore .gitattributes .editorconfig
    .github/dependabot.yml
    images/php-fpm/8.3/Dockerfile images/php-fpm/8.3/php.ini
    images/php-fpm/8.3/php-fpm.conf images/php-fpm/8.3/www.conf
    images/php-cli/8.3/Dockerfile images/php-worker/8.3/Dockerfile
    images/php-frankenphp/8.3/Dockerfile images/php-frankenphp/8.3/Caddyfile
    images/caddy/Dockerfile images/caddy/Caddyfile
    images/nginx/Dockerfile images/nginx/nginx.conf
    profiles/compose.security.yml profiles/compose.readonly.yml
    policies/trivy.yaml policies/grype.yaml policies/syft.yaml
    policies/hadolint.yaml policies/gitleaks.toml
    policies/semgrep/docker-security.yml policies/cosign-policy.md
)

rc=0
for d in "${required_dirs[@]}";  do [ -d "$d" ] || { echo "MISSING dir:  $d"; rc=1; }; done
for f in "${required_files[@]}"; do [ -f "$f" ] || { echo "MISSING file: $f"; rc=1; }; done

# Guardrail: no final-stage root user in any image Dockerfile.
while IFS= read -r -d '' df; do
    grep -q '^USER ' "$df" || { echo "NO USER directive: $df"; rc=1; }
done < <(find images -name Dockerfile -print0)

[ "$rc" -eq 0 ] && echo "==> Structure OK." || echo "==> Structure check FAILED."
exit "$rc"
