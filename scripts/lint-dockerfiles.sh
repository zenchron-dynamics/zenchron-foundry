#!/usr/bin/env bash
# Lint every Dockerfile with Hadolint using the platform policy.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! command -v hadolint >/dev/null 2>&1; then
    echo "hadolint not installed. See https://github.com/hadolint/hadolint"
    exit 1
fi

rc=0
while IFS= read -r -d '' df; do
    echo "==> hadolint $df"
    hadolint --config policies/hadolint.yaml "$df" || rc=1
done < <(find images examples -name Dockerfile -print0)

[ "$rc" -eq 0 ] && echo "==> Hadolint clean." || echo "==> Hadolint found issues."
exit "$rc"
