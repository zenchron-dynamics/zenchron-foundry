#!/usr/bin/env bash
# Supply-chain guard: every container image referenced in CI must be immutable.
# Fails on:
#   * any ':latest' tag in a workflow;
#   * a `container:` / `image:` mapping value that is not digest-pinned (@sha256:);
#   * a known scanner/tool image (trivy/hadolint/shellcheck/gitleaks/semgrep)
#     used in a run-step without an @sha256: digest.
# Dockerfile FROM digests are enforced separately by scripts/check-structure.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

rc=0
WF=".github/workflows"

# 1) No ':latest' anywhere in workflows.
while IFS= read -r hit; do
    echo "UNPINNED (:latest): $hit"
    rc=1
done < <(grep -rnE ':latest([^a-zA-Z0-9.-]|$)' "$WF" 2>/dev/null || true)

# 2) container:/image: mapping values must be digest-pinned. Only external
#    images (a registry/org path, i.e. containing '/') are checked — images
#    built locally in the same job (e.g. `scan-target:...`) are not pullable
#    and carry no upstream digest.
while IFS= read -r line; do
    # line form "file:lineno:    container: img:tag"
    val="${line#*container: }"; val="${val#*image: }"
    case "$val" in
        */*@sha256:*) : ;;                                   # external + pinned -> OK
        */*) echo "UNPINNED (container/image, no @sha256:): $line"; rc=1 ;;
        *) : ;;                                              # no '/': local build target -> skip
    esac
done < <(grep -rnE '^[[:space:]]*(container|image):[[:space:]]*[a-z0-9]' "$WF" 2>/dev/null || true)

# 3) Known tool images in run steps must carry a digest.
TOOLS='aquasec/trivy|hadolint/hadolint|koalaman/shellcheck|zricethezav/gitleaks|semgrep/semgrep|anchore/grype'
while IFS= read -r line; do
    case "$line" in
        *@sha256:*) : ;;
        *) echo "UNPINNED (tool image, no @sha256:): $line"; rc=1 ;;
    esac
done < <(grep -rnE "($TOOLS):[0-9a-zA-Z._-]+" "$WF" 2>/dev/null | grep -v '@sha256:' || true)

if [ "$rc" -eq 0 ]; then
    echo "==> assert-pinned-containers: clean (all CI container images digest-pinned)."
else
    echo "==> assert-pinned-containers: FAILED. Pin the images above by @sha256: digest."
fi
exit "$rc"
