#!/usr/bin/env bash
# =============================================================================
# Zenchron Dynamics — release safety script (free-tier compensating control).
#
# This is a compensating control, not equivalent to enforced GitHub branch
# protection. GitHub Free private repos cannot protect tags, so this script
# gates release-tag creation locally: it runs CI-equivalent checks, refuses on a
# red master CI, validates the tag format, and never pushes without explicit
# confirmation.
#
# Usage:
#   scripts/prepare-release.sh [--dry-run] vYYYY.MM.DD
# Examples:
#   scripts/prepare-release.sh --dry-run v2026.06.01
#   scripts/prepare-release.sh v2026.06.01
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

DRY_RUN=0
TAG=""
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
        *) TAG="$arg" ;;
    esac
done

die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
ok()   { printf '  ✓ %s\n' "$*"; }
step() { printf '\n==> %s\n' "$*"; }

[ -n "$TAG" ] || die "no tag given. Usage: scripts/prepare-release.sh [--dry-run] vYYYY.MM.DD"

# --- Tag format ------------------------------------------------------------
step "Validating release tag '$TAG'"
[ "$TAG" != "latest" ] || die "'latest' is never a release tag."
case "$TAG" in
    latest|*latest*) die "refusing tag containing 'latest'." ;;
esac
echo "$TAG" | grep -Eq '^v[0-9]{4}\.[0-9]{2}\.[0-9]{2}$' \
    || die "tag must match vYYYY.MM.DD (e.g. v2026.06.01). Got: $TAG"
ok "tag format ok"
if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
    die "tag $TAG already exists locally (immutable releases — pick a new date/suffix)."
fi

# --- Clean tree + branch ---------------------------------------------------
step "Checking working tree and branch"
[ -z "$(git status --porcelain)" ] || die "working tree is not clean. Commit or stash first."
ok "working tree clean"
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
[ "$BRANCH" = "master" ] || die "must release from 'master' (on '$BRANCH')."
ok "on master"

# --- CI status (gh) --------------------------------------------------------
step "Checking latest master CI (release blocked on red CI — docs/ci-failure-policy.md)"
if command -v gh >/dev/null 2>&1; then
    CONCL="$(gh run list --workflow ci.yml --branch master --limit 1 \
              --json conclusion -q '.[0].conclusion' 2>/dev/null || echo '')"
    case "$CONCL" in
        success) ok "latest master CI: success" ;;
        "")      echo "  ! could not read CI status (gh not authed?) — verify manually before releasing." ;;
        *)       die "latest master CI is '$CONCL', not success. Fix CI before releasing." ;;
    esac
else
    echo "  ! gh not installed — cannot verify CI status. Verify manually."
fi

# --- CI-equivalent local checks -------------------------------------------
step "Repository structure check"
bash scripts/check-structure.sh >/dev/null && ok "structure ok"

step "Shell syntax check (scripts + hooks + worker scripts)"
rc=0
syntax_check() {  # use the interpreter named in the shebang (bash vs POSIX sh)
    if head -1 "$1" | grep -q 'bash'; then bash -n "$1"; else sh -n "$1"; fi
}
while IFS= read -r f; do
    [ -n "$f" ] || continue
    syntax_check "$f" || { echo "  ✗ $f"; rc=1; }
done <<EOF
$(find scripts -type f \( -name '*.sh' -o -path 'scripts/git-hooks/*' \); find images/php-worker -name 'worker-*' -type f)
EOF
[ "$rc" -eq 0 ] && ok "shell syntax ok" || die "shell syntax errors above"

step "Docker compose config validation"
for p in examples/*/compose.yml; do
    docker compose -f "$p" config -q && ok "compose ok: $p" || die "invalid compose: $p"
done

step "Optional: build representative images (if Docker available)"
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    for ctx in images/php-fpm/8.3 images/nginx images/caddy; do
        docker build -q "$ctx" >/dev/null && ok "build ok: $ctx"
    done
else
    echo "  ! Docker not available — skipping representative builds (CI covers them)."
fi

# --- Release commands ------------------------------------------------------
SHA="$(git rev-parse --short HEAD)"
step "Release plan for $TAG (commit $SHA)"
cat <<PLAN
  Exact commands this script will run on confirmation:

    git tag -a $TAG -m "Platform release $TAG"
    ALLOW_RELEASE_TAG_PUSH=1 git push origin $TAG

  Pushing the tag triggers release.yml -> publish-ghcr.yml (build, push, cosign
  sign, SBOM attest) and creates the GitHub Release.
PLAN

if [ "$DRY_RUN" -eq 1 ]; then
    step "DRY RUN — no tag created, nothing pushed."
    exit 0
fi

# --- Explicit confirmation (no push by default) ----------------------------
step "Confirmation required"
printf 'Create tag %s at %s? [type the tag to confirm]: ' "$TAG" "$SHA"
read -r CONFIRM
[ "$CONFIRM" = "$TAG" ] || die "confirmation did not match. Aborted. No tag created."

git tag -a "$TAG" -m "Platform release $TAG"
ok "created local tag $TAG"

printf 'Push %s to origin now (triggers publish + signing)? [yes/NO]: ' "$TAG"
read -r PUSH
if [ "$PUSH" = "yes" ]; then
    ALLOW_RELEASE_TAG_PUSH=1 git push origin "$TAG"
    ok "pushed $TAG — watch release.yml in GitHub Actions"
else
    echo "  Tag created locally but NOT pushed. To push later:"
    echo "    ALLOW_RELEASE_TAG_PUSH=1 git push origin $TAG"
fi
