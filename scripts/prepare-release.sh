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
#   scripts/prepare-release.sh [--dry-run] vYYYY.MM.DD[.N]
# Examples:
#   scripts/prepare-release.sh --dry-run v2026.06.01
#   scripts/prepare-release.sh v2026.06.01
#   scripts/prepare-release.sh v2026.06.01.1     # hotfix ordinal
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
# shellcheck source=lib/common.sh
. "$ROOT/scripts/lib/common.sh"

ok()   { printf '  ✓ %s\n' "$*"; }
step() { printf '\n==> %s\n' "$*"; }

# Format-only tag validation (shared regexes from common.sh — accepts the
# hotfix .N ordinal, same as check-promotion-ref.sh). die()s on any refusal.
validate_tag() {
    local tag="${1:-}"
    [ -n "$tag" ] || die "no tag given. Usage: scripts/prepare-release.sh [--dry-run] vYYYY.MM.DD[.N]"
    case "$tag" in
        latest|*latest*) die "refusing tag containing 'latest' — 'latest' is never a release tag." ;;
    esac
    require_calver "$tag"
}

# --- self-test ---------------------------------------------------------------
_pr_self_test() {
    local fail=0
    _t() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }
    _t "happy CalVer accepted"        '( validate_tag v2026.06.01 ) >/dev/null 2>&1'
    _t "hotfix .N accepted"           '( validate_tag v2026.06.01.1 ) >/dev/null 2>&1'
    _t "garbage rejected"             '! ( validate_tag not-a-version ) >/dev/null 2>&1'
    _t "empty tag rejected"           '! ( validate_tag "" ) >/dev/null 2>&1'
    _t "latest rejected"              '! ( validate_tag latest ) >/dev/null 2>&1'
    _t "tag containing latest reject" '! ( validate_tag v2026.06.01-latest ) >/dev/null 2>&1'
    _t "non-zero-padded reject"       '! ( validate_tag v2026.6.1 ) >/dev/null 2>&1'
    return $fail
}

DRY_RUN=0
TAG=""
for arg in "$@"; do
    case "$arg" in
        --self-test) _pr_self_test && echo "prepare-release.sh: SELF-TEST OK"; exit ;;
        --dry-run) DRY_RUN=1 ;;
        -h|--help) sed -n '2,19p' "$0"; exit 0 ;;
        *) TAG="$arg" ;;
    esac
done

# --- BEGIN repo-identity guard ---------------------------------------------
# This script creates a v* tag and offers to push it to `origin`. Doing that
# from the wrong repository, or inside another agent's live checkout, is the
# pair of incidents scripts/lib/repo-identity.sh documents -- the second of
# which silently reverted tracked files, and the first of which produced a push
# a security classifier flagged as possible exfiltration.
#
# AFTER argument parsing, so --self-test and --help still work in any checkout
# (the self-test is run by tests/run-all.sh and must not need a real remote).
# BEFORE the first mutation, which is what makes it a precondition rather than a
# report. --allow-dirty is NOT passed: this script already requires a clean tree
# a few steps below, so a dirty protected path refuses either way, and refusing
# here names the actual reason.
# shellcheck source=lib/repo-identity.sh
. "$ROOT/scripts/lib/repo-identity.sh"
require_repo_identity || die "repository-identity guard refused; nothing was tagged or pushed."
# --- END repo-identity guard -----------------------------------------------

# --- Tag format ------------------------------------------------------------
step "Validating release tag '${TAG:-<none>}'"
validate_tag "$TAG"
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

  Pushing the tag triggers NOTHING by itself — release.yml is dispatch-only.
  The tag makes foundry-production (stable tags only) reachable; the ceremony
  continues with promote-stable, rollback-exercise, then the release.yml seal,
  all dispatched FROM this tag (docs/release-checklist.md).
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

printf 'Push %s to origin now (enables tag-dispatched promotion/seal)? [yes/NO]: ' "$TAG"
read -r PUSH
if [ "$PUSH" = "yes" ]; then
    ALLOW_RELEASE_TAG_PUSH=1 git push origin "$TAG"
    ok "pushed $TAG — continue the ceremony per docs/release-checklist.md"
else
    echo "  Tag created locally but NOT pushed. To push later:"
    echo "    ALLOW_RELEASE_TAG_PUSH=1 git push origin $TAG"
fi
