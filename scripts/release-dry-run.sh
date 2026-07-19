#!/usr/bin/env bash
# =============================================================================
# scripts/release-dry-run.sh [out-dir]
# -----------------------------------------------------------------------------
# Exercises the ENTIRE release pipeline offline against a mock registry: RC
# manifest generate -> validate -> sign -> verify -> two-phase promote ->
# post-promotion verify -> evidence build/validate. It pushes NOTHING, mutates
# no real alias, and creates no GitHub release. It emits PLAN.md listing the
# exact live commands a real run would issue.
#
# This is the safe rehearsal used before any authorized live run.
# =============================================================================
set -euo pipefail
_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$_d/.." && pwd)"
# shellcheck source=lib/registry-aliases.sh
. "$_d/lib/registry-aliases.sh"

OUT="${1:-$(mktemp -d)}"; mkdir -p "$OUT/art" "$OUT/mock" "$OUT/bin"
export VERSION="${VERSION:-v2026.07.04}" RC="${RC:-rc1}"
export REVISION="${REVISION:-$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo 7b4985a1234567890abcdef1234567890abcdef1)}"

log() { printf '%s\n' "$*"; }
log "== Zenchron Foundry release DRY RUN — $VERSION $RC @ ${REVISION:0:12} =="
log "   (mock registry, LOCAL crypto — NOTHING is published)"

# Mock digest resolver: deterministic per immutable RC ref.
cat > "$OUT/bin/mockdig" <<'EOF'
#!/usr/bin/env bash
echo "sha256:$(printf '%s' "$1" | shasum -a256 | cut -c1-64)"
EOF
printf '#!/usr/bin/env bash\necho linux/amd64,linux/arm64\n' > "$OUT/bin/mockplat"
chmod +x "$OUT/bin/mockdig" "$OUT/bin/mockplat"
export PATH="$OUT/bin:$PATH"

# 1. RC manifest (offline digests) -> validate -> sign(LOCAL) -> verify(LOCAL)
log "-- generate + validate + sign + verify RC manifest"
RESOLVE_DIGEST_FN=mockdig RESOLVE_PLATFORMS_FN=mockplat \
  bash "$_d/generate-release-manifest.sh" "$VERSION" --rc "$RC" --revision "$REVISION" > "$OUT/art/release-manifest.yaml"
bash "$_d/validate-release-manifest.sh" "$OUT/art/release-manifest.yaml" >/dev/null
LOCAL=1 bash "$_d/sign-release-manifest.sh" "$OUT/art/release-manifest.yaml" >/dev/null
LOCAL=1 bash "$_d/verify-release-manifest.sh" "$OUT/art/release-manifest.yaml" >/dev/null

# 2. Seed the mock registry with prior stable-alias digests, then promote.
log "-- two-phase promotion against mock registry"
export REG_BACKEND=mock REG_MOCK_DIR="$OUT/mock"
# seed priors
# shellcheck source=lib/registry-ops.sh
. "$_d/lib/registry-ops.sh"
for t in $MATRIX_IMAGES; do fam="${t%:*}"; sel="${t#*:}"
  for suf in $(stable_aliases "$sel" "${VERSION#v}"); do
    reg_retag "$(full_ref "$fam" "$suf")" "sha256:$(printf 'prior:%s' "$fam-$suf" | shasum -a256 | cut -c1-64)"
  done
done
LOCAL=1 ARTDIR="$OUT/art" bash "$_d/promote-stable.sh" "$VERSION" "$RC" --manifest "$OUT/art/release-manifest.yaml" >/dev/null

# 3. Evidence (dry-run: verification results not yet produced -> ALLOW_ABSENT)
log "-- build + validate evidence package (dry-run)"
RC_MANIFEST="$OUT/art/release-manifest.yaml" \
  ROLLBACK_MANIFEST="$OUT/art/rollback-${VERSION}.yaml" PROMOTION_JOURNAL="$OUT/art/promotion-journal-${VERSION}.txt" \
  bash "$_d/build-release-evidence.sh" "$OUT/art" >/dev/null
ALLOW_ABSENT=1 bash "$_d/validate-release-evidence.sh" "$OUT/art/evidence.json" >/dev/null

# 4. Emit the plan of LIVE commands a real run would execute (but did NOT).
cat > "$OUT/PLAN.md" <<PLAN
# Live-run plan for $VERSION $RC (NOT executed)

A real, authorized run would:
1. publish-rc.yml: build+push immutable RC tags, sign, attest, generate+sign the RC manifest.
   - each: docker buildx build --push ghcr.io/zenchron-dynamics/<img>:$(immutable_rc_suffix 8.4 "$VERSION" "$RC" "$REVISION")-style tag
   - cosign sign --yes <digest>; cosign attest --type spdxjson <digest>
2. git tag $VERSION && push   (on the exact RC revision; seals nothing by itself)
3. promote-stable.yml, dispatched from refs/tags/$VERSION:
   docker buildx imagetools create <stable-alias> <rc-digest>   (retag, no rebuild)
4. release.yml, dispatched from refs/tags/$VERSION -> seals the GitHub release
   - gh release create $VERSION (with manifest + SBOMs + evidence + VERIFY.md)

Artifacts produced by THIS dry run (offline, mock registry):
$(cd "$OUT/art" && ls -1 | sed 's/^/  - /')
PLAN

log ""
log "DRY RUN OK — no images pushed, no aliases mutated, no release created."
log "  artifacts: $OUT/art"
log "  plan:      $OUT/PLAN.md"
