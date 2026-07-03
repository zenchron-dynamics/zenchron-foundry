#!/usr/bin/env bash
# =============================================================================
# scripts/promote-stable.sh <version> <rc> --manifest <signed-rc-manifest>
# -----------------------------------------------------------------------------
# Two-phase, reversible RC->stable promotion. NO docker build. The signed RC
# manifest is the ONLY source of candidate digests (never rediscovered from
# mutable tags).
#
#   Phase 1  Preflight: verify the signed manifest; enumerate EVERY stable alias
#            that will change; record each alias's current digest to a signed
#            rollback manifest. Mutate nothing.
#   Phase 2  Promote: retag each RC digest onto its aliases, canonical prod LAST,
#            journaling every successful mutation. A failure/interrupt triggers
#            an automatic compensating rollback (reverse order) via rollback-stable.sh.
#   Phase 3  Verify: every alias resolves to the exact RC digest; write a signed
#            promotion manifest.
#
# REG_BACKEND=mock (+ REG_MOCK_DIR, REG_FAIL_AT) drives offline failure tests.
# LOCAL=1 skips cosign (offline). Emergency rollback-failure exit code: 99.
# =============================================================================
set -euo pipefail
_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/registry-aliases.sh
. "$_d/lib/registry-aliases.sh"
# shellcheck source=lib/registry-ops.sh
. "$_d/lib/registry-ops.sh"
# shellcheck source=lib/release-manifest.sh
. "$_d/lib/release-manifest.sh"

VERSION="" RC="" MANIFEST=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --manifest) shift; MANIFEST="${1:?--manifest needs a path}" ;;
    -*) die "unknown option: $1" ;;
    *) if [ -z "$VERSION" ]; then VERSION="$1"; elif [ -z "$RC" ]; then RC="$1"; else die "unexpected arg: $1"; fi ;;
  esac
  shift
done
require_calver "$VERSION"; require_rc "$RC"
[ -n "$MANIFEST" ] || die "--manifest <signed-rc-manifest> is required"
[ -f "$MANIFEST" ] || die "manifest not found: $MANIFEST"
REL="${VERSION#v}"

ARTDIR="${ARTDIR:-release-artifacts}"; mkdir -p "$ARTDIR"
ROLLBACK_MANIFEST="$ARTDIR/rollback-${VERSION}.yaml"
JOURNAL="$ARTDIR/promotion-journal-${VERSION}.txt"
PROMOTION_MANIFEST="$ARTDIR/promotion-${VERSION}.yaml"
: > "$JOURNAL"

mkey() { case "$2" in prod) printf '%s' "$1" ;; *) printf '%s-%s' "$1" "$2" ;; esac; }

# ---- Phase 1: preflight -----------------------------------------------------
echo "== Phase 1: verify signed RC manifest + record rollback state =="
bash "$_d/verify-release-manifest.sh" "$MANIFEST"

# alias inventory: emit "ref rc_digest" per (image x alias); build rollback list
INVENTORY="$(mktemp)"
{
  echo "schema_version: 1"
  echo "release: $VERSION"
  echo "candidate: $RC"
  echo "revision: $(manifest_field "$MANIFEST" '.revision')"
  echo "created_at: ${CREATED_AT:-$(date -u +%FT%TZ)}"
  echo "aliases:"
} > "$ROLLBACK_MANIFEST"

nalias=0
for t in $MATRIX_IMAGES; do
  fam="${t%:*}"; sel="${t#*:}"
  key="$(mkey "$fam" "$sel")"
  rcdig="$(manifest_image_field "$MANIFEST" "$key" digest)"
  is_digest "$rcdig" || die "manifest digest for $key is not sha256: '$rcdig'"
  for suf in $(stable_aliases "$sel" "$REL"); do
    ref="$(full_ref "$fam" "$suf")"
    prior="$(reg_digest "$ref" 2>/dev/null || echo NONE)"
    printf '%s\t%s\n' "$ref" "$rcdig" >> "$INVENTORY"
    printf '  - ref: %s\n    prior_digest: %s\n' "$ref" "$prior" >> "$ROLLBACK_MANIFEST"
    nalias=$((nalias+1))
  done
done
[ "$nalias" -gt 0 ] || die "no aliases enumerated"
echo "Phase 1 OK: $nalias aliases inventoried; rollback -> $ROLLBACK_MANIFEST"
bash "$_d/sign-release-manifest.sh" "$ROLLBACK_MANIFEST" >/dev/null 2>&1 || \
  { checksum_file "$ROLLBACK_MANIFEST" > "$ROLLBACK_MANIFEST.sha256"; warn "rollback manifest checksummed (cosign unavailable)"; }

# ---- rollback trap ----------------------------------------------------------
_do_rollback() {
  warn "!! promotion failed — invoking compensating rollback"
  set +e
  bash "$_d/rollback-stable.sh" "$ROLLBACK_MANIFEST" "$JOURNAL"
  local rc=$?
  if [ "$rc" -eq 99 ]; then
    warn "CRITICAL: rollback INCOMPLETE — see incident artifact; blocking release"
    exit 99
  fi
  warn "rollback complete; promotion aborted"
  exit 1
}
trap '_do_rollback' ERR INT TERM

# ---- Phase 2: promote (canonical last), journaling --------------------------
echo "== Phase 2: promote RC digests onto stable aliases (retag, no rebuild) =="
while IFS="$(printf '\t')" read -r ref rcdig; do
  echo "  $ref <= @$rcdig"
  reg_retag "$ref" "$rcdig"
  printf '%s\n' "$ref" >> "$JOURNAL"     # journal AFTER success
done < "$INVENTORY"
rm -f "$INVENTORY"

# ---- Phase 3: post-promotion verification + promotion manifest --------------
# Trap stays armed: a Phase-3 mismatch also triggers compensating rollback.
echo "== Phase 3: verify every alias resolves to its exact RC digest =="
bash "$_d/verify-promotion-state.sh" "$MANIFEST" "$VERSION" > "$PROMOTION_MANIFEST"
trap - ERR INT TERM
bash "$_d/sign-release-manifest.sh" "$PROMOTION_MANIFEST" >/dev/null 2>&1 || \
  checksum_file "$PROMOTION_MANIFEST" > "$PROMOTION_MANIFEST.sha256"

echo "PROMOTION OK: ${nalias} aliases match their RC digests (${RC} -> ${VERSION})"
echo "  rollback:  $ROLLBACK_MANIFEST"
echo "  journal:   $JOURNAL"
echo "  promotion: $PROMOTION_MANIFEST"
