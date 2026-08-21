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

promote_stable() {
  local VERSION="" RC="" MANIFEST=""
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
  local REL="${VERSION#v}"

  ARTDIR="${ARTDIR:-release-artifacts}"; mkdir -p "$ARTDIR"
  ROLLBACK_MANIFEST="$ARTDIR/rollback-${VERSION}.yaml"
  JOURNAL="$ARTDIR/promotion-journal-${VERSION}.txt"
  PROMOTION_MANIFEST="$ARTDIR/promotion-${VERSION}.yaml"
  : > "$JOURNAL"

  # ---- Phase 1: preflight ---------------------------------------------------
  echo "== Phase 1: verify signed RC manifest + record rollback state =="
  bash "$_d/verify-release-manifest.sh" "$MANIFEST"

  # alias inventory: emit "ref rc_digest" per (image x alias); build rollback list
  INVENTORY="$(mktemp)"
  # EXIT trap (not ERR): the inventory temp file must be removed on EVERY exit
  # path — success, die(), and the ERR/INT/TERM rollback path (whose handler
  # exits, which then fires this EXIT trap). Keep the ERR trap separate below.
  trap 'rm -f "$INVENTORY"' EXIT
  {
    echo "schema_version: 1"
    echo "release: $VERSION"
    echo "candidate: $RC"
    echo "revision: $(manifest_field "$MANIFEST" '.revision')"
    echo "created_at: ${CREATED_AT:-$(date -u +%FT%TZ)}"
    echo "aliases:"
  } > "$ROLLBACK_MANIFEST"

  local nalias=0 t fam sel key rcdig suf ref prior
  for t in $MATRIX_IMAGES; do
    fam="${t%:*}"; sel="${t#*:}"
    key="$(manifest_key "$fam" "$sel")"
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

  # ---- rollback trap --------------------------------------------------------
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

  # ---- Phase 2: promote (canonical last), journaling ------------------------
  echo "== Phase 2: promote RC digests onto stable aliases (retag, no rebuild) =="
  while IFS="$(printf '\t')" read -r ref rcdig; do
    echo "  $ref <= @$rcdig"
    reg_retag "$ref" "$rcdig"
    printf '%s\n' "$ref" >> "$JOURNAL"     # journal AFTER success
  done < "$INVENTORY"

  # ---- Phase 3: post-promotion verification + promotion manifest ------------
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
}

# --- self-test (mock registry backend, offline) ------------------------------
_ps_self_test() {
  command -v yq >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1 \
    || { echo "SKIP - yq/python3 absent"; return 0; }
  python3 -c 'import yaml, jsonschema' 2>/dev/null || { echo "SKIP - pyyaml/jsonschema absent"; return 0; }
  local fail=0
  local R=7b4985a1234567890abcdef1234567890abcdef1
  _t() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

  _mkfix() { # <dir> -> builds rc.yaml (+sha256), seeds mock priors
    # SC-20: the fixture's image list INTENTIONALLY duplicates MATRIX_IMAGES —
    # an independent copy is a drift tripwire for the authoritative matrix
    # (owner-accepted duplication; do not centralize).
    local d="$1"; mkdir -p "$d/mock" "$d/art"
    R="$R" OUT="$d/art/rc.yaml" python3 - <<'PY'
import os, yaml, hashlib
R = os.environ["R"]
keys = [f"php-{f}-{v}" for f in ("cli","fpm","worker","frankenphp") for v in ("8.3","8.4","8.5")] + ["nginx","caddy"]
def repo(k): return "ghcr.io/zenchron-dynamics/%s" % (k.rsplit("-",1)[0] if k.startswith("php-") else k)
def dig(k): return "sha256:" + hashlib.sha256(("ps-rc:"+k).encode()).hexdigest()
imgs = {k: {"repository": repo(k), "immutable_tag": "t-"+k, "digest": dig(k),
            "reference": repo(k)+"@"+dig(k), "revision": R,
            "platforms": ["linux/amd64","linux/arm64"]} for k in keys}
m = {"schema_version":1, "release":"v2026.07.03", "candidate":"rc1", "revision":R,
     "source_repository":"zenchron-dynamics/zenchron-foundry", "source_ref":"refs/heads/master",
     "workflow_run_id":"1", "created_at":"2026-07-03T12:00:00Z", "images":imgs}
yaml.safe_dump(m, open(os.environ["OUT"],"w"), sort_keys=True)
PY
    LOCAL=1 bash "$_d/sign-release-manifest.sh" "$d/art/rc.yaml" >/dev/null 2>&1
    ( export REG_BACKEND=mock REG_MOCK_DIR="$d/mock"
      local t fam sel suf ref
      for t in $MATRIX_IMAGES; do
        fam="${t%:*}"; sel="${t#*:}"
        for suf in $(stable_aliases "$sel" 2026.07.03); do
          ref="$(full_ref "$fam" "$suf")"
          reg_retag "$ref" "$(_pdig "$ref")"
        done
      done )
  }
  _rcdig() { python3 -c "import hashlib,sys;print('sha256:'+hashlib.sha256(('ps-rc:'+sys.argv[1]).encode()).hexdigest())" "$1"; }
  _pdig()  { python3 -c "import hashlib,sys;print('sha256:'+hashlib.sha256(('ps-prior:'+sys.argv[1]).encode()).hexdigest())" "$1"; }
  _run() { # <dir> [extra env assignments...]
    local d="$1"; shift
    ( env "$@" REG_BACKEND=mock REG_MOCK_DIR="$d/mock" ARTDIR="$d/art" LOCAL=1 \
        bash "${BASH_SOURCE[0]}" v2026.07.03 rc1 --manifest "$d/art/rc.yaml" ) >/dev/null 2>&1
  }
  _all_at_rc() { # <dir>: every alias resolves to its image's RC digest
    local d="$1" t fam sel suf ref got
    for t in $MATRIX_IMAGES; do
      fam="${t%:*}"; sel="${t#*:}"
      for suf in $(stable_aliases "$sel" 2026.07.03); do
        ref="$(full_ref "$fam" "$suf")"
        got="$(REG_BACKEND=mock REG_MOCK_DIR="$d/mock" reg_digest "$ref" 2>/dev/null || echo '')"
        [ "$got" = "$(_rcdig "$(manifest_key "$fam" "$sel")")" ] || return 1
      done
    done
  }
  _all_at_prior() { # <dir>: every alias back at its seeded prior digest
    local d="$1" t fam sel suf ref got
    for t in $MATRIX_IMAGES; do
      fam="${t%:*}"; sel="${t#*:}"
      for suf in $(stable_aliases "$sel" 2026.07.03); do
        ref="$(full_ref "$fam" "$suf")"
        got="$(REG_BACKEND=mock REG_MOCK_DIR="$d/mock" reg_digest "$ref" 2>/dev/null || echo '')"
        [ "$got" = "$(_pdig "$ref")" ] || return 1
      done
    done
  }

  # --- happy path ---
  local d1; d1="$(mktemp -d)"; _mkfix "$d1"
  _run "$d1"; local rc=$?
  _t "happy path promotes (exit 0)" '[ "$rc" -eq 0 ]'
  _t "every alias at its RC digest" '_all_at_rc "$d1"'
  # canonical prod alias mutated LAST per image (order read from the journal;
  # the expected canonical name is hardcoded, independent of the alias lib)
  # shellcheck disable=SC2034  # order_ok consumed inside the eval'd assertion below
  local order_ok=1 t fam sel canon lastline
  for t in $MATRIX_IMAGES; do
    fam="${t%:*}"; sel="${t#*:}"
    case "$sel" in
      prod) canon="$NS/$fam:prod"
            lastline="$(grep -E "^.*/${fam}:prod(-|$)" "$d1/art/promotion-journal-v2026.07.03.txt" | tail -1)" ;;
      *)    canon="$NS/$fam:${sel}-prod"
            lastline="$(grep -F "$NS/$fam:$sel-" "$d1/art/promotion-journal-v2026.07.03.txt" | tail -1)" ;;
    esac
    [ "$lastline" = "$canon" ] || { echo "     journal order wrong for $t: last='$lastline' want='$canon'"; order_ok=0; }
  done
  if [ "$order_ok" -eq 1 ]; then echo "ok   - journal shows canonical prod LAST per image"
  else echo "FAIL - journal shows canonical prod LAST per image"; fail=1; fi
  # rollback manifest records every seeded prior digest
  # shellcheck disable=SC2034  # priors_ok consumed inside the eval'd assertion below
  local priors_ok=1 suf ref
  for t in $MATRIX_IMAGES; do
    fam="${t%:*}"; sel="${t#*:}"
    for suf in $(stable_aliases "$sel" 2026.07.03); do
      ref="$(full_ref "$fam" "$suf")"
      [ "$(yq -r ".aliases[] | select(.ref==\"$ref\") | .prior_digest" "$d1/art/rollback-v2026.07.03.yaml")" = "$(_pdig "$ref")" ] \
        || { echo "     prior not recorded for $ref"; priors_ok=0; }
    done
  done
  if [ "$priors_ok" -eq 1 ]; then echo "ok   - rollback manifest records all prior digests"
  else echo "FAIL - rollback manifest records all prior digests"; fail=1; fi
  rm -rf "$d1"

  # --- mid-promotion registry failure -> compensating reverse rollback ---
  local d2; d2="$(mktemp -d)"; _mkfix "$d2"
  _run "$d2" REG_FAIL_AT=14; rc=$?
  _t "REG_FAIL_AT=14 aborts promotion (nonzero)" '[ "$rc" -ne 0 ]'
  _t "journal replay restored every prior"        '_all_at_prior "$d2"'
  rm -rf "$d2"

  # --- Phase-3 mismatch (registry ACKed but stored the wrong digest) ---
  local d3 out; d3="$(mktemp -d)"; _mkfix "$d3"
  # shellcheck disable=SC2034  # out consumed inside the eval'd assertion below
  out="$( ( REG_WRITE_WRONG_AT=5 REG_BACKEND=mock REG_MOCK_DIR="$d3/mock" ARTDIR="$d3/art" LOCAL=1 \
      bash "${BASH_SOURCE[0]}" v2026.07.03 rc1 --manifest "$d3/art/rc.yaml" ) 2>&1 )"; rc=$?
  _t "Phase-3 mismatch exits nonzero"    '[ "$rc" -ne 0 ]'
  _t "Phase-3 mismatch detected (loud)"  'printf "%s" "$out" | grep -q "MISMATCH"'
  rm -rf "$d3"

  return $fail
}

case "${1:-}" in
  --self-test) _ps_self_test && echo "promote-stable.sh: SELF-TEST OK"; exit ;;
  "") die "usage: promote-stable.sh <version> <rc> --manifest <signed-rc-manifest> | --self-test" ;;
esac
promote_stable "$@"
