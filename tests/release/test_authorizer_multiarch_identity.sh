#!/usr/bin/env bash
# =============================================================================
# tests/release/test_authorizer_multiarch_identity.sh
# -----------------------------------------------------------------------------
# D1. The producer names artifacts, JSON records and evidence directories with
# child_slug(), which binds the platform. The authorizer rebuilt the slug itself
# as "${label//\//-}" — the image_label form, which has none — so it searched for
#
#     caddy-prod-evidence            (consumer)
#     caddy-prod-linux-amd64-evidence (producer, on disk)
#
# and found nothing. In run 32150666171 all twenty children refused for that
# reason while every image was otherwise sound: smoke, scan, reconciliation and
# metadata all PASS, checksums independently verifiable.
#
# The self-test could not catch it because its fixture was single-platform AND
# rebuilt the same wrong slug, so production and fixture agreed with each other
# while both disagreed with disk. Every path assertion below therefore states a
# LITERAL expected directory name; none is derived through the helper under test.
# =============================================================================
# shellcheck disable=SC2034
# ^ Assertions run through ck(), which evals its second argument, so shellcheck
#   cannot see that $OUT/$O/$OUTT are referenced inside those quoted strings.
#   CI lints ./scripts, not tests/; this keeps the file clean if that ever widens.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
ASC=scripts/release/authorize-staged-candidates.sh
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

TMP="$(mktemp -d)"
# The sabotage copy must live BESIDE the original: the authorizer resolves
# scripts/lib/common.sh relative to its own $BASH_SOURCE, so a copy in /tmp
# cannot source the canonical helpers and would fail for the wrong reason.
SAB="$ROOT/scripts/release/.sabotage-asc-$$.sh"
trap 'rm -rf "$TMP"; rm -f "$SAB"' EXIT
DIG="sha256:$(printf 'c%.0s' {1..64})"
REV="$(printf 'a%.0s' {1..40})"
PKG="ghcr.io/zenchron-dynamics/foundry-staging"

# The matrix the authorizer expects. Two images keeps fixtures readable; the
# real 20-child replay in test_authorizer_replay.sh covers the full matrix.
run_auth() { # run_auth <evidence-dir> <out.json> [platforms] [script]
  local d="$1" out="$2" plats="${3:-linux/amd64,linux/arm64}" scr="${4:-$ASC}"
  EVIDENCE_ROOT="$d" \
  EXPECTED_REPOSITORY="zenchron-dynamics/zenchron-foundry" \
  EXPECTED_REVISION="$REV" EXPECTED_RUN_ID=1 EXPECTED_RUN_ATTEMPT=1 \
  EXPECTED_PLATFORMS="$plats" EXPECTED_STAGING_PACKAGE="$PKG" \
  EXPECTED_TRIVY_DB="db@2026-08-05" BUILD_CREATED="2026-08-06T00:00:00Z" \
  WORKFLOW_REF="zenchron-dynamics/zenchron-foundry/.github/workflows/stage-and-authorize.yml@refs/heads/master" \
  GENERATED_AT="2026-08-05T00:00:00Z" \
  bash "$scr" "$d" "$out" 2>&1
}

# Build the FULL declared matrix on both platforms. Paths are written literally.
mkfull() { # mkfull <dir>
  local d="$1" lbl plat i=0
  mkdir -p "$d"
  while IFS= read -r lbl; do
    for plat in linux/amd64 linux/arm64; do
      i=$((i+1))
      local arch="${plat#linux/}" slug edir sum
      slug="${lbl//\//-}-linux-${arch}"      # LITERAL, not via child_slug()
      edir="$d/${slug}-evidence"
      mkdir -p "$edir"; printf 'evidence %s %s\n' "$lbl" "$plat" > "$edir/log.txt"
      sum="$(bash scripts/release/evidence-checksum.sh "$edir")"
      jq -nc --arg l "$lbl" --arg ck "$lbl/$plat" --arg pl "$plat" --arg a "$arch" \
             --arg d "$DIG" --arg s "$sum" --arg p "$PKG" --arg rev "$REV" '{
        image_label:$l, child_key:$ck, platform:$pl,
        staging_tag:(($l|gsub("/";"-"))+"-r1-a1-saaaaaaa-"+$a),
        digest_reference:($p+"@"+$d), manifest_digest:$d, tag_resolved_digest:$d,
        visibility:"private", config_architecture:$a,
        manifest_media_type:"application/vnd.oci.image.manifest.v1+json",
        trivy_db_identity:"db@2026-08-05", source_revision:$rev,
        workflow_run_id:1, workflow_run_attempt:1,
        repository:"zenchron-dynamics/zenchron-foundry",
        smoke_test:"PASS", scan:"PASS", reconciliation:"PASS",
        metadata_contract:"PASS", evidence_sha256:$s}' > "$d/child-$i.json"
    done
  done < <(bash -c '. scripts/lib/common.sh; matrix_image_labels')
}

# --- the happy two-platform case --------------------------------------------
D="$TMP/ok"; mkfull "$D"
OUT="$(run_auth "$D" "$D/out.json")"; rc=$?
ck "a full two-platform matrix is authorized" "[ $rc -eq 0 ]"
ck "...verdict is PASS" "[ \"\$(jq -r .verdict '$D/out.json')\" = PASS ]"
ck "...all 20 children are consumed" "[ \"\$(jq -r '.children|length' '$D/out.json')\" -eq 20 ]"
ck "...10 are linux/amd64" \
   "[ \"\$(jq -r '[.children[]|select(.platform==\"linux/amd64\")]|length' '$D/out.json')\" -eq 10 ]"
ck "...10 are linux/arm64" \
   "[ \"\$(jq -r '[.children[]|select(.platform==\"linux/arm64\")]|length' '$D/out.json')\" -eq 10 ]"

# BOTH platform-bound directories are really on disk under LITERAL names, and
# both were checksum-verified (mutating either must refuse — proven below).
ck "the amd64 evidence directory exists at its platform-bound literal path" \
   "test -d '$D/nginx-prod-linux-amd64-evidence'"
ck "the arm64 evidence directory exists at its platform-bound literal path" \
   "test -d '$D/nginx-prod-linux-arm64-evidence'"
ck "no unplatformed directory is created by the producer naming" \
   "! test -d '$D/nginx-prod-evidence'"

# --- each platform's checksum is genuinely validated ------------------------
for A in amd64 arm64; do
  D2="$TMP/tamper-$A"; mkfull "$D2"
  printf 'tampered\n' >> "$D2/nginx-prod-linux-$A-evidence/log.txt"
  O="$(run_auth "$D2" "$D2/out.json")"
  ck "tampering with the $A evidence refuses (its checksum IS verified)" \
     "grep -q 'does not match the evidence directory' <<<\"\$O\""
  ck "...and the refusal names nginx/prod on linux/$A" \
     "grep -q 'nginx/prod@linux/$A' <<<\"\$O\""
done

# --- neither platform may consume the other's evidence ----------------------
D3="$TMP/swap"; mkfull "$D3"
mv "$D3/nginx-prod-linux-amd64-evidence" "$TMP/hold"
mv "$D3/nginx-prod-linux-arm64-evidence" "$D3/nginx-prod-linux-amd64-evidence"
mv "$TMP/hold" "$D3/nginx-prod-linux-arm64-evidence"
O="$(run_auth "$D3" "$D3/out.json")"
ck "SWAPPED platform directories refuse" "[ -n \"\$O\" ] && ! jq -e '.verdict==\"PASS\"' '$D3/out.json' >/dev/null"
ck "...because the checksums no longer match, not for an unrelated reason" \
   "grep -q 'does not match the evidence directory' <<<\"\$O\""
ck "...and BOTH platforms are named in the refusals" \
   "grep -q 'nginx/prod@linux/amd64' <<<\"\$O\" && grep -q 'nginx/prod@linux/arm64' <<<\"\$O\""

# --- a missing platform directory refuses -----------------------------------
D4="$TMP/missdir"; mkfull "$D4"; rm -rf "$D4/nginx-prod-linux-arm64-evidence"
O="$(run_auth "$D4" "$D4/out.json")"
ck "a MISSING platform directory refuses" \
   "grep -q \"no evidence directory at 'nginx-prod-linux-arm64-evidence'\" <<<\"\$O\""
ck "...and the amd64 sibling is NOT implicated" \
   "! grep -q \"no evidence directory at 'nginx-prod-linux-amd64-evidence'\" <<<\"\$O\""

# --- an UNPLATFORMED directory is not accepted ------------------------------
D5="$TMP/unplat"; mkfull "$D5"
mv "$D5/nginx-prod-linux-arm64-evidence" "$D5/nginx-prod-evidence"
O="$(run_auth "$D5" "$D5/out.json")"
ck "an UNPLATFORMED evidence directory is refused, never used as a fallback" \
   "grep -q \"no evidence directory at 'nginx-prod-linux-arm64-evidence'\" <<<\"\$O\""

# --- duplicate child keys ---------------------------------------------------
D6="$TMP/dup"; mkfull "$D6"; cp "$D6/child-1.json" "$D6/child-dup.json"
O="$(run_auth "$D6" "$D6/out.json")"
ck "duplicate child keys refuse" "grep -q 'duplicate entry' <<<\"\$O\""

# --- child_key must agree with family/selector/platform ---------------------
D7="$TMP/keydis"; mkfull "$D7"
f="$(grep -l '"nginx/prod"' "$D7"/child-*.json | head -1)"
jq -c '.child_key="php-cli/8.3/linux/amd64"' "$f" > "$f.tmp" && mv "$f.tmp" "$f"
O="$(run_auth "$D7" "$D7/out.json")"
ck "a child_key disagreeing with family/selector/platform refuses" \
   "grep -q 'disagrees with its family/selector/platform' <<<\"\$O\""
ck "...naming the canonical key it should have carried" \
   "grep -qE \"canonical 'nginx/prod/linux/(amd64|arm64)'\" <<<\"\$O\""

# --- SABOTAGE: restore the pre-fix derivation -------------------------------
# The old code must fail on the SAME fixture the corrected code passes, and it
# must fail for the platform reason — not for schema, child count or fixtures.
sed 's|edir="${EVIDENCE_ROOT}/${cslug}-evidence"|edir="${EVIDENCE_ROOT}/${label//\\//-}-evidence"|; s|refusals+=("$id: no evidence directory at '"'"'${cslug}-evidence'"'"'|refusals+=("$id: no evidence directory at '"'"'${label//\\//-}-evidence'"'"'|' \
    "$ASC" > "$SAB"
ck "the sabotage copy differs from the corrected authorizer" "! cmp -s '$SAB' '$ASC'"
ck "the sabotage really restored the unplatformed derivation" \
   "grep -q 'EVIDENCE_ROOT}/\${label//' '$SAB'"
D8="$TMP/sab"; mkfull "$D8"
O="$(run_auth "$D8" "$TMP/sab-out.json" 'linux/amd64,linux/arm64' "$SAB")"
ck "SABOTAGE: the OLD unplatformed derivation refuses the same good fixture" \
   "! jq -e '.verdict==\"PASS\"' '$TMP/sab-out.json' >/dev/null 2>&1"
ck "...and it fails specifically on the missing platform-bound directory" \
   "grep -q 'no evidence directory' <<<\"\$O\""
ck "...for all 20 children, which is the run-32150666171 signature" \
   "[ \"\$(grep -c 'no evidence directory' <<<\"\$O\")\" -eq 20 ]"
OK8="$(run_auth "$D8" "$TMP/sab-ok.json")"; rc8=$?
if [ $rc8 -ne 0 ]; then echo "--- corrected-authorizer output on the sabotage fixture ---"; printf '%s\n' "$OK8" | head -8; fi
ck "...while the CORRECTED authorizer passes that identical fixture" \
   "[ $rc8 -eq 0 ] && jq -e '.verdict==\"PASS\"' '$TMP/sab-ok.json' >/dev/null"

echo "----"; [ "$fail" -eq 0 ] && echo "test_authorizer_multiarch_identity: PASS" || echo "test_authorizer_multiarch_identity: FAIL"
exit $fail
