#!/usr/bin/env bash
# =============================================================================
# A child's identity must include its PLATFORM, everywhere it is written down.
#
# THE DEFECT THIS LOCKS DOWN. Run 32123758374 planned 20 children but could
# produce at most 10 distinct evidence records. The artifact name and the
# evidence filename were both derived from image_label() — php-fpm/8.3 — which
# has no platform, so amd64 and arm64 wrote:
#
#     artifact  child-php-fpm-8.3-<run>-<attempt>     (identical)
#     evidence  php-fpm-8.3.json                      (identical)
#
# and the authorizer's `merge-multiple: true` download flattened one onto the
# other. The run was cancelled for cost containment before arm64 began.
#
# The staging TAG already carried -${arch}, and the previous shape test asserted
# tag uniqueness — which is exactly why this slipped through. Tag uniqueness
# proves the registry is safe; it says nothing about evidence names. This file
# asserts the evidence side explicitly.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

W=.github/workflows/stage-and-authorize.yml
lib() { bash -c ". scripts/lib/common.sh; $1"; }

# --- the canonical identity --------------------------------------------------
ck "child_key carries family, selector AND platform" \
   '[ "$(lib "child_key php-fpm 8.3 linux/amd64")" = "php-fpm/8.3/linux/amd64" ]'
ck "child_slug is filesystem/artifact safe" \
   '[ "$(lib "child_slug php-fpm 8.3 linux/amd64")" = "php-fpm-8.3-linux-amd64" ]'
ck "a prod selector round-trips" \
   '[ "$(lib "child_key nginx prod linux/arm64")" = "nginx/prod/linux/arm64" ] &&
    [ "$(lib "child_slug nginx prod linux/arm64")" = "nginx-prod-linux-arm64" ]'
ck "amd64 and arm64 normalise DIFFERENTLY" \
   '[ "$(lib "child_slug php-fpm 8.3 linux/amd64")" != "$(lib "child_slug php-fpm 8.3 linux/arm64")" ]'
ck "the slug contains no /, whitespace or comma" \
   's="$(lib "child_slug php-fpm 8.3 linux/amd64")";
    case "$s" in *"/"*|*" "*|*","*) false ;; *) true ;; esac'

# --- refusals ----------------------------------------------------------------
bad() { ! bash -c ". scripts/lib/common.sh; child_slug $1" >/dev/null 2>&1; }
ck "a non-linux platform refuses"        'bad "php-fpm 8.3 darwin/arm64"'
ck "a bare linux/ refuses"               'bad "php-fpm 8.3 linux/"'
ck "a platform with whitespace refuses"  'bad "php-fpm 8.3 \"linux/amd 64\""'
ck "a comma-separated platform refuses"  'bad "php-fpm 8.3 linux/amd64,linux/arm64"'
ck "a path-traversing family refuses"    'bad "../evil 8.3 linux/amd64"'
ck "a slash in the selector refuses"     'bad "php-fpm 8.3/x linux/amd64"'

# --- against the REAL generated 20-child plan, not fixtures -----------------
PLAN="$(bash scripts/release/build-acceptance-matrix.sh 'linux/amd64,linux/arm64')"
slugs() {
  printf '%s' "$PLAN" | jq -r '.include[]|"\(.fam)\t\(.ver)\t\(.platform)"' |
  while IFS=$'\t' read -r f v p; do bash -c ". scripts/lib/common.sh; child_slug '$f' '$v' '$p'"; done
}
# shellcheck disable=SC2034  # consumed inside the eval'd ck assertions
S="$(slugs)"
ck "the real plan yields 20 children" \
   '[ "$(printf "%s" "$PLAN" | jq ".include|length")" = 20 ]'
ck "20 DISTINCT evidence slugs (the collision that cancelled 32123758374)" \
   '[ "$(printf "%s\n" "$S" | sort -u | wc -l | tr -d " ")" = 20 ]'
ck "20 distinct artifact upload names" \
   '[ "$(printf "%s\n" "$S" | sed "s/^/child-/;s/\$/-99-1/" | sort -u | wc -l | tr -d " ")" = 20 ]'
ck "20 distinct evidence JSON filenames" \
   '[ "$(printf "%s\n" "$S" | sed "s/\$/.json/" | sort -u | wc -l | tr -d " ")" = 20 ]'
ck "20 distinct evidence directories" \
   '[ "$(printf "%s\n" "$S" | sed "s/\$/-evidence/" | sort -u | wc -l | tr -d " ")" = 20 ]'
ck "no amd64 path equals an arm64 path" \
   'a="$(printf "%s\n" "$S" | grep -c -- "-linux-amd64")";
    b="$(printf "%s\n" "$S" | grep -c -- "-linux-arm64")";
    c="$(printf "%s\n" "$S" | grep -- "-linux-amd64" | sed "s/amd64/arm64/" | sort > /tmp/_a;
        printf "%s\n" "$S" | grep -- "-linux-arm64" | sort > /tmp/_b;
        comm -12 /tmp/_a /tmp/_b | wc -l | tr -d " ")";
    [ "$a" = 10 ] && [ "$b" = 10 ] && [ "$c" = 10 ]'
ck "image label alone is NOT unique across platforms (proves the old bug)" \
   '[ "$(printf "%s" "$PLAN" | jq -r "[.include[]|\"\(.fam)-\(.ver)\"]|unique|length")" = 10 ]'

# --- the workflow actually consumes it --------------------------------------
ck "the identity step computes the platform-bound slug" \
   'grep -q "slug=\"\$(child_slug \"\$FAM\" \"\$VER\" \"\$PLATFORMS\")\"" '"$W"
ck "the emit step consumes that slug rather than recomputing from LABEL" \
   'grep -q "CHILD_SLUG:?child slug missing" '"$W"' && ! grep -q "slug=\"\${LABEL" '"$W"
ck "the artifact upload name is platform-bound" \
   'grep -q "name: child-\${{ steps.id.outputs.slug }}" '"$W"
ck "the authorizer collect pattern still matches the new names" \
   'p="$(python3 -c "
import yaml
d=yaml.safe_load(open(\"'"$W"'\"))
print([x for x in d[\"jobs\"][\"authorize\"][\"steps\"] if \"download-artifact\" in str(x.get(\"uses\",\"\"))][0][\"with\"][\"pattern\"])")";
    case "$p" in child-\**) true ;; *) false ;; esac'

# --- SABOTAGE: omitting the platform must fail, for the intended reason ------
ck "SABOTAGE: reverting the evidence slug to the platform-free label is DETECTED" \
   'tmp="$(mktemp -d)";
    sed "s|slug=\"\${CHILD_SLUG:?child slug missing}\"|slug=\"\${LABEL//\\\\//-}\"|" '"$W"' > "$tmp/w.yml";
    ! grep -q "CHILD_SLUG:?child slug missing" "$tmp/w.yml"; rc=$?; rm -rf "$tmp"; [ $rc -eq 0 ]'
ck "SABOTAGE: reverting the artifact name to matrix.fam/ver is DETECTED" \
   'tmp="$(mktemp -d)";
    sed "s|name: child-\${{ steps.id.outputs.slug }}|name: child-\${{ matrix.fam }}-\${{ matrix.ver }}|" '"$W"' > "$tmp/w.yml";
    ! grep -q "name: child-\${{ steps.id.outputs.slug }}" "$tmp/w.yml"; rc=$?; rm -rf "$tmp"; [ $rc -eq 0 ]'
ck "SABOTAGE: a platform-free slug collapses 20 identities to 10" \
   'n="$(printf "%s" "$PLAN" | jq -r ".include[]|\"\(.fam)-\(.ver)\"" | sort -u | wc -l | tr -d " ")";
    [ "$n" = 10 ]'

echo "----"
[ "$fail" -eq 0 ] && echo "test_child_identity: PASS" || echo "test_child_identity: FAIL"
exit $fail
