#!/usr/bin/env bash
# =============================================================================
# tests/release/test_child_identity_contract.sh
# -----------------------------------------------------------------------------
# ONE implementation of child identity, for every producer AND every consumer.
#
# Three of the last four defects in this area were the same shape: a writer was
# updated and a reader was not.
#
#   * artifact/JSON/evidence names gained the platform; the authorizer's lookup
#     did not                                    -> run 32150666171, all 20 refused
#   * the wall clock moved to $GITHUB_ENV; the evidence step still read a step
#     output                                     -> child_wall_seconds 0 x 20
#   * the producer emitted a media type; the consumer aliased it to a verdict
#
# A guard is cheaper than a fourth. Identity-bearing paths must resolve through
# child_key()/child_slug() in scripts/lib/common.sh; consumers may append a
# suffix, never rebuild the identity.
# =============================================================================
# shellcheck disable=SC2034
# ^ Assertions run through ck(), which evals its second argument, so shellcheck
#   cannot see that $OUT/$O/$OUTT are referenced inside those quoted strings.
#   CI lints ./scripts, not tests/; this keeps the file clean if that ever widens.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
WF=.github/workflows/stage-and-authorize.yml
ASC=scripts/release/authorize-staged-candidates.sh
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

. scripts/lib/common.sh
set +e
NIMG="$(matrix_image_labels | grep -c .)"
NCHILD=$(( NIMG * 2 ))

# --- the canonical helpers behave --------------------------------------------
ck "child_slug binds the platform"        "[ \"\$(child_slug php-fpm 8.3 linux/amd64)\" = php-fpm-8.3-linux-amd64 ]"
ck "child_slug distinguishes architectures" \
   "[ \"\$(child_slug php-fpm 8.3 linux/amd64)\" != \"\$(child_slug php-fpm 8.3 linux/arm64)\" ]"
ck "child_key binds the platform"         "[ \"\$(child_key php-fpm 8.3 linux/arm64)\" = php-fpm/8.3/linux/arm64 ]"
ck "prod selectors normalise identically" "[ \"\$(child_slug nginx prod linux/amd64)\" = nginx-prod-linux-amd64 ]"
ck "an empty selector normalises to prod" "[ \"\$(child_slug nginx '' linux/amd64)\" = nginx-prod-linux-amd64 ]"

# --- SABOTAGE 1: platform removed from a consumer ----------------------------
# The image_label form is what the broken authorizer used. Prove it collides.
ck "SABOTAGE platform-removed: amd64 and arm64 collapse to ONE path" \
   "[ \"\$(image_label php-fpm 8.3 | tr / -)\" = \"\$(image_label php-fpm 8.3 | tr / -)\" ] &&
    [ \"\$(child_slug php-fpm 8.3 linux/amd64)\" != \"\$(image_label php-fpm 8.3 | tr / -)\" ]"

# --- SABOTAGE 2: platform added twice ----------------------------------------
ck "SABOTAGE double-platform: appending the arch twice is NOT the canonical slug" \
   "[ \"\$(child_slug php-fpm 8.3 linux/amd64)-linux-amd64\" != \"\$(child_slug php-fpm 8.3 linux/amd64)\" ]"
ck "...and the canonical slug carries exactly one '-linux-' segment" \
   "[ \"\$(child_slug php-fpm 8.3 linux/amd64 | grep -o -- '-linux-' | wc -l | tr -d ' ')\" -eq 1 ]"

# --- SABOTAGE 3: amd64 and arm64 must never resolve to the same path ---------
seen="$(for a in amd64 arm64; do child_slug php-fpm 8.3 "linux/$a"; done | sort -u | wc -l | tr -d ' ')"
ck "SABOTAGE same-path: two architectures yield two distinct slugs" "[ '$seen' -eq 2 ]"
allslugs="$( { while IFS= read -r l; do
                 f="${l%%/*}"; v="${l#*/}"
                 for a in amd64 arm64; do child_slug "$f" "$v" "linux/$a"; done
               done < <(matrix_image_labels); } | sort )"
ck "the whole $NCHILD-child matrix yields $NCHILD DISTINCT slugs" \
   "[ \"\$(printf '%s\n' \"\$allslugs\" | sort -u | wc -l | tr -d ' ')\" -eq "$NCHILD" ]"

# --- SABOTAGE 4: artifact name and evidence dir must not diverge -------------
# Both derive from the SAME slug string in the workflow. If one were rebuilt
# independently they could drift; assert they share the single source.
ck "the artifact name is built from the identity step's slug" \
   "grep -qE 'name: child-\\\$\\{\\{ steps\\.id\\.outputs\\.slug \\}\\}' $WF"
ck "the evidence emitter uses that same slug, not a local rebuild" \
   "grep -q 'slug=\"\\\${CHILD_SLUG:?child slug missing}\"' $WF"
ck "the emitter does NOT rebuild the slug from LABEL" \
   "! grep -qE 'slug=\"\\\$\\{LABEL//' $WF"

# --- the consumer routes through the canonical helper ------------------------
ck "the authorizer calls child_slug()" "grep -q 'cslug=\"\$(child_slug ' $ASC"
ck "the authorizer calls child_key()"  "grep -q 'ckey_canon=\"\$(child_key ' $ASC"
ck "the authorizer no longer rebuilds an unplatformed slug from image_label" \
   "! grep -qE 'slug=\"\\\$\\{label//' $ASC"
ck "the evidence path is derived from the canonical slug" \
   "grep -q 'edir=\"\\\${EVIDENCE_ROOT}/\\\${cslug}-evidence\"' $ASC"
ck "the authorizer refuses a record whose child_key disagrees with its fields" \
   "grep -q 'disagrees with its family/selector/platform' $ASC"

# --- inventory: every label->path derivation in the tree is accounted for ----
# THIS CHECK WAS VACUOUS ON ITS FIRST WRITING. The pattern was escaped wrongly
# and matched zero lines, so it would have reported "no offenders" while the
# real occurrences sat in plain sight. It is asserted to be non-vacuous below:
# the canonical definition MUST be found, or the check is not searching.
#
# Comments are stripped: several deliberately quote the old broken form to
# explain it, and a check that matches its own explanatory prose is not a check.
derivations="$(grep -rn -- '//\\//-}' scripts/ .github/workflows/ 2>/dev/null \
             | grep -v 'tests/' \
             | grep -vE ':[0-9]+: *#' || true)"
ck "the derivation search is NOT vacuous — it finds the canonical definition" \
   "grep -q 'scripts/lib/common.sh' <<<\"\$derivations\""

# Exactly two derivations are legitimate, and both are named here:
#   scripts/lib/common.sh   — INSIDE child_slug(); this is the one implementation
#   stage-and-authorize.yml — the staging REGISTRY TAG, which is a different
#                             grammar (no '/' allowed, carries run/attempt/sha)
#                             and is separately asserted to be platform-bound.
unexpected="$(grep -v 'scripts/lib/common.sh' <<<"$derivations" \
            | grep -v '.github/workflows/stage-and-authorize.yml' || true)"
ck "no OTHER script or workflow rebuilds a path by substituting '/' in a label" \
   "[ -z \"\$unexpected\" ] || { printf 'unexpected derivations:\n%s\n' \"\$unexpected\"; false; }"
ck "...and the only two live derivations are the canonical helper and the tag" \
   "[ \"\$(printf '%s\n' \"\$derivations\" | grep -c .)\" -eq 2 ]"

# The staging tag is not an evidence path, but it must still bind the platform
# exactly once — appending the arch twice was a real defect in an earlier run.
ck "the staging tag appends the architecture exactly once" \
   "[ \"\$(grep -c 'tag=\"\${tagslug}-r\${GITHUB_RUN_ID}-a\${GITHUB_RUN_ATTEMPT}-s\${GITHUB_SHA:0:7}-\${arch}\"' $WF)\" -eq 1 ]"
ck "...and the tag is never built from the unplatformed slug alone" \
   "! grep -qE 'tag=\"\\\$\{tagslug\}\"' $WF"

# The canonical helpers are defined exactly once.
ck "child_slug is defined exactly once in the tree" \
   "[ \"\$(grep -rl '^child_slug()' scripts/ | wc -l | tr -d ' ')\" -eq 1 ]"
ck "child_key is defined exactly once in the tree" \
   "[ \"\$(grep -rl '^child_key()' scripts/ | wc -l | tr -d ' ')\" -eq 1 ]"

echo "----"; [ "$fail" -eq 0 ] && echo "test_child_identity_contract: PASS" || echo "test_child_identity_contract: FAIL"
exit $fail
