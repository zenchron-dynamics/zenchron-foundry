#!/usr/bin/env bash
# =============================================================================
# tests/release/test_oci_version_label.sh — OCI version label must match the
# canonical family/selector, not a hardcoded suffix (#126).
#
# The bug: `org.opencontainers.image.version=${{ matrix.ver }}-prod` produced
# `prod-prod` for the edge images, because nginx and caddy declare `ver: prod`.
# Published metadata then contradicted the images' own Dockerfiles, which
# declare `version="prod"` — breaking any inventory or policy tooling that reads
# OCI labels.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

# The publisher that carried this label was deleted with the rest of the
# production publication path. The labelling contract did not go away with it:
# it moved to the staging workflow, now the only thing that builds images.
WF=.github/workflows/stage-and-authorize.yml

ck "the deleted publisher is not still labelling images somewhere" \
   "! test -f .github/workflows/publish-ghcr.yml"
ck "version label is not hardcoded from matrix.ver" \
   "! grep -q 'image.version=\${{ matrix.ver }}-prod' $WF"
ck "version label comes from a computed step output" \
   "grep -q 'image.version=\${{ steps.id.outputs.version_label }}' $WF"
ck "the identity step emits version_label" \
   "grep -q 'echo \"version_label=' $WF"
ck "the canonical identity is NOT used as the version label" \
   "! grep -q 'image.version=\${{ steps.id.outputs.label }}' $WF"

# The selector logic itself: `prod` must stay `prod`, versions gain `-prod`.
suffix_for() { if [ "$1" = "prod" ]; then printf 'prod'; else printf '%s-prod' "$1"; fi; }
ck "edge selector 'prod' yields 'prod' (not prod-prod)" "[ \"\$(suffix_for prod)\" = prod ]"
ck "php selector '8.3' yields '8.3-prod'"               "[ \"\$(suffix_for 8.3)\" = 8.3-prod ]"
ck "php selector '8.4' yields '8.4-prod'"               "[ \"\$(suffix_for 8.4)\" = 8.4-prod ]"

# The label must agree with what each Dockerfile declares.
for df in images/nginx/Dockerfile images/caddy/Dockerfile; do
  ck "$df declares version=prod (matches the published label)" \
     "grep -q 'org.opencontainers.image.version=\"prod\"' $df"
done
# php-frankenphp was missing from this loop — it is a PHP-family image with the
# same label contract and must not be exempt from the check.
for v in 8.3 8.4; do
  for fam in php-cli php-fpm php-worker php-frankenphp; do
    ck "images/$fam/$v declares version=$v-prod" \
       "grep -q 'org.opencontainers.image.version=\"$v-prod\"' images/$fam/$v/Dockerfile"
  done
done


# ---------------------------------------------------------------------------
# BEHAVIOURAL: run the staging workflow's own identity-step logic.
#
# The grep assertions above pass even when the computation is wrong, which is
# how the original defect shipped: the label was hardcoded "${{ matrix.ver }}
# -prod", producing "prod-prod" for nginx and caddy because they declare
# `ver: prod`.
#
# It nearly shipped a second time. The staging workflow first labelled images
# with the CANONICAL IDENTITY (php-fpm/8.3, nginx/prod) — a clean-looking value
# that still contradicted every Dockerfile, which declare 8.3-prod and prod. A
# grep for "not hardcoded" accepts that. Executing the step does not.
# ---------------------------------------------------------------------------
id_run() { # id_run <fam> <ver> -> the step's GITHUB_OUTPUT
  local fam="$1" ver="$2" tmp; tmp="$(mktemp -d)"
  python3 - "$WF" "$fam" "$ver" > "$tmp/id.sh" <<'PYX'
import sys, yaml
wf, fam, ver = sys.argv[1], sys.argv[2], sys.argv[3]
d = yaml.safe_load(open(wf))
steps = d["jobs"]["stage"]["steps"]
run = [s for s in steps if s.get("id") == "id"][0]["run"]
run = run.replace("${{ inputs.platforms }}", "linux/amd64")
assert "${{" not in run, "unrendered expression left in the id step: %r" % run
sys.stdout.write(run)
PYX
  ( set -euo pipefail
    export STAGING_PACKAGE=ghcr.io/zenchron-dynamics/foundry-staging
    export FAM="$fam" VER="$ver" PLATFORMS="linux/amd64"
    export GITHUB_RUN_ID=777 GITHUB_RUN_ATTEMPT=1
    export GITHUB_SHA=1234567890abcdef1234567890abcdef12345678
    export GITHUB_OUTPUT="$tmp/out"
    : > "$tmp/out"
    bash "$tmp/id.sh" >/dev/null 2>&1 ) || { echo "id step failed" >&2; rm -rf "$tmp"; return 1; }
  cat "$tmp/out"; rm -rf "$tmp"
}
out_for() { # out_for <key> <fam> <ver>
  local key="$1"; shift
  local out; out="$(id_run "$@")" || { echo "ID-STEP-FAILED"; return 0; }
  grep "^${key}=" <<<"$out" | tail -1 | cut -d= -f2-
}

ck "the identity step runs at all" "[ -n \"\$(out_for version_label php-cli 8.4)\" ]"

# Every image: the built label must equal what its own Dockerfile declares.
for spec in "php-cli 8.4 8.4-prod" "php-cli 8.3 8.3-prod" \
            "php-fpm 8.4 8.4-prod" "php-fpm 8.3 8.3-prod" \
            "php-worker 8.4 8.4-prod" "php-worker 8.3 8.3-prod" \
            "php-frankenphp 8.4 8.4-prod" "php-frankenphp 8.3 8.3-prod" \
            "nginx prod prod" "caddy prod prod"; do
  read -r fam ver want <<<"$spec"
  ck "$fam/$ver labels version '$want' (agreeing with its Dockerfile)" \
     "[ \"\$(out_for version_label $fam $ver)\" = \"$want\" ]"
done

ck "edge images do not become 'prod-prod'" \
   "[ \"\$(out_for version_label nginx prod)\" != prod-prod ]"

# The canonical identity is still emitted — the authorization record keys on it
# — it is simply not the OCI version label.
ck "the canonical identity is emitted separately" \
   "[ \"\$(out_for label php-fpm 8.3)\" = php-fpm/8.3 ]"
ck "...including for the edge images" \
   "[ \"\$(out_for label nginx prod)\" = nginx/prod ]"
ck "identity and version label are genuinely different values" \
   "[ \"\$(out_for label php-fpm 8.3)\" != \"\$(out_for version_label php-fpm 8.3)\" ]"

# The staging tag format agreed for the quarantine package.
ck "the staging tag carries image, run, attempt, short sha and arch" \
   "[ \"\$(out_for tag php-fpm 8.3)\" = php-fpm-8.3-r777-a1-s1234567-amd64 ]"

# --- promotion no longer exists ---------------------------------------------
# This used to assert that promotion performed no build, because the RC label
# was baked permanently into the promoted digest. There is no promotion now, so
# the guarantee is simpler: nothing but the stager builds anything.
ck "promotion builds nothing" \
   "! grep -qE '^[[:space:]]+uses: docker/build-push-action' .github/workflows/promote-stable.yml"
# Other workflows DO build — scan-images, build-images and trusted-validation
# all build locally in order to scan or validate. Building is not the concern;
# PUSHING is. The staging workflow must be the only one that pushes.
ck "only one workflow pushes what it builds" \
   "[ \"\$(grep -rlF 'push: true' .github/workflows/ | wc -l | tr -d ' ')\" = 1 ]"
ck "...and it is the stager" \
   "[ \"\$(grep -rlF 'push: true' .github/workflows/)\" = .github/workflows/stage-and-authorize.yml ]"

echo "----"; [ "$fail" -eq 0 ] && echo "test_oci_version_label: PASS" || echo "test_oci_version_label: FAIL"
exit $fail
