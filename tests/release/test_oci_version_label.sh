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

WF=.github/workflows/publish-ghcr.yml

ck "version label is not hardcoded from matrix.ver" \
   "! grep -q 'image.version=\${{ matrix.ver }}-prod' $WF"
ck "version label comes from the meta step output" \
   "grep -q 'image.version=\${{ steps.meta.outputs.version_label }}' $WF"
ck "meta step emits version_label" \
   "grep -q 'echo \"version_label=' $WF"

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
# BEHAVIOURAL: run the workflow's own meta-step logic for every publish branch.
#
# The grep assertions above pass even when the RC branch sets a completely
# different label, which is exactly what happened: RC mode set
# version_label="$imm_suffix". promote-stable.yml performs ZERO builds — it
# retags the exact RC digest — so that RC-specific label is what the STABLE
# image ships with permanently, contradicting the Dockerfile assertions above.
#
# This extracts the real `run:` block and executes it, so the four branches are
# tested rather than described.
# ---------------------------------------------------------------------------
meta_run() { # meta_run <fam> <ver> <rc> <version> <revision> <ref_name>
  local fam="$1" ver="$2" rc="$3" version="$4" rev="$5" refname="$6"
  local tmp; tmp="$(mktemp -d)"
  python3 - "$WF" "$fam" "$ver" > "$tmp/meta.sh" <<'PY'
import sys, yaml
wf, fam, ver = sys.argv[1], sys.argv[2], sys.argv[3]
d = yaml.safe_load(open(wf))
steps = d["jobs"]["publish"]["steps"]
run = [s for s in steps if s.get("id") == "meta"][0]["run"]
# Render only the matrix/run-number placeholders; everything else is real env.
run = (run.replace("${{ matrix.ver }}", ver)
          .replace("${{ matrix.fam }}", fam)
          .replace("${{ github.run_number }}", "777"))
assert "${{" not in run, "unrendered expression left in meta step: %r" % run
sys.stdout.write(run)
PY
  ( set -euo pipefail
    export REGISTRY=ghcr.io NAMESPACE=zenchron-dynamics
    export RC="$rc" VERSION="$version" EXPECTED_REVISION="$rev"
    export GITHUB_REF_NAME="$refname" GITHUB_OUTPUT="$tmp/out"
    : > "$tmp/out"
    bash "$tmp/meta.sh" >/dev/null 2>&1 ) || { echo "meta step failed" >&2; rm -rf "$tmp"; return 1; }
  cat "$tmp/out"; rm -rf "$tmp"
}
# label_for <key> <fam> <ver> <rc> <version> <revision> <ref_name>
# Runs the real meta step and prints one output value. Taking the arguments
# directly means there are no intermediate variables that only ck()'s eval
# reads, so a failed meta step surfaces as a failed assertion rather than
# silently becoming an empty string.
label_for() {
  local key="$1"; shift
  local out; out="$(meta_run "$@")" || { echo "META-STEP-FAILED"; return 0; }
  grep "^${key}=" <<<"$out" | tail -1 | cut -d= -f2-
}

# Read inside the strings ck() evals, which the linter cannot follow.
# shellcheck disable=SC2034
REV=1234567890abcdef1234567890abcdef12345678

# --- RC builds: the label must already be the CANONICAL selector, because the
# --- stable image is this very digest retagged.
ck "php RC computes a label at all" \
   "[ -n \"\$(label_for version_label php-cli 8.4 rc1 v2026.07.30 \"\$REV\" master)\" ]"
ck "php RC labels version 8.4-prod (not the rc-sha)" \
   "[ \"\$(label_for version_label php-cli 8.4 rc1 v2026.07.30 \"\$REV\" master)\" = 8.4-prod ]"
ck "php RC still tags the immutable rc-sha ref" \
   "grep -q 'sha-' <<<\"\$(label_for tags php-cli 8.4 rc1 v2026.07.30 \"\$REV\" master)\""
ck "php RC records the immutable suffix in ref.name" \
   "grep -q 'rc1-sha-' <<<\"\$(label_for ref_name_label php-cli 8.4 rc1 v2026.07.30 \"\$REV\" master)\""
ck "edge RC labels version prod (not prod-prod, not rc-sha)" \
   "[ \"\$(label_for version_label nginx prod rc1 v2026.07.30 \"\$REV\" master)\" = prod ]"

# --- stable builds
ck "php stable labels version 8.4-prod" \
   "[ \"\$(label_for version_label php-cli 8.4 '' v2026.07.30 \"\$REV\" v2026.07.30)\" = 8.4-prod ]"
ck "edge stable labels version prod" \
   "[ \"\$(label_for version_label caddy prod '' v2026.07.30 \"\$REV\" v2026.07.30)\" = prod ]"

# --- the promotion invariant that made this a real defect -------------------
# Promotion retags the RC digest, so the RC label IS the stable label. They must
# be equal for the same image, or the stable image lies about itself.
for spec in "php-cli 8.4 8.4-prod" "php-fpm 8.3 8.3-prod" "nginx prod prod" "caddy prod prod"; do
  read -r fam ver want <<<"$spec"
  ck "$fam $ver: RC label is already the canonical $want" \
     "[ \"\$(label_for version_label $fam $ver rc1 v2026.07.30 \"\$REV\" master)\" = \"$want\" ]"
  ck "$fam $ver: promoted (stable) label is the same $want" \
     "[ \"\$(label_for version_label $fam $ver '' v2026.07.30 \"\$REV\" v2026.07.30)\" = \"$want\" ]"
done

ck "promotion really does no build (so the baked label is final)" \
   "! grep -qE '^\s+uses: docker/build-push-action' .github/workflows/promote-stable.yml"

echo "----"; [ "$fail" -eq 0 ] && echo "test_oci_version_label: PASS" || echo "test_oci_version_label: FAIL"
exit $fail
