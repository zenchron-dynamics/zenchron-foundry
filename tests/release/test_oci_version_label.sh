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
for v in 8.3 8.4; do
  for fam in php-cli php-fpm php-worker; do
    ck "images/$fam/$v declares version=$v-prod" \
       "grep -q 'org.opencontainers.image.version=\"$v-prod\"' images/$fam/$v/Dockerfile"
  done
done

echo "----"; [ "$fail" -eq 0 ] && echo "test_oci_version_label: PASS" || echo "test_oci_version_label: FAIL"
exit $fail
