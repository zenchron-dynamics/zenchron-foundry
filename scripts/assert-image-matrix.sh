#!/usr/bin/env bash
# =============================================================================
# assert-image-matrix.sh
# -----------------------------------------------------------------------------
# self-test: waived (thin wrapper; exercised by the "image matrix (10/10)" gate
# in scripts/macro-validate.sh, ci.yml, and tests/lib/test_foundations.sh's
# matrix drift-guard)
#
# Asserts the production image matrix — derived from MATRIX_IMAGES in
# scripts/lib/common.sh, the ONE authoritative definition — is exactly the
# expected images, each backed by a Dockerfile on disk:
#
#   php-cli/8.3        php-cli/8.4
#   php-fpm/8.3        php-fpm/8.4
#   php-worker/8.3     php-worker/8.4
#   php-frankenphp/8.3 php-frankenphp/8.4
#   nginx              caddy
#
# Also fails if any forbidden legacy PHP line is present (php-*/7.4, php-*/8.0).
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/common.sh
. "$ROOT/scripts/lib/common.sh"

IMAGES="${ROOT}/images"

# Expected Dockerfile list, derived from the authoritative matrix:
# <family>:<selector> -> family/selector/Dockerfile (family/Dockerfile for the
# versionless "prod" edge images). No local copy of the matrix (SC-07).
EXPECTED=()
while IFS= read -r token; do
  [ -n "$token" ] || continue
  fam="${token%:*}"; sel="${token#*:}"
  case "$sel" in
    prod) EXPECTED+=("${fam}/Dockerfile") ;;
    *)    EXPECTED+=("${fam}/${sel}/Dockerfile") ;;
  esac
done < <(matrix_images)

# INTENTIONAL independent count assertion: the literal 10 is NOT taken from
# MATRIX_COUNT, so an accidental edit shrinking/growing MATRIX_IMAGES is caught
# here instead of silently re-baselining the gate.
if [[ "${#EXPECTED[@]}" -ne 10 ]]; then
  die "matrix derived ${#EXPECTED[@]} images, expected exactly 10 — MATRIX_IMAGES drifted"
fi

missing=0
found=0

echo "=== Required image matrix ==="
for rel in "${EXPECTED[@]}"; do
  if [[ -f "${IMAGES}/${rel}" ]]; then
    echo "OK:      images/${rel}"
    found=$((found + 1))
  else
    echo "MISSING: images/${rel}"
    missing=$((missing + 1))
  fi
done

echo
echo "=== Forbidden legacy lines ==="
forbidden=0
for legacy in 7.4 8.0; do
  while IFS= read -r dir; do
    echo "FORBIDDEN: ${dir#"${ROOT}/"}"
    forbidden=$((forbidden + 1))
  done < <(find "${IMAGES}" -type d -path "*/php-*/${legacy}" 2>/dev/null || true)
done
if [[ "${forbidden}" -eq 0 ]]; then
  echo "none"
fi

# --- the schema's matrix literals are a DECLARED boundary, not a stale copy ---
# schemas/release-manifest.schema.json pins the image count as two literals and
# enumerates the PHP minors it will accept. Both are deliberate — a release
# manifest with nine images, or one carrying a line that does not build, must
# not validate — but a literal that nothing compares against is a stale
# assumption waiting to happen. It is compared HERE, against MATRIX_IMAGES, so
# the schema and the matrix cannot drift apart silently.
echo
echo "=== Release-manifest schema boundary ==="
schema_drift=0
if ! MATRIX_COUNT="$MATRIX_COUNT" MATRIX_IMAGES="$MATRIX_IMAGES" python3 - \
     "${ROOT}/schemas/release-manifest.schema.json" <<'PY'
import json, os, re, sys
want_n = int(os.environ["MATRIX_COUNT"])
tokens = os.environ["MATRIX_IMAGES"].split()
s = json.load(open(sys.argv[1]))["properties"]["images"]
ok = True
if s.get("minProperties") != want_n or s.get("maxProperties") != want_n:
    print("DRIFT: schema pins %s..%s images, MATRIX_COUNT is %d"
          % (s.get("minProperties"), s.get("maxProperties"), want_n))
    ok = False
if s.get("additionalProperties") is not False:
    print("DRIFT: the images object accepts additional properties, so an "
          "undeclared image line would validate")
    ok = False
pats = list(s.get("patternProperties") or {})
if len(pats) != 1:
    print("DRIFT: expected exactly one key pattern, found %d" % len(pats))
    ok = False
else:
    pat = pats[0]
    for t in tokens:
        fam, _, sel = t.partition(":")
        key = fam if sel == "prod" else "%s-%s" % (fam, sel)
        if not re.match(pat, key):
            print("DRIFT: shipping image %r does not match the schema key "
                  "pattern %r" % (key, pat))
            ok = False
    # DELIBERATELY UNREPRESENTABLE. php-cli-8.5 exists on disk, is contracted
    # and is tested, but it does not build (see MATRIX_IMAGES in
    # scripts/lib/common.sh and policies/lifecycle.yaml php-8.5). The schema
    # must continue to refuse it: an experimental line must not be able to
    # enter a release manifest at all. This asserts the refusal, so nobody
    # "fixes" the pattern into accepting it without deciding to.
    for excluded in ("php-cli-8.5", "php-fpm-8.5", "php-worker-8.5",
                     "php-frankenphp-8.5"):
        if re.match(pat, excluded):
            print("DRIFT: the schema would accept %r. PHP 8.5 is deliberately "
                  "outside the shipping matrix and must remain unrepresentable "
                  "in a release manifest" % excluded)
            ok = False
print("schema images: min=%s max=%s pattern=%s"
      % (s.get("minProperties"), s.get("maxProperties"), pats[0] if pats else None))
sys.exit(0 if ok else 1)
PY
then
  schema_drift=1
fi

echo
echo "=== Summary ==="
printf 'FOUND=%d/%d MISSING=%d FORBIDDEN=%d SCHEMA_DRIFT=%d\n' \
  "${found}" "${MATRIX_COUNT}" "${missing}" "${forbidden}" "${schema_drift}"

if [[ "${missing}" -gt 0 || "${forbidden}" -gt 0 || "${schema_drift}" -gt 0 ]]; then
  echo "RESULT: FAIL"
  exit 1
fi

echo "MATRIX OK: ${found}/${MATRIX_COUNT}"
