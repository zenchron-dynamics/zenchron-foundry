#!/usr/bin/env bash
# Phase A foundations: lib self-tests, schema loads, contract validity, and the
# critical matrix drift-guard (common.sh must agree with the existing consumers).
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

# 1. library self-tests
ck "common.sh self-test"           'bash scripts/lib/common.sh --self-test >/dev/null'
ck "registry-aliases.sh self-test" 'bash scripts/lib/registry-aliases.sh --self-test >/dev/null'
ck "release-manifest.sh self-test" 'bash scripts/lib/release-manifest.sh --self-test >/dev/null'
ck "registry-ops.sh self-test"     'bash scripts/lib/registry-ops.sh --self-test >/dev/null'
ck "cosign-identity.sh self-test"  'bash scripts/lib/cosign-identity.sh --self-test >/dev/null'
ck "repo-identity.sh self-test"    'bash scripts/lib/repo-identity.sh --self-test >/dev/null'

# 2. schemas are valid JSON and load as JSON Schema
for s in schemas/*.json; do
  ck "schema loads: $s" "python3 - <<PY
import json,sys,jsonschema
from jsonschema import Draft202012Validator
Draft202012Validator.check_schema(json.load(open('$s')))
PY"
done

# 3. contracts parse and cover the full matrix
# Subset, not equality: the four PHP 8.5 contracts are retained on purpose while
# 8.5 is out of the live matrix (it does not build — see policies/lifecycle.yaml).
# What must hold is that every SHIPPING image has a contract.
. scripts/lib/common.sh
_missing_contract=""
for _t in $MATRIX_IMAGES; do
  _f="contracts/images/${_t%:*}-${_t#*:}.yaml"
  [ -f "$_f" ] || _missing_contract="$_missing_contract $_f"
done
ck "an image contract exists for every matrix image" '[ -z "$_missing_contract" ]'
for f in contracts/images/*.yaml; do ck "yaml valid: $f" "yq -e '.' '$f' >/dev/null"; done
ck "an extension contract exists for every declaring image contract" \
   'test "$(ls contracts/php-extensions/*.txt | wc -l | tr -d " ")" \
      = "$(grep -h "^extensions_contract:" contracts/images/*.yaml | sort -u | wc -l | tr -d " ")"'

# 4. MATRIX DRIFT GUARD — common.sh is the source of truth; the existing
#    consumers must not diverge from it. A common.sh that fails to source must
#    fail the suite LOUDLY (PT-13) — silently continuing would let every
#    downstream matrix assertion run against unset/stale definitions.
. scripts/lib/common.sh >/dev/null 2>&1 \
  || { echo "FAIL - scripts/lib/common.sh failed to source (aborting suite)"; exit 1; }
ck "assert-image-matrix families match common.sh" '
  am=$(grep -oE "php-(cli|fpm|worker|frankenphp)|nginx|caddy" scripts/assert-image-matrix.sh | sort -u | tr "\n" " ")
  cm=$(matrix_families | sort -u | tr "\n" " ")
  [ "$am" = "$cm" ]'
ck "promote-stable derives matrix from the shared lib (no local IMAGES=)" '
  grep -q "registry-aliases.sh" scripts/promote-stable.sh && ! grep -qE "^IMAGES=" scripts/promote-stable.sh'
ck "each contract selector is in the matrix" '
  ok=1
  for f in contracts/images/*.yaml; do
    img=$(yq -r ".image" "$f"); sel=$(yq -r ".selector" "$f")
    case " $MATRIX_IMAGES " in *" $img:$sel "*) : ;; *) echo "  drift: $img:$sel not in matrix"; ok=0 ;; esac
  done
  [ "$ok" = 1 ]'

echo "----"
[ "$fail" -eq 0 ] && echo "test_foundations: PASS" || echo "test_foundations: FAIL"
exit $fail
