#!/usr/bin/env bash
# Phase A foundations: lib self-tests, schema loads, contract validity, and the
# critical matrix drift-guard (common.sh must agree with the existing consumers).
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

# 1. library self-tests
ck "common.sh self-test"           'bash scripts/lib/common.sh --self-test >/dev/null'
ck "registry-aliases.sh self-test" 'bash scripts/lib/registry-aliases.sh --self-test >/dev/null'
ck "release-manifest.sh self-test" 'bash scripts/lib/release-manifest.sh --self-test >/dev/null'

# 2. schemas are valid JSON and load as JSON Schema
for s in schemas/*.json; do
  ck "schema loads: $s" "python3 - <<PY
import json,sys,jsonschema
from jsonschema import Draft202012Validator
Draft202012Validator.check_schema(json.load(open('$s')))
PY"
done

# 3. contracts parse and cover the full matrix
ck "10 image contracts exist" 'test "$(ls contracts/images/*.yaml | wc -l | tr -d " ")" = 10'
for f in contracts/images/*.yaml; do ck "yaml valid: $f" "yq -e '.' '$f' >/dev/null"; done
ck "4 extension contracts"    'test "$(ls contracts/php-extensions/*.txt | wc -l | tr -d " ")" = 4'

# 4. MATRIX DRIFT GUARD — common.sh is the source of truth; the existing
#    consumers must not diverge from it.
. scripts/lib/common.sh >/dev/null 2>&1 || true
# common.sh families, sorted
COMMON_FAMS="$(matrix_families | tr '\n' ' ')"
ck "assert-image-matrix families match common.sh" '
  am=$(grep -oE "php-(cli|fpm|worker|frankenphp)|nginx|caddy" scripts/assert-image-matrix.sh | sort -u | tr "\n" " ")
  cm=$(matrix_families | sort -u | tr "\n" " ")
  [ "$am" = "$cm" ]'
ck "promote-stable IMAGES count == 10" '
  n=$(PROMOTE_LIB_ONLY=1; grep -E "^IMAGES=" scripts/promote-stable.sh | grep -oE "php-[a-z]+:[0-9.]+|caddy:prod|nginx:prod" | wc -l | tr -d " ")
  [ "$n" = "10" ]'
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
