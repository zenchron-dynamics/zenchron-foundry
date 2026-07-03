#!/usr/bin/env bash
# Phase H — runtime + multi-arch certification helpers + workflow shape.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

ck "verify-platforms self-test"       'bash scripts/verify-platforms.sh --self-test >/dev/null'
ck "verify-image-contract self-test"  'bash scripts/verify-image-contract.sh --self-test >/dev/null'

# verify-rc.yml certifies the full 10-image matrix
ck "verify-rc certify matrix has 10 images" \
   'test "$(yq -r ".jobs.certify.strategy.matrix.include | length" .github/workflows/verify-rc.yml) " = "10 "'
ck "verify-rc runs smoke per image"   'grep -q "scripts/smoke/" .github/workflows/verify-rc.yml'
ck "verify-rc runs contract check"    'grep -q "verify-image-contract.sh" .github/workflows/verify-rc.yml'
ck "verify-rc checks published platforms" 'grep -q "verify-platforms.sh" .github/workflows/verify-rc.yml'

# every matrix image has a contract file
ck "10 image contracts back the matrix" 'test "$(ls contracts/images/*.yaml | wc -l | tr -d " ")" = 10'

echo "----"; [ "$fail" -eq 0 ] && echo "test_runtime: PASS" || echo "test_runtime: FAIL"
exit $fail
