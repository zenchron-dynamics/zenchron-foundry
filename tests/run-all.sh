#!/usr/bin/env bash
# =============================================================================
# tests/run-all.sh — discover and run every tests/**/test_*.sh.
# Offline, assert-based, no framework. Exit non-zero if any test fails.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

pass=0 fail=0 failed=""
while IFS= read -r t; do
  echo "### $t"
  if bash "$t"; then pass=$((pass+1)); else fail=$((fail+1)); failed="$failed $t"; fi
  echo
done < <(find tests -name 'test_*.sh' | sort)

echo "================================================================"
printf 'tests: %d passed, %d failed\n' "$pass" "$fail"
[ -n "$failed" ] && printf 'FAILED:%s\n' "$failed"
[ "$fail" -eq 0 ]
