#!/usr/bin/env bash
# =============================================================================
# tests/run-all.sh — discover and run every tests/**/test_*.sh.
# Offline, assert-based, no framework. Exit non-zero if any test fails.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1

# Tests that MUST be in the run, named rather than merely discovered.
#
# WHY A LIST AT ALL, when discovery already finds everything. Discovery is a
# pattern, and a pattern silently matches less when a file is renamed, moved
# out of tests/, or deleted. For most tests that is acceptable — losing one
# loses one subsystem's unit coverage, and
# tests/governance/test_subsystem_ci_coverage.sh binds each subsystem to a test
# that names it. The end-to-end composition test is different: it is the ONLY
# thing that asserts the OUTPUT of one subsystem is the INPUT the next reads,
# and every per-subsystem suite stays green when it disappears. Losing it
# silently is precisely the failure it exists to detect, so it is named here
# and its absence FAILS the run.
REQUIRED_TESTS="tests/integration/test_evidence_path_e2e.sh"

pass=0 fail=0 failed="" missing=""
discovered="$(find tests -name 'test_*.sh' | sort)"

for r in $REQUIRED_TESTS; do
  # here-string, NOT a pipe into grep -q: grep exits on the first match, the
  # producer takes SIGPIPE, and pipefail reports 141 intermittently.
  if ! grep -qx -- "$r" <<<"$discovered"; then
    missing="$missing $r"
  fi
done

while IFS= read -r t; do
  [ -n "$t" ] || continue
  echo "### $t"
  if bash "$t"; then pass=$((pass+1)); else fail=$((fail+1)); failed="$failed $t"; fi
  echo
done <<<"$discovered"

echo "================================================================"
printf 'tests: %d passed, %d failed\n' "$pass" "$fail"
[ -n "$failed" ] && printf 'FAILED:%s\n' "$failed"
if [ -n "$missing" ]; then
  printf 'MISSING REQUIRED TEST(S):%s\n' "$missing"
  echo "A required test is not in the discovery chain. It was renamed, moved out"
  echo "of tests/, or deleted. Restore it or change REQUIRED_TESTS deliberately."
  fail=$((fail+1))
fi
[ "$fail" -eq 0 ]
