#!/usr/bin/env bash
# Test fixtures must not carry an expiry the wall clock can reach.
#
# WHY. tests/vulnerability-policy/test_cve_2026_14456_governance.sh built a
# fixture ledger with `expires_at: 2026-08-26`. On 2026-08-26 that became
# "today", and because the reconciler refuses at `expires_at <= today`, two
# SELECTOR sabotages went red — they stopped proving anything about selectors
# and started proving the clock had moved. master was red for a reason no
# commit caused.
#
# A fixture whose meaning changes with the date is a time bomb with a
# commit-shaped blast radius: it fails on an unrelated PR, on a day nobody
# chose, and the diff under review looks guilty.
#
# THE RULE. A fixture expiry must either be the far-future sentinel the repo
# already uses (2099-01-01), or the test must pin `--today` so the comparison
# is deterministic. Real POLICY files are exempt: their expiries are supposed
# to be real dates, and letting them lapse is the entire point of the gate.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

# Every expires_at literal written INSIDE a test file (fixtures), with its file.
fixture_expiries() {
  grep -rnE '^[[:space:]]*expires_at:[[:space:]]*[0-9]{4}-[0-9]{2}-[0-9]{2}' tests/ 2>/dev/null
}

today="$(date -u +%F)"
horizon="2027-01-01"   # a fixture expiring before this is close enough to rot
_risky=""
while IFS= read -r line; do
  [ -n "$line" ] || continue
  f="${line%%:*}"
  d="$(printf '%s' "$line" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' | tail -1)"
  [ -n "$d" ] || continue
  # far-future sentinel is always fine
  [ "$d" ">" "$horizon" ] && continue
  # otherwise the file must pin --today, making the comparison deterministic
  grep -q -- '--today' "$f" || _risky="$_risky $f:$d"
done < <(fixture_expiries)

ck "NON-VACUOUS: fixtures with expiries exist to check" \
   "[ \"\$(fixture_expiries | wc -l)\" -ge 1 ]"
ck "no test fixture carries a reachable expiry without pinning --today" \
   "[ -z \"\$_risky\" ] || { printf 'rots:%s\n' \"\$_risky\"; false; }"
ck "NON-VACUOUS: a date before the horizon really is treated as reachable" \
   "[ \"2026-08-26\" \"<\" \"$horizon\" ]"
ck "...and the sentinel really is treated as safe" \
   "[ \"2099-01-01\" \">\" \"$horizon\" ]"
ck "sanity: today is before the horizon, so this guard is still meaningful" \
   "[ \"$today\" \"<\" \"$horizon\" ]"

echo "----"
[ "$fail" -eq 0 ] && echo "test_fixture_date_rot: PASS" || echo "test_fixture_date_rot: FAIL"
exit $fail
