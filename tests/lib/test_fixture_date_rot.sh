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

# --- SABOTAGE: reintroduce each real rotting fixture and require refusal -----
# Both dates below are the ACTUAL values that were in the tree. 2026-08-26 had
# already detonated (it turned master red on the day it arrived); 2026-12-31 had
# not gone off yet and was found by this guard. A sabotage that only replays the
# one that exploded would not prove the guard catches the quiet kind.
_scan_dir() {  # <dir> -> risky entries, using the same rule as the real check
  local d="$1" f dd out=""
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    f="${line%%:*}"
    dd="$(printf '%s' "$line" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' | tail -1)"
    [ -n "$dd" ] || continue
    [ "$dd" ">" "$horizon" ] && continue
    grep -q -- '--today' "$f" || out="$out $f:$dd"
  done < <(grep -rnE '^[[:space:]]*expires_at:[[:space:]]*[0-9]{4}-[0-9]{2}-[0-9]{2}' "$d" 2>/dev/null)
  printf '%s' "$out"
}

for _bad in 2026-08-26 2026-12-31; do
  _sb="$(mktemp -d)"; mkdir -p "$_sb/t"
  printf 'ck "x" "true"\n    expires_at: %s\n' "$_bad" > "$_sb/t/test_planted.sh"
  ck "SABOTAGE: a fixture expiring $_bad without --today is REFUSED" \
     "[ -n \"$(_scan_dir "$_sb")\" ]"
  # ...and the SAME fixture becomes acceptable once the file pins --today,
  # which is the documented escape hatch for tests that exercise expiry itself.
  printf 'bash r.sh --today %s\n    expires_at: %s\n' "$_bad" "$_bad" > "$_sb/t/test_planted.sh"
  ck "...but is ACCEPTED when that same file pins --today (expiry tests stay possible)" \
     "[ -z \"$(_scan_dir "$_sb")\" ]"
  rm -rf "$_sb"
done

# --- the detector must NOT police real policy files -------------------------
# policies/vulnerability-exceptions.yaml legitimately carries 55 entries dated
# 2026-08-31 and 4 dated 2026-09-01. Those are REAL risk decisions whose lapsing
# is the entire point of the gate. A guard that flagged them would be demanding
# the ledger lie about its own expiry dates.
ck "real policy expiries exist and are well inside the horizon" \
   "[ \"$(grep -cE '^[[:space:]]*expires_at:[[:space:]]*2026-' policies/vulnerability-exceptions.yaml)\" -ge 50 ]"
# The exemption is LOAD-BEARING, not incidental: applying the identical rule to
# policies/ flags dozens of real records. What keeps them safe is that the
# production scan only ever looks at tests/.
ck "applying the same rule to policies/ WOULD flag real records (exemption matters)" \
   "[ -n \"$(_scan_dir policies)\" ]"
ck "...and the real detector never reaches a policy file" \
   "[ \"$(fixture_expiries | grep -c '^policies/')\" = 0 ]"

echo "----"
[ "$fail" -eq 0 ] && echo "test_fixture_date_rot: PASS" || echo "test_fixture_date_rot: FAIL"
exit $fail
