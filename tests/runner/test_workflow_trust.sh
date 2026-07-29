#!/usr/bin/env bash
# =============================================================================
# tests/runner/test_workflow_trust.sh — CI trust boundary (issue #96).
#
# Proves the invariant itself, not the presence of a comment: a fork pull
# request must never be schedulable on the persistent privileged self-hosted
# runners. The regression case rebuilds the pre-fix shape from the CURRENT
# ci.yml (static privileged label list) and requires the gate to reject it, so
# the test keeps failing on the old implementation as the workflow evolves.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

GATE="scripts/assert-runner-trust.sh"
TRUST_EXPR='github.event.pull_request.head.repo.full_name == github.repository'

ck "runner-trust gate self-test passes"        "bash $GATE --self-test >/dev/null"
ck "runner-trust gate passes on this repo"     "bash $GATE >/dev/null"

# Regression: the pre-fix shape must FAIL. Rebuild it by collapsing every
# trust-conditional runs-on back to the static privileged label list.
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cp .github/workflows/ci.yml "$tmp/ci.yml"
sed -i.bak -E "s|^    runs-on: \\\$\{\{ fromJSON.*\}\}$|    runs-on: [self-hosted, linux, x64, zenchron]|" "$tmp/ci.yml"
rm -f "$tmp/ci.yml.bak"
ck "fixture actually collapsed to the static privileged list" \
   "grep -q '^    runs-on: \[self-hosted, linux, x64, zenchron\]' $tmp/ci.yml"
ck "pre-fix shape (static privileged runs-on) is REJECTED" \
   "! bash $GATE $tmp >/dev/null 2>&1"

# Every ci.yml job must resolve its runner from the trigger's trust, and the
# fork fallback must be a GitHub-hosted (ephemeral) runner.
ck "no ci.yml job pins the privileged pool statically" \
   "! grep -qE '^    runs-on: \[self-hosted' .github/workflows/ci.yml"
ck "every ci.yml runs-on carries the same-repo trust predicate" \
   "[ \"\$(grep -c '^    runs-on:' .github/workflows/ci.yml)\" = \"\$(grep -c \"^    runs-on:.*${TRUST_EXPR}\" .github/workflows/ci.yml)\" ]"
ck "ci.yml fork fallback is a GitHub-hosted runner" \
   "! grep -E '^    runs-on:' .github/workflows/ci.yml | grep -qv 'ubuntu-latest'"

# pull_request_target is never acceptable in this repository.
# Review found two bypasses in the first, text-matching implementation. Lock
# both shut here as well as in the gate's own self-test.
ck "gate parses YAML rather than matching text" \
   "test -f scripts/lib/runner_trust.py && grep -q 'runner_trust.py' scripts/assert-runner-trust.sh"
ck "inline trigger list is covered (R1 bypass)" \
   "grep -q \"on: \[push, pull_request_target\]\" scripts/assert-runner-trust.sh"
ck "predicate under an unrelated key is covered (R2 bypass)" \
   "grep -q \"does NOT satisfy the gate\" scripts/assert-runner-trust.sh"

ck "no workflow uses pull_request_target" \
   "! grep -rlE '^[[:space:]]+pull_request_target:' .github/workflows/ | grep -q ."

# The gate must be wired into the static gates, not merely present on disk.
ck "gate runs in ci.yml structure job" \
   "grep -q 'scripts/assert-runner-trust.sh' .github/workflows/ci.yml"
ck "gate runs in 'make validate'" \
   "grep -q 'scripts/assert-runner-trust.sh' Makefile"

echo "----"; [ "$fail" -eq 0 ] && echo "test_workflow_trust: PASS" || echo "test_workflow_trust: FAIL"
exit $fail
