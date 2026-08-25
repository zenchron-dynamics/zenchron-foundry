#!/usr/bin/env bash
# Every release-gating subsystem must be reachable from a check that actually
# runs on pull requests.
#
# WHY. The five subsystems merged in #199-#207 (licence, CRA, continuity,
# reproducibility, evidence bundle) are invoked by NO workflow directly. They
# are gated only transitively: tests/run-all.sh discovers every
# tests/**/test_*.sh, and the required `repo structure` job runs run-all. That
# is real coverage — but nothing asserted it. Move a test out of tests/, rename
# it away from test_*.sh, or drop the run-all step, and the subsystem becomes
# ungated with no signal at all. A control nobody can notice losing is the
# vacuous-check class this repository keeps paying for.
#
# This test binds the chain end to end: script -> a test that exercises it ->
# run-all's own discovery -> a REQUIRED PR check.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

# The subsystems that gate a release. Adding one here without a test that
# exercises it is a failure, which is the point.
SUBSYSTEMS="
scripts/license/assert-license-policy.sh
scripts/cra/assert-cra-controls.sh
scripts/continuity-verify.sh
scripts/repro-guarantees.sh
scripts/release/generate-evidence-bundle.sh
scripts/release/assert-evidence-class.sh
scripts/governance-content-binding.sh
"

# run-all's discovery, re-derived rather than assumed. If run-all changes how it
# finds tests, this list changes with it.
discovered() { find tests -name 'test_*.sh' | sort; }

# A test "covers" a subsystem if it names it AND run-all would discover it.
covers() {
  local script="$1" t
  while IFS= read -r t; do
    [ -n "$t" ] || continue
    case "$t" in
      tests/integration/*) continue ;;          # e2e pins gaps, not coverage
      */test_subsystem_ci_coverage.sh) continue ;;  # this file NAMES every
      # subsystem, including the deliberately-uncovered probe below. Counting
      # itself would make every assertion here self-satisfying.
    esac
    grep -q -- "$script" "$t" && { echo "$t"; return 0; }
  done < <(discovered)
  return 1
}

for s in $SUBSYSTEMS; do
  ck "exists: $s" "[ -f '$s' ]"
  ck "a run-all-discovered test exercises $(basename "$s")" "covers '$s' >/dev/null"
done

# NON-VACUITY 1: the discovery must actually find tests.
ck "NON-VACUOUS: run-all's discovery finds tests at all" \
   "[ \"\$(discovered | wc -l)\" -ge 20 ]"
# NON-VACUITY 2: a subsystem no test mentions must FAIL the check above.
ck "NON-VACUOUS: an uncovered subsystem is rejected" \
   "! covers 'scripts/this-subsystem-has-no-test.sh' >/dev/null"

# The chain's last link: run-all is what a REQUIRED check runs. Both halves are
# asserted, so neither the step nor the check name can drift away alone.
ck "the CI workflow runs the offline suite" \
   "grep -q 'bash tests/run-all.sh' .github/workflows/ci.yml"
ck "...in a job whose name is a REQUIRED pr check" \
   'jn=$(yq -r ".jobs.structure.name" .github/workflows/ci.yml)
    req=$(yq -r ".pr_required_checks[]" policies/required-release-checks.yaml)
    # here-string, NOT a pipe. `yq | grep -q` makes grep exit on the first
    # match, yq take SIGPIPE, and pipefail report 141 — intermittently, which
    # is how it passed once here before failing twice. Same class as the
    # RETURN-trap flake: a green run that proves nothing.
    grep -qx "$jn" <<<"$req"'
ck "NON-VACUOUS: that job name lookup resolves to a real name" \
   '[ "$(yq -r ".jobs.structure.name" .github/workflows/ci.yml)" != "null" ]'

echo "----"
[ "$fail" -eq 0 ] && echo "test_subsystem_ci_coverage: PASS" || echo "test_subsystem_ci_coverage: FAIL"
exit $fail
