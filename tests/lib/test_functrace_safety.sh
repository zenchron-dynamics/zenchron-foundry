#!/usr/bin/env bash
# shellcheck disable=SC2034
# =============================================================================
# tests/lib/test_functrace_safety.sh
# -----------------------------------------------------------------------------
# THE FLAKE THIS EXISTS FOR. PR #198 failed four vulnerability-policy suites
# together, then passed on a rerun with ZERO code changes. All four call
# scripts/ci/assert-no-stale-exceptions.sh --self-test.
#
# Root cause: that self-test cleaned up with
#
#     trap "rm -rf '$tmp'" RETURN
#
# A RETURN trap fires on the return of ANY function while it is active once bash
# functrace (set -T) is on — including the ~22 calls to the inner t() helper. The
# fixture directory was deleted after the FIRST assertion and everything after it
# failed on missing files. Whether that happened depended on whether functrace was
# inherited, which is why it looked like noise.
#
# 19 scripts carried the same construct. EXIT is scope-independent and fires
# exactly once, so it is correct with or without functrace.
#
# Reproduce the original defect:  bash -T <script> --self-test
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# --- the construct is gone, everywhere -------------------------------------
offenders="$(grep -rnE "\btrap\s+('[^']*'|\"[^\"]*\")\s+RETURN\b" scripts/ 2>/dev/null || true)"
ck "no script cleans up with a RETURN trap" \
   "[ -z \"\$offenders\" ] || { printf 'offenders:\n%s\n' \"\$offenders\"; false; }"

# Non-vacuity: the search must actually be able to find the construct.
printf 'f() { trap "rm -rf /x" RETURN; }\n' > "$TMP/probe.sh"
ck "...and that search is not vacuous — it matches a planted RETURN trap" \
   "grep -qE \"\\btrap\\s+('[^']*'|\\\"[^\\\"]*\\\")\\s+RETURN\\b\" '$TMP/probe.sh'"

# --- the previously-flaky self-tests must pass UNDER functrace -------------
# These are the four suites' shared dependency plus the other fast fixtures that
# carried the same construct. Slow/network self-tests are deliberately excluded;
# the static check above covers them.
# The invariant is that functrace must not CHANGE the outcome, asserted first
# because it isolates this defect from any unrelated exit-code quirk. All of
# these are additionally clean in both modes today.
for s in scripts/ci/assert-no-stale-exceptions.sh \
         scripts/reconcile-vulnerabilities.sh \
         scripts/release/evidence-checksum.sh \
         scripts/release/assert-native-arch-evidence.sh \
         scripts/assert-lifecycle.sh; do
  bash    "$s" --self-test >/dev/null 2>&1; plain=$?
  bash -T "$s" --self-test >/dev/null 2>&1; traced=$?
  ck "$(basename "$s"): functrace does not change the outcome ($plain vs $traced)" \
     "[ '$plain' -eq '$traced' ]"
done

# And every one of them must be green outright, in both modes.
for s in scripts/ci/assert-no-stale-exceptions.sh scripts/reconcile-vulnerabilities.sh \
         scripts/release/evidence-checksum.sh scripts/assert-lifecycle.sh \
         scripts/assert-publish-platforms-reconciled.sh; do
  bash -T "$s" --self-test >/dev/null 2>&1; rc=$?
  ck "$(basename "$s") self-tests CLEAN under functrace" "[ '$rc' -eq 0 ]"
done

# --- SABOTAGE: put the defect back and prove it is detected ----------------
# The sabotage copy used to be written to $ROOT/scripts/ci/, i.e. INTO THE REAL
# CHECKOUT, because the script under test resolves its own root as
# `dirname $BASH_SOURCE/../..` and must find scripts/lib/common.sh relative to
# it. An EXIT trap removed it — but a SIGKILL, a CI cancellation or a crash
# leaves a stray `.functrace-sabotage-*.sh` sitting in scripts/ci/. That is the
# ambient-mutation class tests/lib/test_no_ambient_mutation.sh exists to refuse,
# and this test was itself an instance of it.
#
# Fixed with a MIRROR ROOT under $TMP: every path the script needs is symlinked
# in, so `../..` resolves to the mirror. Read-only symlinks, and exactly one
# real file — the sabotage itself.
MIRROR="$TMP/mirror"
mkdir -p "$MIRROR/scripts/ci"
for e in "$ROOT"/*; do
  [ "$(basename "$e")" = scripts ] || ln -sfn "$e" "$MIRROR/$(basename "$e")"
done
for e in "$ROOT"/scripts/*; do
  [ "$(basename "$e")" = ci ] || ln -sfn "$e" "$MIRROR/scripts/$(basename "$e")"
done
for e in "$ROOT"/scripts/ci/*; do ln -sfn "$e" "$MIRROR/scripts/ci/$(basename "$e")"; done
SAB="$MIRROR/scripts/ci/.functrace-sabotage-$$.sh"
# shellcheck disable=SC2064
trap "rm -rf '$TMP'" EXIT
sed "s|trap \"rm -rf '\${tmp}'\" EXIT|trap \"rm -rf '\${tmp}'\" RETURN|" \
    scripts/ci/assert-no-stale-exceptions.sh > "$SAB"
ck "SABOTAGE fixture really restored the RETURN trap" \
   "grep -qE '\\btrap .* RETURN\\b' '$SAB'"
bash -T "$SAB" --self-test >"$TMP/sab.out" 2>&1; sabrc=$?
ck "SABOTAGE: the restored RETURN trap FAILS under functrace" "[ '$sabrc' -ne 0 ]"
ck "...because the fixture directory was destroyed mid-run" \
   "grep -qE 'No such file or directory' '$TMP/sab.out'"
bash "$SAB" --self-test >/dev/null 2>&1; sabplain=$?
ck "...while the SAME sabotage passes WITHOUT functrace — the exact flake shape" \
   "[ '$sabplain' -eq 0 ]"

# A single-quoted EXIT trap defers expansion to script exit, when a `local` is
# already out of scope -> "unbound variable" under set -u. I introduced exactly
# that while converting RETURN->EXIT; it broke five self-tests. Bake the value in.
deferred="$(grep -rnE "trap[[:space:]]+'rm -rf \"\\\$\{?[a-zA-Z_]+\}?\"'[[:space:]]+EXIT" scripts/ 2>/dev/null || true)"
ck "no EXIT trap defers expansion of a local past its scope" \
   "[ -z \"\$deferred\" ] || { printf 'deferred:\n%s\n' \"\$deferred\"; false; }"

echo "----"; [ "$fail" -eq 0 ] && echo "test_functrace_safety: PASS" || echo "test_functrace_safety: FAIL"
exit $fail
