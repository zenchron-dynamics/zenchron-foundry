#!/usr/bin/env bash
# =============================================================================
# tests/lib/test_pipefail_sigpipe.sh
# -----------------------------------------------------------------------------
# THE FLAKE THIS EXISTS FOR — the SECOND one, distinct from the RETURN-trap
# defect that tests/lib/test_functrace_safety.sh guards.
#
# scripts/ci/assert-no-stale-exceptions.sh --self-test failed INTERMITTENTLY on
# GitHub-hosted runners on 2026-08-24/25 (CI runs 32814974957, 32815714210,
# 32817501744), passed on re-run of byte-identical code, and passed on macOS
# every single time. One of those runs reported `plain=1, traced=0` — the
# ORDINARY run failed and the functrace run passed — which ruled functrace out.
#
# Root cause: the self-test asserted
#
#     canonical_images | grep -qx nginx/prod && canonical_images | grep -qx php-cli/8.3
#
# under `set -o pipefail`. `grep -q` exits at the FIRST match. `php-cli/8.3` is
# the FIRST of the ten labels, so `matrix_image_labels` — a `while read` loop
# that printf's one line per iteration — is still writing the other nine when
# the read end of the pipe closes. The producer is killed by SIGPIPE, the
# pipeline's status becomes 141, `pipefail` propagates it, the `&&` chain
# short-circuits, and the assertion reports FAIL with nothing at all wrong with
# the image matrix. A REAL refusal and this NON-refusal were indistinguishable.
#
# Whether the producer flushed all ten lines before grep exited is a pure
# scheduling race between two processes. Measured with 300 trials per platform:
#   macOS bash 3.2.57  ->   0/300 SIGPIPE   (which is why it never reproduced locally)
#   Linux bash 5.2.21  -> 289/300 SIGPIPE
#
# The two arms below are the regression. Arm 1 drives the REAL script with a
# deliberately slowed producer, where the race is no longer a race: if the old
# pipeline were still there it would SIGPIPE every time. Arm 2 proves that claim
# is not hypothetical by running the old construct against the same slowed
# producer and demanding exit 141 — so arm 1 can never pass vacuously.
#
# Reproduce the original defect by hand:
#   tests/tools/stress-stale-exception-selftest.sh --linux
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }
TMP="$(mktemp -d)"
# expand NOW: TMP must still be spelled correctly at exit. EXIT, never RETURN.
# shellcheck disable=SC2064
trap "rm -rf '$TMP'" EXIT

# --- a MIRROR ROOT whose only real file is a slowed scripts/lib/common.sh ----
# assert-no-stale-exceptions.sh resolves its own root as
# `dirname $BASH_SOURCE/../..`, so invoking the mirrored path makes it source
# the mirrored library. Everything else is a read-only symlink to the real tree:
# this test mutates NOTHING under the ambient checkout (see
# tests/lib/test_no_ambient_mutation.sh).
MIRROR="$TMP/mirror"
mkdir -p "$MIRROR/scripts/lib"
for e in "$ROOT"/*; do
  [ "$(basename "$e")" = scripts ] || ln -sfn "$e" "$MIRROR/$(basename "$e")"
done
for e in "$ROOT"/scripts/*; do
  [ "$(basename "$e")" = lib ] || ln -sfn "$e" "$MIRROR/scripts/$(basename "$e")"
done
for e in "$ROOT"/scripts/lib/*; do
  [ "$(basename "$e")" = common.sh ] || ln -sfn "$e" "$MIRROR/scripts/lib/$(basename "$e")"
done

# One sleep per emitted label. 10 labels x 30ms = the producer is unambiguously
# still writing when a short-circuiting reader closes the pipe.
sed 's|while read -r t; do image_label|while read -r t; do sleep 0.03; image_label|' \
    "$ROOT/scripts/lib/common.sh" > "$MIRROR/scripts/lib/common.sh"
ck "the slow-producer fixture really slowed matrix_image_labels" \
   "grep -q 'sleep 0.03; image_label' '$MIRROR/scripts/lib/common.sh'"
ck "...and it is the ONLY real file in the mirror (nothing else was copied)" \
   "[ \"\$(find '$MIRROR' -type f | wc -l | tr -d ' ')\" = 1 ]"

# --- ARM 2 (non-vacuity, run first so arm 1 can never pass emptily) ---------
# The exact construct that was removed, against the exact slowed producer.
cat > "$TMP/old-construct.sh" <<'PROBE'
set -euo pipefail
. "$1/scripts/lib/common.sh"
canonical_images() { matrix_image_labels; }
canonical_images | grep -qx php-cli/8.3
PROBE
bash "$TMP/old-construct.sh" "$MIRROR" >/dev/null 2>&1; oldrc=$?
ck "NON-VACUOUS: the removed construct dies of SIGPIPE (141), got $oldrc" \
   "[ '$oldrc' -eq 141 ]"

# ...and the same match, taken from a here-string, does not. This is the fix in
# one line: it is the READER CLOSING THE PIPE that is fatal, not the matching.
cat > "$TMP/new-construct.sh" <<'PROBE'
set -euo pipefail
. "$1/scripts/lib/common.sh"
canonical_images() { matrix_image_labels; }
LABELS="$(canonical_images)"
grep -qx php-cli/8.3 <<<"$LABELS"
PROBE
bash "$TMP/new-construct.sh" "$MIRROR" >/dev/null 2>&1; newrc=$?
ck "...while capture-then-here-string is unaffected by the same producer, got $newrc" \
   "[ '$newrc' -eq 0 ]"

# --- ARM 1: the REAL script, under the producer that guarantees the race ----
# Twice plain and once under functrace, because the two CI call sites ran it in
# both modes and disagreed (`plain=1, traced=0` on run 32815714210). The slowed
# producer makes each run deterministic, so repetition is a cheap sanity margin
# rather than the sampling this used to need. Each run drives the real
# reconciler ten times and costs ~9s; three is the budget.
for mode in plain plain functrace; do
  case "$mode" in
    plain)     bash    "$MIRROR/scripts/ci/assert-no-stale-exceptions.sh" --self-test >"$TMP/real.out" 2>&1 ;;
    functrace) bash -T "$MIRROR/scripts/ci/assert-no-stale-exceptions.sh" --self-test >"$TMP/real.out" 2>&1 ;;
  esac
  rc=$?
  [ "$rc" -eq 0 ] || { echo "  --- $mode run (exit $rc) ---"; sed 's/^/    /' "$TMP/real.out"; }
  ck "assert-no-stale-exceptions.sh --self-test survives a slow producer ($mode, exit $rc)" \
     "[ '$rc' -eq 0 ]"
done

# --- the construct must not come back into THIS script ---------------------
# Narrow on purpose: 146 `| grep -q` pipelines exist under scripts/ and most are
# harmless (their producers are single writes). Banning the shape repo-wide
# would be a large, mostly-false-positive refusal. This locks the one script
# that demonstrably lost the race.
ck "assert-no-stale-exceptions.sh never pipes the label producer into grep -q" \
   "! grep -nE '(canonical_images|matrix_image_labels)[[:space:]]*\\|[[:space:]]*grep[[:space:]]+-[a-zA-Z]*q' scripts/ci/assert-no-stale-exceptions.sh"
ck "...and that search is not vacuous — it matches the construct that was removed" \
   "printf 'canonical_images | grep -qx x\\n' > '$TMP/v.sh'; grep -qE '(canonical_images|matrix_image_labels)[[:space:]]*\\|[[:space:]]*grep[[:space:]]+-[a-zA-Z]*q' '$TMP/v.sh'"

echo "----"; [ "$fail" -eq 0 ] && echo "test_pipefail_sigpipe: PASS" || echo "test_pipefail_sigpipe: FAIL"
exit $fail
