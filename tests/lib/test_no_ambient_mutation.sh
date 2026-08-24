#!/usr/bin/env bash
# shellcheck disable=SC2034  # assertion vars are consumed inside ck() eval strings
# =============================================================================
# tests/lib/test_no_ambient_mutation.sh
# -----------------------------------------------------------------------------
# THE CLASS THIS EXISTS FOR.
#
# scripts/governance-content-binding.sh --self-test appended a mutation marker
# to the REAL policy files to prove that changing an input changes the binding
# aggregate. When it died between the mutation and the restore it left
# policies/required-release-checks.yaml CORRUPTED IN THE CHECKOUT, and the
# corruption was committed. A verification script destroyed the thing it was
# verifying.
#
# That was not one bad script. It is a CLASS: any self-test that writes to a
# path derived from the repository root rather than a disposable fixture. The
# damage does not need the script to be wrong — a SIGKILL, a cancelled CI job or
# a crash between write and restore is enough, and cleanup traps do not run.
#
# THE RULE, fail-closed:
#   A self-test may create, modify or delete files ONLY beneath a disposable
#   fixture root it created (mktemp -d). Anything rooted at the checkout is a
#   refusal, whether or not the script tidies up afterwards.
#
# HOW THIS IS PROVED, and why not weaker:
#
#   1. STATIC, universal. Every write whose target is derived from $ROOT/$REPO
#      is a finding. Cheap, total coverage, and it catches transient writes that
#      a completion-time snapshot cannot see.
#
#   2. DYNAMIC, in a DISPOSABLE COPY, under WRITE PROTECTION. The audited
#      self-tests run against a throwaway copy of the checkout whose tracked
#      files and directories have had their write bits removed. An ambient write
#      then fails with EPERM REGARDLESS OF TIMING. A snapshot-after-completion
#      check is not enough on its own: a script that writes and then restores
#      looks clean at the end and still corrupts the tree when killed midway.
#
#   3. THE AMBIENT CHECKOUT ITSELF is snapshotted around the whole run. This
#      harness inspects the ACTUAL declared audit root, not only its own
#      fixture — a harness that watches a sandbox it built and nothing else
#      proves nothing about the tree that gets committed.
#
#   4. SABOTAGE. An ambient write is reintroduced and must be refused, by the
#      static rule and by the dynamic one independently.
#
# Related: tests/lib/test_functrace_safety.sh (RETURN traps firing on every
# inner function return, which is how the fixture vanished mid-run).
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

TMP="$(mktemp -d)"
# Expand NOW. A single-quoted EXIT trap defers expansion past this scope and
# dies with "unbound variable" under set -u.
# shellcheck disable=SC2064
trap "rm -rf '$TMP'" EXIT

# =============================================================================
# THE DECLARED AUDIT ROOT
# -----------------------------------------------------------------------------
# The tree that must never be mutated is the CHECKOUT — $ROOT — not a sandbox.
# It is named once, here, and every assertion below refers to it.
# =============================================================================
# RECURSION GUARD. The dynamic phase runs self-tests inside a copy of the repo.
# If one of them re-enters this harness the copies nest without bound. Belt and
# braces alongside the enumeration filter below, because a guard that depends on
# getting an enumeration exactly right is not a guard.
if [ -n "${ZF_NO_AMBIENT_AUDIT_ACTIVE:-}" ]; then
  echo "ok   - nested invocation detected; dynamic phase already running upstream"
  echo "test_no_ambient_mutation: PASS"; exit 0
fi
export ZF_NO_AMBIENT_AUDIT_ACTIVE=1

AUDIT_ROOT="$ROOT"
ck "the declared audit root is the real checkout, not a fixture" \
   "[ \"\$AUDIT_ROOT\" = \"\$ROOT\" ] && [ -d \"\$AUDIT_ROOT/.git\" -o -f \"\$AUDIT_ROOT/.git\" ] &&
    [ \"\$AUDIT_ROOT\" != \"${TMP}\" ] && case \"\$AUDIT_ROOT\" in ${TMP}*) false ;; *) true ;; esac"

# Snapshot the AMBIENT checkout. `git status --porcelain` reports both modified
# tracked files and untracked ones in a single call.
ambient_snapshot() { git -C "$AUDIT_ROOT" status --porcelain=v1 --untracked-files=all 2>/dev/null | sort; }
AMBIENT_BEFORE="$TMP/ambient.before"
ambient_snapshot > "$AMBIENT_BEFORE"

# =============================================================================
# 1. STATIC — no self-test may write to a repository-rooted path
# =============================================================================
# Executable lines only. This repository has repeatedly shipped checks that
# matched their OWN explanatory prose and reported a correct file as broken, so
# comments are stripped before matching, and this file is excluded from its own
# scan because it necessarily contains the pattern as data.
SELF="tests/lib/test_no_ambient_mutation.sh"

# ONE definition of "this line writes somewhere rooted at the checkout", used
# both for the repository-wide scan and for the sabotage proof. Two copies would
# let the scan and the proof drift apart, and the proof is worthless the moment
# it stops testing the rule that actually runs.
WRITE_VERB='\bcp\b|\bmv\b|\binstall\b|\bln\b|\bmkdir\b|\btouch\b|\btee\b|\brm\b|\brmdir\b|\bchmod\b|\bchown\b|\btruncate\b|sed[[:space:]]+-i'
ROOT_VAR='\$\{?(ROOT|REPO_ROOT|GITHUB_WORKSPACE)\}?'

# static_scan_file <file> -> prints every ambient-write line (empty = clean)
static_scan_file() {
  # Executable lines only: this repository has repeatedly shipped checks that
  # matched their own explanatory prose.
  grep -vE '^[[:space:]]*#' "$1" 2>/dev/null \
    | grep -nE "($WRITE_VERB)[^|;&#]*[\">]?$ROOT_VAR/|>[[:space:]]*\"?$ROOT_VAR/" \
    | while IFS= read -r hit; do
        # A write whose SOURCE is the checkout but whose TARGET is a fixture is
        # fine — copying OUT of the checkout is how a fixture gets built. Flag
        # only when the LAST token, i.e. the target, is repository-rooted.
        target="$(printf '%s' "$hit" | sed 's/[[:space:]]*$//' | awk '{print $NF}')"
        case "$target" in
          *'$ROOT'*|*'$REPO_ROOT'*|*'$GITHUB_WORKSPACE'*) printf '%s:%s\n' "$1" "$hit" ;;
        esac
      done
}

static_offenders() {
  local f
  while IFS= read -r f; do
    [ "$f" = "$SELF" ] && continue
    static_scan_file "$f"
  done < <( { grep -rl -- '--self-test' scripts/ 2>/dev/null; find tests -name '*.sh'; } | sort -u )
}

offenders="$(static_offenders)"
ck "no self-test writes to a repository-rooted path" \
   "[ -z \"\$offenders\" ] || { printf 'ambient writers:\n%s\n' \"\$offenders\"; false; }"

# NON-VACUITY: the search must be able to find the construct it looks for.
mkdir -p "$TMP/probe/tests"
cat > "$TMP/probe/tests/planted.sh" <<'PLANT'
ROOT="$(pwd)"
cp "$ROOT/policies/lifecycle.yaml" "$ROOT/policies/lifecycle.yaml.bak"
PLANT
ck "...and that search is NOT VACUOUS — the REAL rule matches a planted ambient write" \
   "[ -n \"\$(static_scan_file '$TMP/probe/tests/planted.sh')\" ]"

# =============================================================================
# 2. DYNAMIC — run self-tests in a DISPOSABLE COPY, under write protection
# =============================================================================
# Never, under any circumstance, in $ROOT. The copy is a detached worktree at
# HEAD; if git cannot provide one the dynamic phase reports SKIP rather than
# silently passing.
COPY="$TMP/disposable"
have_copy=0
if git -C "$ROOT" worktree add --detach "$COPY" HEAD >/dev/null 2>&1; then
  have_copy=1
fi
ck "a DISPOSABLE COPY of the checkout was created for the dynamic phase" "[ '$have_copy' = 1 ]"

# Two verbs, no boolean. `protect on/off` read ambiguously enough at the call
# sites that the audited command ran UNPROTECTED and every dynamic assertion
# quietly degraded to a completion-time snapshot.
#   freeze  = remove write bits  -> an ambient write fails with EPERM
#   thaw    = restore write bits -> the copy can be reset
_wperm() { # _wperm <copy> <freeze|thaw>
  python3 - "$1" "$2" <<'PPY'
import os, subprocess, sys
wt, mode = sys.argv[1], sys.argv[2]
files = [f for f in subprocess.check_output(["git", "-C", wt, "ls-files"], text=True).split("\n") if f]
dirs = set()
for f in files:
    d = os.path.dirname(os.path.join(wt, f))
    while len(d) >= len(wt):
        dirs.add(d)
        if d == wt:
            break
        d = os.path.dirname(d)
def chmod(p, on):
    try:
        m = os.stat(p).st_mode
        os.chmod(p, (m & ~0o222) if on else (m | 0o200))
    except OSError:
        pass
if mode == "thaw":
    for d in sorted(dirs, key=len):
        chmod(d, False)          # restore write bit, outermost first
    for f in files:
        chmod(os.path.join(wt, f), False)
elif mode == "freeze":
    for f in files:
        chmod(os.path.join(wt, f), True)   # drop write bit
    for d in sorted(dirs, key=len, reverse=True):
        chmod(d, True)                     # innermost first
else:
    raise SystemExit("_wperm: mode must be freeze or thaw")
PPY
}
freeze() { _wperm "$1" freeze; }
thaw()   { _wperm "$1" thaw; }

# Portable watchdog: this repository's macOS bash has no coreutils `timeout`,
# and a missing `timeout` exits 127 INSTANTLY — which silently turns every
# dynamic assertion into a no-op. That happened while writing this file.
watchdog() { # watchdog <secs> <cmd...>
  "${@:2}" & local p=$!
  ( sleep "$1"; kill -9 "$p" 2>/dev/null ) >/dev/null 2>&1 & local w=$!
  wait "$p"; local rc=$?
  kill -9 "$w" 2>/dev/null; wait "$w" 2>/dev/null
  return "$rc"
}
ck "the watchdog actually runs a command (a missing 'timeout' exits 127 and voids every dynamic check)" \
   "watchdog 10 true && ! watchdog 10 false"

EPERM_RE='Permission denied|Read-only file system|Operation not permitted'

audit_reset() { # restore the disposable copy to a pristine HEAD
  thaw "$1"
  ( cd "$1" && git reset -q --hard && git clean -qfdx ) >/dev/null 2>&1
}

snap_copy() { ( cd "$COPY" && git status --porcelain=v1 --untracked-files=all 2>/dev/null ) | sort; }

# EPERM ONLY COUNTS INSIDE THE AUDIT ROOT.
#
# Freezing the copy has a side effect: `cp` preserves mode, so a self-test that
# copies a governed file OUT of the frozen tree into its own mktemp fixture gets
# a READ-ONLY fixture, and its next legitimate write to that fixture fails with
# EPERM too. Counting those would have condemned assert-upstream-ownership.sh and
# governance-content-binding.sh — both correctly isolated — for writes that never
# came near the checkout. The EPERM must name a path under the copy.
ambient_eperm() { # ambient_eperm <outfile> <copy>
  grep -E "$EPERM_RE" "$1" 2>/dev/null | grep -F "$2"
}

# --- BATCHED, and why -------------------------------------------------------
# The first version reset, froze, ran, thawed and re-snapshotted PER SELF-TEST.
# Correct, and hopelessly slow: three self-tests in twenty minutes, because a
# freeze/thaw is a chmod over every tracked path and there are ~68 self-tests.
# A gate nobody can afford to run is a gate that gets deleted.
#
# Batching gives the same guarantee for two freeze/thaw operations instead of
# 136: if the whole batch leaves the tree untouched, every member of it did. The
# batch is only taken apart when it is DIRTY, which is when the extra cost buys
# something — naming the offender.
run_batch() { # run_batch <outdir> ; reads SELFTESTS
  local outdir="$1" s
  mkdir -p "$outdir"
  while IFS= read -r s; do
    [ -n "$s" ] || continue
    ( cd "$COPY" && watchdog "$WATCHDOG_SECS" bash "$s" --self-test ) \
      > "$outdir/$(printf '%s' "$s" | tr -c 'A-Za-z0-9' '-').out" 2>&1
  done <<< "$SELFTESTS"
}

# Only ever called when the batch is dirty: find which member did it.
bisect_dirty() {
  local s before after bad=""
  while IFS= read -r s; do
    [ -n "$s" ] || continue
    audit_reset "$COPY"
    before="$(snap_copy)"
    ( cd "$COPY" && watchdog "$WATCHDOG_SECS" bash "$s" --self-test ) >/dev/null 2>&1
    after="$(snap_copy)"
    [ "$before" = "$after" ] || bad="$bad $s"
  done <<< "$SELFTESTS"
  printf '%s' "$bad"
}

WATCHDOG_SECS=45

# WHICH SCRIPTS ARE SELF-TESTS, and the recursion this got wrong.
#
# `grep -rl -- '--self-test' scripts/` matches any file that MENTIONS the flag,
# including scripts/macro-validate.sh — which does not implement one, ignores
# the argument, and runs the entire validation suite, `tests/run-all.sh`
# included. Running it here re-entered this very harness, which created another
# disposable copy and ran macro-validate again. Unbounded recursion, and it
# looked like the audit was merely slow.
#
# Two filters, both derived:
#   1. the script must DISPATCH on --self-test, not merely mention it;
#   2. a script that runs the whole suite cannot be audited from inside the
#      suite, so anything invoking tests/run-all.sh is excluded by what it DOES.
selftest_scripts() {
  local f
  while IFS= read -r f; do
    # Comments stripped first — this repository keeps shipping checks that match
    # their own prose. Then: a line that PASSES --self-test to another script is
    # a CALL, not a dispatch. macro-validate.sh contains nothing else, so it
    # falls out on what it does rather than on its name.
    grep -vE '^[[:space:]]*#' "$f" 2>/dev/null \
      | grep -F -- '--self-test' \
      | grep -qvE '(bash|sh|source|\.)[[:space:]]+[^[:space:]]*\.(sh|py)' \
      || continue
    grep -q 'tests/run-all\.sh' "$f" 2>/dev/null && continue
    printf '%s\n' "$f"
  done < <(cd "$ROOT" && grep -rl -- '--self-test' scripts/ | sort)
}
SELFTESTS="$(cd "$ROOT" && selftest_scripts)"
n_selftests="$(printf '%s\n' "$SELFTESTS" | grep -c .)"

ck "the enumeration EXCLUDES whole-suite harnesses (they re-enter this audit)" \
   "! printf '%s\n' \"\$SELFTESTS\" | grep -q 'macro-validate'"
ck "...and that exclusion is by what the script DOES, not a name allowlist" \
   "grep -q 'tests/run-all' '$ROOT/scripts/macro-validate.sh'"
ck "...while still enumerating scripts that really dispatch --self-test" \
   "printf '%s\n' \"\$SELFTESTS\" | grep -q 'assert-no-stale-exceptions' &&
    printf '%s\n' \"\$SELFTESTS\" | grep -q 'governance-content-binding'"

if [ "$have_copy" = 1 ]; then
  # --- The FREEZE mechanism itself must be proven. Every "clean" verdict below
  # --- is the absence of an EPERM; if freezing silently did nothing, every one
  # --- of them would be vacuous.
  audit_reset "$COPY"
  freeze "$COPY"
  froze_file=1; froze_dir=1
  ( : > "$COPY/policies/lifecycle.yaml" ) 2>/dev/null && froze_file=0
  ( touch "$COPY/policies/zz-new-file" ) 2>/dev/null && froze_dir=0
  thaw "$COPY"
  ck "FREEZE actually blocks modifying a tracked file" "[ '$froze_file' = 1 ]"
  ck "FREEZE actually blocks creating a new file in a tracked directory" "[ '$froze_dir' = 1 ]"
  audit_reset "$COPY"
  wrote=0
  ( : > "$COPY/policies/lifecycle.yaml" ) 2>/dev/null && wrote=1
  ck "...and THAW restores writability, so the block is the freeze and not the copy" \
     "[ '$wrote' = 1 ]"

  # The EPERM scoping must not be a blanket mute: a fixture-only EPERM has to be
  # IGNORED and an audit-root EPERM has to be CAUGHT, from the same input.
  printf 'cp: %s/policies/x.yaml: Permission denied\n' "$COPY"     > "$TMP/eperm.mix"
  printf 'cp: /var/folders/zz/tmp.QQQ/fixture/y.yaml: Permission denied\n' >> "$TMP/eperm.mix"
  ck "EPERM scoping catches a write to the audit root" \
     "ambient_eperm '$TMP/eperm.mix' '$COPY' | grep -q 'policies/x.yaml'"
  ck "...and IGNORES an EPERM inside the self-test's own fixture" \
     "! ambient_eperm '$TMP/eperm.mix' '$COPY' | grep -q 'fixture/y.yaml'"

  # --- SABOTAGE. If the detector cannot catch a deliberate ambient write, every
  # --- clean result below is meaningless. Planted AFTER the reset: an earlier
  # --- version reset after planting and deleted its own sabotage, which made
  # --- this proof silently untestable.
  audit_reset "$COPY"
  mkdir -p "$COPY/scripts"
  cat > "$COPY/scripts/zz-ambient-sabotage.sh" <<'SAB'
#!/usr/bin/env bash
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ "${1:-}" = "--self-test" ]; then
  # The governance-content-binding defect, exactly: mutate a REAL policy file to
  # prove the mutation is detected, then put it back. Clean at completion, and
  # catastrophic if the process dies in between.
  printf '\n# ambient sabotage marker\n' >> "$ROOT/policies/lifecycle.yaml"
  git -C "$ROOT" checkout -- policies/lifecycle.yaml 2>/dev/null
  echo "ok   - sabotage self-test 'passed'"
fi
SAB
  sab_before="$(snap_copy)"
  ( cd "$COPY" && watchdog "$WATCHDOG_SECS" bash scripts/zz-ambient-sabotage.sh --self-test ) >/dev/null 2>&1
  sab_after="$(snap_copy)"
  ck "the sabotage really does restore the file (it is CLEAN at completion)" \
     "[ \"\$sab_before\" = \"\$sab_after\" ]"
  freeze "$COPY"
  ( cd "$COPY" && watchdog "$WATCHDOG_SECS" bash scripts/zz-ambient-sabotage.sh --self-test ) \
     > "$TMP/sab.frozen.out" 2>&1
  thaw "$COPY"
  ck "SABOTAGE: the transient ambient write is CAUGHT anyway, by the frozen pass" \
     "[ -n \"\$(ambient_eperm '$TMP/sab.frozen.out' '$COPY')\" ]"
  ck "...and the SAME static rule that scans the repo also refuses it" \
     "[ -n \"\$(static_scan_file '$COPY/scripts/zz-ambient-sabotage.sh')\" ]"
  audit_reset "$COPY"

  # --- THE AUDIT ------------------------------------------------------------
  ck "the self-test enumeration is non-empty (an empty list passes vacuously)" \
     "[ '$n_selftests' -ge 40 ]"

  # ONE FROZEN PASS, and why not two.
  #
  # An earlier version ran every self-test twice — thawed for a faithful
  # completion snapshot, then frozen for transient detection — and projected to
  # ~38 minutes. A gate nobody can afford to run gets deleted, and a deleted
  # gate protects nothing.
  #
  # The frozen pass alone is sufficient, because freezing catches BOTH shapes: a
  # write that persists and a write that is made and restored both fail with
  # EPERM the moment they are attempted. The thawed pass only added
  # faithful-execution coverage, which tests/run-all.sh already provides by
  # running these same self-tests for real.
  #
  # The snapshot is kept around the batch anyway. It is nearly free and it
  # covers the one thing freezing cannot: a write into a directory that holds no
  # tracked files, which therefore has no write bit to remove.
  audit_reset "$COPY"
  batch_before="$(snap_copy)"
  freeze "$COPY"
  run_batch "$TMP/pass"
  thaw "$COPY"
  batch_after="$(snap_copy)"

  transient=""
  for f in "$TMP"/pass/*.out; do
    [ -e "$f" ] || continue
    if [ -n "$(ambient_eperm "$f" "$COPY")" ]; then
      transient="$transient $(basename "$f" .out)"
      echo "     ambient write attempt in $(basename "$f" .out):"
      ambient_eperm "$f" "$COPY" | head -3 | sed 's/^/       /'
    fi
  done
  ck "no self-test writes into the checkout it runs in ($n_selftests audited, frozen)" \
     "[ -z \"\$transient\" ] || { printf 'ambient writers:%s\n' \"\$transient\"; false; }"

  dirty=""
  [ "$batch_before" = "$batch_after" ] || dirty="$(bisect_dirty)"
  ck "...and nothing was left behind that freezing could not have blocked" \
     "[ -z \"\$dirty\" ] || { printf 'left residue:%s\n' \"\$dirty\"; false; }"

  thaw "$COPY"
  git -C "$ROOT" worktree remove --force "$COPY" >/dev/null 2>&1
fi

# =============================================================================
# 3. THE AMBIENT CHECKOUT — untouched by everything above
# =============================================================================
ambient_snapshot > "$TMP/ambient.after"
ck "the AMBIENT checkout is unchanged by this entire audit" \
   "diff -q '$AMBIENT_BEFORE' '$TMP/ambient.after' >/dev/null ||
    { echo 'ambient drift:'; diff '$AMBIENT_BEFORE' '$TMP/ambient.after'; false; }"

# The specific file the class already destroyed once. Named explicitly so a
# regression is reported as itself rather than as a generic drift.
ck "policies/required-release-checks.yaml carries no self-test mutation marker" \
   "! grep -q 'self-test mutation' '$AUDIT_ROOT/policies/required-release-checks.yaml'"
ck "no policy file in the audit root carries a self-test mutation marker" \
   "! grep -rlq 'self-test mutation' '$AUDIT_ROOT/policies' 2>/dev/null"
ck "no stray sabotage fixture was left in the audit root" \
   "[ -z \"\$(find '$AUDIT_ROOT/scripts' '$AUDIT_ROOT/tests' -name '*sabotage*' -o -name '*.orig' -o -name '*.rej' 2>/dev/null)\" ]"

echo "----"
[ "$fail" -eq 0 ] && echo "test_no_ambient_mutation: PASS" || echo "test_no_ambient_mutation: FAIL"
exit $fail
