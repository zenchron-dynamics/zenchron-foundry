#!/usr/bin/env bash
# =============================================================================
# A workflow step that runs git needs a work tree.
#
# stage-and-authorize's `guard` job was a pure ref-string check with no
# checkout. The SOURCE_DATE_EPOCH step (#101) was added to it and ran
# `git log -1 --format=%ct`, so every dispatch died at:
#
#     fatal: not a git repository (or any of the parent directories): .git
#
# The guard failed, the whole matrix skipped, and the workflow could never
# produce anything. Fail-closed, but permanently broken — and invisible,
# because stage-and-authorize is workflow_dispatch-only: no push CI run ever
# executes that job. It took a real dispatch (run 31696927539) to surface it.
#
# This checks the CLASS, not the one line: in every workflow, every job, any
# step invoking git must be preceded by a checkout in the same job.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

scan() {
  # Prints one line per offending step. Empty output == clean.
  python3 - "$1" <<'PY'
import glob, os, re, sys, yaml

root = sys.argv[1]
# Steps that read the repo through git. A step may legitimately run git AFTER a
# checkout; the defect is only ordering.
GIT = re.compile(r"(?m)^[^#\n]*\bgit\s+"
                 r"(log|rev-parse|describe|show|diff|status|rev-list|cat-file|ls-tree|for-each-ref)\b")

for f in sorted(glob.glob(os.path.join(root, ".github/workflows/*.yml"))
                + glob.glob(os.path.join(root, ".github/workflows/*.yaml"))):
    try:
        doc = yaml.safe_load(open(f))
    except Exception as e:
        print("%s: unparseable (%s)" % (os.path.basename(f), e))
        continue
    for jid, job in ((doc or {}).get("jobs") or {}).items():
        steps = job.get("steps") or []
        checkouts = [i for i, s in enumerate(steps) if "checkout" in str(s.get("uses", ""))]
        first = checkouts[0] if checkouts else None
        for i, s in enumerate(steps):
            if not GIT.search(s.get("run") or ""):
                continue
            if first is None:
                print("%s job=%s step=%r runs git with NO checkout in the job"
                      % (os.path.basename(f), jid, s.get("name") or i))
            elif i < first:
                print("%s job=%s step=%r runs git BEFORE the checkout at step %d"
                      % (os.path.basename(f), jid, s.get("name") or i, first))
PY
}

out="$(scan "$ROOT")"
[ -n "$out" ] && printf '%s\n' "$out" | sed 's/^/     /'
ck "no workflow step runs git before its job checks out" '[ -z "$out" ]'

# The specific job that broke, asserted positively so a later refactor that
# drops the checkout again fails here rather than at dispatch time.
ck "stage-and-authorize guard checks out before stamping the commit" '
  python3 -c "
import yaml
j = yaml.safe_load(open(\".github/workflows/stage-and-authorize.yml\"))[\"jobs\"][\"guard\"][\"steps\"]
co = next(i for i, s in enumerate(j) if \"checkout\" in str(s.get(\"uses\", \"\")))
st = next(i for i, s in enumerate(j) if s.get(\"id\") == \"stamp\")
assert co < st, (co, st)"'

# THE test that fails on the previous implementation: the same scan against the
# commit that was dispatched must report the defect. If this ever goes quiet,
# the scan stopped detecting anything and the check above is vacuous.
BROKEN=8a1d0041bc24281a01b9fdf2d47c657ec47f7cad
if git cat-file -e "${BROKEN}^{commit}" 2>/dev/null; then
  tmp="$(mktemp -d)"
  git archive "$BROKEN" .github/workflows | tar -x -C "$tmp"
  before="$(scan "$tmp")"
  rm -rf "$tmp"
  ck "the scan DOES flag ${BROKEN:0:8}, the revision this bug shipped on" \
     'printf "%s" "$before" | grep -q "job=guard"'
else
  echo "skip - ${BROKEN:0:8} not present locally; cannot prove the scan is non-vacuous"
fi

echo "----"
[ "$fail" -eq 0 ] && echo "test_workflow_git_needs_checkout: PASS" \
                  || echo "test_workflow_git_needs_checkout: FAIL"
exit $fail
