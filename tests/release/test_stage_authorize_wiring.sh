#!/usr/bin/env bash
# =============================================================================
# Wiring invariants for the dispatch-only staging workflow.
#
# stage-and-authorize.yml is workflow_dispatch-only, so no push CI run executes
# it and every argument it passes is unverified until someone spends a real
# dispatch. Run 31701249058 spent one and found two mis-wirings:
#
#   1. reconcile-vulnerabilities.sh was called with --arch "amd64" instead of
#      "linux/amd64". --arch is load-bearing (an exception authorises only the
#      architectures it was reconciled on), so a bare machine name matches NO
#      ledger entry: 37 ungoverned findings per image, 0 governed, when the
#      true number was 1. It failed CLOSED, so nothing was wrongly authorised,
#      but the gate was unusable and the one real finding was buried.
#
#   2. Children scan with --skip-java-db-update while freeze-db downloaded only
#      the vulnerability database. Whether a scan worked then depended on the
#      runner's ambient cache — the exact non-hermetic condition the freeze
#      exists to remove. nginx/prod died with FATAL "'--skip-java-db-update'
#      cannot be specified on the first run", produced no report, and
#      reconciliation correctly refused to run on a missing scan.
#
# Both are checked structurally against the workflow, and both are re-checked
# against the revision they shipped on so neither assertion can go quiet.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

# --- 1. every reconcile call passes a FULL platform ---------------------------
# Scans the raw text: the value may be a shell expansion, so this asserts the
# argument is a linux/-qualified platform rather than trying to evaluate it.
arch_defects() {
  python3 - "$1" <<'PY'
import glob, os, re, sys
root = sys.argv[1]
for f in sorted(glob.glob(os.path.join(root, ".github/workflows/*.yml"))):
    lines = open(f).read().splitlines()
    for i, line in enumerate(lines):
        if "reconcile-vulnerabilities.sh" not in line:
            continue
        # Comments name the script too — several workflows explain what it does
        # in prose. Matching those reported a missing --arch on a line that
        # invokes nothing.
        if line.lstrip().startswith("#"):
            continue
        # Rebuild the whole logical command: shell continuation is a trailing
        # backslash, so keep consuming while the previous line ends with one.
        args, j = line, i
        while lines[j].rstrip().endswith("\\") and j + 1 < len(lines):
            j += 1
            args += " " + lines[j].strip()
        a = re.search(r"--arch\s+(?P<v>\S+)", args)
        if not a:
            print("%s: a reconcile call passes no --arch at all" % os.path.basename(f))
            continue
        v = a.group("v").strip('"').strip("'")
        if not v.startswith("linux/"):
            print("%s: reconcile --arch %s is not a linux/-qualified platform"
                  % (os.path.basename(f), a.group("v")))
PY
}

out="$(arch_defects "$ROOT")"
[ -n "$out" ] && printf '%s\n' "$out" | sed 's/^/     /'
ck "every reconcile-vulnerabilities.sh call passes a full linux/<arch> platform" '[ -z "$out" ]'

# --- 2. skipping the java db update requires freezing the java db ------------
# Scanning with --skip-java-db-update is only safe because no image ships a
# Java artifact. That precondition is enforced where it can actually be
# enforced — at build time, in the image that had them — not by downloading a
# 1.5 GB database to scan four files nothing can execute.
ck "the nginx image deletes the gettext-base Java bindings" \
   'grep -q "rm -rf /usr/share/java /usr/share/maven-repo" images/nginx/Dockerfile'
ck "the nginx build REFUSEs if any Java artifact survives" \
   'grep -q "REFUSE: Java artifacts survived removal" images/nginx/Dockerfile &&
    grep -q -- "-name .\*\.jar" images/nginx/Dockerfile'
ck "no workflow ships the 1.5 GB java-db through the stage matrix" \
   '! grep -rq -- "--download-java-db-only" .github/workflows/'
# Deleting the jars is not enough on its own: Trivy analyses LAYERS, and these
# arrive in the nginx base layer, so a scan still finds them there and demands
# the java-db. Any scan that skips the java-db update must also skip the two
# directories that hold them, or it FATALs and produces no report at all.
ck "a scan that skips the java-db update also skips the jar directories" \
   'python3 -c "
import glob, sys
bad = [f for f in sorted(glob.glob(\".github/workflows/*.yml\"))
       if \"--skip-java-db-update\" in open(f).read()
       and \"--skip-dirs\" not in open(f).read()]
print(*bad, sep=chr(10)) if bad else None
sys.exit(1 if bad else 0)
"'

# --- 3. the nginx wedge must actually wedge ----------------------------------
# The old wedge matched "daemon off" in the first 40 bytes of cmdline. The
# master's cmdline is 42 bytes so it truncated, and workers are
# "nginx: worker process" which never matched — it stopped nothing and the
# assertion could not fail for the right reason. Guard the two properties that
# made the replacement work rather than the exact text.
W=scripts/smoke/smoke-nginx.sh
# Strip comments first: the replacement's own comment EXPLAINS the head -c40
# truncation, so a naive grep matches the explanation and reports the bug as
# still present. Assert on executable lines only.
code() { grep -v '^[[:space:]]*#' "$W"; }
ck "the nginx wedge matches on comm, not a truncated cmdline" \
   '! code | grep -q "head -c40" && code | grep -q "comm"'
ck "the nginx wedge asserts the workers really are stopped" \
   'grep -q "State:\[\[:space:\]\]\*T" '"$W"' && grep -q "in state T" '"$W"

# --- 4. non-vacuity: the scans MUST flag the revision this shipped on --------
BROKEN=0624f32a9cc39d873e4d9f9ae3dec17bbf896d3d
if git cat-file -e "${BROKEN}^{commit}" 2>/dev/null; then
  tmp="$(mktemp -d)"
  git archive "$BROKEN" .github/workflows | tar -x -C "$tmp"
  ck "the --arch scan DOES flag ${BROKEN:0:8}" \
     'printf "%s" "$(arch_defects "$tmp")" | grep -q "not a linux/-qualified"'
  rm -rf "$tmp"
  # The Java artifacts really were in the image before this change: prove it
  # from the Dockerfile at the revision that shipped them, so "we removed them"
  # is not a claim about a file that never contained anything.
  ck "${BROKEN:0:8} did NOT delete the Java bindings" \
     '! git show '"$BROKEN"':images/nginx/Dockerfile | grep -q "/usr/share/maven-repo"'
  ck "the old nginx wedge is gone from ${BROKEN:0:8} onwards" \
     'git show '"$BROKEN"':'"$W"' | grep -q "head -c40"'
else
  echo "skip - ${BROKEN:0:8} not present locally; cannot prove the scans are non-vacuous"
fi

echo "----"
[ "$fail" -eq 0 ] && echo "test_stage_authorize_wiring: PASS" \
                  || echo "test_stage_authorize_wiring: FAIL"
exit $fail
