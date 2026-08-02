#!/usr/bin/env bash
# =============================================================================
# tests/governance/test_package_acl_probe_execution.sh
# -----------------------------------------------------------------------------
# EXECUTE the probe's shell logic instead of describing it.
#
# The sibling test asserts structural properties by reading the YAML. That is
# not enough, and run 30769691840 proved it: the workflow carried a comment
# saying "NOT -e", the structural test believed the arrangement, and the actual
# behaviour was the opposite. GitHub invokes `run:` as `bash -e {0}`, so errexit
# was live, and the first production DENIAL — the successful outcome — killed
# the step before it could be recorded. No evidence file, and a PASS verdict was
# unreachable by construction.
#
# So this harness extracts the real `run:` block and runs it under `bash -e`,
# exactly as the runner does, with `docker` and `gh` stubbed on PATH. Nothing
# leaves the machine. What the probe does with a denial, with an unexpected
# write, and with a timeout is then observed rather than assumed.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WF="$ROOT/.github/workflows/package-acl-probe.yml"
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --- extract the real run: block -------------------------------------------
python3 - "$WF" "$WORK/probe.sh" <<'PY'
import sys, yaml
wf, out = sys.argv[1], sys.argv[2]
d = yaml.safe_load(open(wf))
steps = d['jobs']['probe']['steps']
run = [s for s in steps if s.get('name') == 'Probe the boundary']
assert len(run) == 1, 'expected exactly one probe step'
open(out, 'w').write(run[0]['run'])
PY
[ -s "$WORK/probe.sh" ] || { echo "FAIL - could not extract the run block"; exit 1; }

# --- stubs ------------------------------------------------------------------
mkdir -p "$WORK/bin"
cat > "$WORK/bin/docker" <<'STUB'
#!/usr/bin/env bash
case "${1:-}" in
  login|build|tag) exit 0 ;;
  inspect)
    ref="${!#}"; echo "${ref%%:*}@${STUB_DIGEST}" ;;
  buildx)
    echo "${STUB_RESOLVED:-$STUB_DIGEST}" ;;
  push)
    ref="$2"
    case "$ref" in
      *foundry-staging*)
        printf '%s: digest: %s size: 523\n' "$ref" "$STUB_DIGEST" ;;
      *)
        printf '%s\n' "$STUB_PROD_OUT"; exit "$STUB_PROD_RC" ;;
    esac ;;
esac
exit 0
STUB
cat > "$WORK/bin/gh" <<'STUB'
#!/usr/bin/env bash
echo "${STUB_VISIBILITY:-private}"
STUB
chmod +x "$WORK/bin/docker" "$WORK/bin/gh"

# Run the block the way the runner does: `bash -e`. If the probe does not
# disable errexit itself, a denied push aborts it — which is the bug.
run_probe() { # run_probe <prod-rc> <prod-output> [visibility] [resolved-digest]
  local dir; dir="$(mktemp -d)"
  ( cd "$dir" || exit 1
    PATH="$WORK/bin:$PATH" \
    STUB_DIGEST="sha256:$(printf 'a%.0s' {1..64})" \
    STUB_PROD_RC="$1" STUB_PROD_OUT="$2" \
    STUB_VISIBILITY="${3:-private}" STUB_RESOLVED="${4:-}" \
    GH_TOKEN=t AUDIT_TOKEN=t GITHUB_ACTOR=tester \
    ORG=zenchron-dynamics STAGING=foundry-staging \
    RUN_ID=1 RUN_ATTEMPT=1 REPO=zenchron-dynamics/zenchron-foundry \
    SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    bash -e "$WORK/probe.sh" >"$dir/out.txt" 2>&1
    echo "$?" > "$dir/rc" )
  echo "$dir"
}

# --- 1. the boundary holds: every production write is denied ---------------
# This is THE case the previous implementation could not reach.
d="$(run_probe 1 'denied: requested access to the resource is denied')"
ck "a denied production push does not abort the probe" \
   "test -f '$d/evidence/package-acl-probe.json'"
ck "...and the probe exits 0 when the boundary holds" \
   "[ \"\$(cat '$d/rc')\" = 0 ]"
ck "...and the verdict is PASS" \
   "[ \"\$(jq -r .verdict '$d/evidence/package-acl-probe.json' 2>/dev/null)\" = PASS ]"
ck "...with all six production packages recorded as denied" \
   "[ \"\$(jq '[.packages[]|select(.expected_access==\"read-only\" and .result==\"denied\")]|length' '$d/evidence/package-acl-probe.json' 2>/dev/null)\" = 6 ]"
ck "...and staging recorded as allowed" \
   "[ \"\$(jq '[.packages[]|select(.expected_access==\"write\" and .result==\"allowed\")]|length' '$d/evidence/package-acl-probe.json' 2>/dev/null)\" = 1 ]"

# --- 2. the boundary fails: production accepts the write -------------------
d="$(run_probe 0 'pushed')"
ck "an accepted production write yields FAIL" \
   "[ \"\$(jq -r .verdict '$d/evidence/package-acl-probe.json' 2>/dev/null)\" = FAIL ]"
ck "...and the probe exits non-zero" \
   "[ \"\$(cat '$d/rc')\" != 0 ]"
ck "...and each unexpected write is recorded with its reference" \
   "[ \"\$(jq '[.packages[]|select(.unexpected_write)]|length' '$d/evidence/package-acl-probe.json' 2>/dev/null)\" = 6 ]"

# --- 3. a network failure is not a denial ----------------------------------
d="$(run_probe 1 'net/http: request canceled (Client.Timeout exceeded)')"
ck "a timeout is indeterminate, never counted as denied" \
   "[ \"\$(jq '[.packages[]|select(.result==\"indeterminate\")]|length' '$d/evidence/package-acl-probe.json' 2>/dev/null)\" = 6 ]"
ck "...and indeterminate fails the verdict" \
   "[ \"\$(jq -r .verdict '$d/evidence/package-acl-probe.json' 2>/dev/null)\" = FAIL ]"

# --- 4. an unreadable visibility is not assumed private --------------------
d="$(run_probe 1 'denied' 'unreadable')"
ck "an unreadable visibility fails the verdict" \
   "[ \"\$(jq -r .verdict '$d/evidence/package-acl-probe.json' 2>/dev/null)\" = FAIL ]"

# --- 5. a staging tag that does not resolve is not a success ---------------
d="$(run_probe 1 'denied' 'private' 'sha256:0000000000000000000000000000000000000000000000000000000000000000')"
ck "a staging push whose tag resolves elsewhere is indeterminate" \
   "[ \"\$(jq -r '.packages[]|select(.name==\"foundry-staging\")|.result' '$d/evidence/package-acl-probe.json' 2>/dev/null)\" = indeterminate ]"
ck "...and that fails the verdict" \
   "[ \"\$(jq -r .verdict '$d/evidence/package-acl-probe.json' 2>/dev/null)\" = FAIL ]"

echo "----"; [ "$fail" -eq 0 ] && echo "test_package_acl_probe_execution: PASS" || echo "test_package_acl_probe_execution: FAIL"
exit $fail
