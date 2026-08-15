#!/usr/bin/env bash
# =============================================================================
# #139 readiness: the arm64 evidence-acquisition run must produce usable
# evidence even though it is expected to be REFUSED.
#
# The failure mode this guards against is a run that refuses so early that the
# only thing learned is "arm64 is not authorized". That teaches nothing and
# burns a dispatch. The refusal has to happen AFTER every child has been built,
# staged, scanned and recorded, so the run doubles as the measurement.
#
# It also guards the opposite mistake: arm64 must NOT be pre-authorized. Adding
# linux/arm64 to the authorized platforms or to any ledger entry before the
# evidence exists would manufacture an approval for findings nobody has seen.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

W=.github/workflows/stage-and-authorize.yml
A=scripts/release/authorize-staged-candidates.sh

# --- arm64 must still be unauthorized -------------------------------------
ck "arm64 is NOT in the authorized platforms" \
   'grep -q "AUTHORIZED_PLATFORMS=\"\${AUTHORIZED_PLATFORMS:-linux/amd64}\"" '"$A"

ck "no ledger entry claims linux/arm64 yet" \
   'python3 -c "
import yaml
d=yaml.safe_load(open(\"policies/vulnerability-exceptions.yaml\"))
bad=[e[\"cve\"] for sec in (\"exceptions\",\"not_affected\")
     for e in (d.get(sec) or [])
     if \"linux/arm64\" in (e.get(\"verified_architectures\") or [])]
assert not bad, (\"arm64 claimed without evidence\", bad)"'

# --- the refusal must come AFTER the evidence ------------------------------
# The platform check lives in the authorizer, which runs in the post-build job.
# If it ever moves into the guard or the stage job, an arm64 run would abort
# before producing anything.
ck "the platform authorization check is in the authorizer, not a pre-build gate" \
   'grep -q "AUTHORIZED_PLATFORMS" '"$A"' && ! grep -q "AUTHORIZED_PLATFORMS" '"$W"

ck "child evidence upload runs even when the child fails" \
   'python3 -c "
import yaml
d=yaml.safe_load(open(\"$W\"))
steps=d[\"jobs\"][\"stage\"][\"steps\"]
up=[s for s in steps if \"upload-artifact\" in str(s.get(\"uses\",\"\"))]
assert up, \"no upload step\"
assert any(str(s.get(\"if\",\"\")).strip()==\"always()\" for s in up), \
    [s.get(\"if\") for s in up]"'

ck "the authorizer runs on always() so a refusal still emits a record" \
   'python3 -c "
import yaml
d=yaml.safe_load(open(\"$W\"))
cond=str(d[\"jobs\"][\"authorize\"].get(\"if\",\"\"))
assert \"always()\" in cond, cond"'

# --- the evidence must contain what a cross-arch decision needs ------------
for field in execution_mode host_architecture packages_inventoried; do
  ck "child records carry '$field'" "grep -q '$field' $W"
done

ck "the scan lists ALL packages, not only vulnerable ones" \
   'grep -q -- "--list-all-pkgs" '"$W"

ck "a package inventory is derived per child" \
   'grep -q "packages.tsv" '"$W"

ck "execution mode is derived from the runner, not declared" \
   'grep -q "uname -m" '"$W"' && grep -q "exec_mode=qemu" '"$W"

# --- the comparison tool -----------------------------------------------------
ck "the architecture comparison tool self-tests clean" \
   'bash scripts/compare-architecture-evidence.sh --self-test >/dev/null 2>&1'

ck "it refuses an empty evidence directory rather than reporting no differences" \
   'tmp=$(mktemp -d); mkdir -p "$tmp/a" "$tmp/b";
    ! bash scripts/compare-architecture-evidence.sh "$tmp/a" "$tmp/b" >/dev/null 2>&1;
    rc=$?; rm -rf "$tmp"; [ $rc -eq 0 ]'

echo "----"
[ "$fail" -eq 0 ] && echo "test_arm64_evidence_readiness: PASS" \
                  || echo "test_arm64_evidence_readiness: FAIL"
exit $fail
