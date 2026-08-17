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

# --- arm64 is now authorized, FROM EVIDENCE -------------------------------
# These two assertions previously required arm64 to be UNauthorized. Execution A2
# (run 31941819983) produced the evidence and the ledger was reconciled from it,
# so the invariant flipped: arm64 must be authorized, and the authorization must
# be traceable to committed evidence rather than asserted.
ck "arm64 is in the authorized platforms" \
   'grep -qE "AUTHORIZED_PLATFORMS:-linux/amd64,linux/arm64" '"$A"

ck "the authorization records which run evidenced arm64" \
   'grep -q "31941819983" '"$A"

ck "the arm64 authorization is traceable to committed evidence" \
   'test -s docs/audits/arm64-reconciliation-2026-08-17/comparison.json &&
    test -s docs/audits/arm64-reconciliation-2026-08-17/arm64-execution-a2-authorization.json &&
    test -s docs/audits/arm64-reconciliation-2026-08-17/amd64-caddy-rescan-proof.json'

# The platform membership test is comma-vs-space sensitive: the first version of
# this change padded the list with spaces and searched for " linux/amd64 ",
# which stopped matching the moment a second platform was appended and refused
# EVERY platform. Assert both directions rather than trusting the string.
#
# Captured once into a variable: running the self-test inside a multi-line eval'd
# pipeline is both slower and fragile.
# shellcheck disable=SC2034  # consumed inside the eval'd ck assertions below
AUTHZ_SELFTEST="$(bash scripts/release/authorize-staged-candidates.sh --self-test 2>&1 || true)"
ck "the authorizer does NOT refuse an evidenced platform" \
   'grep -q "an evidenced architecture is NOT refused" <<<"$AUTHZ_SELFTEST"'
ck "the authorizer still refuses an unevidenced platform" \
   'grep -q "an unevidenced architecture refuses the WHOLE matrix" <<<"$AUTHZ_SELFTEST"'
ck "...naming the architecture rather than refusing for an unrelated reason" \
   'grep -q "and says so, rather than refusing for an unrelated reason" <<<"$AUTHZ_SELFTEST"'

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
