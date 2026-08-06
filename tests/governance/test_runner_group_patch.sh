#!/usr/bin/env bash
# =============================================================================
# tests/governance/test_runner_group_patch.sh
# -----------------------------------------------------------------------------
# The helper's own self-test drives its real execution path through an injected
# transport. This wires it into the offline suite so CI runs it, and asserts the
# contract that measurement established:
#
#   PATCH with    selected_repository_ids -> 422
#   PATCH without it                      -> 200 OK, membership CLEARED
#   PUT .../repositories                  -> restored
#
# The old helper required the field the API forbids, so it could never succeed.
# Keeping the reason recorded matters more than the code: the next person to see
# a 422 here needs to know that omitting the field is not the safe alternative.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
H=scripts/admin/runner-group-patch.sh
EV=docs/audits/runner-group-patch-semantics-2026-08-06
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

ck "the helper exists" "test -f $H"
ck "its self-test passes (real execution path, injected transport)" \
   "bash $H --self-test >/dev/null 2>&1"

# --- the contract, asserted structurally ----------------------------------
ck "the repository list is a separate mandatory argument" \
   "grep -q 'desired-repositories.json required' $H"
ck "the PATCH allowlist excludes repository membership" \
   "! grep -qE '^PATCH_ALLOWED_KEYS=.*selected_repository_ids' $H"
ck "selected_repository_ids, runners and repositories are forbidden in a PATCH" \
   "grep -q 'PATCH_FORBIDDEN_KEYS=\"selected_repository_ids runners repositories\"' $H"
ck "the repository PUT is unconditional after a successful PATCH" \
   "grep -q 'UNCONDITIONAL after every successful PATCH' $H"
ck "the API version is pinned on every call" \
   "grep -q 'X-GitHub-Api-Version: \${API_VERSION}' $H"
# Not a grep for the word: the helper's own self-test contains that pattern as
# a search string, so grepping the file finds the check rather than a claim.
# The behavioural version lives in the helper's self-test, which asserts against
# the EMITTED evidence; here we only require that the limitation is documented.
ck "the helper documents that it is not atomic" \
   "grep -q 'cannot be made atomic' $H"
ck "the emitted evidence states the same limitation" \
   "grep -q 'are not atomic' $H"
ck "the fail-closed window is named, not hidden" \
   "grep -q 'FAIL-CLOSED AVAILABILITY WINDOW' $H"

# --- the measurement is committed and intact -------------------------------
ck "the canary evidence is committed" "test -f $EV/result.json"
ck "its verdict is CLEARED" "[ \"\$(jq -r .verdict $EV/result.json)\" = CLEARED ]"
ck "the measurement shows membership emptied by the PATCH" \
   "[ \"\$(jq -c .repositories.after_patch $EV/result.json)\" = '[]' ]"
ck "...and restored by the PUT" \
   "[ \"\$(jq -c .repositories.after_put $EV/result.json)\" = '[1254295268]' ]"
ck "production group 3 was never addressed" \
   "[ \"\$(jq -r .production_group_3_touched $EV/result.json)\" = false ]"
ck "no workflow was dispatched by the experiment" \
   "[ \"\$(jq -r .workflows_dispatched $EV/result.json)\" = 0 ]"
ck "the temporary group is gone from the organization" \
   "! jq -e '.[] | select(.name | test(\"patch-semantics\"))' $EV/groups-after-delete.json >/dev/null"
ck "the evidence bundle is checksummed" "test -s $EV/SHA256SUMS"
ck "...and the checksums verify" "( cd $EV && shasum -a 256 -c SHA256SUMS >/dev/null 2>&1 )"
ck "no credentials leaked into the bundle" \
   "! grep -rqE 'gh[pousr]_[A-Za-z0-9]{16,}|Authorization:' $EV/"

# --- this PR must not have performed the production transition -------------
# The helper is the tool; using it on group 3 is a separate, authorized step.
ck "the policy still records stage-and-authorize as PENDING" \
   "python3 -c \"
import yaml
g=yaml.safe_load(open('policies/repository-governance.yaml'))['org_runner_group']
pend=g.get('pending_workflows') or []
assert any('stage-and-authorize' in w for w in pend), pend
assert not any('stage-and-authorize' in w for w in g['selected_workflows'])\""

echo "----"; [ "$fail" -eq 0 ] && echo "test_runner_group_patch: PASS" || echo "test_runner_group_patch: FAIL"
exit $fail
