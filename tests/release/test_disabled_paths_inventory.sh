#!/usr/bin/env bash
# =============================================================================
# tests/release/test_disabled_paths_inventory.sh
# -----------------------------------------------------------------------------
# The production publication path was deleted from executable code. Its tests
# went with it — an assertion about a workflow that does not exist cannot pass
# and cannot be repaired in place.
#
# Deleting them silently would be the real damage. Each guarantee removed is
# listed below, so PR B (immutable RC manifest) and PR E (protected exposure)
# restore the CONTROLS rather than just the workflows. This file is the
# checklist, and it asserts the only thing that is true today: the paths are
# disabled and cannot publish.
#
# Git history holds the deleted implementations and their original tests.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

# --- guarantees removed with the publication path --------------------------
# Restore each ALONGSIDE the control it describes, not afterwards.
#
# tests/evidence/test_evidence.sh
#   - promote-stable requires typed confirmation
#   - promote-stable requires risk acceptance
#   - promote-stable does NOT require two reviewers (solo model)
#   - release builds+validates evidence
#
# tests/release/test_rc_identity.sh
#   - publish-rc serializes signing (org-cosign-publish, never cancelled)
#   - scheduled-rebuild joins the SAME org-cosign-publish group  [#82]
#   - the signing matrix isolates cosign per job (HOME/COSIGN_* per job) [#82]
#   - publish-ghcr computes immutable RC tag
#   - publish-ghcr runs the immutability probe
#   - publish-rc requires input: version / rc / expected_revision / confirmation
#   - publish-ghcr has call input: version / expected_revision
#
# tests/release/test_release_binding.sh
#   - release.yml runs exact-commit CI gate
#   - release.yml verifies RC manifest binding
#   - release.yml verify-artifacts passes revision
#
# tests/release/test_seal_path.sh
#   - release.yml does not read committed release-evidence/
#   - release.yml is dispatch-only (no tag-push auto-seal)
#   - release.yml takes the publish-rc run id
#   - release.yml enforces the stable-tag ref policy
#   - release.yml fetches the signed RC manifest artifact
#   - release.yml verifies stable aliases == RC digests
#   - release.yml keeps the exact-commit CI gate
#   - release.yml still performs no docker build
#   - release.yml can read artifacts (actions: read)
#   - promote-stable.yml enforces the stable-tag ref policy
#   - promote-stable.yml binds tag commit to expected_revision
#   - promote-stable.yml fetches the RC manifest through the verifier
#   - promote-stable.yml keeps the production environment gate
#   - promote-stable.yml still performs no docker build (comments aside)
#   - release guard asserts the check names
#
# tests/vulnerability-policy/test_reconciliation_scope.sh
#   - the platform-reconciliation gate runs in publish preflight, before any push
#
# tests/vulnerability-policy/test_vuln_policy.sh
#   - scheduled-rebuild: rebuild job has no issues:write (job isolation)
#   - scheduled-rebuild: candidate tag is immutable (date+run+attempt+sha)
#   - scheduled-rebuild: validates vuln policy before build
#

# --- what is enforceable today ---------------------------------------------
for wf in release publish-rc promote-stable scheduled-rebuild rollback-exercise; do
  f=".github/workflows/${wf}.yml"
  ck "$wf still exists as an operator entry point" "test -f $f"
  ck "$wf cannot publish (contents:read only, no packages, no id-token)" \
     "python3 -c \"
import yaml
d=yaml.safe_load(open('$f'))
assert d['permissions']=={'contents':'read'}, d['permissions']
for n,j in d['jobs'].items():
    assert j['permissions']=={'contents':'read'}, (n, j['permissions'])
\""
  ck "$wf refuses and names its replacement" \
     "grep -q 'REFUSE: public publication is disabled' $f && grep -q '#139' $f"
done

ck "the reusable production publisher is gone from the tree" \
   "! test -f .github/workflows/publish-ghcr.yml"

# --- #82: the ~/.cosign race, and why it cannot happen today ----------------
# publish-rc and scheduled-rebuild both targeted the self-hosted ORG pool, which
# has two slots and one shared $HOME/.cosign. With separate concurrency groups
# they could run at once and race that directory — observed twice, once failing a
# release mid-publish. The fix asked for was a shared `org-cosign-publish` group
# plus per-job cosign isolation.
#
# Neither is implementable today and neither is needed today: both workflows are
# refuse-only stubs on a GitHub-hosted runner that sign nothing. Asserting a
# concurrency group on a workflow that cannot collide would be theatre. What IS
# assertable is the precondition — that they cannot reach the shared home at all.
for wf in publish-rc scheduled-rebuild; do
  f=".github/workflows/$wf.yml"
  ck "$wf runs GitHub-hosted (never the shared-cosign org pool)" \
     "! grep -qE 'runs-on:.*(self-hosted|zenchron-dynamics)' $f"
  # Comment lines are excluded on purpose: both headers DESCRIBE the deleted
  # signing they used to do, and that prose is the record of what was removed.
  ck "$wf signs nothing (no cosign outside the explanatory header)" \
     "! grep -vE '^[[:space:]]*#' $f | grep -qiE 'cosign|COSIGN_'"
done

# The forward guard. When publication returns (#139) and either workflow regains
# a signing step, the group is no longer optional — and this fails until BOTH
# declare the same one. That is the guarantee the inventory above records, made
# executable rather than left as a comment for someone to remember.
ck "if either workflow signs again, both must share one concurrency group" \
   'python3 -c "
import sys, yaml
files = {w: \".github/workflows/%s.yml\" % w for w in (\"publish-rc\", \"scheduled-rebuild\")}
signs, groups = {}, {}
for w, f in files.items():
    raw = open(f).read()
    code = \"\\n\".join(l for l in raw.splitlines() if not l.lstrip().startswith(\"#\"))
    signs[w] = (\"cosign\" in code.lower())
    groups[w] = ((yaml.safe_load(raw) or {}).get(\"concurrency\") or {}).get(\"group\")
if not any(signs.values()):
    sys.exit(0)                       # nothing signs yet: nothing to serialize
if groups[\"publish-rc\"] is None or groups[\"publish-rc\"] != groups[\"scheduled-rebuild\"]:
    print(\"a signing workflow reappeared without a shared concurrency group: %r\" % groups)
    sys.exit(1)
"' 
INVENTORY_COUNT="$(grep -c '^#   - ' "$0")"
ck "the inventory above is not empty (it is the restoration checklist)" \
   "[ \"$INVENTORY_COUNT\" -gt 20 ]"

echo "----"; [ "$fail" -eq 0 ] && echo "test_disabled_paths_inventory: PASS" || echo "test_disabled_paths_inventory: FAIL"
exit $fail
