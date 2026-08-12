#!/usr/bin/env bash
# =============================================================================
# scripts/assert-governance-model.sh — the operating model, enforced (#112).
#
# policies/governance-model.yaml states that this project has one maintainer and
# that three things people habitually mistake for independent review are not.
# This proves the file is internally complete, that the compensating controls it
# names actually exist in the tree, and — with --check-control-plane — that the
# live GitHub state matches what it claims.
#
# It deliberately does NOT try to verify "there is only one maintainer" from the
# repository alone: that is an organization fact, checked against the API in the
# control-plane mode and otherwise taken from the declaration. What it DOES
# enforce offline is that nothing in the tree quietly claims independence the
# model says does not exist.
#
# Usage:
#   assert-governance-model.sh                     offline
#   assert-governance-model.sh --check-control-plane   + live org/repo state
#   assert-governance-model.sh --self-test
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1
MODEL="${GOVERNANCE_MODEL:-$ROOT/policies/governance-model.yaml}"

pass=0; fail=0
ck() { if eval "$2"; then pass=$((pass+1)); echo "ok   - $1"; else fail=$((fail+1)); echo "FAIL - $1"; fi; }

# --- the model is complete ---------------------------------------------------
ck "the governance model parses and declares schema_version 1" \
   "python3 -c \"
import yaml; d=yaml.safe_load(open('$MODEL')); assert d['schema_version']==1\""
ck "it declares the single-maintainer reality explicitly" \
   "python3 -c \"
import yaml; m=yaml.safe_load(open('$MODEL'))['model']
assert m['single_maintainer'] is True
assert m['independent_review_available'] is False
assert m['segregation_of_duties'] == 'unavailable'\""
# The three conflations must each be asserted FALSE, with a reason. A model that
# merely omits them is not the same as one that refuses them.
ck "all three 'this is not review' claims are recorded as false, with reasons" \
   "python3 -c \"
import yaml
n = yaml.safe_load(open('$MODEL'))['model']['not_equivalent']
assert len(n) == 3, len(n)
for e in n:
    assert e['holds'] is False, e
    assert e.get('why','').strip(), e\""

# --- the compensating controls must EXIST, not merely be listed --------------
ck "every compensating control names a verifier that exists" \
   'python3 -c "
import os, yaml
d = yaml.safe_load(open(\"policies/governance-model.yaml\"))
missing = []
for c in d[\"compensating_controls\"]:
    v = c.get(\"verified_by\", \"\")
    # a script path must exist; a documentary reference must name a real dir
    for tok in v.split():
        if tok.startswith(\"scripts/\") or tok.startswith(\"docs/\") or tok.startswith(\"policies/\"):
            p = tok.rstrip(\"/\").split(\"(\")[0]
            if not os.path.exists(p):
                missing.append((c[\"control\"], p))
assert not missing, missing
"'

# --- sensitive paths are real, and the detector uses THIS list ---------------
ck "the sensitive-path list is non-empty" \
   "[ \"\$(python3 -c \"
import yaml; print(len(yaml.safe_load(open('$MODEL'))['sensitive_paths']))\")\" -gt 5 ]"
ck "every sensitive path pattern matches something in the tree" \
   'python3 -c "
import glob, yaml
d = yaml.safe_load(open(\"policies/governance-model.yaml\"))
dead = [p for p in d[\"sensitive_paths\"] if not glob.glob(p, recursive=True)]
assert not dead, (\"patterns matching nothing — the detector would ignore them\", dead)
"'
ck "the sensitive-change workflow exists and reads the model" \
   "test -f .github/workflows/sensitive-change.yml && \
    grep -q 'policies/governance-model.yaml' .github/workflows/sensitive-change.yml"
ck "...and the checklist it demands comes from the model, not a copy" \
   "! grep -qE '^\\s*- \\[ \\] (blast-radius|fail-direction)' .github/workflows/sensitive-change.yml"

# --- break-glass -------------------------------------------------------------
ck "the break-glass schema requires a retrospective" \
   "python3 -c \"
import yaml; b=yaml.safe_load(open('$MODEL'))['break_glass']
assert b['retrospective_required'] is True
assert 'retrospective' in b['required_fields']
assert isinstance(b['retrospective_deadline_days'], int)\""
# An OPEN break-glass record past its retrospective deadline is the thing this
# schema exists to prevent. Checked against real records when any exist.
ck "no break-glass record is open past its retrospective deadline" \
   'python3 -c "
import datetime, glob, os, yaml
d = yaml.safe_load(open(\"policies/governance-model.yaml\"))[\"break_glass\"]
today = datetime.date.today()
late = []
for f in glob.glob(os.path.join(d[\"record_dir\"], \"*.yaml\")):
    r = yaml.safe_load(open(f)) or {}
    if r.get(\"retrospective\"):
        continue
    opened = r.get(\"opened_at\")
    if not opened:
        late.append((f, \"no opened_at\")); continue
    od = datetime.date.fromisoformat(str(opened)[:10])
    if (today - od).days > int(d[\"retrospective_deadline_days\"]):
        late.append((f, str(od)))
assert not late, late
"'

# --- the residual risk is owned, dated, and has an exit --------------------
ck "the risk register records an owner, a review date and exit criteria" \
   "python3 -c \"
import yaml; r=yaml.safe_load(open('$MODEL'))['risk_register'][0]
assert r['accepted'] is True and r['owner'] and r['review_date'] and r['exit_criteria']\""
ck "the review date has not silently lapsed" \
   'python3 -c "
import datetime, yaml
r = yaml.safe_load(open(\"policies/governance-model.yaml\"))[\"risk_register\"][0]
rd = r[\"review_date\"]
rd = rd if isinstance(rd, datetime.date) else datetime.date.fromisoformat(str(rd))
assert rd >= datetime.date.today(), (\"the single-maintainer risk review is overdue\", rd)
"'
# The named non-mitigations are the whole point of the issue: they must stay
# listed, because they are what a future reader would otherwise reach for.
ck "fake independence is explicitly named as NOT a mitigation" \
   "python3 -c \"
import yaml
r = yaml.safe_load(open('$MODEL'))['risk_register'][0]['explicitly_not_mitigations']
j = ' '.join(r).lower()
assert 'account' in j and 'team' in j and ('ai' in j.split() or 'ai ' in j), r\""

# --- nothing in the tree may claim the independence the model denies ---------
ck "no document claims segregation of duties exists today" \
   '[ -z "$(grep -rn "segregation of duties" docs/ --include=*.md 2>/dev/null \
      | grep -viE "not |no |unavailable|cannot|does not|absent" || true)" ]'
ck "external review triggers are named conditions, not intentions" \
   "[ \"\$(python3 -c \"
import yaml; print(len(yaml.safe_load(open('$MODEL'))['external_review_triggers']))\")\" -ge 4 ]"

# --- live control plane (read-only) -----------------------------------------
if [ "${1:-}" = "--check-control-plane" ]; then
  echo "--- control plane (read-only)"
  if ! command -v gh >/dev/null 2>&1; then
    echo "FAIL - gh is required for --check-control-plane"; fail=$((fail+1))
  else
    # The declaration says one maintainer. Check it, rather than trusting it.
    members="$(gh api orgs/zenchron-dynamics/members --jq 'length' 2>/dev/null || echo "")"
    if [ -z "$members" ]; then
      echo "FAIL - could not read org membership (treating as unverified, not as OK)"; fail=$((fail+1))
    else
      declared="$(python3 -c "
import yaml; print(yaml.safe_load(open('$MODEL'))['model']['maintainer_count'])")"
      ck "live org member count ($members) equals the declared maintainer count" \
         "[ '$members' = \"$declared\" ]"
    fi
    ck "master is protected by an active ruleset" \
       "gh api repos/zenchron-dynamics/zenchron-foundry/rulesets --jq '.[]|select(.target==\"branch\" and .enforcement==\"active\")|.name' 2>/dev/null | grep -q ."
    ck "release tags are protected by an active ruleset" \
       "gh api repos/zenchron-dynamics/zenchron-foundry/rulesets --jq '.[]|select(.target==\"tag\" and .enforcement==\"active\")|.name' 2>/dev/null | grep -q ."
  fi
fi

if [ "${1:-}" = "--self-test" ]; then
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  # A model that claims independence must be rejected: that is the failure mode
  # this whole file exists to make impossible to introduce quietly.
  python3 -c "
import yaml
d = yaml.safe_load(open('$MODEL'))
d['model']['single_maintainer'] = False
d['model']['independent_review_available'] = True
yaml.safe_dump(d, open('$tmp/fake.yaml','w'), sort_keys=False)"
  if GOVERNANCE_MODEL="$tmp/fake.yaml" bash "$0" >/dev/null 2>&1; then
    echo "FAIL - a model claiming independent review was ACCEPTED"; fail=$((fail+1))
  else
    echo "ok   - a model claiming independent review is rejected"; pass=$((pass+1))
  fi
fi

echo "----"
printf 'assert-governance-model: %d ok, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
