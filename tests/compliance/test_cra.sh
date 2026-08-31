#!/usr/bin/env bash
# =============================================================================
# tests/compliance/test_cra.sh — the CRA control set (#113, #114).
#
# The failure mode this guards against is not a broken script. It is a
# compliance artefact that LOOKS complete: a control matrix citing files that
# were deleted, a roles table with plausible names and no real succession, an
# applicability determination nobody made, or a "tabletop" that is really a
# fixture being quoted as an exercise.
#
# So the assertions below are mostly about honesty, and each one has a matching
# sabotage case proving the validator would catch the dishonest version.
# Sabotage is always applied to a COPY — a test that edits policies/ to make a
# point has destroyed the artefact it was asserting about, which has happened
# in this repository before.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

TMP="$(mktemp -d)"
# shellcheck disable=SC2064
trap "rm -rf '$TMP'" EXIT

fingerprint() { find policies scripts docs/cra -type f -exec shasum -a 256 {} + | sort | shasum -a 256; }
PRE_FINGERPRINT="$(fingerprint)"

CRA=scripts/cra/assert-cra-controls.sh
APP=policies/cra-applicability.yaml
ROLES=policies/cra-roles.yaml
MATRIX=policies/cra-control-matrix.yaml

ck "the CRA validator self-test passes"      "bash $CRA --self-test >/dev/null"
ck "the shipped CRA policy set validates"    "bash $CRA >/dev/null 2>&1"

# --- it must never claim compliance or certification ------------------------
ck "applicability is UNDETERMINED and unattributed" \
   "python3 -c \"
import yaml;a=yaml.safe_load(open('$APP'))['applicability']
assert a['status']=='undetermined',a['status']
assert a['determined_by'] is None and a['determined_at'] is None,a\""
ck "the control matrix declares it is not a compliance claim" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$MATRIX'))['disclaimer']
assert d['is_compliance_claim'] is False and d['is_certification'] is False,d\""
ck "no document in docs/cra claims certification or conformity was achieved" \
   "! grep -rniE '(we are|is) (cra )?(compliant|certified)|conformity assessment (completed|passed)' docs/cra/"
ck "every decision-template answer is still null" \
   "python3 -c \"
import yaml;t=yaml.safe_load(open('$APP'))['decision_template']
bad=[r['id'] for r in t if r['answer'] is not None]
assert not bad,bad\""
ck "the output states applicability is undetermined" \
   "bash $CRA >'$TMP/o' 2>&1; grep -q 'not a compliance claim' '$TMP/o'"

# --- product boundary -------------------------------------------------------
ck "every product declares its full boundary" \
   "python3 -c \"
import yaml;p=yaml.safe_load(open('$APP'))['product_boundary']['products']
assert len(p)>=6,len(p)
for x in p:
    for f in ('id','foundry_authored','third_party_core','distribution','recipients','support_line_ref'):
        assert x.get(f),(x['id'],f)\""
ck "the boundary distinguishes authored work from repackaged upstream" \
   "python3 -c \"
import yaml;p=yaml.safe_load(open('$APP'))['product_boundary']['products']
fp=[x for x in p if x['id']=='php-frankenphp'][0]
assert 'compile' in (fp.get('note') or ''),fp\""
ck "support period is referenced, not restated (no drift)" \
   "python3 -c \"
import yaml;s=yaml.safe_load(open('$APP'))['support_period']
assert s['declared_in']=='policies/support-policy.yaml',s
assert s['meets_required_minimum'] is None,s\""

# --- roles and backups ------------------------------------------------------
ck "every role has a backup or a fully DECLARED gap" \
   "python3 -c \"
import yaml;rs=yaml.safe_load(open('$ROLES'))['roles']
for r in rs:
    assert 'backup' in r,r['id']
    if not r['backup']:
        assert r.get('backup_gap') is True,r['id']
        for f in ('gap_reason','gap_owner','gap_tracked_in'):
            assert r.get(f),(r['id'],f)\""
ck "the single-person concentration is recorded as reportable" \
   "python3 -c \"
import yaml;c=yaml.safe_load(open('$ROLES'))['concentration']
assert c['single_person'] is True and c['must_be_stated_in_filings'] is True,c\""
ck "no role invents a deputy that governance-model.yaml says cannot exist" \
   "python3 -c \"
import yaml
g=yaml.safe_load(open('policies/governance-model.yaml'))
rs=yaml.safe_load(open('$ROLES'))['roles']
named={r['backup'] for r in rs if r['backup']}
assert not named, 'a backup was named while governance declares a single maintainer: %s' % named\""

# --- the control matrix must point at reality -------------------------------
ck "every cited evidence path EXISTS on disk" \
   "python3 -c \"
import yaml,os
for o in yaml.safe_load(open('$MATRIX'))['obligations']:
    for p in o['evidence']:
        assert os.path.exists(p),(o['id'],p)\""
ck "every partial/absent obligation names its gap" \
   "python3 -c \"
import yaml
for o in yaml.safe_load(open('$MATRIX'))['obligations']:
    if o['status'] in ('partial','absent'):
        assert o.get('gap'),o['id']\""
ck "the known blockers are represented as gaps, not as coverage" \
   "python3 -c \"
import yaml
o={x['id']:x for x in yaml.safe_load(open('$MATRIX'))['obligations']}
assert '116' in o['business-continuity-of-supply']['gap']
assert '111' in o['native-runtime-assurance']['gap']
assert '139' in o['integrity-of-distribution']['gap']
assert o['conformity-documentation']['status']=='absent'\""

# --- the synthetic tabletop EXECUTES ----------------------------------------
ck "the synthetic tabletop runs and passes" \
   "bash $CRA --tabletop >'$TMP/tt' 2>&1"
ck "...and is labelled a fixture, not an exercise that happened" \
   "grep -q 'FIXTURE ONLY, NOT A REAL EXERCISE' '$TMP/tt'"
ck "...and states nobody participated" \
   "grep -q 'conducted with real participants' '$TMP/tt'"
ck "...and exercised every record refusal condition it claims to" \
   "grep -q 'NO awareness time is refused' '$TMP/tt' &&
    grep -q 'naive timestamp is refused' '$TMP/tt' &&
    grep -q 'disagrees with policy is refused' '$TMP/tt' &&
    grep -q 'omitting early_warning_due is refused' '$TMP/tt' &&
    grep -q 'omitting full_notification_due is refused' '$TMP/tt' &&
    grep -q 'omitting final_report_due is refused' '$TMP/tt' &&
    grep -q 'omitting ALL three deadlines is refused' '$TMP/tt' &&
    grep -q 'cannot be recomputed is refused' '$TMP/tt' &&
    grep -q 'missing evidence is refused' '$TMP/tt' &&
    grep -q 'no customer-impact classification is refused' '$TMP/tt'"
ck "...and proved non-vacuity: the unmodified record still passes" \
   "grep -q 'NON-VACUOUS: the unmodified record still passes' '$TMP/tt'"

# --- SABOTAGE, on disposable copies -----------------------------------------
mk() { python3 - "$2" "$TMP/$1" <<PY
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
$3
yaml.safe_dump(d, open(sys.argv[2], "w"))
PY
}

mk ghost.yaml "$MATRIX" 'd["obligations"][0]["evidence"]=["scripts/nope.sh"]'
ck "sabotage: evidence citing a file that does not exist REFUSES" \
   "! CRA_MATRIX='$TMP/ghost.yaml' bash $CRA >/dev/null 2>&1"
ck "...naming it as absent" \
   "CRA_MATRIX='$TMP/ghost.yaml' bash $CRA >'$TMP/o' 2>&1 || true; grep -q 'DOES NOT EXIST' '$TMP/o'"

mk nogap.yaml "$MATRIX" 'for o in d["obligations"]:
    if o["status"]=="partial":
        o["gap"]=None
        break'
ck "sabotage: a 'partial' obligation with no gap REFUSES" \
   "! CRA_MATRIX='$TMP/nogap.yaml' bash $CRA >/dev/null 2>&1"

mk claim.yaml "$MATRIX" 'd["disclaimer"]["is_compliance_claim"]=True'
ck "sabotage: presenting the matrix as a compliance claim REFUSES" \
   "! CRA_MATRIX='$TMP/claim.yaml' bash $CRA >/dev/null 2>&1"

mk nobackup.yaml "$ROLES" 'r=d["roles"][0]
r.pop("backup_gap",None); r.pop("gap_reason",None)'
ck "sabotage: a role with no backup and no declared gap REFUSES" \
   "! CRA_ROLES='$TMP/nobackup.yaml' bash $CRA >/dev/null 2>&1"
ck "...saying it implies resilience that does not exist" \
   "CRA_ROLES='$TMP/nobackup.yaml' bash $CRA >'$TMP/o' 2>&1 || true;
    grep -q 'implies resilience that does not exist' '$TMP/o'"

mk selfbackup.yaml "$ROLES" 'r=d["roles"][0]
r["backup"]=r["primary"]; r["backup_gap"]=False'
ck "sabotage: a role backed up by itself REFUSES" \
   "! CRA_ROLES='$TMP/selfbackup.yaml' bash $CRA >/dev/null 2>&1"

mk determined.yaml "$APP" 'd["applicability"]["status"]="applies"'
ck "sabotage: an unattributed determination REFUSES" \
   "! CRA_APPLICABILITY='$TMP/determined.yaml' bash $CRA >/dev/null 2>&1"

mk noproducts.yaml "$APP" 'd["product_boundary"]["products"]=[]'
ck "sabotage: an empty product boundary REFUSES" \
   "! CRA_APPLICABILITY='$TMP/noproducts.yaml' bash $CRA >/dev/null 2>&1"

# --- record validation, end to end ------------------------------------------
cat >"$TMP/rec.yaml" <<'YAML'
id: TEST-RECORD
simulated: true
state: CLOSED
awareness_at: "2026-08-13T09:00:00+00:00"
early_warning_due: "2026-08-14T09:00:00+00:00"
classification: not-reportable
classification_rationale: no released artefact is affected
customer_impact: no-customer-impact
customer_impact_rationale: nothing reaching a recipient is affected
YAML
ck "a well-formed not-reportable record validates" \
   "bash $CRA --check-record '$TMP/rec.yaml' >/dev/null 2>&1"
ck "...but removing its rationale REFUSES" \
   "grep -v '^classification_rationale:' '$TMP/rec.yaml' >'$TMP/r2.yaml';
    ! bash $CRA --check-record '$TMP/r2.yaml' >/dev/null 2>&1"
ck "...and removing the customer-impact rationale REFUSES" \
   "grep -v '^customer_impact_rationale:' '$TMP/rec.yaml' >'$TMP/r3.yaml';
    ! bash $CRA --check-record '$TMP/r3.yaml' >/dev/null 2>&1"
ck "an unreadable record REFUSES rather than being skipped" \
   "echo 'not: [valid' >'$TMP/bad.yaml'; ! bash $CRA --check-record '$TMP/bad.yaml' >/dev/null 2>&1"

# --- the SHIPPED records, not just synthetic fixtures ------------------------
# The cases above build their own records in $TMP. That is how the shipped
# tabletop evidence came to be REFUSED by this very validator while CI stayed
# green: `scripts/incident.sh --tabletop` emitted no `customer_impact`, and
# nothing ever pointed --check-record at the artefact the exercise leaves behind.
# Two implementations built to disagree-detect each other were never aimed at
# each other on the one record that ships as evidence. #114 criterion 3.
shipped_incident_records() { ls docs/audits/incidents/*.yaml 2>/dev/null; }
refused_shipped_records() {
  local f
  for f in $(shipped_incident_records); do
    bash "$CRA" --check-record "$f" >/dev/null 2>&1 || echo "$f"
  done
}
# NON-VACUITY: if the glob matches nothing the check below passes trivially.
ck "NON-VACUOUS: at least one incident record actually ships" \
   '[ "$(shipped_incident_records | wc -l)" -ge 1 ]'
ck "every SHIPPED incident record is reportable-ready" \
   '[ -z "$(refused_shipped_records)" ]'

# --- deadlines a record OWES but does not state ------------------------------
# The defect: --check-record fetched each stated deadline and skipped it when
# absent, so the shipped record — which stated none of the three — was reported
# as having deadlines that "agree with policy" after comparing nothing.
SHIPPED=docs/audits/incidents/INC-SIMULATED-20260812.yaml
sabotage() { python3 -c "
import yaml,sys
r=yaml.safe_load(open('$SHIPPED'))
exec(sys.argv[1])
yaml.safe_dump(r,open(sys.argv[2],'w'),sort_keys=False,width=100)" "$1" "$2"; }

ck "the shipped record states all three deadlines and passes" \
   "python3 -c \"
import yaml;r=yaml.safe_load(open('$SHIPPED'))
missing=[k for k in ('early_warning_due','full_notification_due','final_report_due') if not r.get(k)]
assert not missing,missing\" && bash $CRA --check-record '$SHIPPED' >/dev/null 2>&1"

for field in early_warning full_notification final_report; do
  sabotage "r.pop('${field}_due')" "$TMP/no-$field.yaml"
  ck "dropping ${field}_due alone is refused" \
     "! bash $CRA --check-record '$TMP/no-$field.yaml' >/dev/null 2>&1"
  ck "...with a diagnostic naming ${field}_due specifically" \
     "bash $CRA --check-record '$TMP/no-$field.yaml' >'$TMP/o' 2>&1;
      grep -q '${field}_due is MISSING' '$TMP/o'"
done

sabotage "[r.pop(k+'_due') for k in ('early_warning','full_notification','final_report')]" \
         "$TMP/no-due.yaml"
ck "dropping all three is refused, never a silent success" \
   "! bash $CRA --check-record '$TMP/no-due.yaml' >/dev/null 2>&1"
ck "...producing three attributable refusals, one per field" \
   "bash $CRA --check-record '$TMP/no-due.yaml' >'$TMP/o' 2>&1;
    [ \"\$(grep -c '_due is MISSING' '$TMP/o')\" -eq 3 ]"

# A wrong deadline and an absent one are different defects and must not collapse
# into one diagnostic: the first is a miscomputation, the second a gap.
sabotage "r['early_warning_due']='2026-08-14T10:00:00+00:00'" "$TMP/wrong-due.yaml"
ck "a MISMATCHED deadline is refused separately from a missing one" \
   "bash $CRA --check-record '$TMP/wrong-due.yaml' >'$TMP/o' 2>&1;
    grep -q 'but policy computes' '$TMP/o' && ! grep -q '_due is MISSING' '$TMP/o'"

# The second silent hole: with no base timestamp the expected value was never
# computed, so the stated deadline was never compared with anything.
sabotage "r.pop('corrective_measure_available_at')" "$TMP/no-base.yaml"
ck "a final report that cannot be recomputed is refused as unverifiable" \
   "bash $CRA --check-record '$TMP/no-base.yaml' >'$TMP/o' 2>&1;
    grep -q 'final_report_due cannot be verified' '$TMP/o'"

ck "the success line counts the deadlines it actually compared" \
   "bash $CRA --check-record '$SHIPPED' 2>&1 | grep -q '3 owed / 3 checked deadline'"

# --- obligation ownership (#113 criterion 2) ---------------------------------
ck "every obligation names an owner" \
   "python3 -c \"
import yaml;obs=yaml.safe_load(open('$MATRIX'))['obligations']
bad=[o['id'] for o in obs if not o.get('owner')]
assert not bad,bad
assert len(obs)==14,len(obs)\""
ck "every owner is a role declared in cra-roles.yaml, never a person" \
   "python3 -c \"
import yaml
ids={r['id'] for r in yaml.safe_load(open('$ROLES'))['roles']}
bad=[(o['id'],o['owner']) for o in yaml.safe_load(open('$MATRIX'))['obligations']
     if o['owner'] not in ids]
assert not bad,bad\""

python3 -c "
import yaml
m=yaml.safe_load(open('$MATRIX')); m['obligations'][0].pop('owner')
yaml.safe_dump(m,open('$TMP/no-owner.yaml','w'),sort_keys=False)
m=yaml.safe_load(open('$MATRIX')); m['obligations'][0]['owner']='Bogdan Olteanu'
yaml.safe_dump(m,open('$TMP/person-owner.yaml','w'),sort_keys=False)
m=yaml.safe_load(open('$MATRIX')); m['obligations'][0]['owner']='platform-security'
yaml.safe_dump(m,open('$TMP/unknown-owner.yaml','w'),sort_keys=False)"
ck "an ownerless obligation is REFUSED" \
   "! CRA_MATRIX='$TMP/no-owner.yaml' bash $CRA >/dev/null 2>&1"
ck "...saying the obligation names no owner" \
   "CRA_MATRIX='$TMP/no-owner.yaml' bash $CRA >'$TMP/o' 2>&1; grep -q 'names no owner' '$TMP/o'"
ck "an owner naming a PERSON rather than a role is REFUSED" \
   "! CRA_MATRIX='$TMP/person-owner.yaml' bash $CRA >/dev/null 2>&1"
ck "an owner naming an undeclared role is REFUSED" \
   "! CRA_MATRIX='$TMP/unknown-owner.yaml' bash $CRA >/dev/null 2>&1"
ck "...listing the roles that ARE declared, so the fix is obvious" \
   "CRA_MATRIX='$TMP/unknown-owner.yaml' bash $CRA >'$TMP/o' 2>&1;
    grep -q 'is not a role declared in policies/cra-roles.yaml' '$TMP/o'"

# --- the retained deadline verdict (#114 defect ii) --------------------------
# The verdict used to exist only on stdout. These assertions read it from the
# RECORD; none of them runs scripts/incident.sh, so a verdict that lives only in
# a terminal cannot satisfy them.
ck "the shipped record retains a deadline verdict" \
   "python3 -c \"
import yaml;dv=yaml.safe_load(open('$SHIPPED')).get('deadline_verdict')
assert dv,'no deadline_verdict'
assert dv['overall']=='MET',dv['overall']
assert {c['id'] for c in dv['clocks']}=={'early_warning','full_notification','final_report'},dv\""
ck "the retained verdict says it was derived, not observed during the exercise" \
   "python3 -c \"
import yaml;n=yaml.safe_load(open('$SHIPPED'))['deadline_verdict']['note']
assert 'NOT an observation' in n,n\""

sabotage "r.pop('deadline_verdict')" "$TMP/nv.yaml"
ck "a simulated record that reached a submission and retained NO verdict is REFUSED" \
   "! bash $CRA --check-record '$TMP/nv.yaml' >/dev/null 2>&1"
sabotage "r['deadline_verdict']['clocks'][0]['verdict']='MISSED'" "$TMP/lie.yaml"
ck "a retained verdict that disagrees with the record's own times is REFUSED" \
   "bash $CRA --check-record '$TMP/lie.yaml' >'$TMP/o' 2>&1;
    grep -q 'recomputation from the' '$TMP/o'"
sabotage "r['deadline_verdict']['overall']='MISSED'" "$TMP/ov.yaml"
ck "a retained overall verdict inconsistent with its clocks is REFUSED" \
   "! bash $CRA --check-record '$TMP/ov.yaml' >/dev/null 2>&1"
sabotage "r['deadline_verdict']['clocks']=[c for c in r['deadline_verdict']['clocks'] if c['id']!='final_report']" \
         "$TMP/dropclock.yaml"
ck "a verdict omitting one clock is REFUSED, not averaged over" \
   "! bash $CRA --check-record '$TMP/dropclock.yaml' >/dev/null 2>&1"

# --- this batch changed no determination -------------------------------------
ck "applicability is STILL undetermined after all of the above" \
   "python3 -c \"
import yaml;a=yaml.safe_load(open('$APP'))['applicability']
assert a['status']=='undetermined',a['status']
assert a['determined_by'] is None and a['determined_at'] is None,a\""
ck "no CRA role acquired a backup or a holder" \
   "python3 -c \"
import yaml;rs=yaml.safe_load(open('$ROLES'))['roles']
assert all(r['backup'] is None and r.get('backup_gap') for r in rs),rs\""
ck "the retention rationale names WHICH signature it means" \
   "python3 -c \"
import yaml
t=yaml.safe_load(open('policies/incident-reporting.yaml'))['retention']['tamper_evidence']
assert 'GITHUB' in t,t
assert 'NOT author attestation' in t,t
assert 'policy rather than enforcement' in t,t\""

# --- NON-VACUITY -------------------------------------------------------------
ck "non-vacuity: the shipped matrix reports gaps rather than full coverage" \
   "python3 -c \"
import yaml
st=[o['status'] for o in yaml.safe_load(open('$MATRIX'))['obligations']]
assert st.count('partial')>=5,st
assert 'absent' in st,st\""
ck "non-vacuity: every role is reported as lacking a backup" \
   "python3 -c \"
import yaml;rs=yaml.safe_load(open('$ROLES'))['roles']
assert all(r.get('backup_gap') for r in rs),[r['id'] for r in rs if not r.get('backup_gap')]\""
ck "non-vacuity: the validator distinguishes a good record from a bad one" \
   "bash $CRA --check-record '$TMP/rec.yaml' >/dev/null 2>&1 &&
    ! bash $CRA --check-record '$TMP/r2.yaml' >/dev/null 2>&1"

ck "the test mutated nothing under policies/, scripts/ or docs/cra/" \
   "[ \"\$(fingerprint)\" = '$PRE_FINGERPRINT' ]"

echo "----"
[ "$fail" -eq 0 ] && echo "test_cra: PASS" || echo "test_cra: FAIL"
exit "$fail"
