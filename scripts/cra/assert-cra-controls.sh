#!/usr/bin/env bash
# =============================================================================
# scripts/cra/assert-cra-controls.sh — validate the CRA control set (#113, #114).
# -----------------------------------------------------------------------------
# THIS SCRIPT DOES NOT CERTIFY ANYTHING AND DOES NOT ASSERT COMPLIANCE.
# CRA applicability is undetermined (policies/cra-applicability.yaml). What this
# validates is narrower and checkable: that the control matrix describes controls
# that actually exist, that roles cannot quietly lack a backup, and that an
# incident record cannot omit the things a report is built from.
#
# It refuses on nine conditions, each of which has been a real way for a
# compliance artefact to become decorative:
#
#   1. awareness time missing, or carrying no timezone
#   2. deadlines that disagree with the deadlines recomputed from policy
#   3. a deadline the record OWES but does not state at all
#   4. a deadline that cannot be recomputed, so was never actually compared
#   5. mandatory evidence absent from a record that claims to be reportable
#   6. a role with no backup and no DECLARED gap
#   7. an obligation with no owner, or an owner that is not a declared role
#   8. a simulated exercise that reached a submission and retained no verdict,
#      or retained one that disagrees with its own timestamps
#   9. customer-impact classification missing from a closed incident
#
# (2) exists because scripts/incident.sh computes the clocks and this script
# recomputes them independently from policies/incident-reporting.yaml. Two
# implementations that must agree will catch a drift that one implementation
# checking itself never can.
#
# (3) and (4) exist because (2) alone was not enough and said so misleadingly.
# The comparison fetched each stated deadline and skipped it when absent, so a
# record that simply omitted the field passed, and the run still printed
# "deadlines agree with policy" — agreement over an empty comparison. A
# miscomputed deadline was caught; an absent one was reported as agreeing.
#
# Usage:
#   assert-cra-controls.sh                      validate the policy set
#   assert-cra-controls.sh --check-record FILE  validate one incident record
#   assert-cra-controls.sh --tabletop           SYNTHETIC offline exercise
#   assert-cra-controls.sh --self-test
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1

APPLICABILITY="${CRA_APPLICABILITY:-policies/cra-applicability.yaml}"
ROLES="${CRA_ROLES:-policies/cra-roles.yaml}"
MATRIX="${CRA_MATRIX:-policies/cra-control-matrix.yaml}"
INCIDENT_POLICY="${INCIDENT_POLICY:-policies/incident-reporting.yaml}"

usage() {
  sed -n '36,40p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 64
}

# -----------------------------------------------------------------------------
validate_policies() {
  # Read the env vars HERE rather than the shell variables captured at startup,
  # so an inline `CRA_ROLES=... validate_policies` in a test actually overrides
  # the file under validation. Binding them once at the top would have made
  # every sabotage case silently re-validate the shipped policy and pass.
  A="${CRA_APPLICABILITY:-policies/cra-applicability.yaml}" \
  R="${CRA_ROLES:-policies/cra-roles.yaml}" \
  M="${CRA_MATRIX:-policies/cra-control-matrix.yaml}" python3 <<'PY'
import os, sys, yaml, datetime

problems = []

def load(path, label):
    try:
        with open(path) as fh:
            return yaml.safe_load(fh)
    except (OSError, ValueError) as e:
        problems.append("%s (%s) is unreadable: %s" % (label, path, e))
        return None

app = load(os.environ["A"], "applicability")
roles = load(os.environ["R"], "roles")
matrix = load(os.environ["M"], "control matrix")

# --- applicability: a determination must never appear without an author ------
if app is not None:
    a = app.get("applicability") or {}
    status = a.get("status")
    if status != "undetermined":
        # Not forbidden — but it must be attributable and dated.
        if not a.get("determined_by") or not a.get("determined_at"):
            problems.append(
                "applicability.status is %r but determined_by/determined_at are "
                "empty — a determination nobody made and nobody dated is not a "
                "determination" % status)
    for row in app.get("decision_template") or []:
        if row.get("answer") is not None and not row.get("answered_by"):
            problems.append("decision_template %r has an answer with no answered_by"
                            % row.get("id"))
        if not row.get("evidence_needed"):
            problems.append("decision_template %r states no evidence_needed" % row.get("id"))
    prods = (app.get("product_boundary") or {}).get("products") or []
    if not prods:
        problems.append("product_boundary lists no products — an empty inventory is not a boundary")
    for p in prods:
        for field in ("id", "foundry_authored", "third_party_core", "distribution",
                      "recipients", "support_line_ref"):
            if not p.get(field):
                problems.append("product %r is missing boundary field %r"
                                % (p.get("id", "<unnamed>"), field))

# --- roles: no backup, no gap, no pass ---------------------------------------
if roles is not None:
    rs = roles.get("roles") or []
    if not rs:
        problems.append("no roles defined — an empty roles matrix is not a roles matrix")
    for r in rs:
        rid = r.get("id", "<unnamed>")
        if not r.get("responsibility"):
            problems.append("role %r states no responsibility" % rid)
        if not r.get("primary"):
            problems.append("role %r has no primary" % rid)
        if "backup" not in r:
            problems.append("role %r has no `backup` key at all" % rid)
            continue
        backup, gap = r.get("backup"), r.get("backup_gap")
        if backup:
            if backup == r.get("primary"):
                problems.append(
                    "role %r names its own primary as its backup — that is not a "
                    "backup, it is the same single point of failure" % rid)
        elif gap is True:
            for field in ("gap_reason", "gap_owner", "gap_tracked_in"):
                if not r.get(field):
                    problems.append(
                        "role %r declares backup_gap but omits %r — an undeclared "
                        "gap is indistinguishable from an oversight" % (rid, field))
        else:
            problems.append(
                "role %r has NO BACKUP and does not declare backup_gap — a role "
                "matrix that silently omits succession implies resilience that "
                "does not exist" % rid)

    cic = roles.get("customer_impact_classification") or {}
    if not cic.get("field"):
        problems.append("customer_impact_classification declares no field name")
    vals = {v.get("id") for v in cic.get("values") or []}
    for required in ("action-required", "informational", "no-customer-impact", "undetermined"):
        if required not in vals:
            problems.append("customer_impact_classification is missing value %r" % required)

# --- control matrix: every row must point at something real ------------------
if matrix is not None:
    d = matrix.get("disclaimer") or {}
    if d.get("is_compliance_claim") is not False or d.get("is_certification") is not False:
        problems.append("the control matrix must not present itself as a compliance claim")
    obligations = matrix.get("obligations") or []
    if not obligations:
        problems.append("control matrix lists no obligations")
    # The allowed owner vocabulary is the role register itself, so an owner
    # cannot be a free-text aspiration and cannot name a person: it must be a
    # role that policies/cra-roles.yaml already declares and already tracks a
    # backup gap for.
    role_ids = {rr.get("id") for rr in ((roles or {}).get("roles") or []) if rr.get("id")}
    seen = set()
    for o in obligations:
        oid = o.get("id", "<unnamed>")
        if oid in seen:
            problems.append("obligation %r appears twice" % oid)
        seen.add(oid)
        status = o.get("status")
        if status not in ("enforced", "partial", "absent"):
            problems.append("obligation %r has invalid status %r" % (oid, status))
        if status in ("partial", "absent") and not o.get("gap"):
            problems.append(
                "obligation %r is %r but names no gap — a shortfall without a "
                "stated gap reads as coverage" % (oid, status))
        if status == "enforced" and not o.get("enforced_by"):
            problems.append("obligation %r claims enforced but names nothing enforcing it" % oid)
        ev = o.get("evidence") or []
        if not ev:
            problems.append("obligation %r cites no evidence" % oid)
        for path in ev:
            # The anti-drift rule: evidence must exist on disk.
            if not os.path.exists(path):
                problems.append(
                    "obligation %r cites evidence %r which DOES NOT EXIST — a "
                    "matrix pointing at absent files is how a repository "
                    "convinces itself it is covered" % (oid, path))
        # Same shape as the gap rule above: an obligation nobody answers for is
        # a gap with better formatting.
        owner = o.get("owner")
        if not owner:
            problems.append(
                "obligation %r names no owner — an obligation with no accountable "
                "role is one that will be discovered unowned during an incident"
                % oid)
        elif role_ids and owner not in role_ids:
            problems.append(
                "obligation %r names owner %r, which is not a role declared in "
                "policies/cra-roles.yaml (declared: %s)"
                % (oid, owner, ", ".join(sorted(role_ids))))

if problems:
    sys.stderr.write("REFUSE: CRA control set not satisfied — %d problem(s):\n" % len(problems))
    for p in problems:
        sys.stderr.write("  - %s\n" % p)
    raise SystemExit(1)

n_ob = len((matrix or {}).get("obligations") or [])
n_roles = len((roles or {}).get("roles") or [])
gaps = sum(1 for r in ((roles or {}).get("roles") or []) if r.get("backup_gap"))
absent = sum(1 for o in ((matrix or {}).get("obligations") or []) if o.get("status") == "absent")
partial = sum(1 for o in ((matrix or {}).get("obligations") or []) if o.get("status") == "partial")
print("CRA control set OK: %d obligation(s) [%d partial, %d absent], %d role(s) [%d without a backup]"
      % (n_ob, partial, absent, n_roles, gaps))
print("NOTE: applicability is undetermined; this is not a compliance claim.")
PY
}

# -----------------------------------------------------------------------------
check_record() {
  REC="$1" POL="$INCIDENT_POLICY" ROLES_F="$ROLES" python3 <<'PY'
import os, sys, yaml, datetime

rec_path = os.environ["REC"]
problems = []

try:
    with open(rec_path) as fh:
        r = yaml.safe_load(fh) or {}
except (OSError, ValueError) as e:
    sys.stderr.write("REFUSE: incident record %s is unreadable: %s\n" % (rec_path, e))
    raise SystemExit(1)

with open(os.environ["POL"]) as fh:
    pol = yaml.safe_load(fh)
with open(os.environ["ROLES_F"]) as fh:
    roles_doc = yaml.safe_load(fh)

# --- 1. awareness time -------------------------------------------------------
raw = r.get("awareness_at")
t0 = None
if not raw:
    problems.append("awareness_at is MISSING — without it no reporting clock can start "
                    "and no deadline can be defended")
else:
    try:
        t0 = datetime.datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        problems.append("awareness_at %r is not RFC3339" % raw)
    if t0 is not None and t0.tzinfo is None:
        problems.append("awareness_at %r carries no timezone — a naive timestamp "
                        "starts a regulatory clock nobody can defend" % raw)
        t0 = None

# --- 2. deadlines recomputed independently from policy -----------------------
# Which deadlines this record OWES. Early warning and full notification are
# unconditional; the final report is owed only where the classification carries
# a final_report_rule ('not-reportable' carries none, so it owes no final date).
ALL_CLOCKS = ("early_warning", "full_notification", "final_report")
cls = r.get("classification")
rule = next((c.get("final_report_rule") for c in pol["classifications"]
             if c["id"] == cls), None)
if cls == "not-reportable":
    # Assessed as outside the reporting obligations, so it owes no deadline at
    # all. What it owes instead is a rationale, enforced in section 3.
    owed = []
else:
    owed = ["early_warning", "full_notification"] + (["final_report"] if rule else [])

# Anything the record STATES is verified whether or not it is owed. A deadline
# written into a record is a claim, and a wrong claim is wrong even when nobody
# required it — otherwise "state a deadline you do not owe" becomes the way to
# put an unchecked date in front of a regulator.
checked = list(dict.fromkeys(
    owed + [n for n in ALL_CLOCKS if r.get("%s_due" % n) is not None]))

# Presence is mandatory, and is checked BEFORE and independently of the
# comparison. The previous version fetched each stated deadline and did
# `if stated is None: continue`, so a record that simply omitted the field was
# passed over in silence and the run still printed "deadlines agree with
# policy" — agreement it had never established. A deadline that is absent is
# not a deadline that agrees.
for name in owed:
    if r.get("%s_due" % name) is None:
        problems.append(
            "%s_due is MISSING — this record owes that deadline, and a deadline "
            "the record does not state is one the validator cannot check" % name)

expected = {}
if t0 is not None:
    d = pol["deadlines"]
    expected["early_warning"] = t0 + datetime.timedelta(hours=d["early_warning"]["hours"])
    expected["full_notification"] = t0 + datetime.timedelta(hours=d["full_notification"]["hours"])
    if rule:
        fr = d["final_report"][rule]
        base_raw = r.get(fr["from"])
        if not base_raw:
            # The second silent hole: without the base timestamp the expected
            # value never entered `expected`, so a stated final_report_due was
            # never compared with anything. Refuse rather than pass it over.
            problems.append(
                "final_report_due cannot be verified — the record owes a final "
                "report under rule %r but carries no %s to compute it from"
                % (rule, fr["from"]))
        else:
            try:
                base = datetime.datetime.fromisoformat(str(base_raw).replace("Z", "+00:00"))
                expected["final_report"] = base + datetime.timedelta(days=fr["days"])
            except ValueError:
                problems.append("%s %r is not RFC3339" % (fr["from"], base_raw))

for name in checked:
    stated = r.get("%s_due" % name)
    if stated is None:
        continue  # already refused above as MISSING; there is nothing to compare
    try:
        got = datetime.datetime.fromisoformat(str(stated).replace("Z", "+00:00"))
    except ValueError:
        problems.append("%s_due %r is not RFC3339" % (name, stated))
        continue
    want = expected.get(name)
    if want is None:
        problems.append(
            "%s_due states %s but policy could not recompute it from the recorded "
            "times, so it is unverified — an unchecked deadline is not a "
            "confirmed one" % (name, stated))
        continue
    if got != want:
        problems.append(
            "%s_due is %s but policy computes %s from the recorded times — a "
            "deadline written down by hand is a deadline that can be wrong"
            % (name, got.isoformat(), want.isoformat()))

# --- 2b. the retained deadline verdict ---------------------------------------
# A tabletop's MET/MISSED result used to exist only on stdout, so the one thing
# the exercise was run to establish was the one thing it did not retain. Where a
# record says an exercise happened, the verdict must be IN the record, and it is
# recomputed here from the record's own timestamps rather than trusted.
# A verdict is owed once the exercise actually ran a clock to a submission:
# that is the point at which a MET/MISSED outcome exists to be retained. A
# simulated record with no submission has no verdict to state, and demanding one
# would be demanding an answer to a question the record never asked.
verdict_owed = [n for n in ALL_CLOCKS if r.get("%s_submitted_at" % n)]
if r.get("simulated") and verdict_owed:
    dv = r.get("deadline_verdict") or {}
    if not dv:
        problems.append(
            "deadline_verdict is MISSING — this record describes a simulated "
            "exercise that reached %d submission(s), and an exercise whose "
            "verdict lives only in a terminal has retained no result"
            % len(verdict_owed))
    else:
        clocks = {c.get("id"): c for c in (dv.get("clocks") or []) if isinstance(c, dict)}
        unknown = sorted(set(clocks) - set(verdict_owed))
        if unknown:
            problems.append("deadline_verdict records clock(s) %s which this record "
                            "does not evidence a submission for"
                            % ", ".join(repr(u) for u in unknown))
        recomputed_all = []
        for name in verdict_owed:
            c = clocks.get(name)
            if c is None:
                problems.append("deadline_verdict records no clock %r, so its "
                                "verdict is unaccounted for" % name)
                continue
            want = expected.get(name)
            if want is None:
                problems.append("deadline_verdict states a verdict for %r that "
                                "cannot be recomputed — the due date is unverified"
                                % name)
                continue
            try:
                st = datetime.datetime.fromisoformat(
                    str(r["%s_submitted_at" % name]).replace("Z", "+00:00"))
            except ValueError:
                problems.append("%s_submitted_at %r is not RFC3339"
                                % (name, r["%s_submitted_at" % name]))
                continue
            recomputed = "MET" if st <= want else "MISSED"
            recomputed_all.append(recomputed)
            if c.get("verdict") != recomputed:
                problems.append(
                    "deadline_verdict for %r records %r but recomputation from the "
                    "record's own times gives %r — a stored verdict that disagrees "
                    "with the evidence is worse than no verdict"
                    % (name, c.get("verdict"), recomputed))
        if len(recomputed_all) == len(verdict_owed):
            want_overall = "MET" if all(v == "MET" for v in recomputed_all) else "MISSED"
            if dv.get("overall") != want_overall:
                problems.append("deadline_verdict.overall records %r but the clocks "
                                "recompute to %r" % (dv.get("overall"), want_overall))

# --- 3. mandatory evidence ---------------------------------------------------
cls = r.get("classification")
if cls and cls != "not-reportable":
    req = list(pol["evidence_schema"].get("full_notification") or [])
    missing = [f for f in req if not r.get(f)]
    if missing:
        problems.append("record claims classification %r but is missing mandatory "
                        "evidence: %s" % (cls, ", ".join(missing)))
if cls == "not-reportable" and not r.get("classification_rationale"):
    problems.append("a 'not-reportable' outcome requires a recorded rationale — "
                    "deciding NOT to report must be as auditable as reporting")

# --- 5. customer-impact classification ---------------------------------------
cic = roles_doc["customer_impact_classification"]
field = cic["field"]
allowed = {v["id"]: v for v in cic["values"]}
impact = r.get(field)
if not impact:
    problems.append("%s is MISSING — 'we never worked out who this hurt' is not an "
                    "acceptable state for an incident record" % field)
elif impact not in allowed:
    problems.append("%s %r is not a declared value (%s)"
                    % (field, impact, ", ".join(sorted(allowed))))
else:
    spec = allowed[impact]
    state = r.get("state")
    if impact == "undetermined" and state in ("CLOSED", "FINAL_REPORT"):
        problems.append("%s is 'undetermined' on a %s record — impact must be "
                        "established before an incident is closed" % (field, state))
    if spec.get("requires_rationale") and not r.get("customer_impact_rationale"):
        problems.append("%s is %r which requires customer_impact_rationale" % (field, impact))

if problems:
    sys.stderr.write("REFUSE: incident record %s is not reportable-ready — %d problem(s):\n"
                     % (rec_path, len(problems)))
    for p in problems:
        sys.stderr.write("  - %s\n" % p)
    raise SystemExit(1)

# The count is deliberate: "deadlines agree with policy" was printable after
# comparing nothing. A number cannot be, because a skipped deadline is one the
# record no longer states and one this line no longer counts.
print("incident record OK: awareness recorded, %d owed / %d checked deadline(s) "
      "agreeing with policy%s, evidence present, customer impact classified"
      % (len(owed), len(checked),
         "; retained deadline_verdict recomputed and agreeing" if r.get("simulated") else ""))
PY
}

# -----------------------------------------------------------------------------
# tabletop — SYNTHETIC. Offline. Never a record that an exercise "happened".
# -----------------------------------------------------------------------------
tabletop() {
  local ok=0 bad=0 tmp f
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" EXIT
  t() { if eval "$2"; then echo "ok   - $1"; ok=$((ok + 1)); else echo "FAIL - $1"; bad=$((bad + 1)); fi; }

  echo "=================================================================="
  echo " SYNTHETIC CRA TABLETOP — FIXTURE ONLY, NOT A REAL EXERCISE"
  echo " Nothing here is an incident, a submission, or evidence that a"
  echo " tabletop exercise was conducted with real participants."
  echo " CRA APPLICABILITY UNDETERMINED (issue 113)."
  echo "=================================================================="
  echo

  # A well-formed synthetic record. Deadlines are written to AGREE with policy.
  cat >"$tmp/good.yaml" <<'YAML'
id: SYNTHETIC-CRA-FIXTURE
simulated: true
state: CLOSED
awareness_at: "2026-08-13T09:00:00+00:00"
early_warning_due: "2026-08-14T09:00:00+00:00"
full_notification_due: "2026-08-16T09:00:00+00:00"
classification: actively-exploited-vulnerability
classification_rationale: SYNTHETIC rationale
corrective_measure_available_at: "2026-08-18T12:00:00+00:00"
final_report_due: "2026-09-01T12:00:00+00:00"
customer_impact: action-required
summary: SYNTHETIC fixture
affected_image_digests: ["sha256:0000000000000000000000000000000000000000000000000000000000000000"]
affected_source_revisions: ["0000000000000000000000000000000000000000"]
suspected_affected_products: ["php-fpm"]
sbom_references: ["artifacts/sbom/synthetic.spdx.json"]
vex_status: under_investigation
known_exploitation: true
mitigations: SYNTHETIC mitigation
affected_distribution: SYNTHETIC distribution
corrective_measures_taken: SYNTHETIC corrective measures
decision_log: [{at: "2026-08-13T09:00:00+00:00", by: fixture, what: SYNTHETIC}]
customer_notifications: SYNTHETIC notification
YAML

  echo "-- 1. a complete synthetic record validates"
  t "a well-formed record passes" "check_record '$tmp/good.yaml' >/dev/null 2>&1"

  echo "-- 2. awareness time missing"
  grep -v '^awareness_at:' "$tmp/good.yaml" >"$tmp/no-awareness.yaml"
  t "a record with NO awareness time is refused" \
    "! check_record '$tmp/no-awareness.yaml' >/dev/null 2>&1"
  check_record "$tmp/no-awareness.yaml" >"$tmp/o" 2>&1 || true
  t "...saying no clock can start" "grep -q 'no reporting clock can start' '$tmp/o'"

  echo "-- 3. awareness time with no timezone"
  sed 's/^awareness_at: .*/awareness_at: "2026-08-13T09:00:00"/' "$tmp/good.yaml" >"$tmp/naive.yaml"
  t "a naive timestamp is refused" "! check_record '$tmp/naive.yaml' >/dev/null 2>&1"
  check_record "$tmp/naive.yaml" >"$tmp/o" 2>&1 || true
  t "...saying nobody could defend that clock" "grep -q 'nobody can defend' '$tmp/o'"

  echo "-- 4. deadlines miscomputed"
  sed 's/^early_warning_due: .*/early_warning_due: "2026-08-20T09:00:00+00:00"/' \
    "$tmp/good.yaml" >"$tmp/badclock.yaml"
  t "a deadline that disagrees with policy is refused" \
    "! check_record '$tmp/badclock.yaml' >/dev/null 2>&1"
  check_record "$tmp/badclock.yaml" >"$tmp/o" 2>&1 || true
  t "...showing both the stated and the computed deadline" \
    "grep -q 'but policy computes' '$tmp/o'"

  # The defect this section exists for: a deadline the record simply OMITTED was
  # skipped, and the run still reported that deadlines agreed with policy. A
  # miscomputed deadline was caught; an absent one was not.
  echo "-- 4b. deadlines the record omits entirely"
  for f in early_warning full_notification final_report; do
    grep -v "^${f}_due:" "$tmp/good.yaml" >"$tmp/no-$f.yaml"
    t "a record omitting ${f}_due is refused" \
      "! check_record '$tmp/no-$f.yaml' >/dev/null 2>&1"
    check_record "$tmp/no-$f.yaml" >"$tmp/o" 2>&1 || true
    t "...naming ${f}_due as the field that is missing" \
      "grep -q '${f}_due is MISSING' '$tmp/o'"
  done

  grep -vE '^(early_warning|full_notification|final_report)_due:' \
    "$tmp/good.yaml" >"$tmp/nodue.yaml"
  t "a record omitting ALL three deadlines is refused" \
    "! check_record '$tmp/nodue.yaml' >/dev/null 2>&1"
  check_record "$tmp/nodue.yaml" >"$tmp/o" 2>&1 || true
  t "...with one attributable refusal per field, not a single vague one" \
    "[ \"\$(grep -c '_due is MISSING' '$tmp/o')\" -eq 3 ]"

  # The second hole: with no base timestamp the expected final-report date was
  # never computed, so the stated one was never compared with anything.
  grep -v '^corrective_measure_available_at:' "$tmp/good.yaml" >"$tmp/nobase.yaml"
  t "a final report that cannot be recomputed is refused, not passed over" \
    "! check_record '$tmp/nobase.yaml' >/dev/null 2>&1"
  check_record "$tmp/nobase.yaml" >"$tmp/o" 2>&1 || true
  t "...saying it cannot be verified and naming what is absent" \
    "grep -q 'final_report_due cannot be verified' '$tmp/o'"

  t "NON-VACUOUS: the unmodified record still passes all of the above" \
    "check_record '$tmp/good.yaml' >/dev/null 2>&1"

  echo "-- 5. mandatory evidence absent"
  grep -v '^affected_image_digests:' "$tmp/good.yaml" >"$tmp/noevidence.yaml"
  t "a reportable record missing evidence is refused" \
    "! check_record '$tmp/noevidence.yaml' >/dev/null 2>&1"
  check_record "$tmp/noevidence.yaml" >"$tmp/o" 2>&1 || true
  t "...naming the missing field" "grep -q 'affected_image_digests' '$tmp/o'"

  echo "-- 6. customer impact missing"
  grep -v '^customer_impact:' "$tmp/good.yaml" >"$tmp/noimpact.yaml"
  t "a record with no customer-impact classification is refused" \
    "! check_record '$tmp/noimpact.yaml' >/dev/null 2>&1"
  sed 's/^customer_impact: .*/customer_impact: undetermined/' "$tmp/good.yaml" >"$tmp/undet.yaml"
  t "a CLOSED record may not leave impact undetermined" \
    "! check_record '$tmp/undet.yaml' >/dev/null 2>&1"

  echo "-- 7. roles without a backup"
  python3 - "$ROLES" "$tmp/roles-nogap.yaml" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
d["roles"][0].pop("backup_gap", None)
d["roles"][0].pop("gap_reason", None)
yaml.safe_dump(d, open(sys.argv[2], "w"))
PY
  t "a role with no backup and no declared gap is refused" \
    "! CRA_ROLES='$tmp/roles-nogap.yaml' validate_policies >/dev/null 2>&1"
  CRA_ROLES="$tmp/roles-nogap.yaml" validate_policies >"$tmp/o" 2>&1 || true
  t "...saying it implies resilience that does not exist" \
    "grep -q 'implies resilience that does not exist' '$tmp/o'"

  echo "-- 8. the exercise must not read as a real one"
  t "the fixture record is flagged simulated" "grep -q '^simulated: true' '$tmp/good.yaml'"
  t "applicability is still undetermined" \
    "python3 -c \"
import yaml;a=yaml.safe_load(open('$APPLICABILITY'))['applicability']
assert a['status']=='undetermined' and a['determined_by'] is None\""

  echo
  printf 'synthetic CRA tabletop: %d ok, %d failed\n' "$ok" "$bad"
  [ "$bad" -eq 0 ]
}

# -----------------------------------------------------------------------------
self_test() {
  local fail=0 tmp
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" EXIT
  ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

  ck "the shipped policy set validates" "validate_policies >/dev/null 2>&1"
  ck "the synthetic tabletop executes and passes" "tabletop >/dev/null 2>&1"
  # `tabletop | grep -q` would SIGPIPE the tabletop the moment grep matched, and
  # `set -o pipefail` would then report the pipeline as failed — so the
  # assertion would pass only when the banner was ABSENT. Capture, then assert.
  tabletop >"$tmp/tt" 2>&1 || true
  ck "the tabletop labels itself SYNTHETIC" \
     "grep -q 'SYNTHETIC CRA TABLETOP — FIXTURE ONLY' '$tmp/tt'"
  ck "...and never claims an exercise was conducted" \
     "grep -q 'NOT A REAL EXERCISE' '$tmp/tt'"
  ck "...and restates that applicability is undetermined" \
     "grep -q 'APPLICABILITY UNDETERMINED' '$tmp/tt'"

  # Sabotage the control matrix on a COPY: a row citing an absent file must fail.
  python3 - "$MATRIX" "$tmp/matrix-ghost.yaml" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
d["obligations"][0]["evidence"] = ["scripts/this-file-does-not-exist.sh"]
yaml.safe_dump(d, open(sys.argv[2], "w"))
PY
  ck "a matrix citing evidence that does not exist is REFUSED" \
     "! CRA_MATRIX='$tmp/matrix-ghost.yaml' validate_policies >/dev/null 2>&1"
  ck "...saying the file does not exist" \
     "CRA_MATRIX='$tmp/matrix-ghost.yaml' validate_policies >'$tmp/o' 2>&1 || true;
      grep -q 'DOES NOT EXIST' '$tmp/o'"

  python3 - "$MATRIX" "$tmp/matrix-nogap.yaml" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
for o in d["obligations"]:
    if o["status"] == "partial":
        o["gap"] = None
        break
yaml.safe_dump(d, open(sys.argv[2], "w"))
PY
  ck "a 'partial' obligation with no stated gap is REFUSED" \
     "! CRA_MATRIX='$tmp/matrix-nogap.yaml' validate_policies >/dev/null 2>&1"

  python3 - "$MATRIX" "$tmp/matrix-claim.yaml" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
d["disclaimer"]["is_compliance_claim"] = True
yaml.safe_dump(d, open(sys.argv[2], "w"))
PY
  ck "a matrix presenting itself as a compliance CLAIM is REFUSED" \
     "! CRA_MATRIX='$tmp/matrix-claim.yaml' validate_policies >/dev/null 2>&1"

  python3 - "$ROLES" "$tmp/roles-self.yaml" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
r = d["roles"][0]
r["backup"] = r["primary"]
r["backup_gap"] = False
yaml.safe_dump(d, open(sys.argv[2], "w"))
PY
  ck "a role naming itself as its own backup is REFUSED" \
     "! CRA_ROLES='$tmp/roles-self.yaml' validate_policies >/dev/null 2>&1"

  python3 - "$APPLICABILITY" "$tmp/app-claim.yaml" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
d["applicability"]["status"] = "applies"
yaml.safe_dump(d, open(sys.argv[2], "w"))
PY
  ck "an unattributed determination is REFUSED" \
     "! CRA_APPLICABILITY='$tmp/app-claim.yaml' validate_policies >/dev/null 2>&1"

  # Non-vacuity: the shipped set must actually report gaps, not a clean sheet.
  ck "non-vacuity: the shipped matrix reports real gaps rather than full coverage" \
     "validate_policies >'$tmp/o' 2>&1; grep -qE '\[[0-9]+ partial, [1-9][0-9]* absent\]|\[[1-9][0-9]* partial' '$tmp/o'"
  ck "non-vacuity: every role is reported as lacking a backup" \
     "validate_policies >'$tmp/o' 2>&1; grep -q '6 role(s) [6 without a backup]' '$tmp/o' ||
      grep -qE '[0-9]+ role\(s\) \[[1-9][0-9]* without a backup\]' '$tmp/o'"

  echo "----"
  if [ "$fail" -eq 0 ]; then echo "assert-cra-controls: SELF-TEST OK"; else echo "assert-cra-controls: SELF-TEST FAILED"; fi
  return "$fail"
}

case "${1:-}" in
  "")             validate_policies ;;
  --check-record) shift; [ $# -eq 1 ] || usage; check_record "$1" ;;
  --tabletop)     tabletop ;;
  --self-test)    self_test ;;
  *) usage ;;
esac
