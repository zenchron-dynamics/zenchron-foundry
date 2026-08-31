#!/usr/bin/env bash
# =============================================================================
# scripts/incident.sh — the CRA reporting state machine, executable (#114).
#
# Deadlines are COMPUTED from a recorded awareness timestamp, not written down
# in a runbook for someone to work out under pressure at 3am. Packets are
# refused when their required evidence is missing, because a report assembled
# from whatever was at hand is how a wrong digest reaches a regulator.
#
# EVERY artefact carries two banners it cannot be produced without:
#   * SIMULATED, when produced by --tabletop
#   * CRA APPLICABILITY UNDETERMINED, until #113 records a determination
# A tabletop artefact that could be mistaken for a real filing is worse than no
# tabletop, and a draft that reads like a legal conclusion is worse than a gap.
#
# It NEVER submits anything. Producing a packet and filing it are different
# acts; only the first is automatable, and the second needs an account and a
# person who does not exist in this repository.
#
# Usage:
#   incident.sh deadlines <awareness_at>            compute every clock
#   incident.sh new <id> <awareness_at> <summary>   open a record
#   incident.sh packet <record.yaml> <kind>         early_warning|full_notification|final_report
#   incident.sh status <record.yaml> [--persist]    clocks; --persist stores the verdict
#   incident.sh --tabletop                          full simulated exercise
#   incident.sh --self-test
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1
POLICY="${INCIDENT_POLICY:-$ROOT/policies/incident-reporting.yaml}"
RECORDS="$ROOT/docs/audits/incidents"

py() { INCIDENT_POLICY="$POLICY" RECORDS_DIR="$RECORDS" python3 "$@"; }

# --- deadlines ---------------------------------------------------------------
deadlines() {
  local awareness="${1:?usage: incident.sh deadlines <awareness_at RFC3339>}"
  AWARENESS="$awareness" py - <<'PY'
import datetime, os, sys, yaml

pol = yaml.safe_load(open(os.environ["INCIDENT_POLICY"]))
raw = os.environ["AWARENESS"]
try:
    t0 = datetime.datetime.fromisoformat(raw.replace("Z", "+00:00"))
except ValueError:
    print("REFUSE: awareness_at %r is not RFC3339" % raw, file=sys.stderr)
    sys.exit(1)
if t0.tzinfo is None:
    print("REFUSE: awareness_at must carry a timezone — a naive timestamp starts "
          "a regulatory clock nobody can defend", file=sys.stderr)
    sys.exit(1)

d = pol["deadlines"]
print("awareness_at (t0)      %s" % t0.isoformat())
ew = t0 + datetime.timedelta(hours=d["early_warning"]["hours"])
fn = t0 + datetime.timedelta(hours=d["full_notification"]["hours"])
print("early warning  (+%dh)  %s" % (d["early_warning"]["hours"], ew.isoformat()))
print("full notif.    (+%dh)  %s" % (d["full_notification"]["hours"], fn.isoformat()))
print()
print("final report depends on classification:")
fr = d["final_report"]
print("  actively-exploited-vulnerability  +%d days from corrective measure availability"
      % fr["actively_exploited_vulnerability"]["days"])
print("  severe-incident                   +%d days from the full notification"
      % fr["severe_incident"]["days"])
PY
}

# --- record lifecycle --------------------------------------------------------
new_record() {
  local id="${1:?id}" awareness="${2:?awareness_at}" summary="${3:?summary}"
  mkdir -p "$RECORDS"
  local f="$RECORDS/${id}.yaml"
  [ -e "$f" ] && { echo "REFUSE: $f already exists — an incident id is not reused" >&2; return 1; }
  ID="$id" AWARENESS="$awareness" SUMMARY="$summary" OUT="$f" py - <<'PY'
import datetime, os, yaml
now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()
rec = {
    "id": os.environ["ID"],
    "simulated": False,
    "state": "AWARENESS_RECORDED",
    "awareness_at": os.environ["AWARENESS"],
    "recorded_by": os.environ.get("USER", "unknown"),
    "recorded_at": now,
    "summary": os.environ["SUMMARY"],
    "classification": None,
    "classification_rationale": None,
    # "undetermined" is permitted ONLY while the incident is open
    # (policies/cra-roles.yaml). Recording it at awareness means the field is
    # never absent, and the validator refuses it on a CLOSED record — so impact
    # must be established before closure rather than discovered missing after.
    "customer_impact": "undetermined",
    "decision_log": [
        {"at": now, "by": os.environ.get("USER", "unknown"),
         "what": "awareness recorded; reporting clocks start"},
    ],
}
yaml.safe_dump(rec, open(os.environ["OUT"], "w"), sort_keys=False, width=100)
print("opened %s" % os.environ["OUT"])
PY
}

status() {
  # `--persist` writes the MET/MISSED verdict back into the record. Without it
  # the verdict exists only on stdout, which is where the tabletop's only result
  # used to go and stay.
  local rec="${1:?record.yaml}" persist="${2:-}"
  REC="$rec" PERSIST="$persist" py - <<'PY'
import datetime, os, yaml
pol = yaml.safe_load(open(os.environ["INCIDENT_POLICY"]))
r = yaml.safe_load(open(os.environ["REC"]))
now = datetime.datetime.now(datetime.timezone.utc)
t0 = datetime.datetime.fromisoformat(str(r["awareness_at"]).replace("Z", "+00:00"))

print("incident   %s%s" % (r["id"], "   [SIMULATED]" if r.get("simulated") else ""))
print("state      %s" % r["state"])
print("t0         %s" % t0.isoformat())

d = pol["deadlines"]
clocks = []
def clock(cid, name, due, submitted_key):
    sub = r.get(submitted_key)
    if sub:
        st = datetime.datetime.fromisoformat(str(sub).replace("Z", "+00:00"))
        verdict = "MET" if st <= due else "MISSED"
        print("  %-16s due %s  submitted %s  %s" % (name, due.isoformat(), st.isoformat(), verdict))
        clocks.append({"id": cid, "due": due.isoformat(),
                       "submitted_at": st.isoformat(), "verdict": verdict})
        return verdict == "MET"
    left = (due - now).total_seconds() / 3600.0
    print("  %-16s due %s  %s" % (name, due.isoformat(),
          "OVERDUE" if left < 0 else "%.1fh remaining" % left))
    return left >= 0

ok = True
ok &= clock("early_warning", "early warning",
            t0 + datetime.timedelta(hours=d["early_warning"]["hours"]),
            "early_warning_submitted_at")
ok &= clock("full_notification", "full notification",
            t0 + datetime.timedelta(hours=d["full_notification"]["hours"]),
            "full_notification_submitted_at")

cls = r.get("classification")
rule = next((c["final_report_rule"] for c in pol["classifications"] if c["id"] == cls), None)
if rule:
    fr = d["final_report"][rule]
    base_key = fr["from"]
    base = r.get(base_key)
    if base:
        b = datetime.datetime.fromisoformat(str(base).replace("Z", "+00:00"))
        ok &= clock("final_report", "final report", b + datetime.timedelta(days=fr["days"]),
                    "final_report_submitted_at")
    else:
        print("  %-16s not started — waiting on %s" % ("final report", base_key))
elif cls:
    print("  %-16s not applicable (%s)" % ("final report", cls))
else:
    print("  %-16s unknown until CLASSIFIED" % "final report")

print()
print("no deadline missed" if ok else "AT LEAST ONE DEADLINE MISSED OR OVERDUE")

if os.environ.get("PERSIST") == "--persist":
    # No wall-clock field here on purpose: the record is committed, and a
    # regenerated timestamp would make every run a diff. When it was computed is
    # what git already records.
    r["deadline_verdict"] = {
        "computed_by": "scripts/incident.sh status --persist",
        "policy_schema_version": pol.get("schema_version"),
        "clocks": clocks,
        "overall": "MET" if all(c["verdict"] == "MET" for c in clocks) and clocks else "MISSED",
        "note": (
            "Derived from the submission timestamps this record already retains, "
            "and recomputed independently by scripts/cra/assert-cra-controls.sh "
            "--check-record. It is NOT an observation made during the original "
            "exercise: that run printed its verdict to stdout and retained none."
        ),
    }
    yaml.safe_dump(r, open(os.environ["REC"], "w"), sort_keys=False, width=100)
    print("persisted deadline_verdict into %s" % os.environ["REC"])

raise SystemExit(0 if ok else 1)
PY
}

packet() {
  local rec="${1:?record.yaml}" kind="${2:?early_warning|full_notification|final_report}"
  REC="$rec" KIND="$kind" py - <<'PY'
import datetime, os, sys, yaml

pol = yaml.safe_load(open(os.environ["INCIDENT_POLICY"]))
r   = yaml.safe_load(open(os.environ["REC"]))
kind = os.environ["KIND"]

schema = pol["evidence_schema"].get(kind)
if schema is None:
    print("REFUSE: unknown packet kind %r" % kind, file=sys.stderr); sys.exit(1)

# expand the composite requirement
req = []
for f in schema:
    req.extend(pol["evidence_schema"]["full_notification"] if f == "all_of_full_notification" else [f])

missing = [f for f in req if not r.get(f)]
if missing:
    print("REFUSE: %s packet is missing required evidence:" % kind, file=sys.stderr)
    for m in missing:
        print("  %s" % m, file=sys.stderr)
    print("\nA report assembled from whatever is at hand is how a wrong digest\n"
          "reaches a regulator. Fill these in on the record first.", file=sys.stderr)
    sys.exit(1)

app = pol["applicability"]
banner = []
if r.get("simulated"):
    banner.append("*** SIMULATED — TABLETOP ARTEFACT, NOT A REAL SUBMISSION ***")
if app.get("status") != "determined":
    banner.append("*** CRA APPLICABILITY UNDETERMINED (see issue %s) — DRAFT ONLY ***"
                  % app.get("tracked_in"))

out = []
out += banner
out.append("")
out.append("%s PACKET" % kind.replace("_", " ").upper())
out.append("=" * 60)
out.append("")
out.append("incident id      %s" % r["id"])
out.append("awareness (t0)   %s" % r["awareness_at"])
out.append("classification   %s" % (r.get("classification") or "UNCLASSIFIED"))
out.append("route            %s / CSIRT: %s" % (pol["reporting_route"]["platform"],
                                                pol["reporting_route"]["csirt"]))
out.append("")
for f in req:
    v = r.get(f)
    if isinstance(v, list):
        out.append("%s:" % f)
        for item in v:
            out.append("  - %s" % item)
    else:
        out.append("%-32s %s" % (f + ":", v))
out.append("")
out += banner
path = os.environ["REC"].replace(".yaml", "-%s.txt" % kind)
open(path, "w").write("\n".join(out) + "\n")
print("packet written: %s" % path)
print("evidence fields: %d, all present" % len(req))
PY
}

# --- tabletop ----------------------------------------------------------------
tabletop() {
  local dir; dir="$RECORDS"
  mkdir -p "$dir"
  local id; id="INC-SIMULATED-$(date -u +%Y%m%d)"
  local rec="$dir/${id}.yaml"
  rm -f "$rec" "${rec%.yaml}"-*.txt

  echo "=============================================================="
  echo " TABLETOP EXERCISE — SIMULATED INCIDENT (#114)"
  echo " Nothing here is a real incident or a real submission."
  echo "=============================================================="
  echo

  # A fixed t0 so the exercise is deterministic and its verdicts reproducible.
  local t0="2026-08-13T09:00:00+00:00"
  echo "-- t0: $t0"
  deadlines "$t0"
  echo

  # Build a fully-populated SIMULATED record, with real current digests so the
  # evidence binding is exercised against reality rather than placeholders.
  echo "-- binding affected digests from the live shipping matrix"
  local digests=""
  while IFS= read -r img; do
    [ -n "$img" ] || continue
    local d
    d="$(docker buildx imagetools inspect "ghcr.io/zenchron-dynamics/${img}" \
          --format '{{.Manifest.Digest}}' 2>/dev/null | tr -d '[:space:]')"
    case "$d" in sha256:*) digests="${digests}ghcr.io/zenchron-dynamics/${img}@${d}"$'\n' ;; esac
  done < <(py -c "
import glob, yaml
for f in sorted(glob.glob('contracts/images/*.yaml')):
    d = yaml.safe_load(open(f)); s = d['selector']
    print('%s:%s' % (d['image'], 'prod' if s=='prod' else s+'-prod'))")
  echo "   bound $(printf '%s' "$digests" | grep -c . || true) digests"

  ID="$id" T0="$t0" OUT="$rec" DIGESTS="$digests" \
  REV="$(git rev-parse HEAD)" py - <<'PY'
import datetime, os, yaml
t0 = os.environ["T0"]
rec = {
  "id": os.environ["ID"],
  "simulated": True,
  "state": "CLOSED",
  "awareness_at": t0,
  "recorded_by": "tabletop",
  "summary": "SIMULATED: hypothetical actively-exploited flaw in a shipped image.",
  "classification": "actively-exploited-vulnerability",
  "classification_rationale":
      "SIMULATED. Treated as actively exploited to exercise the 14-day final "
      "report branch, which is the tighter of the two.",
  "suspected_affected_products": ["all ten Zenchron Foundry images"],
  "known_exploitation": "SIMULATED: exploitation observed in the wild.",
  "affected_image_digests": [l for l in os.environ["DIGESTS"].splitlines() if l.strip()],
  "affected_source_revisions": [os.environ["REV"]],
  "sbom_references": ["SBOMs are produced per image by scripts/generate-sbom.sh"],
  "vex_status": "SIMULATED: under_investigation -> affected",
  "mitigations": ["SIMULATED: no TLS termination on the edge image; "
                  "cap_drop ALL and read-only rootfs limit post-exploitation."],
  "affected_distribution": "SIMULATED: GHCR, private packages, no public consumers.",
  "corrective_measures_taken": "SIMULATED: base digest bump, rebuild, rescan.",
  "corrective_release": "SIMULATED-v2026.08.13",
  "root_cause": "SIMULATED root cause for exercise purposes.",
  "customer_notifications": ["SIMULATED: advisory drafted; nothing sent."],
  # policies/cra-roles.yaml -> customer_impact_classification.required_on:
  # "every incident record". Without it the record this exercise SHIPS as
  # evidence is refused by scripts/cra/assert-cra-controls.sh --check-record,
  # which is the one artefact #114 offers as proof the runbook produces
  # reportable output. An exercise whose output the validator rejects has not
  # exercised the thing it claims to.
  "customer_impact": "action-required",
  "customer_impact_rationale":
      "SIMULATED: a corrective release exists, so recipients must re-pin to the "
      "corrective digest to be safe.",
  "retrospective": "SIMULATED retrospective.",
  # submitted ON TIME relative to t0, so the exercise asserts a clean run
  "early_warning_submitted_at":     "2026-08-13T20:00:00+00:00",
  "full_notification_submitted_at": "2026-08-15T09:00:00+00:00",
  "corrective_measure_available_at":"2026-08-18T12:00:00+00:00",
  "final_report_submitted_at":      "2026-08-25T10:00:00+00:00",
  "closed_at":                      "2026-08-25T11:00:00+00:00",
  "early_warning_packet": "generated by the exercise",
  "full_notification_packet": "generated by the exercise",
  "final_report_packet": "generated by the exercise",
  "decision_log": [
    {"at": t0, "by": "tabletop", "what": "awareness recorded; clocks start"},
    {"at": "2026-08-13T12:00:00+00:00", "by": "tabletop",
     "what": "classified as actively-exploited-vulnerability"},
  ],
}

# The three deadlines the record OWES, computed from the policy rather than
# typed in. scripts/cra/assert-cra-controls.sh --check-record now refuses a
# record that omits any of them, so a record generated without these is a record
# the validator rejects — which is the point: the exercise must produce output
# its own validator accepts.
pol = yaml.safe_load(open(os.environ["INCIDENT_POLICY"]))
d = pol["deadlines"]
_t0 = datetime.datetime.fromisoformat(t0)
rec["early_warning_due"] = (
    _t0 + datetime.timedelta(hours=d["early_warning"]["hours"])).isoformat()
rec["full_notification_due"] = (
    _t0 + datetime.timedelta(hours=d["full_notification"]["hours"])).isoformat()
_rule = next(c["final_report_rule"] for c in pol["classifications"]
             if c["id"] == rec["classification"])
_fr = d["final_report"][_rule]
_base = datetime.datetime.fromisoformat(rec[_fr["from"]])
rec["final_report_due"] = (_base + datetime.timedelta(days=_fr["days"])).isoformat()

yaml.safe_dump(rec, open(os.environ["OUT"], "w"), sort_keys=False, width=100)
print("   record: %s" % os.environ["OUT"])
PY

  echo
  echo "-- generating packets"
  local k rc=0
  for k in early_warning full_notification final_report; do
    packet "$rec" "$k" || rc=1
  done
  echo
  echo "-- deadline verdict (persisted into the record, not left on stdout)"
  status "$rec" --persist || rc=1

  echo
  echo "-- asserting the exercise is honest"
  local p=0 f=0
  a() { if eval "$2"; then p=$((p+1)); echo "ok   - $1"; else f=$((f+1)); echo "FAIL - $1"; fi; }
  a "every packet is marked SIMULATED" \
    'for x in early_warning full_notification final_report; do head -3 "'"${rec%.yaml}"'-$x.txt" | grep -q SIMULATED || exit 1; done; true'
  a "every packet is marked APPLICABILITY UNDETERMINED" \
    'for x in early_warning full_notification final_report; do grep -q "APPLICABILITY UNDETERMINED" "'"${rec%.yaml}"'-$x.txt" || exit 1; done; true'
  a "the full notification binds real image digests" \
    "grep -qE 'sha256:[0-9a-f]{64}' '${rec%.yaml}-full_notification.txt'"
  a "the record is flagged simulated" \
    "python3 -c \"import yaml;assert yaml.safe_load(open('$rec'))['simulated'] is True\""
  a "no deadline was missed in the exercise" "status '$rec' >/dev/null"
  echo "----"
  printf 'tabletop: %d ok, %d failed\n' "$p" "$f"
  [ "$f" -eq 0 ] && [ "$rc" -eq 0 ]
}

self_test() {
  local p=0 f=0 tmp
  tmp="$(mktemp -d)"
  # expand NOW: the local is out of scope by EXIT time
  # shellcheck disable=SC2064
  trap "rm -rf '${tmp}'" EXIT
  a() { if eval "$2"; then p=$((p+1)); echo "  ok   $1"; else f=$((f+1)); echo "  FAIL $1"; fi; }

  a "deadlines compute from a valid awareness timestamp" \
    "deadlines 2026-08-13T09:00:00+00:00 >/dev/null"
  a "24h and 72h land where the policy says" \
    "deadlines 2026-08-13T09:00:00+00:00 | grep -q '2026-08-14T09:00' && \
     deadlines 2026-08-13T09:00:00+00:00 | grep -q '2026-08-16T09:00'"
  # A naive timestamp cannot defensibly start a regulatory clock.
  a "a timestamp without a timezone is REFUSED" \
    "! deadlines 2026-08-13T09:00:00 >/dev/null 2>&1"
  a "a malformed timestamp is REFUSED" \
    "! deadlines 'yesterday' >/dev/null 2>&1"

  # The core refusal: no packet without its evidence.
  cat > "$tmp/thin.yaml" <<'Y'
id: INC-TEST
simulated: true
state: AWARENESS_RECORDED
awareness_at: "2026-08-13T09:00:00+00:00"
summary: "thin record"
Y
  a "a packet with missing evidence is REFUSED" \
    "! packet '$tmp/thin.yaml' full_notification >/dev/null 2>&1"
  a "...and it names what is missing" \
    "out=\"\$(packet '$tmp/thin.yaml' full_notification 2>&1 || true)\"; \
     grep -q affected_image_digests <<<\"\$out\""
  a "an unknown packet kind is REFUSED" \
    "! packet '$tmp/thin.yaml' whatever >/dev/null 2>&1"

  # The two branches of the final-report clock must differ.
  a "the two final-report rules are distinct" \
    "python3 -c \"
import yaml; d=yaml.safe_load(open('$POLICY'))['deadlines']['final_report']
assert d['actively_exploited_vulnerability']['days'] == 14
assert d['severe_incident']['days'] == 30
assert d['actively_exploited_vulnerability']['from'] != d['severe_incident']['from']\""
  a "applicability is UNDETERMINED and points at the issue that decides it" \
    "python3 -c \"
import yaml; a=yaml.safe_load(open('$POLICY'))['applicability']
assert a['status']=='undetermined' and a['tracked_in']==113 and a['determined_by'] is None\""
  a "the competent CSIRT is not invented" \
    "python3 -c \"
import yaml; r=yaml.safe_load(open('$POLICY'))['reporting_route']
assert r['csirt']=='undetermined' and r['submission_account']=='undetermined'\""
  # A missed deadline must be DETECTED, not smoothed over.
  cat > "$tmp/late.yaml" <<'Y'
id: INC-LATE
simulated: true
state: EARLY_WARNING
awareness_at: "2026-01-01T00:00:00+00:00"
summary: "late"
classification: severe-incident
early_warning_submitted_at: "2026-01-05T00:00:00+00:00"
Y
  a "a missed deadline is reported as MISSED" \
    "! status '$tmp/late.yaml' >/dev/null 2>&1; \
     out=\"\$(status '$tmp/late.yaml' 2>&1 || true)\"; grep -q MISSED <<<\"\$out\""

  echo "self-test: $p ok, $f failed"
  [ "$f" -eq 0 ]
}

case "${1:-}" in
  deadlines)   shift; deadlines "$@" ;;
  new)         shift; new_record "$@" ;;
  packet)      shift; packet "$@" ;;
  status)      shift; status "$@" ;;
  --tabletop)  tabletop ;;
  --self-test) self_test ;;
  *) sed -n '20,28p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 64 ;;
esac
