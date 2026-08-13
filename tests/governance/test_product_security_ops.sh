#!/usr/bin/env bash
# =============================================================================
# tests/governance/test_product_security_ops.sh — the product-security operating
# model, offline (#112, #125, #114).
#
# The executable exercises (withdrawal simulation, incident tabletop) need docker
# and a registry. This is the offline half: the three policies are complete and
# consistent with each other, nothing claims a capability that does not exist,
# and — the part that matters most here — no contact, channel or legal
# determination has been invented to fill a gap.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

# --- #112 -------------------------------------------------------------------
ck "the governance model gate passes"        "bash scripts/assert-governance-model.sh >/dev/null"
ck "...and rejects a model claiming independence" \
   "bash scripts/assert-governance-model.sh --self-test >/dev/null"
ck "the sensitive-change workflow reads the model rather than copying it" \
   "grep -q 'policies/governance-model.yaml' .github/workflows/sensitive-change.yml"
ck "the sensitive-change workflow cannot write to the pull request" \
   'python3 -c "
import yaml
d = yaml.safe_load(open(\".github/workflows/sensitive-change.yml\"))
assert d[\"permissions\"] == {\"contents\": \"read\", \"pull-requests\": \"read\"}, d[\"permissions\"]
"'
ck "break-glass records have a home and a documented schema" \
   "test -f docs/audits/break-glass/README.md && test -f docs/audits/break-glass/break-glass-EXAMPLE.yaml"

# --- #125 -------------------------------------------------------------------
ck "the support policy derives its dates from lifecycle.yaml, not a copy" \
   'python3 -c "
import yaml
sp = yaml.safe_load(open(\"policies/support-policy.yaml\"))
lc = {e[\"id\"] for e in yaml.safe_load(open(\"policies/lifecycle.yaml\"))[\"lines\"]}
for l in sp[\"lines\"]:
    assert l[\"derives_from\"] in lc, l[\"derives_from\"]
    # a support line must NOT carry its own end date — that is the duplication
    assert \"support_ends\" not in l, l
"'
ck "every channel records a status and a verification" \
   'python3 -c "
import yaml
for c in yaml.safe_load(open(\"policies/support-policy.yaml\"))[\"channels\"]:
    assert c[\"status\"] in (\"available\", \"unavailable\"), c
    assert c.get(\"verification\"), c[\"id\"]
"'
# THE honesty assertion: an unavailable channel must say what a human must do.
ck "an unavailable channel names the required human action" \
   'python3 -c "
import yaml
for c in yaml.safe_load(open(\"policies/support-policy.yaml\"))[\"channels\"]:
    if c[\"status\"] == \"unavailable\":
        assert c.get(\"required_human_action\"), c[\"id\"]
"'
ck "security.txt carries the RFC 9116 required fields" \
   "grep -q '^Contact:' .well-known/security.txt && grep -q '^Expires:' .well-known/security.txt"
ck "security.txt advertises only the contact the policy verified" \
   'python3 -c "
import re, yaml
sp = yaml.safe_load(open(\"policies/support-policy.yaml\"))
ok = {c[\"endpoint\"] for c in sp[\"channels\"] if c[\"status\"] == \"available\"}
txt = open(\".well-known/security.txt\").read()
for m in re.findall(r\"^Contact: mailto:(.+)$\", txt, re.M):
    assert m in ok, (\"security.txt advertises an unverified contact\", m)
"'
ck "no PGP key is claimed that does not exist" \
   "! grep -qE '^Encryption:' .well-known/security.txt"
# The LIVE cross-check deliberately does NOT live here: tests/ is offline by
# construction, and reading private-vulnerability-reporting needs an admin token
# a pull-request context does not have. It is in scripts/verify-repo-governance.sh
# with the other live comparisons. What IS checkable offline is that the two
# documents agree with each other.
#
# Derived, not hardcoded. The first version asserted "SECURITY.md says PVR is
# DISABLED", which was true when written and became a false assertion the moment
# the setting was enabled. What must hold is that the two AGREE — whichever way
# the fact goes.
ck "SECURITY.md agrees with the policy about private vulnerability reporting" \
   'python3 -c "
import re, yaml
sp = yaml.safe_load(open(\"policies/support-policy.yaml\"))
c = [x for x in sp[\"channels\"] if x[\"id\"] == \"github-private-vulnerability-reporting\"][0]
txt = open(\"SECURITY.md\").read()
m = re.search(r\"(?im)^.*private vulnerability reporting.*$\", txt)
assert m, \"SECURITY.md does not mention private vulnerability reporting at all\"
line = m.group(0).lower()
if c[\"status\"] == \"available\":
    assert \"disabled\" not in line and \"not enabled\" not in line, line
else:
    assert \"disabled\" in line or \"not enabled\" in line, line
"'
ck "no PGP key is claimed that does not exist" \
   "! grep -qE '^Encryption:' .well-known/security.txt"
# The LIVE cross-check deliberately does NOT live here: tests/ is offline by
# construction, and reading private-vulnerability-reporting needs an admin token
# a pull-request context does not have. It is in scripts/verify-repo-governance.sh
# with the other live comparisons. What IS checkable offline is that the two
# documents agree with each other.
#
# Derived, not hardcoded. The first version asserted "SECURITY.md says PVR is
# DISABLED", which was true when written and became a false assertion the moment
# the setting was enabled. What must hold is that the two AGREE — whichever way
# the fact goes.
ck "SECURITY.md agrees with the policy about private vulnerability reporting" \
   'python3 -c "
import re, yaml
sp = yaml.safe_load(open(\"policies/support-policy.yaml\"))
c = [x for x in sp[\"channels\"] if x[\"id\"] == \"github-private-vulnerability-reporting\"][0]
txt = open(\"SECURITY.md\").read()
m = re.search(r\"(?im)^.*private vulnerability reporting.*$\", txt)
assert m, \"SECURITY.md does not mention private vulnerability reporting at all\"
line = m.group(0).lower()
if c[\"status\"] == \"available\":
    assert \"disabled\" not in line and \"not enabled\" not in line, line
else:
    assert \"disabled\" in line or \"not enabled\" in line, line
"'
ck "SECURITY.md no longer lists 7.4/8.0 as shipped images" \
   "! grep -qE '^\| php-fpm / php-cli / php-worker \| \*\*7\.4' SECURITY.md"
ck "the withdrawal exercise self-test passes" \
   "bash scripts/exercise-withdrawal.sh --self-test >/dev/null"
ck "withdrawal states that published digests cannot be unpublished" \
   "grep -qi 'immutable' docs/release-withdrawal.md"

# --- #114 -------------------------------------------------------------------
ck "the incident state machine self-test passes" \
   "bash scripts/incident.sh --self-test >/dev/null"
ck "CRA applicability is UNDETERMINED and nobody claimed to determine it" \
   'python3 -c "
import yaml
a = yaml.safe_load(open(\"policies/incident-reporting.yaml\"))[\"applicability\"]
assert a[\"status\"] == \"undetermined\", a
assert a[\"determined_by\"] is None and a[\"determined_at\"] is None, a
assert a[\"tracked_in\"] == 113
"'
ck "the competent CSIRT and submission account are not invented" \
   'python3 -c "
import yaml
r = yaml.safe_load(open(\"policies/incident-reporting.yaml\"))[\"reporting_route\"]
assert r[\"csirt\"] == \"undetermined\" and r[\"submission_account\"] == \"undetermined\", r
"'
ck "the 24h and 72h clocks are declared, from awareness" \
   'python3 -c "
import yaml
d = yaml.safe_load(open(\"policies/incident-reporting.yaml\"))[\"deadlines\"]
assert d[\"early_warning\"][\"hours\"] == 24 and d[\"early_warning\"][\"from\"] == \"awareness_at\"
assert d[\"full_notification\"][\"hours\"] == 72 and d[\"full_notification\"][\"from\"] == \"awareness_at\"
"'
ck "the two final-report branches differ in both length and origin" \
   'python3 -c "
import yaml
f = yaml.safe_load(open(\"policies/incident-reporting.yaml\"))[\"deadlines\"][\"final_report\"]
a, s = f[\"actively_exploited_vulnerability\"], f[\"severe_incident\"]
assert a[\"days\"] == 14 and s[\"days\"] == 30, (a, s)
assert a[\"from\"] == \"corrective_measure_available_at\"
assert s[\"from\"] == \"full_notification_submitted_at\"
"'
ck "a 'not reportable' outcome still requires a recorded rationale" \
   'python3 -c "
import yaml
st = {s[\"id\"]: s for s in yaml.safe_load(open(\"policies/incident-reporting.yaml\"))[\"states\"]}
assert \"classification_rationale\" in st[\"NOT_REPORTABLE\"][\"requires\"], st[\"NOT_REPORTABLE\"]
"'
ck "the full notification requires digest-level evidence" \
   'python3 -c "
import yaml
e = yaml.safe_load(open(\"policies/incident-reporting.yaml\"))[\"evidence_schema\"][\"full_notification\"]
for f in (\"affected_image_digests\", \"affected_source_revisions\", \"sbom_references\", \"vex_status\"):
    assert f in e, f
"'
ck "every simulated artefact in the tree is labelled as such" \
   'python3 -c "
import glob, yaml
for f in glob.glob(\"docs/audits/incidents/*SIMULATED*.yaml\") + glob.glob(\"docs/audits/withdrawals/*SIMULATED*.yaml\"):
    assert (yaml.safe_load(open(f)) or {}).get(\"simulated\") is True, f
for f in glob.glob(\"docs/audits/incidents/*SIMULATED*.txt\") + glob.glob(\"docs/audits/withdrawals/*SIMULATED*.txt\"):
    head = open(f).read(400)
    assert \"SIMULATED\" in head, f
"'
# The three human boundaries must stay recorded, or the batch silently starts
# looking complete when it is not.
ck "the human-only inputs are recorded in all three policies" \
   'python3 -c "
import yaml
assert yaml.safe_load(open(\"policies/incident-reporting.yaml\"))[\"required_human_inputs\"]
assert yaml.safe_load(open(\"policies/support-policy.yaml\"))[\"required_human_actions\"]
assert yaml.safe_load(open(\"policies/governance-model.yaml\"))[\"external_review_triggers\"]
"'

echo "----"; [ "$fail" -eq 0 ] && echo "test_product_security_ops: PASS" || echo "test_product_security_ops: FAIL"
exit $fail
