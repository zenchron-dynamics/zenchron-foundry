#!/usr/bin/env bash
# =============================================================================
# tests/governance/test_admission_and_continuity.sh — offline half of #124/#116.
#
# The ENGINE evaluation (real Kyverno) and the registry exercise need docker and
# live in scripts/test-admission-policy.sh and scripts/continuity-export.sh.
# This asserts what can be checked without either: that the admission policies
# still match the sources they are generated from, that every rule the issue
# names exists, and that the continuity policy has not quietly started claiming
# an independent mirror it does not have.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

# --- #124: generated, and still matching its sources ------------------------
ck "the admission policies match the policies they are generated from" \
   "python3 scripts/generate-admission-policy.py --check >/dev/null"
ck "the identity regexps come from cosign-identities.yaml, not a copy" \
   'python3 -c "
import yaml
ci = yaml.safe_load(open(\"policies/cosign-identities.yaml\"))
d  = yaml.safe_load(open(\"policy/kubernetes/kyverno-signatures.yaml\"))
subs = {e[\"keyless\"][\"subject\"] for r in d[\"spec\"][\"rules\"]
        for v in r.get(\"verifyImages\", []) for a in v.get(\"attestors\", [])
        for e in a[\"entries\"]}
want = {ci[\"roles\"][\"rc-publisher\"][\"identity_regexp\"], ci[\"roles\"][\"release\"][\"identity_regexp\"]}
assert want <= subs, (want - subs)
"'
ck "the runtime rules come from runtime-contract.yaml" \
   'python3 -c "
import yaml
rt = yaml.safe_load(open(\"policies/runtime-contract.yaml\"))[\"profile\"]
d  = yaml.safe_load(open(\"policy/kubernetes/kyverno-runtime.yaml\"))
txt = yaml.safe_dump(d)
for c in rt[\"cap_drop\"]:
    assert c in txt, c
"'
# Every rejection the issue names must be a rule that EXISTS. The engine test
# proves they fire; this proves none was dropped.
for r in images-must-be-digest-pinned images-must-come-from-the-declared-repository; do
  ck "provenance rule '$r' exists" \
     "python3 -c \"
import yaml; d=yaml.safe_load(open('policy/kubernetes/kyverno-image-provenance.yaml'))
assert '$r' in [x['name'] for x in d['spec']['rules']]\""
done
for r in must-run-as-non-root root-filesystem-must-be-read-only \
         privilege-escalation-must-be-disabled must-not-be-privileged \
         all-capabilities-must-be-dropped seccomp-must-be-the-runtime-default \
         host-namespaces-must-not-be-shared \
         the-container-runtime-socket-must-not-be-mounted; do
  ck "runtime rule '$r' exists" \
     "python3 -c \"
import yaml; d=yaml.safe_load(open('policy/kubernetes/kyverno-runtime.yaml'))
assert '$r' in [x['name'] for x in d['spec']['rules']]\""
done
ck "signature and attestation rules exist" \
   "python3 -c \"
import yaml; d=yaml.safe_load(open('policy/kubernetes/kyverno-signatures.yaml'))
n=[x['name'] for x in d['spec']['rules']]
assert 'images-must-be-signed-by-a-production-identity' in n
assert 'images-must-carry-sbom-and-provenance' in n\""
# The positive control must exist, or the negative fixtures prove nothing.
ck "a COMPLIANT fixture exists alongside the violations" \
   "test -f policy/kubernetes/tests/compliant.yaml && \
    [ \"\$(ls policy/kubernetes/tests/violation-*.yaml | wc -l | tr -d ' ')\" -ge 10 ]"
ck "the signature rules are NOT mixed with the evaluable ones" \
   'python3 -c "
import yaml
for f in (\"kyverno-image-provenance\", \"kyverno-runtime\"):
    d = yaml.safe_load(open(\"policy/kubernetes/%s.yaml\" % f))
    for r in d[\"spec\"][\"rules\"]:
        assert \"verifyImages\" not in r, (
            f, r[\"name\"],
            \"Kyverno skips a whole policy file when a rule needs registry \"
            \"credentials, so this rule would never evaluate\")
"'

# --- #116: the gap must stay declared ---------------------------------------
ck "the continuity self-test passes" \
   "bash scripts/continuity-export.sh --self-test >/dev/null"
ck "the policy still says there is NO independent mirror" \
   'python3 -c "
import yaml
d = yaml.safe_load(open(\"policies/continuity.yaml\"))
assert d[\"current_state\"][\"independent_mirror\"] == \"none\", d[\"current_state\"]
assert d[\"current_state\"][\"acceptance_gap\"]
"'
ck "no shipped document claims a mirror exists" \
   '[ -z "$(grep -rniE "(independent|second) (registry|mirror) (is|now) (in place|available|configured)" docs/ --include=*.md 2>/dev/null || true)" ]'
ck "the exercise is described as a mechanism test, not as a mirror" \
   'python3 -c "
import re
# Read as one blob: the statement spans a line break, and a line-based grep was
# failing on prose wrapping rather than on substance.
t = re.sub(r\"\\s+\", \" \", open(\"docs/continuity.md\").read().lower())
assert \"local registry\" in t, \"the exercise must be described as running against a local registry\"
assert \"no independent second registry\" in t or \"independent mirror\" in t, \
    \"the absence of an independent mirror must be stated\"
"' 
echo "----"; [ "$fail" -eq 0 ] && echo "test_admission_and_continuity: PASS" || echo "test_admission_and_continuity: FAIL"
exit $fail
