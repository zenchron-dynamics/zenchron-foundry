#!/usr/bin/env bash
# The expiry-refresh audit is a DECISION INPUT. Two of its cells were materially
# wrong; a maintainer acting on either would have decided differently.
#
#   G21 gave the clearing floor as `0.141.0`. Trivy reports per-CVE FixedVersions
#   of 0.141.0 and 0.142.0, but the same binary carries GHSA-r277-6w6q-xmqw
#   (CRITICAL, fixed 0.144.0). Acting on 0.141.0 clears two HIGH findings and
#   LEAVES THE CRITICAL. The ledger was always right; only the audit prose was wrong.
#
#   G03 asserted "a Foundry-side removal path exists today and is not blocked on
#   upstream". The ownership investigation (#224) built and measured every
#   candidate and disproved it.
#
# These assertions exist so neither claim can return. They check the AUDIT, not
# the ledger — the ledger has its own gates.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

AUDIT=docs/audits/expiry-refresh-2026-08-25/README.md

ck "the audit exists" "[ -f '$AUDIT' ]"
ck "NON-VACUOUS: it is a substantial document, not a stub" \
   "[ \"\$(wc -l <'$AUDIT')\" -ge 200 ]"

# --- G21: the stale clearing floor must not return -------------------------
# The floor is stated as a REQUIREMENT only when 0.141.0/0.142.0 appear as an
# exit condition. They may legitimately appear as per-CVE scanner metadata, so
# the sabotage targets the exit-condition phrasing, not the bare version string.
g21_row() { grep -E '^\| G21 ' "$AUDIT"; }
ck "G21 states the clearing floor as >= 0.144.0" \
   "grep -q '0\.144\.0' <<<\"\$(g21_row)\""
ck "SABOTAGE: G21 no longer offers 0.141.0 as the thing that clears the group" \
   "! grep -qE 'vendoring .kin-openapi 0\.141\.0. or later' <<<\"\$(g21_row)\""
ck "...and it says why 0.141.0/0.142.0 are insufficient" \
   "grep -qi 'GHSA-r277' <<<\"\$(g21_row)\""
ck "...and it keeps fix_available: true as SCANNER metadata, not a remediation claim" \
   "grep -qi 'scanner metadata' <<<\"\$(g21_row)\""
ck "NON-VACUOUS: the G21 row is actually found and non-empty" \
   "[ -n \"\$(g21_row)\" ]"

# --- G03: the retracted remediation claim must not return ------------------
# The retraction block QUOTES the withdrawn phrase on purpose — that is what
# makes the retraction auditable. What must not survive is the phrase as a LIVE
# claim in the decision row itself.
g03_row() { grep -E '^\| G03 ' "$AUDIT"; }
ck "NON-VACUOUS: the G03 row is actually found and non-empty" \
   "[ -n \"\$(g03_row)\" ]"
ck "SABOTAGE: the G03 decision row no longer claims a Foundry removal path exists" \
   "! grep -q 'removal path exists today and is not blocked on upstream' <<<\"\$(g03_row)\""
# Exactly one occurrence, and it must sit inside the corrections section (5b),
# not in the decision table. A retraction that deletes the original wording is
# not auditable; one that leaves it live is not a retraction.
ck "...the phrase survives EXACTLY once, and only in the corrections record" \
   "[ \"\$(grep -c 'a Foundry-side removal path exists today' '$AUDIT')\" = 1 ] &&
    [ \"\$(awk '/^## 5b\\./{f=1} /^## 6\\./{f=0} f' '$AUDIT' | grep -c 'a Foundry-side removal path exists today')\" = 1 ]"
for _fact in 'Debian owns and patches' 'no contract-preserving Foundry remediation exists today' \
             'IPE_GD_WITHOUTAVIF=1' 'capability deprecation' 'major-distribution change'; do
  ck "G03 records the proven determination: '$_fact'" \
     "grep -qF -- '$_fact' '$AUDIT'"
done
ck "the retraction is VISIBLE in the document, not a silent rewrite" \
   "grep -qE 'RETRACTED AND REPLACED|CORRECTIONS TO THIS DOCUMENT' '$AUDIT'"

# --- the audit must not contradict the ledger it describes ------------------
# The ledger is the authority. If the audit ever states a floor the records do
# not carry, the audit is wrong.
ck "the ledger's kin-openapi records state the 0.144.0 floor" \
   "python3 -c \"
import yaml,sys
d=yaml.safe_load(open('policies/vulnerability-exceptions.yaml'))
r=[e for e in d['exceptions'] if e.get('cve') in ('CVE-2026-76905','CVE-2026-77354')]
sys.exit(0 if r and all('0.144.0' in str(e.get('note','')) for e in r) else 1)\""
ck "the audit's own expiring-population figure is reconciled to the live ledger" \
   "grep -q '61 exceptions' '$AUDIT'"

# --- selectors, not family labels ------------------------------------------
ck "a selector appendix exists so family labels cannot be mistaken for selectors" \
   "grep -q 'SELECTOR APPENDIX' '$AUDIT'"
ck "...and every ledger selector appears in it" \
   "python3 -c \"
import yaml,sys
d=yaml.safe_load(open('policies/vulnerability-exceptions.yaml'))
sel={str(e.get('image')) for e in d['exceptions']}
txt=open('$AUDIT').read()
missing=[x for x in sel if x not in txt]
sys.exit(1 if missing else 0)\""

echo "----"
[ "$fail" -eq 0 ] && echo "test_expiry_audit_consistency: PASS" || echo "test_expiry_audit_consistency: FAIL"
exit $fail
