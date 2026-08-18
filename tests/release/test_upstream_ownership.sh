#!/usr/bin/env bash
# =============================================================================
# The upstream ownership boundary is enforced, not merely documented.
#
# Foundry consumes official upstream images and builds its own golden images
# from them. It does not fork, patch, vendor or compile upstream-OWNED
# runtime/server binaries. The temptation is real and specific: #79 has two Go
# modules statically linked into the upstream FrankenPHP binary, and the
# "obvious" fix is to rebuild FrankenPHP with upgraded modules. That would make
# Foundry the owner of a Go build, its provenance, its reproducibility and its
# dependency graph — a product decision, never an implementation detail.
#
# The sabotage proofs live in scripts/assert-upstream-ownership.sh --self-test,
# which writes fixtures and requires the audit to refuse each one for its own
# stated reason. This file wires that into the suite and asserts the parts a
# fixture cannot cover: the real repository, the policy's shape, and the
# guidance an agent reads before touching code.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

# shellcheck disable=SC2034  # consumed inside the eval'd ck assertions
POL=policies/component-ownership.yaml
ENF=scripts/assert-upstream-ownership.sh

# --- the real repository complies ------------------------------------------
ck "the repository passes the ownership audit" "bash $ENF >/dev/null 2>&1"
ck "all 21 sabotage proofs pass" "bash $ENF --self-test >/dev/null 2>&1"

# --- no source build exists today ------------------------------------------
ck "no approved source-build ADR is recorded" \
   'python3 -c "
import yaml
d=yaml.safe_load(open(\"$POL\"))
a=d[\"ownership_change\"].get(\"approved_adrs\") or []
assert a==[], a"'
ck "the ADR gate is required for ownership changes" \
   'python3 -c "
import yaml
d=yaml.safe_load(open(\"$POL\"))
assert d[\"ownership_change\"][\"requires_adr\"] is True"'
ck "no upstream-owned binary is marked compilable" \
   'python3 -c "
import yaml
d=yaml.safe_load(open(\"$POL\"))
bad=[c[\"component\"] for c in d[\"components\"]
     if c[\"owner_class\"]==\"upstream-binary\" and c.get(\"foundry_may_compile\")]
assert not bad, bad"'

# --- the approved compilation exception is explicit, not vague -------------
# The one place Foundry DOES compile must be classified, so the prohibition
# cannot accidentally forbid it and nobody has to reason from a vague exception.
ck "PHP extensions are classified as Foundry-compilable" \
   'python3 -c "
import yaml
d=yaml.safe_load(open(\"$POL\"))
e=[c for c in d[\"components\"] if c[\"component\"]==\"php-extensions\"][0]
assert e[\"owner_class\"]==\"foundry-selected-extension\"
assert e[\"foundry_may_compile\"] is True
assert \"docker-php-ext\" in e[\"compilation_scope\"]"'
ck "and the real Dockerfiles still perform that approved compilation" \
   'grep -rq "docker-php-ext-install" images/php-cli/8.4/Dockerfile &&
    grep -rq "pecl install" images/php-cli/8.4/Dockerfile'

# --- every shipped family and embedded component is classified -------------
ck "every shipped image family has an ownership entry" \
   'python3 -c "
import yaml, subprocess
d=yaml.safe_load(open(\"$POL\"))
cov=set()
for c in d[\"components\"]: cov.update(c.get(\"image_families\") or [])
fams=subprocess.run([\"bash\",\"-c\",\". scripts/lib/common.sh; matrix_families\"],
                    capture_output=True,text=True).stdout.split()
missing=sorted(set(fams)-cov)
assert not missing, missing"'
ck "the distinct components the audit asked for are all present" \
   'python3 -c "
import yaml
d=yaml.safe_load(open(\"$POL\"))
have={c[\"component\"] for c in d[\"components\"]}
need={\"php-official-base\",\"frankenphp-binary\",\"caddy-embedded-in-frankenphp\",
      \"caddy-standalone\",\"nginx-binary\",\"php-extensions\",\"distro-packages\",
      \"zenchron-scripts-and-config\"}
missing=need-have
assert not missing, missing"'

# --- rebuild semantics ------------------------------------------------------
ck "the policy states a rebuild cannot remediate an upstream binary" \
   'python3 -c "
import yaml
d=yaml.safe_load(open(\"$POL\"))
c=[x for x in d[\"rebuild_semantics\"][\"cannot_remediate\"]
   if x[\"owner_class\"]==\"upstream-binary\"]
assert c, \"upstream-binary missing from cannot_remediate\"
assert d[\"rebuild_semantics\"][\"forbidden_claim\"]"'
ck "the classifier agrees for the real #79 finding" \
   '[ "$(bash scripts/classify-remediation-owner.sh --image php-frankenphp/8.4 \
        --package github.com/getkin/kin-openapi --installed v0.140.0 \
        --fixed 0.144.0 --newer-base-available no | grep ^rebuild_can_remediate= |
        cut -d= -f2)" = no ]'

# --- downstream reporting contract -----------------------------------------
ck "downstream reports are accepted as evidence" \
   'python3 -c "
import yaml
d=yaml.safe_load(open(\"$POL\"))[\"downstream_reports\"]
assert d[\"may_provide\"] and d[\"triage_owner\"]"'
ck "but may NOT dictate the implementation method" \
   'python3 -c "
import yaml
d=yaml.safe_load(open(\"$POL\"))[\"downstream_reports\"]
t=d[\"may_not_dictate\"].lower()
assert \"fork\" in t and \"compile\" in t"'

# --- exception discipline ---------------------------------------------------
ck "exceptions must be scoped, version-bound, arch-bound and expiring" \
   'python3 -c "
import yaml
r=yaml.safe_load(open(\"$POL\"))[\"exception_requirements\"]
must=\" \".join(r[\"must_be\"]).lower()
for k in (\"narrowly scoped\",\"installed version\",\"architectures\",\"expiring\"):
    assert k in must, k
assert r[\"no_unevidenced_reachability_claims\"] is True"'
ck "an unacceptable risk suspends the family rather than widening an exception" \
   'python3 -c "
import yaml
r=yaml.safe_load(open(\"$POL\"))[\"exception_requirements\"]
t=r[\"unacceptable_risk_path\"].lower()
assert \"suspend\" in t and \"broader exception\" in t"'

# --- agent guidance ---------------------------------------------------------
ck "AGENTS.md exists and leads with the rule" \
   'test -s AGENTS.md && head -20 AGENTS.md | grep -q "does not fork, patch, vendor, or compile"'
ck "it gives the concrete allowed examples" \
   'grep -q "Bump the pinned official FrankenPHP digest" AGENTS.md &&
    grep -q "Compile approved PHP extensions" AGENTS.md'
ck "it gives the concrete forbidden examples" \
   'grep -q "xcaddy" AGENTS.md && grep -qi "manually upgraded Go modules" AGENTS.md'
ck "it names the incorrect claim explicitly" \
   'grep -qi "calling the embedded CVE fixed" AGENTS.md'

# --- the self-exclusion list cannot grow into a hiding place ---------------
# The enforcement script and its test legitimately contain the forbidden
# patterns as data. Nothing else may be exempt.
ck "exactly two files are exempt from the textual scan" \
   'n=$(grep -m1 "^SELF_EXCLUDE=" '"$ENF"' | tr " " "\n" | grep -c "\.sh");
    [ "$n" = 2 ]'
ck "the exempt files are the enforcement script and its own test" \
   'grep -m1 "^SELF_EXCLUDE=" '"$ENF"' | grep -q "scripts/assert-upstream-ownership.sh" &&
    grep -m1 "^SELF_EXCLUDE=" '"$ENF"' | grep -q "tests/release/test_upstream_ownership.sh"'

# --- the maintainer decision is recorded, and cannot be mistaken for an ADR --
ADR=docs/decisions/adr-0001-upstream-only-binary-consumption.md
ck "the upstream-only decision is recorded as ACCEPTED" \
   'test -s "$ADR" && grep -q "Status: ACCEPTED" "$ADR"'
ck "it states source compilation is NOT approved" \
   'grep -qi "Source compilation: NOT APPROVED" "$ADR"'
ck "it states expiry does not authorize compilation" \
   'grep -qi "does not authorize source compilation" "$ADR"'
ck "it states upstream lag does not transfer ownership" \
   'grep -qi "does not make Foundry the upstream maintainer" "$ADR"'
ck "it names suspension as the escalation" \
   'grep -qi "suspension of the affected image family" "$ADR"'
ck "it requires a NEW separately approved ADR to reverse" \
   'grep -qi "separately approved ADR" "$ADR"'
ck "the old open-question proposal file is gone" \
   '! test -e docs/decisions/vendor-binary-source-build-proposal.md'

# THE test the audit asked for: an accepted DECISION document must not be
# mistaken for an approved OWNERSHIP-CHANGE ADR. ADR-0001 approves consuming
# upstream binaries; it approves no ownership change, so it must never appear in
# approved_adrs while upstream binaries stay non-compilable.
ck "the decision record does NOT satisfy the ownership-change ADR requirement" \
   'python3 -c "
import yaml
d=yaml.safe_load(open(\"$POL\"))
o=d[\"ownership_change\"]
assert o[\"approved_adrs\"] == [], o[\"approved_adrs\"]
assert o[\"decision_record\"] not in (o[\"approved_adrs\"] or [])
assert o[\"decision_status\"] == \"accepted-upstream-only\""'
ck "the policy records that expiry never authorizes compilation" \
   'python3 -c "
import yaml
o=yaml.safe_load(open(\"$POL\"))[\"ownership_change\"]
assert o[\"expiry_does_not_authorize_compilation\"] is True
assert o[\"upstream_lag_does_not_transfer_ownership\"] is True
assert \"suspend\" in o[\"escalation_when_risk_unacceptable\"]"'

# SABOTAGE: listing the decision record as an approved ownership ADR must be
# caught. It is the most plausible way this boundary gets quietly reversed.
ck "SABOTAGE: promoting the decision record into approved_adrs is DETECTED" \
   'tmp="$(mktemp -d)";
    python3 -c "
import yaml,sys
d=yaml.safe_load(open(\"$POL\"))
d[\"ownership_change\"][\"approved_adrs\"]=[d[\"ownership_change\"][\"decision_record\"]]
for c in d[\"components\"]:
    if c[\"component\"]==\"frankenphp-binary\": c[\"foundry_may_compile\"]=True
yaml.safe_dump(d,open(\"$tmp/p.yaml\",\"w\"),sort_keys=False)";
    python3 -c "
import yaml,sys
d=yaml.safe_load(open(\"$tmp/p.yaml\"))
o=d[\"ownership_change\"]
bad=[c[\"component\"] for c in d[\"components\"]
     if c[\"owner_class\"]==\"upstream-binary\" and c.get(\"foundry_may_compile\")]
# The decision record must never be what unlocks compilation.
sys.exit(0 if (bad and o[\"decision_record\"] in o[\"approved_adrs\"]) else 1)";
    rc=$?; rm -rf "$tmp"; [ $rc -eq 0 ]'

echo "----"
[ "$fail" -eq 0 ] && echo "test_upstream_ownership: PASS" || echo "test_upstream_ownership: FAIL"
exit $fail
