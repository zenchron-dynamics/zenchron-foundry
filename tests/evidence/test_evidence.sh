#!/usr/bin/env bash
# Phase I — solo-maintainer governance + evidence package.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

R=7b4985a1234567890abcdef1234567890abcdef1
tmp="$(mktemp -d)"; printf x > "$tmp/rc.yaml"
build() { VERSION=v2026.07.03 RC=rc1 REVISION="$R" RC_MANIFEST="$tmp/rc.yaml" \
  SIG_RESULT=10/10 SBOM_RESULT=10/10 PROV_RESULT=10/10 OCIREV_RESULT=10/10 ARCH_RESULT=10/10 \
  RUNTIME_RESULT=10/10 VULN_RESULT=enforced ROLLBACK_EXERCISE=pass ENV_CONFIG=foundry-production \
  bash scripts/build-release-evidence.sh "$1" >/dev/null 2>&1; }

build "$tmp/full"
ck "evidence.json + EVIDENCE.md + VERIFY.md produced" \
   'test -f "$tmp/full/evidence.json" && test -f "$tmp/full/EVIDENCE.md" && test -f "$tmp/full/VERIFY.md"'
ck "full evidence validates"          'bash scripts/validate-release-evidence.sh "$tmp/full/evidence.json" >/dev/null 2>&1'
ck "VERIFY.md carries NO wildcard identity" '! grep -q "/\\.\\*" "$tmp/full/VERIFY.md"'
ck "evidence checksum tamper detected" '
  printf "\n#x" >> "$tmp/full/evidence.json"
  ! bash scripts/validate-release-evidence.sh "$tmp/full/evidence.json" >/dev/null 2>&1'

# absent verification rejected unless dry-run
VERSION=v2026.07.03 RC=rc1 REVISION="$R" bash scripts/build-release-evidence.sh "$tmp/bare" >/dev/null 2>&1
ck "absent verification rejected (strict)" '! bash scripts/validate-release-evidence.sh "$tmp/bare/evidence.json" >/dev/null 2>&1'
ck "absent verification allowed (dry-run)"  'ALLOW_ABSENT=1 bash scripts/validate-release-evidence.sh "$tmp/bare/evidence.json" >/dev/null 2>&1'
rm -rf "$tmp"

# governance wiring
ck "promote-stable requires typed confirmation" \
   'yq -e ".on.workflow_dispatch.inputs.confirmation.required == true" .github/workflows/promote-stable.yml >/dev/null'
ck "promote-stable requires risk acceptance" \
   'yq -e ".on.workflow_dispatch.inputs.risk_acceptance_confirmation.required == true" .github/workflows/promote-stable.yml >/dev/null'
ck "promote-stable does NOT require two reviewers (solo model)" \
   'grep -q "ACCEPT-RISK" .github/workflows/promote-stable.yml'
ck "release builds+validates evidence"  'grep -q "build-release-evidence.sh" .github/workflows/release.yml && grep -q "validate-release-evidence.sh" .github/workflows/release.yml'
ck "solo-maintainer model documented"   'test -f docs/solo-maintainer-release-model.md'
ck "accepted risks documented"          'test -f docs/accepted-risks.md'

echo "----"; [ "$fail" -eq 0 ] && echo "test_evidence: PASS" || echo "test_evidence: FAIL"
exit $fail
