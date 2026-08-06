#!/usr/bin/env bash
# Phase I — solo-maintainer governance + evidence package.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

ck "evidence builder self-test"   'bash scripts/build-release-evidence.sh --self-test >/dev/null'
ck "evidence validator self-test" 'bash scripts/validate-release-evidence.sh --self-test >/dev/null'
ck "release artifacts verifier self-test" 'bash scripts/verify-release-artifacts.sh --self-test >/dev/null'

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
ck "solo-maintainer model documented"   'test -f docs/solo-maintainer-release-model.md'
ck "accepted risks documented"          'test -f docs/accepted-risks.md'

echo "----"; [ "$fail" -eq 0 ] && echo "test_evidence: PASS" || echo "test_evidence: FAIL"
exit $fail
