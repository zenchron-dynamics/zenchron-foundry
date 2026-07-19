#!/usr/bin/env bash
# Phase D — exact-commit CI gate + release equality-chain binding.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

ck "exact-commit CI gate self-test"  'bash scripts/check-exact-commit-ci.sh --self-test >/dev/null'
ck "release binding self-test"        'bash scripts/verify-release-binding.sh --self-test >/dev/null'

ck "release.yml runs exact-commit CI gate" 'grep -q "check-exact-commit-ci.sh" .github/workflows/release.yml'
ck "release.yml verifies RC manifest binding" 'grep -q "verify-release-binding.sh" .github/workflows/release.yml'
ck "release.yml verify-artifacts passes revision" \
   'yq -e ".jobs.release.steps[] | select(.name==\"Verify release artifacts (identity, SBOM, provenance, revision, multi-arch — all 10)\") | .env.EXPECTED_REVISION" .github/workflows/release.yml >/dev/null'
ck "required-release-checks names match the real workflow jobs" \
   'bash scripts/assert-required-checks.sh >/dev/null'
ck "required-release-checks still gates the vulnerability scan" \
   'yq -e ".required_checks | map(select(. == \"scan php-cli 8.4\")) | length == 1" policies/required-release-checks.yaml >/dev/null'

echo "----"; [ "$fail" -eq 0 ] && echo "test_release_binding: PASS" || echo "test_release_binding: FAIL"
exit $fail
