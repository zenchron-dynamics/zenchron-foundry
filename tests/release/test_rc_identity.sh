#!/usr/bin/env bash
# Phase B — RC identity binding: validator + immutability probe + workflow shape.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

ck "validate-release-version self-test" 'bash scripts/validate-release-version.sh --self-test >/dev/null'
ck "registry-probe self-test"           'bash scripts/lib/registry-probe.sh --self-test >/dev/null'

# publish-rc.yml carries the four required bound inputs
for i in version rc expected_revision confirmation; do
  ck "publish-rc requires input: $i" "yq -e '.on.workflow_dispatch.inputs.$i.required == true' .github/workflows/publish-rc.yml >/dev/null"
done
ck "publish-rc concurrency binds version+rc+revision" \
   'grep -q "publish-rc-.*version.*rc.*expected_revision" .github/workflows/publish-rc.yml'

# publish-ghcr.yml gained version + expected_revision call inputs
for i in version expected_revision; do
  ck "publish-ghcr has call input: $i" "yq -e '.on.workflow_call.inputs.$i' .github/workflows/publish-ghcr.yml >/dev/null"
done
ck "publish-ghcr computes immutable RC tag" 'grep -q "immutable_rc_suffix" .github/workflows/publish-ghcr.yml'
ck "publish-ghcr runs the immutability probe" 'grep -q "probe_immutable_tag" .github/workflows/publish-ghcr.yml'

echo "----"; [ "$fail" -eq 0 ] && echo "test_rc_identity: PASS" || echo "test_rc_identity: FAIL"
exit $fail
