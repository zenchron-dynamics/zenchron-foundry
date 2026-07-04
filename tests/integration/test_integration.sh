#!/usr/bin/env bash
# Phase J — integration: dry-run, readiness verdict, version/changelog.
# NOTE: does NOT call macro-validate.sh (which runs this suite) — no recursion.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

# release dry-run completes offline and produces a plan + full artifact set
d="$(mktemp -d)"
ck "release dry-run succeeds offline"  'bash scripts/release-dry-run.sh "$d" >/dev/null 2>&1'
ck "dry-run wrote PLAN.md"             'test -f "$d/PLAN.md"'
ck "dry-run produced RC manifest"      'test -f "$d/art/release-manifest.yaml"'
ck "dry-run produced rollback manifest" 'test -f "$d/art/rollback-v2026.07.04.yaml"'
ck "dry-run produced promotion manifest" 'test -f "$d/art/promotion-v2026.07.04.yaml"'
ck "dry-run produced evidence"         'test -f "$d/art/evidence.json"'
ck "PLAN names no executed live op"    '! grep -qE "^(docker|gh|cosign) " "$d/PLAN.md"'
rm -rf "$d"

# readiness verdict is one of the six allowed
ck "readiness report exists"           'test -f docs/production-readiness-report.md'
ck "readiness verdict is allowed" '
  grep -qE "Verdict: .(NOT READY|READY FOR RC|RC VALIDATED — STABLE RELEASE DEFERRED|RC VALIDATED — READY FOR PROMOTION|STABLE PROMOTED — RELEASE SEALING PENDING|PRODUCTION RELEASE COMPLETE)." docs/production-readiness-report.md'

# version + changelog + war-room
ck "VERSION is CalVer"                 'grep -qE "^v[0-9]{4}\.[0-9]{2}\.[0-9]{2}" VERSION'
ck "changelog notes the increment"     'grep -q "RC identity binding" CHANGELOG.md'
ck "war-room runbook exists"           'test -f docs/releases/v2026.07.04-war-room.md'

echo "----"; [ "$fail" -eq 0 ] && echo "test_integration: PASS" || echo "test_integration: FAIL"
exit $fail
