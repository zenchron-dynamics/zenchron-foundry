#!/usr/bin/env bash
# =============================================================================
# tests/lib/test_dependabot_manifests.sh — Dependabot entries must update
# something real (#119).
#
# The defect: composer was configured for examples/laravel and examples/symfony,
# which ship no composer.json ("Reference only … No app code shipped here"), so
# the entry silently matched nothing while implying example dependencies were
# monitored. False assurance is worse than no control.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

ck "guard self-test passes"            "bash scripts/assert-dependabot-manifests.sh --self-test >/dev/null"
ck "repo config passes the guard"      "bash scripts/assert-dependabot-manifests.sh >/dev/null"
ck "guard runs in make validate"       "grep -q 'assert-dependabot-manifests.sh' Makefile"
ck "guard runs in ci.yml"              "grep -q 'assert-dependabot-manifests.sh' .github/workflows/ci.yml"

# The inert composer entry must stay gone until a manifest actually exists.
ck "no composer ecosystem without a manifest" \
   "python3 -c \"
import yaml, os
d = yaml.safe_load(open('.github/dependabot.yml'))
for u in d['updates']:
    if u['package-ecosystem'] != 'composer': continue
    for x in (u.get('directories') or [u.get('directory')]):
        assert os.path.exists(os.path.join(x.lstrip('/'), 'composer.json')), x\""

# The examples must not tell you to build something that cannot build.
for e in laravel symfony; do
  ck "examples/$e README states it does not build as-is" \
     "grep -qi 'does not build as-is' examples/$e/README.md"
done

echo "----"; [ "$fail" -eq 0 ] && echo "test_dependabot_manifests: PASS" || echo "test_dependabot_manifests: FAIL"
exit $fail
