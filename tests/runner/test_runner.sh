#!/usr/bin/env bash
# Phase F — runner + Docker hardening: helper self-tests + workflow static checks.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

# helper self-tests
ck "reset-workspace-ownership self-test" 'bash scripts/ci/reset-workspace-ownership.sh --self-test >/dev/null'
ck "cleanup-docker-job self-test"        'bash scripts/ci/cleanup-docker-job.sh --self-test >/dev/null'
ck "install-runner-hook self-test"       'bash scripts/ci/install-runner-hook.sh --self-test >/dev/null'

# every workflow uses the shared reset helper, not an inline chown block
ck "no inline chown -R remains in workflows" \
   '! grep -rlED "chown -R" .github/workflows/ 2>/dev/null | grep -q .'
ck "workflows call the shared reset helper" \
   'grep -rl "scripts/ci/reset-workspace-ownership.sh" .github/workflows/ | grep -q .'
# no broad docker prune
ck "no global builder/system prune in workflows" \
   '! grep -rED "docker (builder prune -af|system prune)" .github/workflows/ 2>/dev/null | grep -q .'
# image-building jobs run the job-scoped cleanup
ck "job-scoped docker cleanup is wired" \
   'grep -rl "scripts/ci/cleanup-docker-job.sh" .github/workflows/ | grep -q .'

echo "----"; [ "$fail" -eq 0 ] && echo "test_runner: PASS" || echo "test_runner: FAIL"
exit $fail
