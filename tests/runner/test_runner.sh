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

# Ownership reset MUST be inline + PRE-checkout on this runner (the repo script
# is absent before checkout; a post-checkout reset lets checkout fail on a
# root-owned .git). So the workflows carry the inline chown, NOT the repo helper.
ck "workflows carry an inline pre-checkout ownership reset" \
   'grep -rl "chown -R" .github/workflows/ 2>/dev/null | grep -q .'
ck "workflows do NOT call the repo reset script (would run post-checkout)" \
   '! grep -rl "scripts/ci/reset-workspace-ownership.sh" .github/workflows/ | grep -q .'
# no broad docker prune, and no shared-daemon cleanup in PR-path jobs
ck "no global builder/system prune in workflows" \
   '! grep -rED "docker (builder prune -af|system prune)" .github/workflows/ 2>/dev/null | grep -q .'
ck "job-scoped docker cleanup only in verify-rc (named builder)" \
   '[ "$(grep -rl "scripts/ci/cleanup-docker-job.sh" .github/workflows/ | grep -v verify-rc.yml | wc -l | tr -d " ")" = 0 ]'
# the reset helper still exists + self-tests (used by the runner job-started hook)
ck "reset helper retained for the runner hook" 'test -x scripts/ci/reset-workspace-ownership.sh'

echo "----"; [ "$fail" -eq 0 ] && echo "test_runner: PASS" || echo "test_runner: FAIL"
exit $fail
