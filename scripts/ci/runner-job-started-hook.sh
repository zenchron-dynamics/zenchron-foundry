#!/usr/bin/env bash
# =============================================================================
# scripts/ci/runner-job-started-hook.sh
# -----------------------------------------------------------------------------
# ACTIONS_RUNNER_HOOK_JOB_STARTED hook. Runs on the self-hosted runner BEFORE
# checkout, so it CANNOT rely on repo scripts. It calls the installed copy of
# reset-workspace-ownership.sh that sits alongside it (placed by
# install-runner-hook.sh), giving non-root runners a safe pre-checkout reset
# without duplicating the strict logic.
#
# Install: copy this file + reset-workspace-ownership.sh into a runner dir, then
#   export ACTIONS_RUNNER_HOOK_JOB_STARTED=<dir>/runner-job-started-hook.sh
# (see scripts/ci/install-runner-hook.sh).
# =============================================================================
set -euo pipefail
_hook_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_reset="$_hook_dir/reset-workspace-ownership.sh"

if [ ! -x "$_reset" ] && [ ! -f "$_reset" ]; then
  echo "job-started-hook: reset-workspace-ownership.sh not installed alongside hook ($_reset)" >&2
  exit 1
fi
# GITHUB_WORKSPACE is exported by the runner before this hook runs.
exec bash "$_reset"
