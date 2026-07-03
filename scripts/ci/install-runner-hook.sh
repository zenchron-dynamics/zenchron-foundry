#!/usr/bin/env bash
# =============================================================================
# scripts/ci/install-runner-hook.sh <dest-dir>
# -----------------------------------------------------------------------------
# Installs the job-started hook + the strict reset script into a runner-owned
# directory (outside any repo checkout) and prints the exact env line to add to
# the runner's `.env`. For future NON-ROOT runners: gives them a safe
# pre-checkout ownership reset without repo scripts being present yet.
#
# The current root/no-sudo runner does not strictly need this (checkout as root
# reclaims the tree, and workflows call reset-workspace-ownership.sh
# post-checkout). Installing it is forward-compatible and harmless.
# =============================================================================
set -euo pipefail
_src="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="${1:-}"

usage() { echo "usage: install-runner-hook.sh <dest-dir>   (e.g. /opt/actions-runner/hooks)" >&2; exit 2; }
[ "${1:-}" = "--self-test" ] && { _selftest() {
  # Install into a temp dir; verify both files land and the env line is printed.
  local d; d="$(mktemp -d)/hooks"; local out
  out="$(DEST="$d" bash "$_src/install-runner-hook.sh" "$d" 2>&1)"
  local ok=0
  [ -f "$d/runner-job-started-hook.sh" ] && [ -f "$d/reset-workspace-ownership.sh" ] && ok=1
  printf '%s' "$out" | grep -q "ACTIONS_RUNNER_HOOK_JOB_STARTED=$d/runner-job-started-hook.sh" || ok=0
  rm -rf "$(dirname "$d")"
  [ "$ok" = 1 ] && echo "install-runner-hook.sh: SELF-TEST OK" || { echo "install-runner-hook.sh: SELF-TEST FAIL"; return 1; }
}; _selftest; exit $?; }

[ -n "$DEST" ] || usage
mkdir -p "$DEST"
cp "$_src/runner-job-started-hook.sh" "$_src/reset-workspace-ownership.sh" "$DEST/"
chmod +x "$DEST/runner-job-started-hook.sh" "$DEST/reset-workspace-ownership.sh"
echo "installed hook + reset script into: $DEST"
echo
echo "Add this to the runner's .env (or systemd Environment=) and restart it:"
echo "  ACTIONS_RUNNER_HOOK_JOB_STARTED=$DEST/runner-job-started-hook.sh"
