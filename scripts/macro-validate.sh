#!/usr/bin/env bash
# self-test: waived (thin harness; the gates it runs are the coverage — each gated script self-tests via the tests/run-all.sh gate)
# =============================================================================
# scripts/macro-validate.sh
# -----------------------------------------------------------------------------
# Runs the offline macro-increment validation suite and prints a pass/fail
# summary. Everything here is local/offline — no registry, no docker build, no
# network. Live image builds + published-digest checks run in CI (ci.yml,
# verify-rc.yml); this is the gate a maintainer runs before pushing.
# =============================================================================
# -e is safe here: every gate command runs inside gate()'s `if`, so a failing
# gate is counted rather than aborting the sweep; errexit only guards the
# harness's own plumbing (cd, mktemp-style failures).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

pass=0 fail=0 skip=0
gate() { # gate <label> <cmd...>
  local label="$1"; shift
  if ! command -v "$1" >/dev/null 2>&1 && [ ! -f "$1" ] && [ "$1" != bash ]; then
    echo "SKIP  $label (tool '$1' absent)"; skip=$((skip+1)); return; fi
  if "$@" >/dev/null 2>&1; then echo "PASS  $label"; pass=$((pass+1));
  else echo "FAIL  $label"; fail=$((fail+1)); fi
}

echo "== Zenchron Foundry — macro validation (offline) =="
gate "repo structure"            bash scripts/check-structure.sh
gate "action pinning"            bash scripts/assert-pinned-actions.sh
gate "container pinning"         bash scripts/assert-pinned-containers.sh
gate "examples pinned/fail-closed" bash scripts/assert-examples-pinned.sh
gate "no wolfi/apk guard"        bash scripts/assert-no-wolfi.sh
gate "image matrix (10/10)"      bash scripts/assert-image-matrix.sh
gate "environment names"         bash scripts/assert-environment-names.sh
gate "actionlint"                actionlint
gate "shellcheck (scripts)"      bash -c 'shellcheck -S warning $(find scripts -name "*.sh")'
gate "vulnerability policy"      bash scripts/validate-vulnerability-exceptions.sh
gate "upstream lifecycle"        bash scripts/assert-lifecycle.sh
gate "confinement profiles"      bash scripts/assert-runtime-profiles.sh
gate "supply-chain inputs"       bash scripts/assert-supply-chain-inputs.sh
gate "self-test + unit suite"    bash tests/run-all.sh
gate "release dry-run"           bash scripts/release-dry-run.sh

echo "---------------------------------------------"
printf 'macro-validate: %d pass, %d fail, %d skip\n' "$pass" "$fail" "$skip"
[ "$fail" -eq 0 ]
