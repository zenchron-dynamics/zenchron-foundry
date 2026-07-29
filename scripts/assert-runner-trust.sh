#!/usr/bin/env bash
# =============================================================================
# scripts/assert-runner-trust.sh
# -----------------------------------------------------------------------------
# CI trust-boundary gate: fork pull requests must never schedule work on the
# persistent, privileged self-hosted runners.
#
# This repository is PUBLIC. A fork PR's head commit is attacker-controlled code
# (Dockerfiles, scripts/*.sh, compose files, linter configs). The runners
# labelled `[self-hosted, linux, x64, zenchron]` are persistent, shared,
# Docker-capable and sudo-capable, and later trusted jobs reuse that host and its
# workspaces — so running fork code there is a release-supply-chain compromise.
#
# Enforced invariants (any violation fails the build):
#
#   R1  No workflow uses the `pull_request_target` trigger at all. It runs with
#       the BASE repo's token/secrets in the context of PR-authored content and
#       is the classic privilege-escalation trigger.
#
#   R2  In a workflow reachable from `pull_request`, every job whose `runs-on`
#       names a privileged label MUST carry the same-repo trust decision in its
#       job-level configuration — either
#         * a trust-conditional `runs-on` that falls back to a GitHub-hosted
#           runner for forks, or
#         * a job-level `if:` that skips the job for forks
#       both spelled with the exact, unspoofable comparison
#           github.event.pull_request.head.repo.full_name == github.repository
#
#   R3  A `pull_request`-triggered workflow must not delegate a job to another
#       workflow (`uses:` at job level). The callee's runner labels are outside
#       this file's view, so trust cannot be proven — fail closed and re-review
#       instead of guessing.
#
#   R4  Discovery must not be silently empty: zero workflow files is a FAIL, not
#       a vacuous PASS.
#
# Usage:
#   assert-runner-trust.sh [<workflows-dir>]   # default: <repo>/.github/workflows
#   assert-runner-trust.sh --self-test         # fixture-driven self-check
#
# Comments are stripped before matching, so prose mentioning "self-hosted" or
# the comparison string can neither trip nor satisfy the gate.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Labels that identify a persistent privileged runner pool.
PRIVILEGED_LABELS="${PRIVILEGED_LABELS:-self-hosted,zenchron}"
# The one accepted trust predicate. GitHub fills head.repo.full_name from the
# head ref itself, so a PR branch cannot forge it.
TRUST_EXPR='github.event.pull_request.head.repo.full_name == github.repository'

# The rules are enforced by a real YAML PARSER (scripts/lib/runner_trust.py),
# not by matching text. Review proved the previous text-matching version had two
# bypasses: `on: [push, pull_request_target]` slipped past R1 because only the
# `pull_request_target:` mapping form was recognised, and R2 accepted the
# predicate anywhere before `steps:` — including under `env:` — while `runs-on`
# stayed unconditionally privileged. Both are security-boundary bypasses in the
# guard meant to prevent workflow drift.
assert_all() {
  python3 "${ROOT}/scripts/lib/runner_trust.py" "$1" --labels "$PRIVILEGED_LABELS"
}

# --- self-test ---------------------------------------------------------------
self_test() {
  local tmp ok=0 bad=0
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  chk() { # chk <label> <want-rc> <dir>
    local label="$1" want="$2" dir="$3" got=0
    assert_all "$dir" >/dev/null 2>&1 || got=1
    if [ "$got" = "$want" ]; then ok=$((ok + 1)); echo "  ok   $label"
    else bad=$((bad + 1)); echo "  FAIL $label: got rc=$got want rc=$want"; fi
  }

  # The pre-fix shape: PR-triggered job pinned to the privileged pool, no guard.
  mkdir -p "$tmp/unguarded"
  cat > "$tmp/unguarded/ci.yml" <<'EOF'
name: ci
on:
  push:
    branches: [master]
  pull_request:
    branches: [master]
jobs:
  structure:
    name: repo structure
    runs-on: [self-hosted, linux, x64, zenchron]
    steps:
      - run: bash scripts/check-structure.sh
EOF
  chk "unguarded PR job on privileged runner fails (pre-fix shape)" 1 "$tmp/unguarded"

  # Fixed shape: trust-conditional runs-on.
  mkdir -p "$tmp/runson"
  sed "s|    runs-on: \[self-hosted, linux, x64, zenchron\]|    runs-on: \${{ fromJSON((github.event_name != 'pull_request' \|\| ${TRUST_EXPR}) \&\& '[\"self-hosted\",\"linux\",\"x64\",\"zenchron\"]' \|\| '[\"ubuntu-latest\"]') }}|" \
    "$tmp/unguarded/ci.yml" > "$tmp/runson/ci.yml"
  chk "trust-conditional runs-on passes" 0 "$tmp/runson"

  # Fixed shape: job-level if guard (scan-images.yml style).
  mkdir -p "$tmp/ifguard"
  sed "s|    steps:|    if: \${{ github.event_name != 'pull_request' \|\| ${TRUST_EXPR} }}\n    steps:|" \
    "$tmp/unguarded/ci.yml" > "$tmp/ifguard/ci.yml"
  chk "job-level same-repo if guard passes" 0 "$tmp/ifguard"

  # A STEP-level if must not be mistaken for a job guard.
  mkdir -p "$tmp/stepif"
  sed "s|      - run: bash scripts/check-structure.sh|      - if: \${{ ${TRUST_EXPR} }}\n        run: bash scripts/check-structure.sh|" \
    "$tmp/unguarded/ci.yml" > "$tmp/stepif/ci.yml"
  chk "step-level if does not satisfy the gate" 1 "$tmp/stepif"

  # A COMMENT mentioning the predicate must not satisfy the gate.
  mkdir -p "$tmp/commentonly"
  sed "s|    steps:|    # guarded elsewhere: ${TRUST_EXPR}\n    steps:|" \
    "$tmp/unguarded/ci.yml" > "$tmp/commentonly/ci.yml"
  chk "comment mentioning the predicate does not satisfy the gate" 1 "$tmp/commentonly"

  # Non-PR workflows may pin the privileged pool freely.
  mkdir -p "$tmp/pushonly"
  cat > "$tmp/pushonly/release.yml" <<'EOF'
name: release
on:
  push:
    tags: ["v*"]
jobs:
  seal:
    runs-on: [self-hosted, linux, x64, zenchron]
    steps:
      - run: echo trusted
EOF
  chk "push/tag-only workflow on privileged runner passes" 0 "$tmp/pushonly"

  # pull_request_target is banned even without a privileged runner.
  mkdir -p "$tmp/prtarget"
  cat > "$tmp/prtarget/wf.yml" <<'EOF'
name: risky
on:
  pull_request_target:
    branches: [master]
jobs:
  hello:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
EOF
  chk "pull_request_target is rejected outright" 1 "$tmp/prtarget"

  # GitHub-hosted PR jobs need no guard.
  mkdir -p "$tmp/hosted"
  cat > "$tmp/hosted/wf.yml" <<'EOF'
name: ci
on:
  pull_request:
    branches: [master]
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
EOF
  chk "GitHub-hosted PR job passes without a guard" 0 "$tmp/hosted"

  # A PR job delegating to another workflow cannot be proven -> fail closed.
  mkdir -p "$tmp/reusable"
  cat > "$tmp/reusable/wf.yml" <<'EOF'
name: ci
on:
  pull_request:
    branches: [master]
jobs:
  call:
    uses: ./.github/workflows/build-images.yml
EOF
  chk "PR job delegating to another workflow fails closed" 1 "$tmp/reusable"

  # Empty discovery must fail, never pass vacuously.
  mkdir -p "$tmp/empty"
  chk "empty workflow directory fails closed" 1 "$tmp/empty"

  # --- bypasses found in review -------------------------------------------
  # R1: the inline trigger list is as reachable as the mapping form.
  mkdir -p "$tmp/inline-trigger"
  cat > "$tmp/inline-trigger/wf.yml" <<'EOF'
name: risky
on: [push, pull_request_target]
jobs:
  hello:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
EOF
  chk "inline 'on: [push, pull_request_target]' is rejected" 1 "$tmp/inline-trigger"

  mkdir -p "$tmp/inline-pr"
  cat > "$tmp/inline-pr/wf.yml" <<'EOF'
name: ci
on: [push, pull_request]
jobs:
  unsafe:
    runs-on: [self-hosted, linux, x64, zenchron]
    steps:
      - run: ./attacker-controlled.sh
EOF
  chk "inline 'on: [push, pull_request]' still enforces R2" 1 "$tmp/inline-pr"

  # R2: the predicate must gate the job, not merely appear somewhere in it.
  for key in env name concurrency; do
    mkdir -p "$tmp/pred-$key"
    { echo "name: ci"
      echo "on:"
      echo "  pull_request:"
      echo "    branches: [master]"
      echo "jobs:"
      echo "  unsafe:"
      echo "    runs-on: [self-hosted, linux, x64, zenchron]"
      case "$key" in
        env)         printf '    env:\n      TRUST_NOTE: ${{ %s }}\n' "$TRUST_EXPR" ;;
        name)        printf '    name: guarded ${{ %s }}\n' "$TRUST_EXPR" ;;
        concurrency) printf '    concurrency: grp-${{ %s }}\n' "$TRUST_EXPR" ;;
      esac
      echo "    steps:"
      echo "      - run: ./attacker-controlled.sh"
    } > "$tmp/pred-$key/wf.yml"
    chk "predicate under '$key:' does NOT satisfy the gate" 1 "$tmp/pred-$key"
  done

  # A job-level `if:` and a trust-conditional runs-on DO satisfy it.
  mkdir -p "$tmp/real-if"
  { echo "name: ci"; echo "on:"; echo "  pull_request:"; echo "    branches: [master]"
    echo "jobs:"; echo "  guarded:"
    echo "    runs-on: [self-hosted, linux, x64, zenchron]"
    printf '    if: ${{ %s }}\n' "$TRUST_EXPR"
    echo "    steps:"; echo "      - run: echo ok"
  } > "$tmp/real-if/wf.yml"
  chk "real job-level if: satisfies the gate" 0 "$tmp/real-if"

  # Unparseable YAML must fail closed, not be skipped.
  mkdir -p "$tmp/broken"
  printf 'name: ci\non: [\n  pull_request\njobs: : :\n' > "$tmp/broken/wf.yml"
  chk "unparseable workflow fails closed" 1 "$tmp/broken"

  echo "self-test: $ok ok, $bad failed"
  [ "$bad" -eq 0 ]
}

case "${1:-}" in
  --self-test) self_test ;;
  "")          assert_all "$ROOT/.github/workflows" ;;
  *)           assert_all "$1" ;;
esac
