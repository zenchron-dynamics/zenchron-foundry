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
PRIVILEGED_LABELS='self-hosted|zenchron'
# The one accepted trust predicate. GitHub fills head.repo.full_name from the
# head ref itself, so a PR branch cannot forge it.
TRUST_EXPR='github.event.pull_request.head.repo.full_name == github.repository'

# _strip_comments: drop `#` comments so prose cannot influence any match.
# Approximate but safe here: workflow keys we inspect never contain a literal
# '#' inside a quoted value.
_strip_comments() { sed -E 's/[[:space:]]#.*$//; s/^[[:space:]]*#.*$//'; }

# _on_block <file>: the top-level `on:` mapping (until the next column-0 key).
_on_block() {
  awk '
    /^[[:space:]]*(on|"on"|'"'"'on'"'"'):/ && !seen { seen=1; print; next }
    seen && /^[^[:space:]#]/ { seen=0 }
    seen { print }
  ' "$1" | _strip_comments
}

# _jobs_block <file>: everything from `jobs:` to EOF.
_jobs_block() { awk '/^jobs:[[:space:]]*$/ {seen=1; next} seen {print}' "$1"; }

# check_file <file> -> prints violations, returns count via global VIOLATIONS
check_file() {
  local file="$1" on_block jobs job_names job_id body pre_steps runs_on

  on_block="$(_on_block "$file")"

  # R1 — pull_request_target is banned outright, PR-triggered or not.
  if grep -qE '(^|[^_a-z])pull_request_target[[:space:]]*:' <<<"$on_block"; then
    echo "VIOLATION [R1] ${file}: uses the 'pull_request_target' trigger" >&2
    VIOLATIONS=$((VIOLATIONS + 1))
  fi

  # Only pull_request-reachable workflows are subject to R2/R3.
  grep -q 'pull_request' <<<"$on_block" || return 0

  jobs="$(_jobs_block "$file" | _strip_comments)"
  job_names="$(grep -oE '^  [A-Za-z0-9_-]+:' <<<"$jobs" | tr -d ' :' || true)"

  if [ -z "$job_names" ]; then
    echo "VIOLATION [R4] ${file}: pull_request-triggered but no jobs parsed" >&2
    VIOLATIONS=$((VIOLATIONS + 1))
    return 0
  fi

  while IFS= read -r job_id; do
    [ -n "$job_id" ] || continue
    # Job body: from this job's header to the next job header (or EOF).
    body="$(awk -v id="$job_id" '
      $0 ~ "^  " id ":[[:space:]]*$" { inside=1; next }
      inside && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ { inside=0 }
      inside { print }
    ' <<<"$jobs")"
    # Job-level configuration only: `steps:` and everything after it is step
    # scope, where a step-level `if:` must not be mistaken for a job guard.
    pre_steps="$(awk '/^    steps:/ {exit} {print}' <<<"$body")"

    # R3 — a job that delegates to another workflow cannot be proven safe here.
    if grep -qE '^    uses:' <<<"$pre_steps"; then
      echo "VIOLATION [R3] ${file}:${job_id}: pull_request-reachable job calls another workflow; runner trust is unprovable from this file" >&2
      VIOLATIONS=$((VIOLATIONS + 1))
      continue
    fi

    # runs-on value: inline scalar/flow-list plus any block-list continuation.
    runs_on="$(awk '
      /^    runs-on:/ { inside=1; print; next }
      inside && /^[[:space:]]+- / { print; next }
      inside { inside=0 }
    ' <<<"$pre_steps")"

    if [ -z "$runs_on" ]; then
      echo "VIOLATION [R4] ${file}:${job_id}: no runs-on found; cannot prove runner trust" >&2
      VIOLATIONS=$((VIOLATIONS + 1))
      continue
    fi

    grep -qE "$PRIVILEGED_LABELS" <<<"$runs_on" || continue   # GitHub-hosted: fine

    # R2 — privileged: the trust predicate must appear in job-level config
    # (inside runs-on itself, or in a job-level `if:`).
    if ! grep -qF "$TRUST_EXPR" <<<"$pre_steps"; then
      echo "VIOLATION [R2] ${file}:${job_id}: privileged runner on a pull_request-reachable job without the same-repo trust guard" >&2
      echo "               expected '${TRUST_EXPR}' in runs-on or a job-level if:" >&2
      VIOLATIONS=$((VIOLATIONS + 1))
    fi
  done <<<"$job_names"
}

assert_all() {
  local dir="$1" f found=0
  VIOLATIONS=0
  for f in "$dir"/*.yml "$dir"/*.yaml; do
    [ -f "$f" ] || continue
    found=$((found + 1))
    check_file "$f"
  done

  # R4 — never pass vacuously.
  if [ "$found" -eq 0 ]; then
    echo "FAIL: no workflow files found under '${dir}' — gate would be vacuous" >&2
    return 1
  fi
  if [ "$VIOLATIONS" -gt 0 ]; then
    printf 'RESULT: FAIL (%d runner-trust violation(s) across %d workflow(s))\n' "$VIOLATIONS" "$found" >&2
    return 1
  fi
  printf 'RESULT: PASS (%d workflow(s); no fork PR can reach a privileged runner)\n' "$found"
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

  echo "self-test: $ok ok, $bad failed"
  [ "$bad" -eq 0 ]
}

case "${1:-}" in
  --self-test) self_test ;;
  "")          assert_all "$ROOT/.github/workflows" ;;
  *)           assert_all "$1" ;;
esac
