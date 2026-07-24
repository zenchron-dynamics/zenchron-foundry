#!/usr/bin/env bash
# SC-02 drift gate for the inline "Reset workspace ownership" blocks.
#
# Every workflow carries a byte-identical, minimal PRE-CHECKOUT copy of the
# _safe_workspace guards from scripts/ci/reset-workspace-ownership.sh — the
# canonical source. The inline copy exists only because that script is not on
# disk before checkout (chicken-and-egg: the block makes checkout possible).
# This gate extracts every copy and diffs it against the canonical text below,
# so ANY drift fails CI: "N divergent copies" becomes "N verified-identical
# copies with a drift gate".
#
# The step NAME suffix may vary ("pre-checkout" / "pre-download"); everything
# after the `- name:` line must be byte-identical.
#
# Usage: assert-canonical-reset-block.sh [--self-test]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

MARKER='- name: Reset workspace ownership'

# Canonical step tail (everything after the step's `- name:` line). Keep in
# lockstep with the guards in scripts/ci/reset-workspace-ownership.sh: change
# the script first, then update this text AND every workflow copy together.
# NOTE: assigned via `read -d ''` (not `$(cat <<EOF)`) — the case patterns in
# the body carry unbalanced `)` which older bash mis-parses inside `$( )`.
IFS= read -r -d '' CANONICAL <<'EOF' || true
        # Canonical source: scripts/ci/reset-workspace-ownership.sh (_safe_workspace
        # guards). Inline because it must run BEFORE checkout puts that script on
        # disk. Do NOT edit this copy alone: every workflow carries the same block,
        # and scripts/ci/assert-canonical-reset-block.sh fails CI on any drift.
        run: |
          set -euo pipefail
          ws="${GITHUB_WORKSPACE:?}"; root="${RUNNER_WORKSPACE:?}"
          # Guards from the canonical script: canonicalize via realpath so a
          # symlinked workspace cannot escape the runner root; refuse root paths.
          ws="$(realpath "$ws")"; root="$(realpath "$root")"
          case "$ws" in ""|"/"|"//") echo "REFUSE: workspace resolves to a root path: '$ws'" >&2; exit 1 ;; esac
          case "$root" in ""|"/"|"//") echo "REFUSE: runner root resolves to a root path: '$root'" >&2; exit 1 ;; esac
          case "$ws" in "$root"|"$root"/*) : ;; *) echo "REFUSE: workspace '$ws' outside runner root '$root'" >&2; exit 1 ;; esac
          # Unconditionally reclaim the WHOLE tree: a nested root-owned .git/ left by a
          # prior container step blocks checkout even when $ws itself looks ours.
          if [ "$(id -u)" -eq 0 ]; then chown -R "$(id -u):$(id -g)" "$ws"
          elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then sudo -n chown -R "$(id -u):$(id -g)" "$ws"
          else echo "ERROR: '$ws' not owned by $(id -u) and cannot elevate" >&2; exit 1; fi
EOF
CANONICAL="${CANONICAL%$'\n'}"   # read -d '' keeps the heredoc's final newline

# assert_all <workflows-dir>: extract-and-diff every reset block in the dir.
assert_all() {
  local dir="$1" found=0 bad=0 n_lines wf lns ln actual
  n_lines="$(printf '%s\n' "$CANONICAL" | wc -l | tr -d ' ')"
  for wf in "$dir"/*.yml "$dir"/*.yaml; do
    [ -f "$wf" ] || continue
    lns="$(grep -nF -- "$MARKER" "$wf" | cut -d: -f1)" || continue
    while IFS= read -r ln; do
      [ -n "$ln" ] || continue
      found=$((found+1))
      actual="$(sed -n "$((ln+1)),$((ln+n_lines))p" "$wf")"
      if [ "$actual" != "$CANONICAL" ]; then
        bad=$((bad+1))
        echo "DRIFT: $wf:$((ln+1)) — reset block differs from the canonical text:" >&2
        diff <(printf '%s\n' "$CANONICAL") <(printf '%s\n' "$actual") >&2 || true
      fi
    done <<<"$lns"
  done
  # Fail closed if the marker matches nothing: a renamed step name must never
  # silently turn this gate into a no-op.
  [ "$found" -gt 0 ] \
    || { echo "FAIL: no '$MARKER' steps found under $dir — step renamed? gate would be vacuous" >&2; return 1; }
  [ "$bad" -eq 0 ] \
    || { echo "FAIL: $bad of $found reset blocks drifted (canonical: scripts/ci/reset-workspace-ownership.sh)" >&2; return 1; }
  echo "OK: $found reset blocks verified byte-identical to the canonical text"
}

self_test() {
  local ok=0 badc=0 tmp
  tmp="$(mktemp -d)"
  chk() { # chk <label> <want:0|1> <dir>  (want 0 = assert_all passes)
    local label="$1" want="$2" dir="$3" got=0
    assert_all "$dir" >/dev/null 2>&1 || got=1
    if [ "$got" = "$want" ]; then ok=$((ok+1)); echo "  ok   $label"
    else badc=$((badc+1)); echo "  FAIL $label: got rc=$got want rc=$want"; fi
  }

  # fixture 1: a workflow with two canonical copies -> pass
  mkdir -p "$tmp/good"
  { printf '      %s (self-hosted hygiene, pre-checkout)\n' "$MARKER"
    printf '%s\n' "$CANONICAL"
    printf '      %s (self-hosted hygiene, pre-download)\n' "$MARKER"
    printf '%s\n' "$CANONICAL"
  } > "$tmp/good/wf.yml"
  chk "canonical copies pass" 0 "$tmp/good"

  # fixture 2: one mutated character -> fail
  mkdir -p "$tmp/drift"
  sed 's/chown -R/chown -R --preserve-root/' "$tmp/good/wf.yml" > "$tmp/drift/wf.yml"
  chk "mutated copy fails" 1 "$tmp/drift"

  # fixture 3: truncated copy (block cut short) -> fail
  mkdir -p "$tmp/trunc"
  head -n 10 "$tmp/good/wf.yml" > "$tmp/trunc/wf.yml"
  chk "truncated copy fails" 1 "$tmp/trunc"

  # fixture 4: marker absent entirely -> fail closed (vacuous gate refused)
  mkdir -p "$tmp/empty"
  echo "name: nothing-here" > "$tmp/empty/wf.yml"
  chk "missing marker fails closed" 1 "$tmp/empty"

  # fixture 5: weakened copy (guards deleted, old 3-line body) -> fail
  mkdir -p "$tmp/weak"
  { printf '      %s (self-hosted hygiene, pre-checkout)\n' "$MARKER"
    printf '        run: |\n          set -euo pipefail\n          chown -R "$(id -u):$(id -g)" "$GITHUB_WORKSPACE" || true\n'
  } > "$tmp/weak/wf.yml"
  chk "weakened copy fails" 1 "$tmp/weak"

  rm -rf "$tmp"
  echo "self-test: $ok ok, $badc failed"
  [ "$badc" -eq 0 ]
}

if [ "${1:-}" = "--self-test" ]; then self_test; else assert_all "$ROOT/.github/workflows"; fi
