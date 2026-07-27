#!/usr/bin/env bash
# =============================================================================
# scripts/assert-no-identity-wildcards.sh
# -----------------------------------------------------------------------------
# Fails if any documentation or policy file teaches a cosign identity that is
# broader than the anchored per-role identities in
# policies/cosign-identities.yaml (#99).
#
# Why this matters: a repository-wide identity such as
#   --certificate-identity-regexp 'https://github.com/<org>/<repo>/.*'
# accepts a signature from ANY workflow in the repository — including
# scheduled-rebuild.yml, whose dated candidate images must never satisfy the
# production identity, and including any workflow a future compromise adds.
# Documentation that teaches it hands consumers a weaker trust policy than the
# release gates enforce, which is the gap this repository closed in code and had
# left open in its docs.
#
# A wildcard is rejected when it is REACHABLE — i.e. it appears in an identity
# flag or as an identity value. Prose that names the pattern in order to warn
# against it (as this script's own header does) is fine: what must not exist is a
# runnable example a consumer can copy.
#
# Usage: assert-no-identity-wildcards.sh [<dir>]   (default: repo root)
#        assert-no-identity-wildcards.sh --self-test
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# An identity regexp is "broad" when the path component after the repo is a
# bare wildcard rather than an anchored .github/workflows/<file>@<ref> form.
BROAD_RE='--certificate-identity(-regexp)?[[:space:]]*(\\)?[[:space:]]*.?https?://github\.com/[^ '"'"'"]*/\.\*'

scan() {
  local dir="$1" hits=0 found=0 f line
  while IFS= read -r f; do
    found=$((found + 1))
    # Join continuation lines so a flag split across `\` newlines is still seen.
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      printf '%s: %s\n' "${f#"$dir"/}" "$line"
      hits=$((hits + 1))
    done < <(sed -e ':a' -e '/\\$/{N;s/\\\n[[:space:]]*/ /;ba' -e '}' "$f" \
             | grep -nE -e "$BROAD_RE" || true)
  done < <(find "$dir" \( -name '*.md' -o -name '*.yaml' -o -name '*.yml' -o -name '*.sh' \) \
             -not -path '*/.git/*' -not -path '*/node_modules/*' \
             -not -name 'assert-no-identity-wildcards.sh' | sort)

  # Fail closed: scanning nothing must never look like success.
  if [ "$found" -eq 0 ]; then
    echo "FAIL: no files scanned under '${dir}' — gate would be vacuous" >&2
    return 1
  fi
  if [ "$hits" -gt 0 ]; then
    printf 'RESULT: FAIL (%d repository-wide cosign identity example(s) in %d file(s) scanned)\n' \
      "$hits" "$found" >&2
    echo "        Use the anchored per-role identity from policies/cosign-identities.yaml," >&2
    echo "        or better, scripts/verify-image-release-identity.sh." >&2
    return 1
  fi
  printf 'RESULT: PASS (%d files; no repository-wide cosign identity examples)\n' "$found"
}

self_test() {
  local tmp ok=0 bad=0
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '${tmp}'" RETURN
  t() { if eval "$2"; then ok=$((ok+1)); echo "  ok   $1"; else bad=$((bad+1)); echo "  FAIL $1"; fi; }

  mkdir -p "$tmp/good" "$tmp/wild" "$tmp/split" "$tmp/prose" "$tmp/empty"

  printf 'cosign verify \\\n  --certificate-identity-regexp %s \\\n  img\n' \
    "'^https://github\\.com/o/r/\\.github/workflows/publish-rc\\.yml@refs/heads/master\$'" \
    > "$tmp/good/ok.md"
  t "anchored identity passes" "scan '$tmp/good' >/dev/null"

  printf "cosign verify --certificate-identity-regexp 'https://github.com/o/r/.*' img\n" \
    > "$tmp/wild/bad.md"
  t "repo-wide wildcard is rejected" "! scan '$tmp/wild' >/dev/null 2>&1"

  # The real-world shape: flag and value split across a line continuation.
  printf 'cosign verify \\\n  --certificate-identity-regexp \\\n  %s \\\n  img\n' \
    "'https://github.com/o/r/.*'" > "$tmp/split/bad.md"
  t "wildcard split across continuation lines is rejected" "! scan '$tmp/split' >/dev/null 2>&1"

  printf 'Never use https://github.com/o/r/.* as an identity: it accepts any workflow.\n' \
    > "$tmp/prose/warn.md"
  t "prose warning about the pattern still passes" "scan '$tmp/prose' >/dev/null"

  t "empty directory fails closed" "! scan '$tmp/empty' >/dev/null 2>&1"
  t "the repository itself passes" "scan '$ROOT' >/dev/null"

  echo "self-test: $ok ok, $bad failed"
  [ "$bad" -eq 0 ]
}

case "${1:-}" in
  --self-test) self_test ;;
  "")          scan "$ROOT" ;;
  *)           scan "$1" ;;
esac
