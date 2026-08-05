#!/usr/bin/env bash
# =============================================================================
# scripts/release/evidence-checksum.sh <dir>
# -----------------------------------------------------------------------------
# ONE deterministic, PATH-INDEPENDENT checksum of an evidence directory.
#
# This exists as a shared script rather than as two copies — one inline in the
# workflow, one in the authorizer — because the two copies were not the same
# function, and could not be.
#
# The producer hashed `evidence/child`. The authorizer recomputed after the
# directory had been collected into `authorization/child-evidence/<slug>-evidence`.
# `shasum` prints the PATHNAME beside each digest, so byte-identical files under
# two different prefixes hash to two different aggregate values. Every child
# would have been refused for a mismatch that meant nothing, and the failure
# would only have appeared in the first real run, because the test computed and
# verified without ever moving the directory.
#
# So: cd into the directory and hash RELATIVE paths. The result depends on the
# file contents and their names within the tree, and not on where the tree sits.
#
# -print0 / sort -z / xargs -0 throughout, because an evidence filename may
# contain anything, and LC_ALL=C so the ordering does not depend on the locale
# of whichever machine recomputes it.
# =============================================================================
set -euo pipefail

evidence_checksum() { # <dir>
  local dir="${1:?usage: evidence-checksum.sh <dir>}"
  [ -d "$dir" ] || { printf 'REFUSE: not a directory: %s\n' "$dir" >&2; return 1; }
  (
    cd "$dir" || exit 1
    find . -type f -print0 \
      | LC_ALL=C sort -z \
      | xargs -0 shasum -a 256 \
      | shasum -a 256 \
      | awk '{print $1}'
  )
}

_ec_self_test() {
  local ok=0 nbad=0 tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  t() { if eval "$2"; then echo "ok   - $1"; ok=$((ok+1)); else echo "FAIL - $1"; nbad=$((nbad+1)); fi; }

  mkdir -p "$tmp/a/evidence/child/sub"
  printf 'alpha\n' > "$tmp/a/evidence/child/one.log"
  printf 'beta\n'  > "$tmp/a/evidence/child/sub/two.json"

  local before after
  before="$(evidence_checksum "$tmp/a/evidence/child")"
  t "produces a 64-hex digest" "printf '%s' '$before' | grep -Eq '^[0-9a-f]{64}$'"

  # THE case the previous implementation got wrong: same bytes, new location.
  mkdir -p "$tmp/b/authorization/child-evidence"
  cp -r "$tmp/a/evidence/child" "$tmp/b/authorization/child-evidence/nginx-prod-evidence"
  after="$(evidence_checksum "$tmp/b/authorization/child-evidence/nginx-prod-evidence")"
  t "survives relocation to the collection directory" "[ '$before' = '$after' ]"

  # ...and still detects a change.
  printf 'x' >> "$tmp/b/authorization/child-evidence/nginx-prod-evidence/one.log"
  t "one altered byte changes the checksum" \
    "[ \"\$(evidence_checksum '$tmp/b/authorization/child-evidence/nginx-prod-evidence')\" != '$before' ]"

  # a new file changes it too
  cp -r "$tmp/a/evidence/child" "$tmp/c"
  printf 'extra\n' > "$tmp/c/three.txt"
  t "an added file changes the checksum" "[ \"\$(evidence_checksum '$tmp/c')\" != '$before' ]"

  # a removed file changes it
  cp -r "$tmp/a/evidence/child" "$tmp/d"; rm "$tmp/d/one.log"
  t "a removed file changes the checksum" "[ \"\$(evidence_checksum '$tmp/d')\" != '$before' ]"

  # renaming within the tree is a real difference and must be visible
  cp -r "$tmp/a/evidence/child" "$tmp/e"; mv "$tmp/e/one.log" "$tmp/e/renamed.log"
  t "a rename inside the tree changes the checksum" "[ \"\$(evidence_checksum '$tmp/e')\" != '$before' ]"

  # deterministic across repeated runs
  t "is stable when nothing changed" \
    "[ \"\$(evidence_checksum '$tmp/a/evidence/child')\" = '$before' ]"

  # a missing directory refuses rather than emitting a hash of nothing
  t "a missing directory refuses" "! evidence_checksum '$tmp/does-not-exist' >/dev/null 2>&1"

  echo "self-test: $ok ok, $nbad failed"
  [ "$nbad" -eq 0 ]
}

# Sourced by the authorizer; executed by the workflow.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  case "${1:-}" in
    --self-test) _ec_self_test && echo "evidence-checksum.sh: SELF-TEST OK" ;;
    "") echo "usage: evidence-checksum.sh <dir> | --self-test" >&2; exit 2 ;;
    *) evidence_checksum "$1" ;;
  esac
fi
