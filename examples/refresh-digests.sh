#!/usr/bin/env bash
# =============================================================================
# examples/refresh-digests.sh — re-resolve every pinned digest in the examples.
#
# #109 asked for an "automated digest-refresh mechanism". A digest pin that
# nobody can update turns into an unpatchable pin, and the usual response to that
# is to delete the pin — which is how examples drift back to moving tags.
#
# Usage:
#   ./refresh-digests.sh            rewrite the ARG lines in place
#   ./refresh-digests.sh --check    report drift, change nothing (CI-friendly)
#
# Resolves through `docker buildx imagetools inspect`, so it reads what the
# registry serves right now rather than whatever happens to be in the local
# daemon cache. Every failure is fatal: an unresolvable reference must never
# silently leave the old digest in place looking freshly verified.
# =============================================================================
set -euo pipefail

cd "$(dirname "$0")"

MODE="${1:-write}"
case "$MODE" in
  write|--check) ;;
  *) echo "usage: $(basename "$0") [--check]" >&2; exit 64 ;;
esac

command -v docker >/dev/null 2>&1 || { echo "REFUSE: docker is required to resolve digests" >&2; exit 1; }

rc=0
changed=0
found=0

for df in */Dockerfile; do
  # ARG NAME="ref:tag@sha256:..." — the tag is what we re-resolve.
  while IFS= read -r line; do
    name="${line%%=*}"; name="${name##ARG }"
    val="${line#*=}"; val="${val%\"}"; val="${val#\"}"
    ref="${val%@*}"                      # registry/path:tag
    old="${val##*@}"                     # sha256:...
    case "$old" in sha256:*) ;; *) echo "REFUSE: $df ARG $name is not digest-pinned: $val" >&2; rc=1; continue ;; esac
    found=$((found + 1))

    new="$(docker buildx imagetools inspect "$ref" --format '{{.Manifest.Digest}}' 2>/dev/null | tr -d '[:space:]')" || true
    case "$new" in
      sha256:*) ;;
      *) echo "REFUSE: cannot resolve $ref (no digest returned)" >&2; rc=1; continue ;;
    esac

    if [ "$new" = "$old" ]; then
      printf '  ok      %-14s %s\n' "$name" "$ref"
      continue
    fi
    changed=$((changed + 1))
    if [ "$MODE" = "--check" ]; then
      printf '  DRIFT   %-14s %s\n            %s -> %s\n' "$name" "$ref" "$old" "$new"
      rc=1
    else
      printf '  updated %-14s %s\n            %s -> %s\n' "$name" "$ref" "$old" "$new"
      tmp="$(mktemp)"
      # Replace only this ARG's digest, anchored on the ARG name, so two ARGs
      # pointing at the same tag cannot overwrite each other's line.
      OLD="$old" NEW="$new" NAME="$name" python3 -c '
import os, sys
path = sys.argv[1]
name, old, new = os.environ["NAME"], os.environ["OLD"], os.environ["NEW"]
out = []
for l in open(path):
    if l.startswith("ARG %s=" % name):
        l = l.replace(old, new)
    out.append(l)
open(path, "w").writelines(out)' "$df"
      rm -f "$tmp"
    fi
  done < <(grep -E '^ARG [A-Z0-9_]+="[^"]+@sha256:' "$df" || true)
done

# Zero pins found means the loop matched nothing — a refactor that renamed the
# ARGs would otherwise report a clean run having checked nothing at all.
if [ "$found" -eq 0 ]; then
  echo "REFUSE: no digest-pinned ARG found in examples/*/Dockerfile — nothing was checked" >&2
  exit 1
fi

echo "checked $found pinned reference(s); $changed differ from the registry"
exit "$rc"
