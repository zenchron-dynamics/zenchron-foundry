#!/usr/bin/env bash
# =============================================================================
# scripts/assert-examples-pinned.sh — reference code must obey the platform's
# own supply-chain rules (#108, #109).
#
# The defect this closes: examples/ and docs/consuming-images.md told readers to
# digest-pin their bases and to fail closed, while themselves using moving tags
# (`php-cli:8.3-prod`, `composer:2`), suppressing a failed build step with
# `|| true`, and baking `php artisan config:cache` into an image layer. Copied
# reference code is how a platform's practices actually reach consumers, so a
# bad example is a distributed defect, not a documentation nit.
#
# check-structure.sh enforces digest pins for images/*/Dockerfile only. This is
# the same rule for the code we hand to consumers.
#
# Usage:
#   assert-examples-pinned.sh [--self-test]
#
# Exit 0 = clean, 1 = at least one violation. Finding no files to check is a
# FAILURE: a rename that empties the search must not read as a pass.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Build steps whose failure must not be suppressed. `|| true` on a cache warm-up
# or an environment dump ships a broken image and turns a build error into a
# runtime mystery.
FAILOPEN_RE='\|\|[[:space:]]*(true|:)([[:space:]]|$)'

# Commands that resolve the BUILD environment into a shipped layer. Laravel's
# config:cache evaluates env() while writing bootstrap/cache/config.php;
# `composer dump-env prod` writes .env.local.php. Both freeze whatever secrets
# were present at build time into the image, the SBOM and the provenance.
SECRET_BAKE_RE='(artisan[[:space:]]+config:cache|composer[[:space:]]+dump-env)'

# grep exits 0 on match, 1 on no-match, >=2 on ERROR. `... || true` collapses all
# three into success, which is how a mis-typed pattern reports a clean gate — the
# exact fail-open class this script exists to catch. Keep them distinct.
g() { # g <grep-args...> -> 0 on match, 1 on no match; dies on a real error
  local out st
  out="$(grep "$@" 2>&1)"; st=$?
  if [ "$st" -ge 2 ]; then
    echo "REFUSE: grep failed (rc=$st): $out" >&2
    exit 1
  fi
  [ -n "$out" ] && printf '%s\n' "$out"
  return "$st"
}

scan() { # scan <dir-or-file>... -> prints violations, returns 1 if any
  local rc=0 n=0 f line
  for f in "$@"; do
    [ -f "$f" ] || continue
    n=$((n + 1))

    # 1) every external image reference must carry a digest.
    #    `--from=<stage>` names a local build stage and has no digest by design;
    #    an external reference always contains a '/' or a ':' tag.
    while IFS= read -r line; do
      case "$line" in
        *'@sha256:'*) : ;;
        *) echo "UNPINNED: $f: $line"; rc=1 ;;
      esac
    done < <(g -hE -- '^[[:space:]]*(FROM[[:space:]]+|COPY[[:space:]]+--from=)[a-zA-Z0-9]' "$f" \
             | { grep -vE -- '(FROM|--from=)\$\{' || true; } \
             | { grep -vE -- '--from=(vendor|composer|build|builder)([[:space:]]|$)' || true; })

    # ARG *_BASE= lines are the indirection the FROMs use — pin them too.
    while IFS= read -r line; do
      case "$line" in
        *'@sha256:'*) : ;;
        *) echo "UNPINNED ARG: $f: $line"; rc=1 ;;
      esac
    done < <(g -hE -- '^ARG[[:space:]]+[A-Z0-9_]*BASE=' "$f")

    # 2) no fail-open build steps.
    while IFS= read -r line; do
      echo "FAIL-OPEN: $f: $line"; rc=1
    done < <(g -hnE -- "^[[:space:]]*(RUN|&&|\|).*${FAILOPEN_RE}" "$f")

    # 3) no build-time command that bakes the environment into a layer.
    while IFS= read -r line; do
      echo "SECRET-BAKE: $f: $line"; rc=1
    done < <(g -hnE -- "${SECRET_BAKE_RE}" "$f" \
             | { grep -vE -- '^[[:space:]]*[0-9]+:[[:space:]]*#' || true; })
  done

  if [ "$n" -eq 0 ]; then
    echo "REFUSE: no files matched — nothing was checked" >&2
    return 1
  fi
  return "$rc"
}

self_test() {
  local tmp ok=0 bad=0
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  t() { if eval "$2"; then ok=$((ok+1)); echo "  ok   $1"; else bad=$((bad+1)); echo "  FAIL $1"; fi; }

  printf 'FROM alpine:3@sha256:%064d AS a\nRUN echo hi\n' 0 > "$tmp/good"
  printf 'FROM alpine:3 AS a\n'                                > "$tmp/tag"
  printf 'FROM alpine@sha256:%064d\nRUN foo || true\n' 0       > "$tmp/failopen"
  printf 'FROM alpine@sha256:%064d\nRUN php artisan config:cache\n' 0 > "$tmp/bake"
  printf 'FROM alpine@sha256:%064d\nRUN composer dump-env prod\n' 0   > "$tmp/dumpenv"
  printf 'FROM alpine@sha256:%064d\n# php artisan config:cache is deliberately absent\n' 0 > "$tmp/comment"
  printf 'ARG X_BASE="alpine:3"\nFROM ${X_BASE}\n'             > "$tmp/argtag"
  printf 'ARG X_BASE="alpine:3@sha256:%064d"\nFROM ${X_BASE}\nCOPY --from=vendor /a /a\n' 0 > "$tmp/argpin"

  t "a digest-pinned Dockerfile passes"          "scan '$tmp/good' >/dev/null"
  t "a tag-only FROM is rejected"                "! scan '$tmp/tag' >/dev/null"
  t "a fail-open build step is rejected"         "! scan '$tmp/failopen' >/dev/null"
  t "artisan config:cache is rejected"           "! scan '$tmp/bake' >/dev/null"
  t "composer dump-env is rejected"              "! scan '$tmp/dumpenv' >/dev/null"
  t "...but naming it in a COMMENT is allowed"   "scan '$tmp/comment' >/dev/null"
  t "an unpinned ARG *_BASE is rejected"         "! scan '$tmp/argtag' >/dev/null"
  t "a pinned ARG with a stage COPY passes"      "scan '$tmp/argpin' >/dev/null"
  t "no files at all fails closed"               "! scan '$tmp/nothing-here' >/dev/null 2>&1"
  # The message must name the file, or a failing gate is unactionable.
  t "the violation names the offending file" \
    "{ scan '$tmp/tag' 2>&1 || true; } | grep -q 'UNPINNED: $tmp/tag'"

  echo "self-test: $ok ok, $bad failed"
  [ "$bad" -eq 0 ]
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit $?
fi

cd "$ROOT"
targets=()
while IFS= read -r f; do targets+=("$f"); done < <(find examples -name Dockerfile -type f | sort)
targets+=(docs/consuming-images.md)

if scan "${targets[@]}"; then
  echo "==> assert-examples-pinned: clean (${#targets[@]} file(s) checked)."
  exit 0
fi
echo "==> assert-examples-pinned: FAILED. Pin by @sha256:, drop '|| true', and cache configuration at deploy time." >&2
exit 1
