#!/usr/bin/env bash
# =============================================================================
# scripts/reproducibility-check.sh — build the same source twice, compare (#101).
#
# WHAT IS COMPARED, AND WHY THAT AND NOT THE IMAGE DIGEST.
#
#   RootFS.Layers   the UNCOMPRESSED content digest of every layer. If these
#                   match, the filesystem content is bit-identical. This is the
#                   reproducibility claim.
#   Config          env, labels, entrypoint, cmd, user, exposed ports, working
#                   dir — everything a consumer can observe about the image.
#   packages        dpkg/apk inventory, compared only to ATTRIBUTE a difference
#                   when the layers differ. It is diagnosis, not the claim.
#
# The published image DIGEST is deliberately NOT the claim. BuildKit embeds
# build-time metadata in its attestation manifest, so a local `docker build`
# without `provenance:false` produces an index whose digest differs run to run
# for reasons that are not the source. That exclusion is declared in
# policies/supply-chain-inputs.yaml under `known_nondeterminism` — stated up
# front, not discovered after a failure and used to move the goalposts.
#
# Usage:
#   reproducibility-check.sh <context-dir> <label> [--build-arg K=V ...]
#   reproducibility-check.sh --self-test
#
# Exit 0 only if content AND config match. Any failure to build or inspect is a
# failure, never a skip.
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The commit timestamp, so both builds get the same SOURCE_DATE_EPOCH — the
# whole point of #101's timestamp fix. Falls back only when git is unavailable,
# and says so rather than silently using wall-clock.
source_date_epoch() {
  local e
  e="$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || true)"
  case "$e" in
    ''|*[!0-9]*) echo "REFUSE: cannot derive SOURCE_DATE_EPOCH from git" >&2; return 1 ;;
  esac
  printf '%s' "$e"
}

compare() { # compare <ctx> <label> [extra build args...]
  local ctx="$1" label="$2"; shift 2
  local epoch tagA tagB rc=0
  epoch="$(source_date_epoch)" || return 1
  tagA="zenchron-repro/${label}:a"
  tagB="zenchron-repro/${label}:b"

  printf '\n== reproducibility: %s (SOURCE_DATE_EPOCH=%s)\n' "$label" "$epoch"

  # A dedicated buildx builder, and BOTH builds --no-cache. A cached first build
  # would compare an image against its own cache and always "reproduce".
  docker buildx inspect zenchron-repro >/dev/null 2>&1 || \
    docker buildx create --name zenchron-repro --driver docker-container >/dev/null 2>&1 || true

  local a
  for a in a b; do
    local tag="zenchron-repro/${label}:${a}"
    # rewrite-timestamp=true is the whole reason this passes. Without it,
    # directories created by `RUN mkdir` carry the WALL CLOCK mtime of the build,
    # so two builds of the same source differ by a handful of header bytes —
    # measured at 31 differing bytes in a 63 MB caddy rootfs, invisible to
    # `tar -tv` because they were 19 seconds apart inside the same minute.
    # BuildKit rewrites them to SOURCE_DATE_EPOCH when asked; it does not by
    # default.
    if ! docker buildx build --builder zenchron-repro --no-cache \
           --platform linux/amd64 \
           --build-arg "SOURCE_DATE_EPOCH=$epoch" \
           --build-arg "BUILD_DATE=$(date -u -r "$epoch" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "@$epoch" +%Y-%m-%dT%H:%M:%SZ)" \
           --build-arg "VCS_REF=$(git -C "$ROOT" rev-parse HEAD)" \
           --output "type=docker,name=${tag},rewrite-timestamp=true" \
           "$@" "$ctx" >/dev/null 2>"/tmp/repro-$label-$a.err"; then
      echo "FAIL  build $a did not complete"; tail -5 "/tmp/repro-$label-$a.err" | sed 's/^/        /'
      return 1
    fi
    echo "ok    build $a complete (--no-cache, rewrite-timestamp)"
  done

  # --- content -------------------------------------------------------------
  local la lb
  la="$(docker image inspect "$tagA" --format '{{range .RootFS.Layers}}{{println .}}{{end}}' 2>/dev/null)"
  lb="$(docker image inspect "$tagB" --format '{{range .RootFS.Layers}}{{println .}}{{end}}' 2>/dev/null)"
  if [ -z "$la" ] || [ -z "$lb" ]; then
    echo "FAIL  could not read RootFS layers — treating as NOT reproducible"; return 1
  fi
  if [ "$la" = "$lb" ]; then
    echo "PASS  filesystem content identical ($(printf '%s' "$la" | grep -c .) layers)"
  else
    echo "FAIL  filesystem content DIFFERS"
    diff <(printf '%s' "$la") <(printf '%s' "$lb") | sed 's/^/        /' | head -10
    rc=1
    # Attribute it: which packages differ? Diagnosis only — the verdict is above.
    local pa pb
    pa="$(docker run --rm --entrypoint sh "$tagA" -c 'dpkg-query -W -f="${Package}=${Version}\n" 2>/dev/null || apk info -v 2>/dev/null' 2>/dev/null | sort)"
    pb="$(docker run --rm --entrypoint sh "$tagB" -c 'dpkg-query -W -f="${Package}=${Version}\n" 2>/dev/null || apk info -v 2>/dev/null' 2>/dev/null | sort)"
    if [ "$pa" != "$pb" ]; then
      echo "        attributed to package differences:"
      diff <(printf '%s\n' "$pa") <(printf '%s\n' "$pb") | grep -E '^[<>]' | head -10 | sed 's/^/          /'
    else
      echo "        package sets are IDENTICAL — the difference is elsewhere"
    fi
  fi

  # --- filesystem export, the claim in its most direct form ----------------
  # Layer digests answer "is the packaging identical". This answers "is the
  # FILESYSTEM identical", which is what a consumer actually depends on, and it
  # localises a failure to a path instead of to an opaque digest.
  local ea eb da db
  ea="$(mktemp)"; eb="$(mktemp)"; da="$(mktemp -d)"; db="$(mktemp -d)"
  local ca_id cb_id
  ca_id="$(docker create "$tagA" 2>/dev/null)"; cb_id="$(docker create "$tagB" 2>/dev/null)"
  docker export "$ca_id" 2>/dev/null | tar -x -C "$da" 2>/dev/null
  docker export "$cb_id" 2>/dev/null | tar -x -C "$db" 2>/dev/null
  docker rm "$ca_id" "$cb_id" >/dev/null 2>&1 || true
  # sha256 of every regular file. A metadata-only comparison (`tar -tv`) reported
  # nginx as identical while 8 files differed byte-for-byte with the SAME size
  # and mtime — apt/dpkg logs and ldconfig's aux-cache. A check that cannot see
  # the difference it exists to find is not a check.
  ( cd "$da" && find . -type f -exec shasum -a 256 {} \; 2>/dev/null | sort -k2 ) > "$ea"
  ( cd "$db" && find . -type f -exec shasum -a 256 {} \; 2>/dev/null | sort -k2 ) > "$eb"
  rm -rf "$da" "$db"
  if [ ! -s "$ea" ] || [ ! -s "$eb" ]; then
    echo "FAIL  could not export a filesystem — treating as NOT reproducible"; rc=1
  elif cmp -s "$ea" "$eb"; then
    echo "PASS  every file byte-identical ($(wc -l < "$ea" | tr -d ' ') files hashed)"
  else
    echo "FAIL  file CONTENT differs ($(diff "$ea" "$eb" | grep -c '^[<>]') of $(wc -l < "$ea" | tr -d ' ') files)"
    diff "$ea" "$eb" | grep '^[<>]' | head -8 | sed 's/^/        /'
    rc=1
  fi
  rm -f "$ea" "$eb"

  # --- config --------------------------------------------------------------
  # Everything a consumer can observe. Compared whole; no field is excluded
  # here, because the excluded nondeterminism lives in the attestation manifest,
  # not in the config.
  local ca cb
  ca="$(docker image inspect "$tagA" --format '{{json .Config}}' | python3 -m json.tool --sort-keys 2>/dev/null)"
  cb="$(docker image inspect "$tagB" --format '{{json .Config}}' | python3 -m json.tool --sort-keys 2>/dev/null)"
  if [ "$ca" = "$cb" ]; then
    echo "PASS  image configuration identical (env, labels, entrypoint, user, ports)"
  else
    echo "FAIL  image configuration DIFFERS"
    diff <(printf '%s\n' "$ca") <(printf '%s\n' "$cb") | head -14 | sed 's/^/        /'
    rc=1
  fi

  docker rmi -f "$tagA" "$tagB" >/dev/null 2>&1 || true
  return "$rc"
}

self_test() {
  local ok=0 bad=0
  t() { if eval "$2"; then ok=$((ok+1)); echo "  ok   $1"; else bad=$((bad+1)); echo "  FAIL $1"; fi; }
  t "SOURCE_DATE_EPOCH resolves from the git history" \
    "[ -n \"\$(source_date_epoch)\" ]"
  t "...and is a plain integer" \
    "case \"\$(source_date_epoch)\" in ''|*[!0-9]*) false ;; *) true ;; esac"
  t "...and is stable across calls (it is a property of the commit)" \
    "[ \"\$(source_date_epoch)\" = \"\$(source_date_epoch)\" ]"
  # The claim's boundary must be declared in the inventory, not invented here.
  t "the excluded nondeterminism is declared in the inventory" \
    "python3 -c \"
import yaml
d=yaml.safe_load(open('$ROOT/policies/supply-chain-inputs.yaml'))
kn=d['build_determinism']['known_nondeterminism']
assert kn and all(k.get('excluded_from_claim') is not None for k in kn), kn\""
  t "the inventory declares SOURCE_DATE_EPOCH comes from the source commit" \
    "python3 -c \"
import yaml
d=yaml.safe_load(open('$ROOT/policies/supply-chain-inputs.yaml'))
assert d['build_determinism']['source_date_epoch']['derived_from']=='source-commit'\""
  echo "self-test: $ok ok, $bad failed"
  [ "$bad" -eq 0 ]
}

case "${1:-}" in
  --self-test) self_test ;;
  "") echo "usage: $(basename "$0") <context-dir> <label> [--build-arg K=V ...]" >&2; exit 64 ;;
  *) compare "$@" ;;
esac
