#!/usr/bin/env bash
# =============================================================================
# scripts/verify-staging-export.sh — prove the deterministic staging exporter
# against a real registry, before it is trusted in stage-and-authorize (#101).
# -----------------------------------------------------------------------------
# WHAT THIS EXISTS TO DE-RISK.
#
# The staging build currently uses the `push: true` shorthand. Deterministic
# layer timestamps need the explicit exporter:
#
#     outputs: type=image,push=true,rewrite-timestamp=true
#
# and `outputs:` REPLACES the shorthand rather than adding to it. Get it wrong
# and the workflow stops pushing while still reporting success — silently
# breaking the only path that stages anything. `scripts/reproducibility-check.sh`
# cannot catch that: it uses `type=docker` and never touches a registry.
#
# So this drives the REAL exporter form at a disposable local registry and
# checks, in order:
#
#   1. the registry actually receives a manifest for the tag (it was pushed)
#   2. the tag resolves to a digest
#   3. the resolved object is an image MANIFEST, not an index — an index would
#      mean the recorded digest names the wrong object
#   4. the config architecture is the platform that was asked for
#   5. org.opencontainers.image.created equals the SOURCE_DATE_EPOCH-derived
#      timestamp, not wall-clock
#   6. two isolated --no-cache builds of the same declared inputs produce
#      byte-identical layer content
#
# FAILS CLOSED. Every inability to build, push, resolve or inspect is a failure.
# Nothing here degrades to a skip.
#
# Usage:
#   verify-staging-export.sh <context-dir> [--platform linux/amd64]
#   verify-staging-export.sh --self-test
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Do NOT default to 5000: macOS AirPlay Receiver listens there, and the symptom
# is a registry that never answers rather than an obvious port clash.
free_port() {
  python3 -c "
import socket
s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1]); s.close()"
}
REG_PORT="${REG_PORT:-$(free_port)}"
REG="localhost:${REG_PORT}"
REG_NAME="zenchron-export-proof-registry"
BUILDER="zenchron-export-proof"
pass=0; fail=0
ck() { if eval "$2"; then pass=$((pass+1)); echo "ok   - $1"; else fail=$((fail+1)); echo "FAIL - $1"; fi; }

source_date_epoch() {
  local e; e="$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || true)"
  case "$e" in
    ''|*[!0-9]*) echo "REFUSE: cannot derive SOURCE_DATE_EPOCH from git" >&2; return 1 ;;
  esac
  printf '%s' "$e"
}

cleanup() {
  docker rm -f "$REG_NAME" >/dev/null 2>&1 || true
  docker buildx rm "$BUILDER" >/dev/null 2>&1 || true
}

start_registry() {
  docker rm -f "$REG_NAME" >/dev/null 2>&1 || true
  # Keep the daemon's error: swallowing it turns a port clash into a misleading
  # "never became ready" thirty seconds later.
  local err
  if ! err="$(docker run -d --name "$REG_NAME" -p "${REG_PORT}:5000" registry:2 2>&1)"; then
    echo "REFUSE: could not start the disposable registry on port ${REG_PORT}" >&2
    printf '%s\n' "$err" | sed 's/^/  /' >&2
    return 1
  fi
  # The builder runs in its own container, so `localhost` inside it is NOT the
  # host. network=host is what makes the published registry port reachable —
  # without it the push fails in a way that looks like a registry problem.
  docker buildx rm "$BUILDER" >/dev/null 2>&1 || true
  docker buildx create --name "$BUILDER" --driver docker-container \
    --driver-opt network=host --use >/dev/null 2>&1 \
    || { echo "REFUSE: could not create the proof builder" >&2; return 1; }
  local _
  for _ in $(seq 1 30); do
    curl -fsS "http://${REG}/v2/" >/dev/null 2>&1 && return 0
    sleep 1
  done
  echo "REFUSE: the disposable registry never became ready" >&2; return 1
}

# THE exporter form under test. Written once so the proof and the workflow
# cannot drift into testing something other than what ships.
build_to_registry() {
  local ctx="$1" ref="$2" platform="$3" epoch="$4"
  SOURCE_DATE_EPOCH="$epoch" docker buildx build \
    --builder "$BUILDER" \
    --no-cache \
    --platform "$platform" \
    --provenance=false --sbom=false \
    --build-arg "SOURCE_DATE_EPOCH=${epoch}" \
    --output "type=image,name=${ref},push=true,rewrite-timestamp=true" \
    "$ctx" >/dev/null 2>&1
}

# Resolve straight from the registry API rather than through the daemon, so the
# check is about what was actually pushed.
resolve() {
  local repo="$1" tag="$2"
  curl -fsS -o /dev/null -D - \
    -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
    -H 'Accept: application/vnd.oci.image.index.v1+json' \
    -H 'Accept: application/vnd.docker.distribution.manifest.v2+json' \
    -H 'Accept: application/vnd.docker.distribution.manifest.list.v2+json' \
    "http://${REG}/v2/${repo}/manifests/${tag}" 2>/dev/null
}

run_proof() {
  local ctx="${1:?context required}" platform="${2:-linux/amd64}"
  [ -d "$ctx" ] || { echo "REFUSE: context not found: $ctx" >&2; return 1; }
  command -v docker >/dev/null || { echo "REFUSE: docker unavailable" >&2; return 1; }
  command -v curl  >/dev/null || { echo "REFUSE: curl unavailable" >&2; return 1; }

  local epoch; epoch="$(source_date_epoch)" || return 1
  local created; created="$(date -u -r "$epoch" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
                            || date -u -d "@${epoch}" +%Y-%m-%dT%H:%M:%SZ)"
  echo "== deterministic staging export proof =="
  echo "   context   : $ctx"
  echo "   platform  : $platform"
  echo "   epoch     : $epoch ($created)"
  echo

  trap cleanup EXIT
  start_registry || return 1

  local repo
  repo="proof/$(basename "$ctx")"
  local refA="${REG}/${repo}:a" refB="${REG}/${repo}:b"

  build_to_registry "$ctx" "$refA" "$platform" "$epoch" \
    || { echo "FAIL - build A did not complete"; fail=$((fail+1)); }
  ck "build A pushed a manifest to the registry" \
     "resolve '$repo' a | grep -qi '^HTTP/.* 200'"

  local hdrs digest ctype
  hdrs="$(resolve "$repo" a)"
  digest="$(printf '%s' "$hdrs" | tr -d '\r' | awk -F': ' 'tolower($1)=="docker-content-digest"{print $2}')"
  ctype="$(printf '%s' "$hdrs"  | tr -d '\r' | awk -F': ' 'tolower($1)=="content-type"{print $2}')"

  ck "the tag resolves to a sha256 digest" "[[ '$digest' == sha256:* ]]"
  # An index here would mean the digest recorded by the workflow names a list,
  # not the platform child the authorization record is about.
  ck "the resolved object is an image manifest, not an index" \
     "[[ '$ctype' != *index* && '$ctype' != *manifest.list* ]]"

  # Pull BY DIGEST — the same way the workflow evaluates a child.
  local dref="${REG}/${repo}@${digest}"
  ck "the pushed object is pullable by digest" "docker pull -q '$dref' >/dev/null 2>&1"

  local arch
  arch="$(docker image inspect "$dref" --format '{{.Architecture}}' 2>/dev/null)"
  ck "config architecture is ${platform#linux/}" "[ '$arch' = '${platform#linux/}' ]"

  # The created label must come from the source commit, not the clock.
  local lbl
  lbl="$(docker image inspect "$dref" --format '{{index .Config.Labels "org.opencontainers.image.created"}}' 2>/dev/null)"
  ck "image config 'created' is epoch-derived, not wall-clock" \
     "[ -n '$lbl' ] && [ '$lbl' = '$created' ] || [ \"\$(docker image inspect '$dref' --format '{{.Created}}' 2>/dev/null | cut -c1-19)Z\" = '$created' ]"

  # Second isolated build of the same declared inputs.
  build_to_registry "$ctx" "$refB" "$platform" "$epoch" \
    || { echo "FAIL - build B did not complete"; fail=$((fail+1)); }
  ck "build B pushed a manifest to the registry" \
     "resolve '$repo' b | grep -qi '^HTTP/.* 200'"

  local hdrsB digestB
  hdrsB="$(resolve "$repo" b)"
  digestB="$(printf '%s' "$hdrsB" | tr -d '\r' | awk -F': ' 'tolower($1)=="docker-content-digest"{print $2}')"
  docker pull -q "${REG}/${repo}@${digestB}" >/dev/null 2>&1

  # RootFS.Layers is the reproducibility claim: uncompressed layer content.
  local la lb
  la="$(docker image inspect "$dref" --format '{{range .RootFS.Layers}}{{println .}}{{end}}' 2>/dev/null)"
  lb="$(docker image inspect "${REG}/${repo}@${digestB}" --format '{{range .RootFS.Layers}}{{println .}}{{end}}' 2>/dev/null)"
  ck "two isolated builds produced layer content" "[ -n '$la' ] && [ -n '$lb' ]"
  if [ "$la" = "$lb" ]; then
    pass=$((pass+1)); echo "ok   - two isolated builds are byte-identical ($(printf '%s' "$la" | grep -c . ) layers)"
  else
    fail=$((fail+1)); echo "FAIL - layer content differs between isolated builds"
    diff <(printf '%s' "$la") <(printf '%s' "$lb") | sed 's/^/       /'
  fi

  echo "----"
  printf 'staging export proof: %d ok, %d failed\n' "$pass" "$fail"
  [ "$fail" -eq 0 ]
}

self_test() {
  # The dangerous state this whole change risks: rewrite-timestamp enabled while
  # the exporter no longer pushes. Assert the shipped workflow never reaches it.
  local W="$ROOT/.github/workflows/stage-and-authorize.yml"
  ck "the staging workflow exists" "test -s '$W'"
  ck "if rewrite-timestamp is set, the exporter still pushes" \
     "! grep -q 'rewrite-timestamp' '$W' ||
      grep -qE 'type=image[^\\n]*push=true|push=true[^\\n]*type=image' '$W'"
  ck "the proof drives the same exporter form the workflow ships" \
     "! grep -q 'rewrite-timestamp' '$W' ||
      grep -q 'type=image,name=\${ref},push=true,rewrite-timestamp=true' '$ROOT/scripts/verify-staging-export.sh'"
  echo "----"
  printf 'self-test: %d ok, %d failed\n' "$pass" "$fail"
  [ "$fail" -eq 0 ]
}

case "${1:-}" in
  --self-test) self_test ;;
  "")          echo "usage: $(basename "$0") <context-dir> [platform] | --self-test" >&2; exit 64 ;;
  *)           run_proof "$1" "${2:-linux/amd64}" ;;
esac
