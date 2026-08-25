#!/usr/bin/env bash
# =============================================================================
# scripts/release/native-smoke-candidates.sh
# -----------------------------------------------------------------------------
# Run the runtime smoke on a NATIVE arm64 host against EXISTING IMMUTABLE
# candidate digests, and emit one gating-shaped evidence record per image.
#
# WHY BY DIGEST AND NOT FROM SOURCE. The native smoke's original mode rebuilds
# every image on the runner. That proves the runtime works on arm64 hardware,
# but the thing it proves it about is a NEW image that no release will ever
# ship. Release authorization needs evidence about the exact bytes being
# authorized, so this mode pulls the candidate children BY DIGEST and smokes
# those. It is also much cheaper: nothing is built.
#
# WHAT IT REFUSES.
#   * a host that is not really the target architecture — measured twice, once
#     from `uname -m` (the caller's measurement, passed in) and once from the
#     PULLED IMAGE's own config architecture, which catches a manifest that
#     served the wrong child;
#   * a mutable reference — every candidate must be `@sha256:<64-hex>`;
#   * a digest that does not resolve, or resolves to something else;
#   * an image label that is not in the production matrix;
#   * a candidate set that does not cover the whole production matrix, unless
#     --allow-subset is given (which stamps every record `full_matrix:false`);
#   * any failing smoke — the record is still written, with runtime_smoke=FAIL,
#     because a failing native result is evidence and the gate refuses it.
#
# The records it writes are exactly the shape
# scripts/release/assert-native-arch-evidence.sh --gate-release requires.
#
# Usage:
#   native-smoke-candidates.sh <candidate-set.json> <out-dir> [--allow-subset]
#   native-smoke-candidates.sh --self-test
#
# The candidate set:
#   {"source_revision":"<40-hex>", "platform":"linux/arm64",
#    "images":{"php-fpm/8.4":"ghcr.io/owner/pkg@sha256:<64-hex>", ...}}
#
# Environment (all mandatory in a real run; the caller MEASURES them):
#   NSC_UNAME_M        the runner's `uname -m`
#   NSC_RUNNER_KIND    a runner kind policies/native-arch-requirements.yaml accepts
#   NSC_RUNNER_LABEL   the label the job was routed to (recorded, never trusted)
#   NSC_RUN_ID         the workflow run id
#   NSC_AUTHORITATIVE  true only for the default branch
# =============================================================================
set -uo pipefail
_NSC_D="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NSC_ROOT="${NSC_ROOT:-$(cd "$_NSC_D/../.." && pwd)}"

nsc_die() { echo "REFUSE: $*" >&2; exit 1; }

# uname -m as the kernel spells it -> the architecture name this tree uses.
nsc_arch_of_uname() {
  case "${1:-}" in
    aarch64|arm64) echo arm64 ;;
    x86_64|amd64)  echo amd64 ;;
    *) return 1 ;;
  esac
}

nsc_run() {
  local set_file="${1:?usage: native-smoke-candidates.sh <candidate-set.json> <out-dir>}"
  local out="${2:?usage: native-smoke-candidates.sh <candidate-set.json> <out-dir>}"
  local allow_subset="${3:-0}"

  command -v jq >/dev/null || nsc_die "jq is required"
  [ -f "$set_file" ] || nsc_die "candidate set not found: $set_file"

  local v
  for v in NSC_UNAME_M NSC_RUNNER_KIND NSC_RUNNER_LABEL NSC_RUN_ID NSC_AUTHORITATIVE; do
    [ -n "${!v:-}" ] || nsc_die "$v is required — native evidence that cannot say where it ran is not evidence"
  done

  local host_arch
  host_arch="$(nsc_arch_of_uname "$NSC_UNAME_M")" \
    || nsc_die "NSC_UNAME_M '$NSC_UNAME_M' is not a machine name this gate recognises"

  local platform rev want_arch
  platform="$(jq -r '.platform // ""' "$set_file")"
  rev="$(jq -r '.source_revision // ""' "$set_file")"
  case "$platform" in
    linux/*) want_arch="${platform#linux/}" ;;
    *) nsc_die "candidate set platform '$platform' must be linux/<arch>" ;;
  esac
  printf '%s' "$rev" | grep -Eq '^[0-9a-f]{40}$' \
    || nsc_die "candidate set source_revision '$rev' is not a 40-hex revision"

  # THE REFUSAL THAT MATTERS MOST. The job was ROUTED by a label; the label is a
  # request. If the measurement disagrees with the platform being evidenced,
  # nothing here is native and the run must stop before it produces a record.
  [ "$host_arch" = "$want_arch" ] || nsc_die \
    "this host measures as '$host_arch' (uname -m = $NSC_UNAME_M) but the candidate
  set is for '$platform'. The runner label '$NSC_RUNNER_LABEL' is a claim about
  where the job was requested; the measurement is the fact, and it says this job
  landed on the wrong architecture. Refusing rather than emulating."

  local labels; labels="$(jq -r '.images | keys[]' "$set_file")"
  [ -n "$labels" ] || nsc_die "the candidate set names no images — an empty candidate set proves nothing"

  # Every label must be a real production image, and (by default) the set must
  # cover the whole matrix. A subset that silently passed would be the same
  # "9 of 10 reads as green" failure the gate exists to refuse.
  # shellcheck source=../lib/common.sh
  . "$NSC_ROOT/scripts/lib/common.sh"
  local known; known="$(matrix_image_labels)"
  local l
  while IFS= read -r l; do
    [ -n "$l" ] || continue
    grep -qxF "$l" <<<"$known" || nsc_die "'$l' is not a production image label"
  done <<<"$labels"
  local n_want n_known
  n_want="$(printf '%s\n' "$labels" | grep -c .)"
  n_known="$(printf '%s\n' "$known" | grep -c .)"
  if [ "$n_want" -ne "$n_known" ] && [ "$allow_subset" -ne 1 ]; then
    nsc_die "the candidate set covers $n_want of $n_known production images. Pass
  --allow-subset to smoke a subset deliberately; a partial set is otherwise a
  refusal, because partial native coverage must never read as full coverage."
  fi

  mkdir -p "$out"
  local failures=0 done_n=0
  while IFS= read -r l; do
    [ -n "$l" ] || continue
    local ref fam ver smoke_ref verdict summary dig cfg_arch
    ref="$(jq -r --arg l "$l" '.images[$l]' "$set_file")"
    case "$ref" in
      *"@sha256:"*) : ;;
      *) nsc_die "candidate '$l' -> '$ref' is not an immutable by-digest reference" ;;
    esac
    dig="${ref#*@}"
    printf '%s' "$dig" | grep -Eq '^sha256:[0-9a-f]{64}$' \
      || nsc_die "candidate '$l' digest '$dig' is not sha256:<64-hex>"

    fam="${l%%/*}"; ver="${l#*/}"
    case "$ver" in prod) ver=""; smoke_ref="zenchron/${fam}:smoke" ;;
                   *)    smoke_ref="zenchron/${fam}:${ver}-smoke" ;; esac

    echo "==> pulling $l by digest: $ref"
    if ! docker pull --platform "$platform" "$ref" >/dev/null; then
      echo "!! could not pull $ref" >&2
      failures=$((failures+1)); verdict=FAIL; cfg_arch=""
    else
      # SECOND, INDEPENDENT MEASUREMENT. `docker pull --platform` asks; the
      # image's own config answers. A multi-arch index that served the wrong
      # child would otherwise be smoked as if it were the right one.
      cfg_arch="$(docker image inspect --format '{{.Architecture}}' "$ref" 2>/dev/null || echo "")"
      if [ "$cfg_arch" != "$want_arch" ]; then
        echo "!! $l resolved to a ${cfg_arch:-unknown} image, not $want_arch" >&2
        failures=$((failures+1)); verdict=FAIL
      else
        docker tag "$ref" "$smoke_ref"
        summary="$(bash "$NSC_ROOT/scripts/smoke-test.sh" "$fam" "$ver" 2>&1 \
                    | tee /dev/stderr | grep -E '^SMOKE SUMMARY: ' | tail -n1)"
        if [ -z "$summary" ]; then
          verdict=FAIL; failures=$((failures+1))
        else
          case "$summary" in
            *" 0 failed"*) verdict=PASS ;;
            *) verdict=FAIL; failures=$((failures+1)) ;;
          esac
        fi
        docker rmi -f "$smoke_ref" >/dev/null 2>&1 || true
      fi
      docker rmi -f "$ref" >/dev/null 2>&1 || true
    fi

    jq -n --arg l "$l" --arg ck "$l/$platform" --arg pl "$platform" \
          --arg ha "$host_arch" --arg um "$NSC_UNAME_M" \
          --arg rk "$NSC_RUNNER_KIND" --arg rl "$NSC_RUNNER_LABEL" \
          --arg rev "$rev" --arg dg "$dig" --arg ref "$ref" \
          --arg sm "$verdict" --arg ca "$cfg_arch" \
          --argjson run "$NSC_RUN_ID" \
          --argjson auth "$([ "$NSC_AUTHORITATIVE" = true ] && echo true || echo false)" \
          --argjson full "$([ "$n_want" -eq "$n_known" ] && echo true || echo false)" '{
      record_type:"native-arch-runtime-evidence",
      child_key:$ck, image_label:$l, platform:$pl,
      host_architecture:$ha, execution_mode:"native",
      architecture_source:"measured", uname_m:$um,
      image_config_architecture:$ca,
      runner_kind:$rk, runner_label:$rl,
      source_revision:$rev,
      manifest_digest:$dg, digest_reference:$ref,
      runtime_smoke:$sm,
      workflow_run_id:$run, authoritative:$auth, full_matrix:$full
    }' > "$out/$(printf '%s' "$l" | tr '/' '-').json"
    done_n=$((done_n+1))
  done <<<"$labels"

  echo "native smoke over immutable candidates: $done_n image(s), $failures failure(s)"
  [ "$failures" -eq 0 ]
}

_nsc_self_test() {
  local tmp ok=0 bad=0
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" EXIT
  t() { if eval "$2"; then echo "  ok   $1"; ok=$((ok+1)); else echo "  FAIL $1"; bad=$((bad+1)); fi; }

  export NSC_UNAME_M=aarch64 NSC_RUNNER_KIND=ephemeral-hosted \
         NSC_RUNNER_LABEL=ubuntu-24.04-arm NSC_RUN_ID=1 NSC_AUTHORITATIVE=true

  local D; D="sha256:$(printf 'a%.0s' $(seq 64))"
  # A full-matrix candidate set, generated from the real matrix.
  # shellcheck source=../lib/common.sh
  . "$NSC_ROOT/scripts/lib/common.sh"
  matrix_image_labels | jq -R . | jq -sc --arg d "ghcr.io/o/p@$D" \
    '{source_revision:"1111111111111111111111111111111111111111",
      platform:"linux/arm64",
      images:(map({key:., value:$d})|from_entries)}' > "$tmp/full.json"

  # Wrong architecture: the single most important refusal, and it must fire
  # BEFORE anything is pulled or smoked.
  ( NSC_UNAME_M=x86_64 nsc_run "$tmp/full.json" "$tmp/o1" ) > "$tmp/o1.out" 2>&1
  t "a job that landed on the wrong architecture REFUSES" \
    "! ( NSC_UNAME_M=x86_64 nsc_run '$tmp/full.json' '$tmp/o1' ) >/dev/null 2>&1"
  t "...saying the measurement is the fact and the label is a claim" \
    "grep -q 'the measurement is the fact' '$tmp/o1.out'"
  t "...and it names the architecture it actually landed on" \
    "grep -q \"measures as 'amd64'\" '$tmp/o1.out'"

  ( NSC_UNAME_M=riscv64 nsc_run "$tmp/full.json" "$tmp/o1b" ) > "$tmp/o1b.out" 2>&1
  t "an unrecognised machine name REFUSES rather than being mapped optimistically" \
    "grep -q 'is not a machine name this gate recognises' '$tmp/o1b.out'"

  # A mutable reference.
  jq '.images["nginx/prod"]="ghcr.io/o/p:latest"' "$tmp/full.json" > "$tmp/mut.json"
  ( nsc_run "$tmp/mut.json" "$tmp/o2" ) > "$tmp/o2.out" 2>&1
  t "a mutable candidate reference REFUSES" \
    "grep -q 'is not an immutable by-digest reference' '$tmp/o2.out'"

  # A subset.
  jq 'del(.images["nginx/prod"])' "$tmp/full.json" > "$tmp/sub.json"
  ( nsc_run "$tmp/sub.json" "$tmp/o3" ) > "$tmp/o3.out" 2>&1
  t "a partial candidate set REFUSES unless the subset is deliberate" \
    "grep -q 'partial native coverage must never read as full coverage' '$tmp/o3.out'"

  # An image outside the matrix.
  jq '.images["not-an-image/prod"]="ghcr.io/o/p@'"$D"'"' "$tmp/full.json" > "$tmp/alien.json"
  ( nsc_run "$tmp/alien.json" "$tmp/o4" ) > "$tmp/o4.out" 2>&1
  t "an image outside the production matrix REFUSES" \
    "grep -q \"is not a production image label\" '$tmp/o4.out'"

  # An empty set.
  jq '.images={}' "$tmp/full.json" > "$tmp/none.json"
  ( nsc_run "$tmp/none.json" "$tmp/o5" ) > "$tmp/o5.out" 2>&1
  t "an EMPTY candidate set REFUSES, never vacuously passes" \
    "grep -q 'an empty candidate set proves nothing' '$tmp/o5.out'"

  # A malformed revision.
  jq '.source_revision="HEAD"' "$tmp/full.json" > "$tmp/badrev.json"
  ( nsc_run "$tmp/badrev.json" "$tmp/o6" ) > "$tmp/o6.out" 2>&1
  t "a candidate set with no real source revision REFUSES" \
    "grep -q 'is not a 40-hex revision' '$tmp/o6.out'"

  # Missing measurement.
  ( unset NSC_UNAME_M; nsc_run "$tmp/full.json" "$tmp/o7" ) > "$tmp/o7.out" 2>&1
  t "evidence with no recorded measurement REFUSES" \
    "grep -q 'cannot say where it ran is not evidence' '$tmp/o7.out'"

  echo "self-test: $ok ok, $bad failed"
  [ "$bad" -eq 0 ]
}

case "${1:-}" in
  --self-test) _nsc_self_test && echo "native-smoke-candidates.sh: SELF-TEST OK" ;;
  "") echo "usage: native-smoke-candidates.sh <candidate-set.json> <out-dir> [--allow-subset] | --self-test" >&2; exit 2 ;;
  *)
    _set="$1"; _out="${2:?usage: native-smoke-candidates.sh <candidate-set.json> <out-dir>}"; shift 2
    _subset=0
    while [ $# -gt 0 ]; do
      case "$1" in
        --allow-subset) _subset=1; shift ;;
        *) nsc_die "unknown argument: $1" ;;
      esac
    done
    nsc_run "$_set" "$_out" "$_subset"
    ;;
esac
