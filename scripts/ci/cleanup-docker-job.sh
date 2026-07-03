#!/usr/bin/env bash
# =============================================================================
# scripts/ci/cleanup-docker-job.sh
# -----------------------------------------------------------------------------
# Targeted, job-scoped Docker cleanup for the shared self-hosted runner. Removes
# ONLY what this job created — never a global `docker builder prune -af` / system
# prune that would corrupt a concurrent job's build state.
#
# A job builds under a UNIQUE builder name derived from workflow + run id +
# attempt + matrix key, so cleanup can target exactly it.
#
#   job_builder_name          -> echoes the unique builder name for this job
#   cleanup_docker_job        -> remove this job's builder + temp tags/containers,
#                                verify registry logout, wipe temp cosign/creds
#
# Env: GITHUB_WORKFLOW, GITHUB_RUN_ID, GITHUB_RUN_ATTEMPT, MATRIX_KEY (optional),
#      REGISTRY (default ghcr.io). DOCKER_FN injectable for tests.
# =============================================================================
set -uo pipefail

_slug() { printf '%s' "$1" | tr '[:upper:] /:@.' '[:lower:]______' | tr -cd 'a-z0-9_-'; }

job_builder_name() {
  local wf="${GITHUB_WORKFLOW:-wf}" run="${GITHUB_RUN_ID:-0}" att="${GITHUB_RUN_ATTEMPT:-1}" mk="${MATRIX_KEY:-}"
  printf 'zf-%s-%s-%s%s' "$(_slug "$wf")" "$run" "$att" "${mk:+-$(_slug "$mk")}"
}

_docker() { "${DOCKER_FN:-docker}" "$@"; }

cleanup_docker_job() {
  local name; name="$(job_builder_name)"
  local reg="${REGISTRY:-ghcr.io}"
  echo "cleanup: job builder = $name"
  # Remove ONLY this job's builder (ignore 'not found' — nothing to clean).
  _docker buildx rm "$name" >/dev/null 2>&1 || true
  # Remove containers/images tagged with this job's namespace only.
  local ids; ids="$(_docker ps -aq --filter "label=zf.job=$name" 2>/dev/null || true)"
  [ -n "$ids" ] && _docker rm -f $ids >/dev/null 2>&1 || true
  # Verify we are not left logged in to the registry (leak prevention).
  _docker logout "$reg" >/dev/null 2>&1 || true
  # Wipe any temp cosign material / generated credentials this job may have left.
  rm -f "${COSIGN_TMP:-/nonexistent}" cosign.key cosign.pub sbom.spdx.json 2>/dev/null || true
  echo "cleanup: done (builder + job containers + logout + temp material)"
}

# --- self-test (mock docker captures the commands) ---------------------------
_cdj_self_test() {
  local fail=0
  _t() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }
  # name generation is unique + deterministic per (workflow,run,attempt,matrix)
  local n1 n2 n3
  n1="$(GITHUB_WORKFLOW='Publish RC' GITHUB_RUN_ID=42 GITHUB_RUN_ATTEMPT=1 MATRIX_KEY='php-cli/8.4' job_builder_name)"
  n2="$(GITHUB_WORKFLOW='Publish RC' GITHUB_RUN_ID=42 GITHUB_RUN_ATTEMPT=1 MATRIX_KEY='php-fpm/8.4' job_builder_name)"
  n3="$(GITHUB_WORKFLOW='Publish RC' GITHUB_RUN_ID=42 GITHUB_RUN_ATTEMPT=2 MATRIX_KEY='php-cli/8.4' job_builder_name)"
  : "$n1" "$n2" "$n3"   # (consumed inside the single-quoted eval assertions below)
  _t "name is slugified/safe"        'printf "%s" "$n1" | grep -Eq "^zf-[a-z0-9_-]+$"'
  _t "different matrix -> different"  '[ "$n1" != "$n2" ]'
  _t "different attempt -> different" '[ "$n1" != "$n3" ]'
  _t "deterministic"                  '[ "$n1" = "$(GITHUB_WORKFLOW="Publish RC" GITHUB_RUN_ID=42 GITHUB_RUN_ATTEMPT=1 MATRIX_KEY="php-cli/8.4" job_builder_name)" ]'
  # cleanup targets ONLY this job's builder (mock docker records args)
  local log; log="$(mktemp)"
  _mock() { printf '%s\n' "$*" >> "$log"; }
  DOCKER_FN=_mock GITHUB_WORKFLOW=ci GITHUB_RUN_ID=7 GITHUB_RUN_ATTEMPT=1 MATRIX_KEY=nginx cleanup_docker_job >/dev/null
  _t "removes this job's builder"     'grep -q "buildx rm zf-ci-7-1-nginx" "'"$log"'"'
  _t "logs out of the registry"       'grep -q "logout ghcr.io" "'"$log"'"'
  _t "no global builder prune"        '! grep -qE "builder prune|system prune" "'"$log"'"'
  rm -f "$log"
  return $fail
}

if [ "${1:-}" = "--self-test" ]; then _cdj_self_test && echo "cleanup-docker-job.sh: SELF-TEST OK"
elif [ "${1:-}" = "name" ]; then job_builder_name
else cleanup_docker_job; fi
