#!/usr/bin/env bash
# =============================================================================
# scripts/lib/registry-ops.sh
# -----------------------------------------------------------------------------
# The two registry primitives promotion + rollback need, behind one seam so the
# whole transaction is testable offline:
#
#   reg_digest <ref>          -> echoes the digest <ref> currently points at,
#                                or empty if the alias does not exist
#   reg_retag  <dst-ref> <dg> -> points <dst-ref> at digest <dg> (registry-side
#                                copy; signatures ride the digest)
#   reg_untag  <ref>          -> removes an alias (used to undo a NONE->new alias)
#
# Backends (REG_BACKEND):
#   real  (default) docker buildx imagetools
#   mock            filesystem under REG_MOCK_DIR; a ref is a file holding its
#                   digest. REG_FAIL_AT=<n> makes the n-th reg_retag fail (to
#                   simulate a mid-transaction registry error). Enables full
#                   promotion/rollback failure-path tests with no network.
# =============================================================================
set -euo pipefail
_ro_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
[ -n "${_COMMON_SOURCED:-}" ] || . "$_ro_dir/common.sh"
_COMMON_SOURCED=1

REG_BACKEND="${REG_BACKEND:-real}"

_mock_path() { printf '%s/%s' "${REG_MOCK_DIR:?REG_MOCK_DIR required}" "$(printf '%s' "$1" | tr '/:@' '___')"; }

reg_digest() {
  case "$REG_BACKEND" in
    mock) local p; p="$(_mock_path "$1")"; [ -f "$p" ] && cat "$p" || return 1 ;;
    *)    docker buildx imagetools inspect "$1" --format '{{.Manifest.Digest}}' 2>/dev/null ;;
  esac
}

reg_retag() { # <dst-ref> <digest>
  case "$REG_BACKEND" in
    mock)
      REG_RETAG_COUNT=$(( ${REG_RETAG_COUNT:-0} + 1 ))
      if [ -n "${REG_FAIL_AT:-}" ] && [ "$REG_RETAG_COUNT" -eq "$REG_FAIL_AT" ]; then
        # RETURN (not exit): the caller's `set -e`/ERR trap must see the failure
        # and run its compensating rollback. exit here would bypass the trap.
        warn "mock registry: simulated retag failure at #$REG_RETAG_COUNT ($1)"
        return 1
      fi
      if [ -n "${REG_WRITE_WRONG_AT:-}" ] && [ "$REG_RETAG_COUNT" -eq "$REG_WRITE_WRONG_AT" ]; then
        # Mock-only seam: the registry ACKs the retag but stores the WRONG
        # manifest — a silent corruption Phase-3 verification must catch.
        warn "mock registry: simulated wrong-write at #$REG_RETAG_COUNT ($1)"
        printf 'sha256:%064d' 0 > "$(_mock_path "$1")"
        return 0
      fi
      printf '%s' "$2" > "$(_mock_path "$1")" ;;
    *)
      # SC-01: the real backend mutates production aliases (*-prod). That must
      # only ever happen inside CI (promote-stable.yml / an operator-invoked
      # workflow), never silently from a laptop. ALLOW_LOCAL_PROMOTE=1 is the
      # explicit, deliberate operator override (documented in docs/rollback.md).
      [ "${GITHUB_ACTIONS:-}" = "true" ] || [ "${ALLOW_LOCAL_PROMOTE:-}" = "1" ] \
        || die "production alias mutation outside CI (set ALLOW_LOCAL_PROMOTE=1 to override deliberately)"
      local base="${1%:*}"; docker buildx imagetools create -t "$1" "${base}@${2}" ;;
  esac
}

reg_untag() { # <ref>
  case "$REG_BACKEND" in
    mock) rm -f "$(_mock_path "$1")" ;;
    *)    warn "reg_untag: real backend cannot delete a GHCR tag from CI; leaving $1 (record in incident)" ;;
  esac
}

# --- self-test (mock backend) ------------------------------------------------
_ro_self_test() {
  local fail=0 d rc; d="$(mktemp -d)"
  export REG_BACKEND=mock REG_MOCK_DIR="$d"
  _t() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }
  local A=ghcr.io/x/php-cli:8.4-prod D1=sha256:1111111111111111111111111111111111111111111111111111111111111111
  _t "absent alias -> reg_digest fails" '! reg_digest "$A" >/dev/null 2>&1'
  reg_retag "$A" "$D1"
  _t "after retag -> digest matches"    'test "$(reg_digest "$A")" = "$D1"'
  reg_untag "$A"
  _t "after untag -> absent again"      '! reg_digest "$A" >/dev/null 2>&1'
  # REG_FAIL_AT triggers on the nth retag. Capture the subshell status into rc
  # IMMEDIATELY — asserting on a later `$?` relies on nothing running in
  # between, which the _t indirection cannot guarantee.
  ( REG_RETAG_COUNT=0 REG_FAIL_AT=2 bash -c '
      . '"$_ro_dir"'/registry-ops.sh
      export REG_BACKEND=mock REG_MOCK_DIR="'"$d"'"
      reg_retag ghcr.io/x/a:1 sha256:'"$(printf a | shasum -a256 | cut -c1-64)"'
      reg_retag ghcr.io/x/b:1 sha256:'"$(printf b | shasum -a256 | cut -c1-64)"'
    ' ) >/dev/null 2>&1; rc=$?
  _t "REG_FAIL_AT=2 fails second retag" '[ "$rc" -ne 0 ]'
  # REG_WRITE_WRONG_AT: retag ACKs but stores a wrong digest (silent corruption)
  ( REG_RETAG_COUNT=0 REG_WRITE_WRONG_AT=1 bash -c '
      . '"$_ro_dir"'/registry-ops.sh
      export REG_BACKEND=mock REG_MOCK_DIR="'"$d"'"
      reg_retag ghcr.io/x/c:1 sha256:'"$(printf c | shasum -a256 | cut -c1-64)"'
    ' ) >/dev/null 2>&1; rc=$?
  if [ "$rc" -eq 0 ]; then echo "ok   - REG_WRITE_WRONG_AT retag still ACKs (exit 0)"
  else echo "FAIL - REG_WRITE_WRONG_AT retag still ACKs (exit 0)"; fail=1; fi
  _t "REG_WRITE_WRONG_AT stored digest differs" \
     '[ "$(reg_digest ghcr.io/x/c:1)" != "sha256:$(printf c | shasum -a256 | cut -c1-64)" ]'
  # --- SC-01: real backend refuses to mutate *-prod outside CI ----------------
  # docker is STUBBED (records invocation, exits 0) so no real registry call can
  # happen either way; the refusal must fire BEFORE the backend is touched.
  local stub="$d/bin"
  mkdir -p "$stub"
  printf '#!/usr/bin/env bash\ntouch "${DOCKER_CALLED:?}"\nexit 0\n' > "$stub/docker"
  chmod +x "$stub/docker"
  _sc01() { # <marker-file> [extra env...] -> runs one real-backend reg_retag
    local marker="$1"; shift
    ( env -u GITHUB_ACTIONS -u ALLOW_LOCAL_PROMOTE "$@" \
        PATH="$stub:$PATH" DOCKER_CALLED="$marker" \
        bash -c '. '"$_ro_dir"'/registry-ops.sh
                 export REG_BACKEND=real
                 reg_retag ghcr.io/x/php-cli:8.4-prod sha256:'"$(printf a | shasum -a256 | cut -c1-64)" \
    ) >/dev/null 2>&1
  }
  _sc01 "$d/called1"; rc=$?
  _t "real backend refuses outside CI (SC-01)"     '[ "$rc" -ne 0 ]'
  _t "refused retag never reached docker"          '[ ! -e "$d/called1" ]'
  _sc01 "$d/called2" ALLOW_LOCAL_PROMOTE=1; rc=$?
  _t "ALLOW_LOCAL_PROMOTE=1 permits (stub docker)" '[ "$rc" -eq 0 ]'
  _t "override retag reached the stub backend"     '[ -e "$d/called2" ]'
  _sc01 "$d/called3" GITHUB_ACTIONS=true; rc=$?
  _t "GITHUB_ACTIONS=true permits (stub docker)"   '[ "$rc" -eq 0 ]'
  _t "CI retag reached the stub backend"           '[ -e "$d/called3" ]'
  rm -rf "$d"; return $fail
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-}" in
    --self-test) _ro_self_test && echo "registry-ops.sh: SELF-TEST OK" ;;
    *) echo "usage: registry-ops.sh --self-test" >&2; exit 2 ;;
  esac
fi
