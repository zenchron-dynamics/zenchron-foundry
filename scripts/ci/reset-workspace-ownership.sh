#!/usr/bin/env bash
# Centralized self-hosted-runner workspace ownership reset.
# Replaces per-workflow inline `chown` blocks (previously duplicated across 7
# workflows). Canonicalizes paths, refuses to operate outside the runner's
# _work tree, and NEVER masks failure with `|| true`.
#
# Contract:
#   - GITHUB_WORKSPACE (required): checkout dir to reset.
#   - RUNNER_WORK_ROOT (optional): allowed `_work` root. If unset, derived from
#     the `_work` segment of the canonicalized workspace.
#   - RESET_UID / RESET_GID (optional): target owner; default current uid:gid.
#
# Behavior (matches the hardening spec):
#   root                     -> chown directly
#   non-root + working sudo  -> chown via sudo
#   non-root + already-owned -> no-op
#   non-root + wrong + no sudo -> FAIL with explicit diagnosis
#
# Usage: reset-workspace-ownership.sh [--self-test]
set -euo pipefail

die() { echo "workspace-reset FAIL: $*" >&2; exit 1; }

# Pure decision function — testable without actually chowning.
# _decide <is_root:0|1> <has_working_sudo:0|1> <already_owned:0|1>
#   -> echoes one of: noop | chown-root | chown-sudo | fail-no-sudo
_decide() {
  local is_root="$1" has_sudo="$2" owned="$3"
  if [ "$owned" = 1 ]; then echo noop; return; fi
  if [ "$is_root" = 1 ]; then echo chown-root; return; fi
  if [ "$has_sudo" = 1 ]; then echo chown-sudo; return; fi
  echo fail-no-sudo
}

# Resolve + guard the workspace path. Echoes the canonical path or dies.
_safe_workspace() {
  local ws="${GITHUB_WORKSPACE:-}" allowed="${RUNNER_WORK_ROOT:-}"
  [ -n "$ws" ] || die "GITHUB_WORKSPACE is required"
  [ -e "$ws" ] || die "workspace does not exist: $ws"
  local rp; rp="$(realpath "$ws")" || die "cannot canonicalize workspace: $ws"
  case "$rp" in ""|"/"|"//") die "refusing to operate on root path: '$rp'";; esac

  if [ -z "$allowed" ]; then
    case "$rp" in
      */_work/*) allowed="${rp%%/_work/*}/_work";;
      *) die "workspace is not under a runner _work tree and RUNNER_WORK_ROOT unset: $rp";;
    esac
  fi
  allowed="$(realpath "$allowed")" || die "cannot canonicalize allowed root: $allowed"
  [ "$rp" != "$allowed" ] || die "workspace equals allowed root; refusing: $rp"
  case "$rp/" in
    "$allowed"/*) : ;;
    *) die "workspace '$rp' is not strictly below allowed root '$allowed'";;
  esac
  printf '%s\n' "$rp"
}

_owner_of() { stat -c '%u:%g' "$1" 2>/dev/null || stat -f '%u:%g' "$1"; }

reset_ownership() {
  local rp; rp="$(_safe_workspace)"
  local uid gid; uid="${RESET_UID:-$(id -u)}"; gid="${RESET_GID:-$(id -g)}"
  local cur; cur="$(_owner_of "$rp")"

  local is_root=0 has_sudo=0 owned=0
  [ "$(id -u)" -eq 0 ] && is_root=1
  { command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; } && has_sudo=1
  [ "$cur" = "$uid:$gid" ] && owned=1

  case "$(_decide "$is_root" "$has_sudo" "$owned")" in
    noop)        echo "workspace-reset: already $uid:$gid — nothing to do ($rp)";;
    chown-root)  chown -R "$uid:$gid" "$rp"; echo "workspace-reset: chown as root -> $uid:$gid ($rp)";;
    chown-sudo)  sudo chown -R "$uid:$gid" "$rp"; echo "workspace-reset: chown via sudo -> $uid:$gid ($rp)";;
    fail-no-sudo) die "ownership is $cur, expected $uid:$gid; user is non-root and sudo unavailable — cannot reset '$rp'";;
  esac
}

self_test() {
  local ok=0 bad=0 tmp; tmp="$(mktemp -d)"
  eq() { if [ "$2" = "$3" ]; then ok=$((ok+1)); echo "  ok   $1"; else bad=$((bad+1)); echo "  FAIL $1: got '$2' want '$3'"; fi; }
  # dies <label> <cmd...> : cmd runs in the parent's if-condition; counters stay in parent scope.
  dies() { local l="$1"; shift; if "$@" >/dev/null 2>&1; then bad=$((bad+1)); echo "  FAIL $l (expected die)"; else ok=$((ok+1)); echo "  ok   dies: $l"; fi; }

  # _decide truth table
  eq "root -> chown-root"                  "$(_decide 1 0 0)" chown-root
  eq "root+owned -> noop"                  "$(_decide 1 0 1)" noop
  eq "nonroot+sudo -> chown-sudo"          "$(_decide 0 1 0)" chown-sudo
  eq "nonroot+owned -> noop"               "$(_decide 0 0 1)" noop
  eq "nonroot+nosudo+wrong -> fail"        "$(_decide 0 0 0)" fail-no-sudo
  eq "root/no-sudo (runner) -> chown-root" "$(_decide 1 0 0)" chown-root

  mkdir -p "$tmp/_work/repo/repo" "$tmp/_work/re po/re po" "$tmp/outside"
  ln -s "$tmp/outside" "$tmp/_work/repo/escape"

  # path guards. _run isolates env in a subshell but surfaces the exit code,
  # so parent-scope counters stay correct.
  dies "missing GITHUB_WORKSPACE"  _run
  dies "nonexistent workspace"     _run GITHUB_WORKSPACE="/nonexistent-$$-xyz"
  dies "root path /"               _run GITHUB_WORKSPACE="/"
  dies "outside _work, no root"    _run GITHUB_WORKSPACE="$tmp"                 RUNNER_WORK_ROOT=
  dies "workspace == allowed root" _run GITHUB_WORKSPACE="$tmp/_work"          RUNNER_WORK_ROOT="$tmp/_work"
  dies "symlink escape rejected"   _run GITHUB_WORKSPACE="$tmp/_work/repo/escape" RUNNER_WORK_ROOT="$tmp/_work"

  # valid path with spaces -> returns canonical path
  local got; got="$(GITHUB_WORKSPACE="$tmp/_work/re po/re po" RUNNER_WORK_ROOT="$tmp/_work" _safe_workspace)"
  eq "valid nested path accepted" "${got##*/_work/}" "re po/re po"

  # end-to-end no-op: a dir we already own -> "nothing to do"
  local out; out="$(GITHUB_WORKSPACE="$tmp/_work/repo/repo" RUNNER_WORK_ROOT="$tmp/_work" \
                    RESET_UID="$(id -u)" RESET_GID="$(id -g)" reset_ownership)"
  case "$out" in *"nothing to do"*) ok=$((ok+1)); echo "  ok   already-owned -> no-op";;
                 *) bad=$((bad+1)); echo "  FAIL already-owned no-op: $out";; esac

  rm -rf "$tmp"
  echo "self-test: $ok ok, $bad failed"
  [ "$bad" -eq 0 ]
}

# _run VAR=val ... : run _safe_workspace with the given env, isolated to a subshell
# but with its exit code surfaced to the caller (so parent-scope counters are correct).
_run() { ( unset GITHUB_WORKSPACE RUNNER_WORK_ROOT; for kv in "$@"; do export "${kv?}"; done; _safe_workspace ); }

if [ "${1:-}" = "--self-test" ]; then self_test; else reset_ownership; fi
