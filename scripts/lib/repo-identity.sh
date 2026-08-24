#!/usr/bin/env bash
# =============================================================================
# scripts/lib/repo-identity.sh
# -----------------------------------------------------------------------------
# THE TWO INCIDENTS THIS EXISTS FOR.
#
# 1. WRONG-REPOSITORY OPERATION. A multi-agent workflow used `git worktree`
#    isolation. Worktrees are derived from the repository the SESSION happens to
#    be sitting in, not from the repository the work targets, so two agents were
#    handed checkouts of an entirely unrelated repository (bogdaniel/
#    zenchron-infra) while believing they were in zenchron-dynamics/
#    zenchron-foundry. They did no useful work; a third had to build its own
#    clone. A push made from that state was flagged by a security classifier as
#    possible exfiltration to the wrong repository. It was a false positive —
#    but nothing in the tooling could say so, and it took manual inspection of
#    the remote to establish it. "Which repository am I in" was never asserted,
#    only assumed.
#
# 2. SHARED-WORKTREE COLLISION. A coordinator ran git commands inside a lane
#    agent's live checkout and switched branches under it. Two TRACKED files the
#    agent had edited were silently reverted; the agent's backup covered only
#    untracked files. Recovered by luck and manual comparison. "Whose checkout
#    is this" was likewise never asserted.
#
# Neither is a knowledge problem — everyone involved knew the rules. They are
# missing PRECONDITIONS on mutating operations, so this file supplies them.
#
# WHAT IT IS NOT. It is not a general-purpose pre-flight for the repository and
# it deliberately does not run for ordinary contributors. Building, testing and
# committing never reach it. It guards exactly the paths named in
# `guarded_scripts` in policies/repo-identity.yaml — operations that push to the
# canonical remote or mutate the org control plane — plus the documented
# multi-agent workflow (docs/agent-worktree-convention.md). A guard that fires
# on `make test` in a fork would be removed within a week, and a removed guard
# protects nothing.
#
# WHERE IDENTITY COMES FROM. The git remote and the repository's own metadata.
# Never a hardcoded filesystem path: this must hold for any contributor, any
# clone location, any worktree, on any machine.
#
# FIVE REFUSAL CODES, one per failure mode, because a guard that says only
# "refused" cannot be acted on:
#
#   unexpected-remote     the `origin` URL is missing, unparseable, or points at
#                         a host the policy does not allow
#   wrong-repository      the remote resolves to a different owner/name — the
#                         incident-1 shape
#   wrong-worktree        this tooling belongs to a different checkout than the
#                         one it is being pointed at — the incident-2 shape
#   dirty-protected-path  a policy/script/workflow path has uncommitted changes
#                         and the caller did not explicitly allow it
#   foreign-lane          this checkout is registered to another agent lane
#   branch-ownership      the lane's registered branch is not the checked-out
#                         branch (something moved HEAD underneath it)
#
# USAGE — sourced (the guarded scripts):
#     . "$ROOT/scripts/lib/repo-identity.sh"
#     require_repo_identity            # refuses, non-zero, before any mutation
#
# USAGE — executed (agents and coordinators):
#     bash scripts/lib/repo-identity.sh check            # verify and report
#     bash scripts/lib/repo-identity.sh register-lane D  # claim this checkout
#     bash scripts/lib/repo-identity.sh status
#     bash scripts/lib/repo-identity.sh release-lane
#     bash scripts/lib/repo-identity.sh --self-test
#
# Portable to bash 3.2 (macOS system bash): no associative arrays, no ${x,,}.
# Offline by construction: it reads git metadata and a policy file. It never
# contacts a remote, so it cannot be made to leak by being run in a bad place.
# =============================================================================
set -euo pipefail

_ri_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# The policy path is resolved from THIS FILE's location, never from $PWD — the
# whole point is to work when $PWD is somewhere unexpected. ZF_REPO_IDENTITY_POLICY
# redirects it at fixtures in tests; it is not a bypass, because a fixture policy
# still has to be satisfied.
RI_POLICY="${ZF_REPO_IDENTITY_POLICY:-$_ri_dir/../../policies/repo-identity.yaml}"

# THE BOUND ROOT: the working tree this copy of the tooling belongs to.
#
# Derived, not configured. There is deliberately no environment override — an
# override is exactly the mistake incident 2 made by hand, and a guard whose
# subject can be reassigned by an environment variable guards nothing.
RI_BOUND_ROOT="$(git -C "$_ri_dir" rev-parse --show-toplevel 2>/dev/null || true)"
[ -n "$RI_BOUND_ROOT" ] || RI_BOUND_ROOT="$(cd "$_ri_dir/../.." && pwd -P)"

# Code of the last refusal, so callers and tests can assert on the SPECIFIC
# diagnostic rather than on "it exited non-zero".
RI_REFUSAL=""

ri_refuse() { # ri_refuse <code> <message>
  RI_REFUSAL="$1"
  printf 'REFUSE: repo-identity/%s: %s\n' "$1" "$2" >&2
  return 1
}

# --- policy reading ----------------------------------------------------------
# A five-line awk parser, not yq. This runs at the top of mutating scripts and
# inside git-adjacent tooling, where a hard dependency on a binary that may be
# absent turns a fail-closed guard into an unconditional refusal. The shape it
# accepts is deliberately tiny: top-level `key: value` scalars and top-level
# `key:` followed by an indented `- item` block. The self-test cross-checks it
# against yq whenever yq IS present, so the two cannot drift.

ri_policy_scalar() { # ri_policy_scalar <key> [policy]
  awk -v k="$1" '
    index($0, k ":") == 1 {
      sub("^" k ":[ \t]*", ""); sub("[ \t]*$", "")
      gsub(/^"|"$/, ""); print; exit
    }' "${2:-$RI_POLICY}"
}

ri_policy_list() { # ri_policy_list <key> [policy]  -> one item per line
  awk -v k="$1" '
    index($0, k ":") == 1 && $0 ~ ("^" k ":[ \t]*$") { inl = 1; next }
    inl && /^[ \t]*(#.*)?$/ { next }
    inl && /^[ \t]+-[ \t]*/ {
      sub(/^[ \t]+-[ \t]*/, ""); sub("[ \t]*$", "")
      gsub(/^"|"$/, ""); print; next
    }
    inl { exit }' "${2:-$RI_POLICY}"
}

# --- remote URL decomposition ------------------------------------------------
# Every form git actually hands back, reduced to host and owner/name:
#   https://github.com/o/n.git      ssh://git@github.com/o/n.git
#   git@github.com:o/n.git          https://x-token:SECRET@github.com/o/n
# A local path (a fixture, a mirror, a filesystem clone) yields an EMPTY host,
# which no allowed-hosts list can contain, so it refuses rather than parsing
# into something plausible.

ri_url_host() { # ri_url_host <url>
  printf '%s' "$1" | sed -E \
    -e 's#^[a-zA-Z][a-zA-Z0-9+.-]*://##' \
    -e 's#^[^/@]*@##' \
    -e 's#[:/].*$##' \
    | tr '[:upper:]' '[:lower:]'
}

ri_url_slug() { # ri_url_slug <url> -> owner/name, lowercased
  printf '%s' "$1" | sed -E \
    -e 's#^[a-zA-Z][a-zA-Z0-9+.-]*://##' \
    -e 's#^[^/@]*@##' \
    -e 's#^[^/:]*[:/]+##' \
    -e 's#/+$##' \
    -e 's#\.git$##' \
    | tr '[:upper:]' '[:lower:]'
}

# --- worktree / lane plumbing ------------------------------------------------
# `--git-common-dir` is the MAIN repository's git dir even from inside a linked
# worktree, so the lane registry is shared by every worktree of one clone, while
# `--absolute-git-dir` is per-worktree, so a lane marker belongs to exactly one
# checkout. Both are relative-path hazards; both are normalised here.

ri_git_dir() { # ri_git_dir <dir>  -> absolute per-worktree git dir
  git -C "$1" rev-parse --absolute-git-dir 2>/dev/null
}

ri_common_dir() { # ri_common_dir <dir> -> absolute shared git dir
  local d
  d="$(git -C "$1" rev-parse --git-common-dir 2>/dev/null)" || return 1
  case "$d" in
    /*) printf '%s' "$d" ;;
    *)  ( cd "$1" && cd "$d" && pwd -P ) ;;
  esac
}

ri_marker_path()   { printf '%s/%s' "$(ri_git_dir "$1")"    "$(ri_policy_scalar lane_marker_filename)"; }
ri_registry_dir()  { printf '%s/%s' "$(ri_common_dir "$1")" "$(ri_policy_scalar lane_registry_dirname)"; }

# Marker/registry entries are `key=value` lines. Not YAML, not JSON: they are
# written and read by this file alone, they live inside .git (never tracked,
# never committed, never shipped), and a format with no parser is one fewer
# thing that can fail while the guard is deciding whether to refuse.
ri_kv() { # ri_kv <file> <key>
  [ -f "$1" ] || return 1
  sed -n "s/^$2=//p" "$1" | head -1
}

ri_current_branch() { git -C "$1" rev-parse --abbrev-ref HEAD 2>/dev/null || printf 'HEAD'; }

# =============================================================================
# THE CHECKS. Each answers ONE question and refuses with ONE code.
# =============================================================================

ri_check_remote() { # ri_check_remote <dir>
  local dir="$1" remote url host allowed hit=0 h
  remote="$(ri_policy_scalar remote)"
  [ -n "$remote" ] || { ri_refuse policy "no 'remote' declared in $RI_POLICY"; return 1; }
  url="$(git -C "$dir" remote get-url "$remote" 2>/dev/null || true)"
  [ -n "$url" ] || { ri_refuse unexpected-remote \
    "no '$remote' remote in $dir — an unattached checkout cannot be identified"; return 1; }
  host="$(ri_url_host "$url")"
  allowed="$(ri_policy_list allowed_remote_hosts)"
  # `if`, not `&&`: a `for` whose last iteration ends in a false test returns 1,
  # which aborts this function the moment anyone calls it under errexit — and
  # would abort it having decided nothing, which is the worst kind of refusal.
  for h in $allowed; do if [ "$h" = "$host" ]; then hit=1; fi; done
  [ "$hit" = 1 ] || { ri_refuse unexpected-remote \
    "'$remote' points at host '${host:-<none>}' ($url); policy allows: $(printf '%s' "$allowed" | tr '\n' ' ')"; return 1; }
  [ -n "$(ri_url_slug "$url")" ] || { ri_refuse unexpected-remote \
    "'$remote' URL has no owner/name component: $url"; return 1; }
  return 0
}

ri_check_repository() { # ri_check_repository <dir>
  local dir="$1" remote url slug want
  remote="$(ri_policy_scalar remote)"
  want="$(ri_policy_scalar owner)/$(ri_policy_scalar name)"
  url="$(git -C "$dir" remote get-url "$remote" 2>/dev/null || true)"
  slug="$(ri_url_slug "$url")"
  [ "$slug" = "$(printf '%s' "$want" | tr '[:upper:]' '[:lower:]')" ] || {
    ri_refuse wrong-repository \
      "this checkout is '$slug', expected '$want' (remote $remote = $url)"; return 1; }
  return 0
}

ri_check_worktree() { # ri_check_worktree <dir> <bound-root>
  local dir="$1" bound="$2" here
  here="$(git -C "$dir" rev-parse --show-toplevel 2>/dev/null || true)"
  [ -n "$here" ] || { ri_refuse wrong-worktree "'$dir' is not inside a git working tree"; return 1; }
  here="$(cd "$here" && pwd -P)"
  if [ -d "$bound" ]; then bound="$(cd "$bound" && pwd -P)"; fi
  [ "$here" = "$bound" ] || { ri_refuse wrong-worktree \
    "this tooling belongs to '$bound' but was pointed at '$here' — run it from its own checkout"; return 1; }
  return 0
}

ri_check_clean() { # ri_check_clean <dir>
  local dir="$1" paths dirty
  paths="$(ri_policy_list protected_paths)"
  [ -n "$paths" ] || return 0
  # Only paths that EXIST are passed to git: a pathspec matching nothing makes
  # `git status` exit non-zero, which would refuse for the wrong reason in a
  # partial checkout.
  local present="" p
  for p in $paths; do if [ -e "$dir/$p" ]; then present="$present $p"; fi; done
  [ -n "$present" ] || return 0
  # shellcheck disable=SC2086  # word splitting is the point: one pathspec each
  dirty="$(git -C "$dir" status --porcelain=v1 --untracked-files=all -- $present 2>/dev/null || true)"
  [ -z "$dirty" ] || { ri_refuse dirty-protected-path \
    "uncommitted changes under protected paths (pass --allow-dirty, or set ZF_ALLOW_DIRTY=1, to proceed anyway):
$(printf '%s' "$dirty" | sed 's/^/    /')"; return 1; }
  return 0
}

ri_check_lane() { # ri_check_lane <dir> <lane-id>
  local dir="$1" lane="$2" marker owner branch head
  marker="$(ri_marker_path "$dir")"
  # NO MARKER MEANS NO CLAIM. An ordinary clone has never registered a lane, so
  # ownership cannot be violated and this returns clean. This single line is why
  # the guard does not touch contributors.
  [ -f "$marker" ] || return 0
  owner="$(ri_kv "$marker" lane || true)"
  branch="$(ri_kv "$marker" branch || true)"
  if [ -z "$lane" ]; then
    ri_refuse foreign-lane \
      "this checkout is registered to lane '$owner'; you supplied no lane identity (set ZF_LANE or --lane)"
    return 1
  fi
  [ "$lane" = "$owner" ] || { ri_refuse foreign-lane \
    "this checkout belongs to lane '$owner'; you are lane '$lane' — use your own checkout"; return 1; }
  head="$(ri_current_branch "$dir")"
  [ "$head" = "$branch" ] || { ri_refuse branch-ownership \
    "lane '$owner' registered branch '$branch' but HEAD is on '$head' — something moved it underneath you"; return 1; }
  return 0
}

# =============================================================================
# require_repo_identity — the one call a guarded script makes.
# =============================================================================
# Order is deliberate. The remote is read first because every other answer is
# derived from it; ownership is read last because it is the only check that can
# be legitimately absent.
require_repo_identity() {
  local cwd="$PWD" bound="$RI_BOUND_ROOT" lane="${ZF_LANE:-}" allow_dirty="${ZF_ALLOW_DIRTY:-0}"
  while [ $# -gt 0 ]; do
    case "$1" in
      --cwd)         cwd="$2"; shift 2 ;;
      --root)        bound="$2"; shift 2 ;;
      --lane)        lane="$2"; shift 2 ;;
      --allow-dirty) allow_dirty=1; shift ;;
      *) ri_refuse usage "unknown option '$1'"; return 1 ;;
    esac
  done
  # shellcheck disable=SC2034  # read by callers and tests to branch on the code
  RI_REFUSAL=""
  ri_check_remote     "$cwd"          || return 1
  ri_check_repository "$cwd"          || return 1
  ri_check_worktree   "$cwd" "$bound" || return 1
  [ "$allow_dirty" = 1 ] || ri_check_clean "$cwd" || return 1
  ri_check_lane       "$cwd" "$lane"  || return 1
  return 0
}

# =============================================================================
# LANE REGISTRY. Deliberately lightweight: two `key=value` files inside .git.
# =============================================================================
# A marker in the worktree's own git dir says WHO owns this checkout; an entry
# in the shared registry says WHICH checkout a lane owns. Both are needed —
# the marker refuses a stranger walking in, the registry refuses a lane claiming
# a second checkout while its first is still live.

ri_register_lane() { # ri_register_lane <lane> [dir]
  local lane="$1" dir="${2:-$PWD}" marker reg entry owner branch other
  [ -n "$lane" ] || { ri_refuse usage "register-lane needs a lane identifier"; return 1; }
  case "$lane" in *[!A-Za-z0-9._-]*) ri_refuse usage "lane id '$lane' has characters outside [A-Za-z0-9._-]"; return 1 ;; esac
  # Registering in the wrong repository is the incident this file opens with.
  ri_check_remote     "$dir" || return 1
  ri_check_repository "$dir" || return 1
  marker="$(ri_marker_path "$dir")"
  if [ -f "$marker" ]; then
    owner="$(ri_kv "$marker" lane || true)"
    [ "$owner" = "$lane" ] || { ri_refuse foreign-lane \
      "this checkout is already registered to lane '$owner'; release it there first"; return 1; }
  fi
  reg="$(ri_registry_dir "$dir")"
  entry="$reg/$lane"
  if [ -f "$entry" ]; then
    other="$(ri_kv "$entry" worktree || true)"
    if [ -n "$other" ] && [ "$other" != "$(cd "$dir" && git rev-parse --show-toplevel)" ]; then
      ri_refuse foreign-lane \
        "lane '$lane' is already registered to a different checkout: $other"
      return 1
    fi
  fi
  branch="$(ri_current_branch "$dir")"
  mkdir -p "$reg"
  printf 'lane=%s\nbranch=%s\nworktree=%s\n' \
    "$lane" "$branch" "$(cd "$dir" && git rev-parse --show-toplevel)" > "$marker"
  cp "$marker" "$entry"
  printf 'registered lane %s -> %s (branch %s)\n' \
    "$lane" "$(cd "$dir" && git rev-parse --show-toplevel)" "$branch"
}

ri_release_lane() { # ri_release_lane [dir]
  local dir="${1:-$PWD}" marker owner
  marker="$(ri_marker_path "$dir")"
  [ -f "$marker" ] || { printf 'no lane registered for this checkout\n'; return 0; }
  owner="$(ri_kv "$marker" lane || true)"
  rm -f "$marker" "$(ri_registry_dir "$dir")/$owner"
  printf 'released lane %s\n' "$owner"
}

ri_status() { # ri_status [dir]
  local dir="${1:-$PWD}" marker
  marker="$(ri_marker_path "$dir")"
  printf 'policy:      %s\n' "$RI_POLICY"
  printf 'expected:    %s/%s\n' "$(ri_policy_scalar owner)" "$(ri_policy_scalar name)"
  printf 'remote:      %s\n' "$(git -C "$dir" remote get-url "$(ri_policy_scalar remote)" 2>/dev/null || echo '<none>')"
  printf 'worktree:    %s\n' "$(git -C "$dir" rev-parse --show-toplevel 2>/dev/null || echo '<none>')"
  printf 'bound root:  %s\n' "$RI_BOUND_ROOT"
  printf 'branch:      %s\n' "$(ri_current_branch "$dir")"
  if [ -f "$marker" ]; then
    printf 'lane:        %s (branch %s)\n' "$(ri_kv "$marker" lane || true)" "$(ri_kv "$marker" branch || true)"
  else
    printf 'lane:        <unregistered>\n'
  fi
}

# =============================================================================
# SELF-TEST — pure functions only.
# =============================================================================
# Deliberately no git fixtures here. This self-test is executed by
# tests/lib/test_no_ambient_mutation.sh inside a frozen disposable worktree under
# a 45-second watchdog; building clones and linked worktrees would blow that
# budget and the whole audit would degrade to a timeout. The git-level sabotage
# matrix lives in tests/lib/test_repo_identity_guard.sh, which has room for it.
_ri_self_test() {
  local fail=0
  t() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

  local tmp; tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" EXIT

  # --- URL decomposition, every form git actually produces --------------------
  t "https URL -> host"        '[ "$(ri_url_host https://github.com/o/n.git)" = github.com ]'
  t "https URL -> slug"        '[ "$(ri_url_slug https://github.com/o/n.git)" = o/n ]'
  t "scp-style URL -> host"    '[ "$(ri_url_host git@github.com:o/n.git)" = github.com ]'
  t "scp-style URL -> slug"    '[ "$(ri_url_slug git@github.com:o/n.git)" = o/n ]'
  t "ssh:// URL -> host"       '[ "$(ri_url_host ssh://git@github.com/o/n.git)" = github.com ]'
  t "ssh:// URL -> slug"       '[ "$(ri_url_slug ssh://git@github.com/o/n.git)" = o/n ]'
  t "embedded credentials do not become the host" \
     '[ "$(ri_url_host https://x-access-token:SECRET@github.com/o/n)" = github.com ]'
  t "slug is case-folded (GitHub slugs are case-insensitive)" \
     '[ "$(ri_url_slug https://GitHub.com/Zenchron-Dynamics/Zenchron-Foundry)" = zenchron-dynamics/zenchron-foundry ]'
  t "no .git suffix is fine"   '[ "$(ri_url_slug https://github.com/o/n)" = o/n ]'
  # A different HOST with the RIGHT slug is the case that makes host checking
  # load-bearing: the slug alone would accept it.
  t "a look-alike host is a different host" \
     '[ "$(ri_url_host https://github.example.com/zenchron-dynamics/zenchron-foundry.git)" = github.example.com ]'
  t "...while its slug is identical to the real one" \
     '[ "$(ri_url_slug https://github.example.com/zenchron-dynamics/zenchron-foundry.git)" = zenchron-dynamics/zenchron-foundry ]'
  # A filesystem path must NOT parse into a plausible host.
  t "a local path yields no host" '[ -z "$(ri_url_host /srv/mirrors/foundry)" ]'

  # --- policy parsing ---------------------------------------------------------
  t "policy declares the expected owner" '[ "$(ri_policy_scalar owner)" = zenchron-dynamics ]'
  t "policy declares the expected name"  '[ "$(ri_policy_scalar name)"  = zenchron-foundry ]'
  t "policy declares the remote"         '[ "$(ri_policy_scalar remote)" = origin ]'
  t "allowed_remote_hosts parses as a list" \
     '[ "$(ri_policy_list allowed_remote_hosts)" = github.com ]'
  t "protected_paths is non-empty"       '[ -n "$(ri_policy_list protected_paths)" ]'
  t "guarded_scripts is non-empty"       '[ -n "$(ri_policy_list guarded_scripts)" ]'
  t "an absent scalar yields empty, not garbage" '[ -z "$(ri_policy_scalar no_such_key)" ]'
  t "an absent list yields empty, not the next block" '[ -z "$(ri_policy_list no_such_list)" ]'
  # NON-VACUITY of the parser: it must be able to read a value it is NOT already
  # returning, or every assertion above could be a constant.
  printf 'owner: someone-else\nname: other-repo\nremote: upstream\nlist_a:\n  - alpha\n  - beta\nlist_b:\n  - gamma\n' \
    > "$tmp/probe.yaml"
  t "the parser reads a DIFFERENT policy's scalar" \
     '[ "$(ri_policy_scalar owner "'"$tmp"'/probe.yaml")" = someone-else ]'
  t "the parser stops a list at the next top-level key" \
     '[ "$(ri_policy_list list_a "'"$tmp"'/probe.yaml" | tr "\n" " ")" = "alpha beta " ]'

  # --- the awk parser must agree with a real YAML reader ----------------------
  if command -v yq >/dev/null 2>&1; then
    t "awk scalar parse == yq (owner)" \
       '[ "$(ri_policy_scalar owner)" = "$(yq -r ".owner" "$RI_POLICY")" ]'
    t "awk scalar parse == yq (name)" \
       '[ "$(ri_policy_scalar name)" = "$(yq -r ".name" "$RI_POLICY")" ]'
    t "awk list parse == yq (protected_paths)" \
       '[ "$(ri_policy_list protected_paths)" = "$(yq -r ".protected_paths[]" "$RI_POLICY")" ]'
    t "awk list parse == yq (guarded_scripts)" \
       '[ "$(ri_policy_list guarded_scripts)" = "$(yq -r ".guarded_scripts[]" "$RI_POLICY")" ]'
  else
    echo "ok   - yq absent; awk/yq cross-check skipped"
  fi

  # --- refusal plumbing -------------------------------------------------------
  t "ri_refuse returns non-zero"  '! ( ri_refuse test-code "message" ) 2>/dev/null'
  # NOTE: no subshell, and no bare pipeline. `( … )` would discard the variable
  # this asserts on, and `pipefail` makes a pipeline whose FIRST element refuses
  # return non-zero regardless of what grep found.
  t "ri_refuse records the code"  'ri_refuse zzz m 2>/dev/null; [ "$RI_REFUSAL" = zzz ]'
  t "ri_refuse names the code on stderr" \
     '{ ri_refuse zzz "the message" 2>&1 || true; } | grep -q "repo-identity/zzz: the message"'
  t "an unknown option refuses rather than being ignored" \
     '! ( require_repo_identity --no-such-flag ) >/dev/null 2>&1'

  echo "self-test: $( [ "$fail" -eq 0 ] && echo OK || echo FAILED )"
  return "$fail"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-}" in
    --self-test)   _ri_self_test && echo "repo-identity.sh: SELF-TEST OK" ;;
    check)         shift; require_repo_identity "$@" && echo "repo-identity: OK" ;;
    status)        shift; ri_status "$@" ;;
    register-lane) shift; ri_register_lane "${1:-}" "${2:-$PWD}" ;;
    release-lane)  shift; ri_release_lane "${1:-$PWD}" ;;
    *) echo "usage: repo-identity.sh {check|status|register-lane <id>|release-lane|--self-test}" >&2; exit 2 ;;
  esac
fi
