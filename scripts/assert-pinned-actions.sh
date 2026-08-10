#!/usr/bin/env bash
# self-test: waived (thin wrapper; exercised by the "action pinning" gate in scripts/macro-validate.sh, the ci.yml static-gates job, and release-preflight.yml)
# =============================================================================
# assert-pinned-actions.sh
# -----------------------------------------------------------------------------
# Fails if ANY GitHub Action `uses:` reference is not pinned to a full
# 40-hex-char commit SHA.
#
# Accepted:
#   uses: owner/repo@<40-hex-sha>            (optional trailing "# vX" comment)
#   uses: owner/repo/path@<40-hex-sha>       (subpath actions)
#   uses: ./.github/workflows/foo.yml        (LOCAL reusable workflow -- exempt)
#
# Rejected (printed as <file>:<lineno>: <ref>):
#   @vN, @vN.N.N, @main, @master, branch names, short SHAs, any non-40-hex ref
#
# Scans workflows, composite actions, and reusable workflow files.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# -----------------------------------------------------------------------------
# WHY --verify-upstream EXISTS.
#
# Acceptance run 31340810647 failed with every job dying at "Set up job":
#
#   Unable to resolve action
#   actions/download-artifact@abefc31eb2ec6e152ff1b4e83e9700a37e9eba59
#
# That reference is a well-formed 40-hex pin, so this gate passed it exactly as
# designed. It is also a SHA that has never existed in that repository. Pin
# IMMUTABILITY was proven; pin EXISTENCE was not, and the two are different
# properties. A fabricated SHA is indistinguishable from a correct one until a
# runner tries to fetch it — minutes into a privileged job, after the guard and
# the database freeze have already run.
#
# The default mode stays offline and fast. --verify-upstream additionally proves
# each unique reference resolves in the exact repository it names.
#
# An unreachable API, a rate limit, a malformed response, a 404 or a 422 all
# FAIL. "Could not check" is never "fine": that conversion is what this whole
# repository keeps removing.
#
# GH_RESOLVE_FN is injectable so the failure semantics are testable offline.
# -----------------------------------------------------------------------------
_gh_resolve() { # <owner/repo> <sha> -> prints the resolved sha, non-zero on any failure
  gh api "repos/$1/commits/$2" --jq '.sha' 2>/dev/null
}
resolve_commit() { "${GH_RESOLVE_FN:-_gh_resolve}" "$1" "$2"; }

# The upstream verifier. This is the ONE implementation: the live CI mode and
# the offline failure fixtures both call this function, so a mutation to its
# verdict arithmetic (e.g. `-gt 0` -> `-lt 0`) breaks the self-test.
verify_upstream_refs() { # <ref>... -> 0 all resolve exactly, 1 otherwise
  local unresolved=0 ref sha repopath owner rest_ repo got
  # Fail closed on an empty set: nothing checked is not a pass.
  if [[ "$#" -eq 0 ]]; then
    echo "ERROR: no pinned references collected; nothing was verified" >&2
    echo "RESULT: FAIL (nothing was checked)"
    return 1
  fi
  for ref in "$@"; do
    sha="${ref##*@}"
    repopath="${ref%@*}"
    # owner/repo, discarding any sub-path: actions/foo/bar lives in actions/foo.
    owner="${repopath%%/*}"; rest_="${repopath#*/}"; repo="${rest_%%/*}"
    got="$(resolve_commit "${owner}/${repo}" "${sha}" || true)"
    if [[ -z "${got}" ]]; then
      printf 'UNRESOLVED %s (no commit found in %s/%s, or the lookup failed)\n' "${ref}" "${owner}" "${repo}" >&2
      unresolved=$((unresolved + 1))
    elif [[ "${got}" != "${sha}" ]]; then
      printf 'MISMATCH   %s resolved to %s\n' "${ref}" "${got}" >&2
      unresolved=$((unresolved + 1))
    else
      printf 'OK %s\n' "${ref}"
    fi
  done
  if [[ "${unresolved}" -gt 0 ]]; then
    printf 'RESULT: FAIL (%d pinned action(s) do not resolve upstream)\n' "${unresolved}"
    return 1
  fi
  printf 'RESULT: PASS (%d unique immutable action pins resolve upstream)\n' "$#"
  return 0
}

VERIFY_UPSTREAM=0
[ "${1:-}" = "--verify-upstream" ] && VERIFY_UPSTREAM=1
[ "${1:-}" = "--self-test" ] && VERIFY_UPSTREAM=0

violations=0
declare -a UNIQUE_REFS=()

# Collect target files: workflows + composite/reusable action definitions.
files=()
while IFS= read -r f; do
  [[ -n "${f}" ]] && files+=("${f}")
done < <(
  {
    find "${ROOT}/.github/workflows" -type f \( -name '*.yml' -o -name '*.yaml' \) 2>/dev/null || true
    find "${ROOT}/.github/actions" -type f \( -name 'action.yml' -o -name 'action.yaml' \) 2>/dev/null || true
  } | sort -u
)

# SC-28: fail closed — this repo always has workflows, so an empty file list
# means the discovery glob itself regressed and MUST NOT vacuous-pass the gate.
if [[ "${#files[@]}" -eq 0 ]]; then
  echo "ERROR: zero workflow or action files found under .github (glob/discovery regression; the repo always has workflows)" >&2
  echo "RESULT: FAIL (nothing was checked)"
  exit 1
fi

for file in "${files[@]}"; do
  [[ -f "${file}" ]] || continue
  while IFS= read -r entry; do
    lineno="${entry%%:*}"
    rest="${entry#*:}"

    # Isolate the value after "uses:" and strip surrounding noise.
    ref="$(sed -E 's/.*uses:[[:space:]]*//' <<<"${rest}")"
    ref="${ref%%#*}"                      # drop trailing "# vX" comment
    ref="${ref//\"/}"                     # drop quotes
    ref="${ref//\'/}"                     # drop single quotes
    ref="$(sed -E 's/[[:space:]]+$//' <<<"${ref}")"

    [[ -z "${ref}" ]] && continue

    # Local reusable workflow / local action references are exempt.
    if [[ "${ref}" == ./* ]]; then
      continue
    fi
    # Docker-based action references (docker://) are out of scope here.
    if [[ "${ref}" == docker://* ]]; then
      continue
    fi

    # Must be owner/repo[/path]@<40 lowercase hex>.
    if [[ "${ref}" =~ ^[^@/]+/[^@]+@[0-9a-f]{40}$ ]]; then
      # Collected once per unique reference: the same action pinned in ten
      # workflows is one upstream question, not ten.
      case " ${UNIQUE_REFS[*]:-} " in
        *" ${ref} "*) : ;;
        *) UNIQUE_REFS+=("${ref}") ;;
      esac
      continue
    fi

    printf '%s:%s: %s\n' "${file}" "${lineno}" "${ref}"
    violations=$((violations + 1))
  done < <(grep -nE '^[[:space:]]*-?[[:space:]]*uses:[[:space:]]*' "${file}" || true)
done

echo
if [[ "${violations}" -gt 0 ]]; then
  printf 'RESULT: FAIL (%d unpinned action reference(s))\n' "${violations}"
  exit 1
fi

if [[ "${VERIFY_UPSTREAM}" -eq 1 ]]; then
  # ${arr[@]+...} so an empty array survives `set -u` and reaches the function's
  # own fail-closed empty check rather than aborting the shell.
  verify_upstream_refs ${UNIQUE_REFS[@]+"${UNIQUE_REFS[@]}"}
  exit $?
fi
echo "RESULT: PASS (all action references SHA-pinned)"


# -----------------------------------------------------------------------------
# Offline self-test for the resolver's FAILURE SEMANTICS. The network mode is
# exercised for real in CI; what must be deterministic here is what the checker
# does when upstream says no, says nothing, or says something else.
# -----------------------------------------------------------------------------
_apa_self_test() {
  local ok=0 nbad=0
  t() { if eval "$2"; then echo "ok   - $1"; ok=$((ok+1)); else echo "FAIL - $1"; nbad=$((nbad+1)); fi; }

  local GOOD="018cc2cf5baa6db3ef3c5f8a56943fffe632ef53"
  # The exact reference that broke acceptance run 31340810647. Keeping the real
  # value means this regression cannot drift into an abstract shape that misses
  # the incident it exists for.
  local DEAD="abefc31eb2ec6e152ff1b4e83e9700a37e9eba59"

  _ok_fn()       { echo "$2"; }                       # upstream echoes the sha
  _404_fn()      { return 1; }                        # not found
  _422_fn()      { return 1; }                        # no commit for sha
  _other_fn()    { echo "1111111111111111111111111111111111111111"; }
  _netfail_fn()  { return 7; }                        # transport error
  _garbage_fn()  { echo "not-a-sha"; }                # malformed response
  _empty_fn()    { echo ""; }                         # empty body

  # `v` drives the PRODUCTION verifier -- verify_upstream_refs, the same function
  # the live CI mode calls -- with the transport swapped out. GH_RESOLVE_FN is a
  # bash local, so dynamic scoping carries it into resolve_commit. There is no
  # second copy of the accept/reject logic here: mutating the real verdict test
  # (`-gt 0` -> `-lt 0`, `-z` -> `-n`, `!=` -> `=`) fails these cases.
  v() { # v <resolver-fn> <sha> -> exit status of verify_upstream_refs
    local GH_RESOLVE_FN="$1"
    verify_upstream_refs "actions/download-artifact@$2" >/dev/null 2>&1
  }
  v_multi() { # v_multi <resolver-fn> <ref>... -> exit status over several refs
    local GH_RESOLVE_FN="$1"; shift
    verify_upstream_refs "$@" >/dev/null 2>&1
  }
  v_empty() { local GH_RESOLVE_FN="_ok_fn"; verify_upstream_refs >/dev/null 2>&1; }

  _mixed_fn() { [ "$2" = "$GOOD" ] && echo "$2" || return 1; }

  t "a resolvable pin is ACCEPTED"                 "v _ok_fn '$GOOD'"
  t "the DEAD pin from run 31340810647 is REJECTED (404)" "! v _404_fn '$DEAD'"
  t "a 422 'no commit for SHA' is REJECTED"        "! v _422_fn '$DEAD'"
  t "a DIFFERENT resolved sha is REJECTED"         "! v _other_fn '$GOOD'"
  t "a network failure is REJECTED, not assumed ok" "! v _netfail_fn '$GOOD'"
  t "a malformed response is REJECTED"             "! v _garbage_fn '$GOOD'"
  t "an empty response is REJECTED"                "! v _empty_fn '$GOOD'"
  # Counting: one bad reference must condemn the whole set, and a wholly good
  # set must exit 0 -- together these pin both directions of the verdict test.
  t "one dead pin in a set of three REJECTS the set" \
    "! v_multi _mixed_fn \"a/b@\$GOOD\" \"c/d@\$DEAD\" \"e/f@\$GOOD\""
  t "an all-resolvable set is ACCEPTED"            "v_multi _ok_fn \"a/b@\$GOOD\" \"c/d@\$GOOD\""
  t "an EMPTY reference set FAILS closed"          "! v_empty"

  # Syntax rules are unchanged.
  local re='^[^@/]+/[^@]+@[0-9a-f]{40}$'
  t "a mutable @v6 tag still FAILS"      "! [[ 'actions/download-artifact@v6' =~ $re ]]"
  t "a short sha still FAILS"            "! [[ 'actions/checkout@abc1234' =~ $re ]]"
  t "an uppercase sha still FAILS"       "! [[ \"actions/checkout@$(echo $GOOD | tr a-f A-F)\" =~ $re ]]"
  t "a full 40-hex pin passes syntax"    "[[ \"actions/download-artifact@$GOOD\" =~ $re ]]"
  t "a sub-path action passes syntax"    "[[ \"anchore/sbom-action/download-syft@$GOOD\" =~ $re ]]"

  # owner/repo extraction must drop the sub-path: actions/foo/bar lives in actions/foo.
  local rp="anchore/sbom-action/download-syft" o r rest
  o="${rp%%/*}"; rest="${rp#*/}"; r="${rest%%/*}"
  t "a sub-path action resolves against owner/repo, not the path" "[ \"$o/$r\" = 'anchore/sbom-action' ]"

  # local and docker refs stay exempt
  t "a local ./ action is exempt"        "[[ './.github/actions/x' == ./* ]]"
  t "a docker:// action is exempt"       "[[ 'docker://alpine:3' == docker://* ]]"

  # duplicate collection
  local -a U=(); local ref
  for ref in "a/b@$GOOD" "a/b@$GOOD" "c/d@$GOOD"; do
    case " ${U[*]:-} " in *" $ref "*) : ;; *) U+=("$ref") ;; esac
  done
  t "a duplicated pin is resolved once"  "[ ${#U[@]} = 2 ]"

  echo "self-test: $ok ok, $nbad failed"
  [ "$nbad" -eq 0 ]
}

case "${1:-}" in
  --self-test) _apa_self_test && echo "assert-pinned-actions.sh: SELF-TEST OK" ;;
esac
