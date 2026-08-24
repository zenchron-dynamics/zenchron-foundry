#!/usr/bin/env bash
# shellcheck disable=SC2034  # assertion values are consumed inside ck() eval strings
# =============================================================================
# tests/lib/test_repo_identity_guard.sh
# -----------------------------------------------------------------------------
# THE TWO INCIDENTS UNDER TEST (docs/agent-worktree-convention.md).
#
# 1. Agents were handed `git worktree` checkouts derived from the SESSION's
#    repository (bogdaniel/zenchron-infra) rather than the target
#    (zenchron-dynamics/zenchron-foundry). Two of them worked in the wrong
#    repository entirely. A push from that state was flagged by a security
#    classifier as possible exfiltration — a false positive that could only be
#    established by manually inspecting the remote, because nothing had ever
#    asserted which repository it was.
#
# 2. A coordinator ran git commands inside a lane agent's live checkout and
#    switched branches under it, silently reverting two TRACKED files.
#
# WHAT IS PROVED HERE, for every control:
#   * happy path                — the control does not fire when it should not
#   * the EXACT refusal code    — five failure modes, five distinguishable
#                                 diagnostics, so a refusal can be acted on
#   * sabotage                  — the failure is reintroduced and must be caught
#   * pre-change proof          — the same sabotage is shown to go UNDETECTED
#                                 against the guard-free version of the script
#   * non-vacuity               — flip ONE fact back and the refusal disappears,
#                                 so the refusal is caused by the thing named
#   * blast radius              — the guard is wired into exactly the declared
#                                 scripts and nothing else, and an ordinary
#                                 clone passes unimpeded
#
# EVERY fixture is a disposable `git init` repository under mktemp. Nothing in
# this file writes to the checkout — tests/lib/test_no_ambient_mutation.sh
# enforces that repository-wide, and this test additionally fingerprints the
# tree around itself. The fixture remotes are plausible GitHub URLs that are
# never contacted: the guard reads `git remote get-url` and never fetches, so
# the whole suite is offline.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

TMP="$(mktemp -d)"
# Expand NOW: a single-quoted EXIT trap defers expansion past this scope and dies
# with "unbound variable" under set -u. EXIT, never RETURN — a RETURN trap fires
# on every inner function return under functrace and would delete the fixtures
# after the first assertion (tests/lib/test_functrace_safety.sh).
# shellcheck disable=SC2064
trap "rm -rf '$TMP'" EXIT

# The tree must be byte-identical before and after. One test in this repository
# has already destroyed a policy file it was asserting about.
fingerprint() { find policies scripts docs/agent-worktree-convention.md -type f -exec shasum -a 256 {} + | sort | shasum -a 256; }
PRE_FINGERPRINT="$(fingerprint)"

GUARD="$ROOT/scripts/lib/repo-identity.sh"
POLICY="$ROOT/policies/repo-identity.yaml"

REAL_URL="https://github.com/zenchron-dynamics/zenchron-foundry.git"
# The repository the agents actually landed in. Not a hypothetical.
WRONG_URL="https://github.com/bogdaniel/zenchron-infra.git"
# Correct owner/name, different service. The slug check alone would accept it.
LOOKALIKE_URL="https://github.example.com/zenchron-dynamics/zenchron-foundry.git"

# --- fixture construction ---------------------------------------------------
# A miniature checkout carrying the REAL guard and the REAL policy, so every
# assertion below exercises shipped code rather than a paraphrase of it.
mkfixture() { # mkfixture <dir> <remote-url> [branch]
  local dir="$1" url="$2" br="${3:-master}"
  mkdir -p "$dir/policies" "$dir/scripts/lib"
  cp "$GUARD"  "$dir/scripts/lib/repo-identity.sh"
  cp "$POLICY" "$dir/policies/repo-identity.yaml"
  printf '# fixture\n' > "$dir/README.md"
  printf '#!/usr/bin/env bash\necho maintenance\n' > "$dir/scripts/maintenance.sh"
  git init -q "$dir" >/dev/null 2>&1
  git -C "$dir" symbolic-ref HEAD "refs/heads/$br"
  git -C "$dir" config user.email agent@example.invalid
  git -C "$dir" config user.name "lane fixture"
  git -C "$dir" config commit.gpgsign false
  git -C "$dir" add -A >/dev/null 2>&1
  git -C "$dir" commit -qm fixture >/dev/null 2>&1
  [ -n "$url" ] && git -C "$dir" remote add origin "$url"
  return 0
}

# guard <outfile> <dir> [args...] -> runs the SHIPPED entry point, returns its rc
guard() {
  local out="$1" dir="$2"; shift 2
  ( cd "$dir" && bash scripts/lib/repo-identity.sh check "$@" ) >"$out" 2>&1
}

# =============================================================================
# 0. THE SOURCED FORM — how the guarded scripts actually use it
# =============================================================================
# Sourcing imports `set -euo pipefail` from the lib, exactly as it does from
# common.sh. Under errexit the first intentional refusal below would kill this
# harness instead of being measured, so errexit is dropped again immediately.
# shellcheck source=../../scripts/lib/repo-identity.sh
. "$GUARD"
set +e
ck "sourcing the guard exposes require_repo_identity to the caller" \
   'type -t require_repo_identity | grep -q function'
ck "...and the declared expectations are readable through it" \
   '[ "$(ri_policy_scalar owner)/$(ri_policy_scalar name)" = zenchron-dynamics/zenchron-foundry ]'
# The pattern is ASSEMBLED AT RUNTIME so that this file does not contain the
# literal it searches for. A check that matches its own source reports a correct
# file as broken, which this repository has shipped more than once.
HOMEPAT="$(printf '/%s/|/%s/[a-z]' Users home)"
ck "no product file hardcodes a personal filesystem path" \
   '! grep -nE "$HOMEPAT" "$GUARD" "$POLICY" "$ROOT/docs/agent-worktree-convention.md" "$0"'
ck "...and that search is NOT VACUOUS — it matches a planted personal path" \
   'printf "ROOT=/%s/someone/checkout\n" Users > "$TMP/homeprobe" && grep -qE "$HOMEPAT" "$TMP/homeprobe"'

# =============================================================================
# 1. HAPPY PATH — a correct, clean, unclaimed checkout is not touched
# =============================================================================
mkfixture "$TMP/happy" "$REAL_URL"
guard "$TMP/happy.out" "$TMP/happy"; rc_happy=$?
ck "HAPPY: a correct, clean, unclaimed checkout PASSES" \
   '[ "$rc_happy" -eq 0 ] || { cat "$TMP/happy.out"; false; }'
ck "...and says so rather than passing silently" 'grep -q "repo-identity: OK" "$TMP/happy.out"'

# The same repository at a DIFFERENT path also passes. Identity is derived from
# the remote, so no filesystem location is privileged — which is the property
# that lets this work for every contributor and every clone location.
mkfixture "$TMP/elsewhere/deeper/happy2" "$REAL_URL"
guard "$TMP/happy2.out" "$TMP/elsewhere/deeper/happy2"; rc_happy2=$?
ck "...at ANY path, because identity comes from the remote and not from a path" \
   '[ "$rc_happy2" -eq 0 ]'

# =============================================================================
# 2. SABOTAGE — correct branch, WRONG REPOSITORY  (incident 1)
# =============================================================================
# Same branch name as the real work, entirely the wrong repository: the exact
# state two agents were handed.
mkfixture "$TMP/wrongrepo" "$WRONG_URL" feat/repo-identity-guard
guard "$TMP/wrongrepo.out" "$TMP/wrongrepo"; rc_wrongrepo=$?
ck "SABOTAGE(wrong repository): REFUSED" '[ "$rc_wrongrepo" -ne 0 ]'
ck "...with the wrong-repository code, not a generic failure" \
   'grep -q "REFUSE: repo-identity/wrong-repository:" "$TMP/wrongrepo.out"'
ck "...naming BOTH the repository found and the one expected" \
   'grep -q "bogdaniel/zenchron-infra" "$TMP/wrongrepo.out" &&
    grep -q "zenchron-dynamics/zenchron-foundry" "$TMP/wrongrepo.out"'
ck "...and the BRANCH is demonstrably not the reason" \
   '[ "$(git -C "$TMP/wrongrepo" rev-parse --abbrev-ref HEAD)" = feat/repo-identity-guard ] &&
    ! grep -q "branch-ownership" "$TMP/wrongrepo.out"'
# NON-VACUITY: flip the ONE fact under test and the refusal must vanish.
git -C "$TMP/wrongrepo" remote set-url origin "$REAL_URL"
guard "$TMP/wrongrepo.fixed.out" "$TMP/wrongrepo"; rc_wrongrepo_fixed=$?
ck "...NON-VACUOUS: correcting only the remote makes the same checkout PASS" \
   '[ "$rc_wrongrepo_fixed" -eq 0 ]'

# =============================================================================
# 3. SABOTAGE — correct repository, WRONG WORKTREE  (incident 2)
# =============================================================================
# Two linked worktrees of ONE repository. The tooling in worktree A is pointed
# at worktree B: same repository, same remote, different checkout. This is the
# coordinator-in-a-lane's-checkout move.
mkfixture "$TMP/wtA" "$REAL_URL"
git -C "$TMP/wtA" worktree add -q -b lane-b "$TMP/wtB" >/dev/null 2>&1
have_wt=$?
ck "a linked worktree of the same repository was created" '[ "$have_wt" -eq 0 ] && [ -e "$TMP/wtB/.git" ]'
( cd "$TMP/wtB" && bash "$TMP/wtA/scripts/lib/repo-identity.sh" check ) >"$TMP/wtcross.out" 2>&1
rc_wtcross=$?
ck "SABOTAGE(wrong worktree): REFUSED" '[ "$rc_wtcross" -ne 0 ]'
ck "...with the wrong-worktree code, distinct from wrong-repository" \
   'grep -q "REFUSE: repo-identity/wrong-worktree:" "$TMP/wtcross.out" &&
    ! grep -q "wrong-repository" "$TMP/wtcross.out"'
ck "...naming both checkouts so the operator can tell which is which" \
   'grep -q "$TMP/wtA" "$TMP/wtcross.out" && grep -q "$TMP/wtB" "$TMP/wtcross.out"'
ck "...and the REPOSITORY is demonstrably not the reason (both worktrees share the remote)" \
   '[ "$(git -C "$TMP/wtB" remote get-url origin)" = "$REAL_URL" ]'
# NON-VACUITY: the same tooling, run in its OWN worktree, passes.
guard "$TMP/wtA.out" "$TMP/wtA"; rc_wtA=$?
ck "...NON-VACUOUS: the same tooling in its OWN checkout PASSES" '[ "$rc_wtA" -eq 0 ]'
( cd "$TMP/wtB" && bash scripts/lib/repo-identity.sh check ) >"$TMP/wtB.out" 2>&1
rc_wtB=$?
ck "...and worktree B's OWN copy of the tooling passes there too" '[ "$rc_wtB" -eq 0 ]'

# =============================================================================
# 4. SABOTAGE — UNEXPECTED REMOTE
# =============================================================================
# The dangerous case is not a wrong-looking URL. It is a RIGHT-looking one: the
# correct owner/name on a host that is not GitHub. A slug-only check accepts it.
mkfixture "$TMP/lookalike" "$LOOKALIKE_URL"
guard "$TMP/lookalike.out" "$TMP/lookalike"; rc_lookalike=$?
ck "SABOTAGE(unexpected remote): REFUSED" '[ "$rc_lookalike" -ne 0 ]'
ck "...with the unexpected-remote code, not wrong-repository" \
   'grep -q "REFUSE: repo-identity/unexpected-remote:" "$TMP/lookalike.out" &&
    ! grep -q "wrong-repository" "$TMP/lookalike.out"'
ck "...naming the host it found and the hosts policy allows" \
   'grep -q "github.example.com" "$TMP/lookalike.out" && grep -q "github.com" "$TMP/lookalike.out"'
ck "...and this is NOT a slug mismatch — the owner/name is exactly right" \
   '[ "$(ri_url_slug "$LOOKALIKE_URL")" = zenchron-dynamics/zenchron-foundry ]'
# NON-VACUITY: correct the host only.
git -C "$TMP/lookalike" remote set-url origin "$REAL_URL"
guard "$TMP/lookalike.fixed.out" "$TMP/lookalike"; rc_lookalike_fixed=$?
ck "...NON-VACUOUS: correcting only the host makes the same checkout PASS" \
   '[ "$rc_lookalike_fixed" -eq 0 ]'
# A checkout with no remote at all cannot be identified, and must not be assumed.
mkfixture "$TMP/noremote" ""
guard "$TMP/noremote.out" "$TMP/noremote"; rc_noremote=$?
ck "...an UNATTACHED checkout is refused rather than assumed to be this one" \
   '[ "$rc_noremote" -ne 0 ] && grep -q "repo-identity/unexpected-remote:" "$TMP/noremote.out"'

# =============================================================================
# 5. SABOTAGE — DIRTY PROTECTED FILES
# =============================================================================
mkfixture "$TMP/dirty" "$REAL_URL"
printf '\n# uncommitted edit\n' >> "$TMP/dirty/scripts/maintenance.sh"
guard "$TMP/dirty.out" "$TMP/dirty"; rc_dirty=$?
ck "SABOTAGE(dirty protected path): REFUSED" '[ "$rc_dirty" -ne 0 ]'
ck "...with the dirty-protected-path code" \
   'grep -q "REFUSE: repo-identity/dirty-protected-path:" "$TMP/dirty.out"'
ck "...naming the offending file, not just the fact of dirtiness" \
   'grep -q "scripts/maintenance.sh" "$TMP/dirty.out"'
ck "...and the refusal is EXPLICITLY overridable, because a clean tree is not always required" \
   'guard "$TMP/dirty.allow.out" "$TMP/dirty" --allow-dirty'
# The env form matters: scripts/admin/runner-group-patch.sh sources the guard in
# a subshell and has no flag to forward, so ZF_ALLOW_DIRTY is its only override.
# The diagnostic names both, and both must actually work.
( cd "$TMP/dirty" && ZF_ALLOW_DIRTY=1 bash scripts/lib/repo-identity.sh check ) >"$TMP/dirty.env.out" 2>&1
rc_dirty_env=$?
ck "...by flag OR by ZF_ALLOW_DIRTY, exactly as the diagnostic advertises" \
   '[ "$rc_dirty_env" -eq 0 ] && grep -q -- "--allow-dirty" "$TMP/dirty.out" &&
    grep -q "ZF_ALLOW_DIRTY" "$TMP/dirty.out"'
# NON-VACUITY, and the contributor-scoping property at the same time: a dirty
# file OUTSIDE the protected set must not refuse. Editing a README while cutting
# a release is not a safety problem and is not treated as one.
mkfixture "$TMP/dirtydoc" "$REAL_URL"
printf 'edited\n' >> "$TMP/dirtydoc/README.md"
guard "$TMP/dirtydoc.out" "$TMP/dirtydoc"; rc_dirtydoc=$?
ck "...NON-VACUOUS: an uncommitted change OUTSIDE the protected paths PASSES" \
   '[ "$rc_dirtydoc" -eq 0 ]'

# =============================================================================
# 6. SABOTAGE — MUTATING ANOTHER REGISTERED LANE  (incident 2)
# =============================================================================
mkfixture "$TMP/laneC" "$REAL_URL"
( cd "$TMP/laneC" && bash scripts/lib/repo-identity.sh register-lane laneC ) >"$TMP/reg.out" 2>&1
rc_reg=$?
ck "a lane can claim its own checkout" '[ "$rc_reg" -eq 0 ] && grep -q "registered lane laneC" "$TMP/reg.out"'
ck "...and the claim lives inside .git, so it can never be committed" \
   '[ -f "$TMP/laneC/.git/zf-lane" ] && [ -f "$TMP/laneC/.git/zf-lanes/laneC" ] &&
    [ -z "$(git -C "$TMP/laneC" status --porcelain)" ]'

# The lane itself is unaffected by its own marker.
( cd "$TMP/laneC" && ZF_LANE=laneC bash scripts/lib/repo-identity.sh check ) >"$TMP/laneC.self.out" 2>&1
rc_laneC_self=$?
ck "NON-VACUOUS: the OWNING lane still passes in its own checkout" '[ "$rc_laneC_self" -eq 0 ]'

# Another lane walks in.
( cd "$TMP/laneC" && ZF_LANE=laneD bash scripts/lib/repo-identity.sh check ) >"$TMP/foreign.out" 2>&1
rc_foreign=$?
ck "SABOTAGE(another lane's checkout): REFUSED" '[ "$rc_foreign" -ne 0 ]'
ck "...with the foreign-lane code, distinct from wrong-worktree" \
   'grep -q "REFUSE: repo-identity/foreign-lane:" "$TMP/foreign.out" &&
    ! grep -q "wrong-worktree" "$TMP/foreign.out"'
ck "...naming the owning lane and the caller" \
   'grep -q "laneC" "$TMP/foreign.out" && grep -q "laneD" "$TMP/foreign.out"'

# The coordinator case: no lane identity at all. This is exactly what happened —
# a coordinator, holding no lane, operating in a lane's live checkout.
( cd "$TMP/laneC" && bash scripts/lib/repo-identity.sh check ) >"$TMP/coord.out" 2>&1
rc_coord=$?
ck "...a caller with NO lane identity is refused too (the coordinator case)" \
   '[ "$rc_coord" -ne 0 ] && grep -q "repo-identity/foreign-lane:" "$TMP/coord.out"'
ck "...and is told how to identify itself rather than just refused" \
   'grep -q "ZF_LANE" "$TMP/coord.out"'

# A lane cannot claim a second checkout while its first is still registered.
git -C "$TMP/laneC" worktree add -q -b lane-c2 "$TMP/laneC2" >/dev/null 2>&1
( cd "$TMP/laneC2" && bash scripts/lib/repo-identity.sh register-lane laneC ) >"$TMP/regdup.out" 2>&1
rc_regdup=$?
ck "...and a lane cannot register a SECOND checkout while its first is live" \
   '[ "$rc_regdup" -ne 0 ] && grep -q "repo-identity/foreign-lane:" "$TMP/regdup.out"'
ck "...naming the checkout it already holds" 'grep -q "$TMP/laneC" "$TMP/regdup.out"'

# Registering in the wrong repository is refused before anything is written.
( cd "$TMP/wrongrepo" && git remote set-url origin "$WRONG_URL" &&
  bash scripts/lib/repo-identity.sh register-lane laneX ) >"$TMP/regwrong.out" 2>&1
rc_regwrong=$?
ck "...and a lane cannot register at all in the WRONG repository" \
   '[ "$rc_regwrong" -ne 0 ] && grep -q "repo-identity/wrong-repository:" "$TMP/regwrong.out" &&
    [ ! -f "$TMP/wrongrepo/.git/zf-lane" ]'

# BRANCH OWNERSHIP — the other half of incident 2. Something moved HEAD under a
# live lane; the next guarded operation must refuse instead of proceeding.
git -C "$TMP/laneC" checkout -q -b hijacked
( cd "$TMP/laneC" && ZF_LANE=laneC bash scripts/lib/repo-identity.sh check ) >"$TMP/hijack.out" 2>&1
rc_hijack=$?
ck "SABOTAGE(HEAD moved under a live lane): REFUSED" '[ "$rc_hijack" -ne 0 ]'
ck "...with the branch-ownership code, distinct from foreign-lane" \
   'grep -q "REFUSE: repo-identity/branch-ownership:" "$TMP/hijack.out" &&
    ! grep -q "foreign-lane" "$TMP/hijack.out"'
ck "...naming the registered branch and the one actually checked out" \
   'grep -q "master" "$TMP/hijack.out" && grep -q "hijacked" "$TMP/hijack.out"'
git -C "$TMP/laneC" checkout -q master
( cd "$TMP/laneC" && ZF_LANE=laneC bash scripts/lib/repo-identity.sh check ) >"$TMP/hijack.fixed.out" 2>&1
rc_hijack_fixed=$?
ck "...NON-VACUOUS: restoring the registered branch clears the refusal" '[ "$rc_hijack_fixed" -eq 0 ]'

# Releasing is symmetrical and leaves nothing behind.
( cd "$TMP/laneC" && bash scripts/lib/repo-identity.sh release-lane ) >/dev/null 2>&1
ck "release-lane clears the marker AND the registry entry" \
   '[ ! -f "$TMP/laneC/.git/zf-lane" ] && [ ! -f "$TMP/laneC/.git/zf-lanes/laneC" ]'
( cd "$TMP/laneC" && ZF_LANE=laneD bash scripts/lib/repo-identity.sh check ) >/dev/null 2>&1
ck "...after which any lane may use the checkout again" '[ "$?" -eq 0 ]'

# =============================================================================
# 7. THE PRE-CHANGE PROOF — the sabotage went UNDETECTED before this change
# =============================================================================
# A check that has never been shown to fail on the previous state is
# indistinguishable from a check that cannot fail. So: take the REAL guarded
# script, strip the guard block out of it to reconstruct the pre-change file,
# and run BOTH in a checkout of the wrong repository.
#
# The fixture is a miniature root that scripts/prepare-release.sh resolves to on
# its own (`ROOT=$(dirname $0)/..`), carrying real copies of the two libraries it
# sources. It dies a few steps later on an unrelated precondition; the observable
# under test is whether it reaches release work AT ALL while sitting in
# bogdaniel/zenchron-infra.
PRE="$TMP/prechange"
mkdir -p "$PRE/scripts/lib" "$PRE/policies"
cp "$ROOT/scripts/lib/common.sh" "$ROOT/scripts/lib/repo-identity.sh" "$PRE/scripts/lib/"
cp "$POLICY" "$PRE/policies/repo-identity.yaml"
cp "$ROOT/scripts/prepare-release.sh" "$PRE/scripts/prepare-release.sh"
sed '/--- BEGIN repo-identity guard/,/--- END repo-identity guard/d' \
    "$ROOT/scripts/prepare-release.sh" > "$PRE/scripts/prepare-release-prechange.sh"
git init -q "$PRE" >/dev/null 2>&1
git -C "$PRE" config user.email agent@example.invalid
git -C "$PRE" config user.name "lane fixture"
git -C "$PRE" config commit.gpgsign false
# Committed, so that the ONLY thing separating the two runs below is the remote.
# Left uncommitted, the protected-path check would refuse the corrected-remote
# run for an unrelated reason and the comparison would prove nothing.
git -C "$PRE" add -A >/dev/null 2>&1
git -C "$PRE" commit -qm fixture >/dev/null 2>&1
git -C "$PRE" remote add origin "$WRONG_URL"

ck "the pre-change reconstruction really removed the guard" \
   'grep -q require_repo_identity "$PRE/scripts/prepare-release.sh" &&
    ! grep -q require_repo_identity "$PRE/scripts/prepare-release-prechange.sh"'
ck "...and removed ONLY the guard (the rest of the script is byte-identical)" \
   '[ "$( ( diff "$PRE/scripts/prepare-release.sh" "$PRE/scripts/prepare-release-prechange.sh" |
            grep -c "^>" ) )" -eq 0 ]'

bash "$PRE/scripts/prepare-release-prechange.sh" v2026.06.01 >"$TMP/pre.out" 2>&1
bash "$PRE/scripts/prepare-release.sh"           v2026.06.01 >"$TMP/post.out" 2>&1
ck "PRE-CHANGE: the release script proceeds into release work in the WRONG repository" \
   'grep -q "Validating release tag" "$TMP/pre.out" &&
    ! grep -q "repo-identity/" "$TMP/pre.out"'
ck "POST-CHANGE: the same script in the same checkout REFUSES first" \
   'grep -q "REFUSE: repo-identity/wrong-repository:" "$TMP/post.out" &&
    ! grep -q "Validating release tag" "$TMP/post.out"'
ck "...and says nothing was tagged or pushed" \
   'grep -q "nothing was tagged or pushed" "$TMP/post.out"'
# NON-VACUITY of the whole comparison: with the remote corrected, the guarded
# script behaves exactly like the pre-change one. The guard is the difference,
# and the repository is the reason.
git -C "$PRE" remote set-url origin "$REAL_URL"
bash "$PRE/scripts/prepare-release.sh" v2026.06.01 >"$TMP/post.right.out" 2>&1
ck "...NON-VACUOUS: in the RIGHT repository the guarded script proceeds as before" \
   'grep -q "Validating release tag" "$TMP/post.right.out" &&
    ! grep -q "repo-identity/" "$TMP/post.right.out"'

# =============================================================================
# 8. BLAST RADIUS — the wiring is exactly what the policy declares
# =============================================================================
# Both directions. Declared-but-not-wired makes the policy a work of fiction;
# wired-but-not-declared makes the blast radius unknowable. Comments are stripped
# before matching: this repository has repeatedly shipped checks that matched
# their own explanatory prose.
declared="$(ri_policy_list guarded_scripts | sort)"
ck "the policy declares at least one guarded script (an empty list passes vacuously)" \
   '[ -n "$declared" ]'
missing=""
for s in $declared; do
  [ -f "$s" ] || { missing="$missing $s(absent)"; continue; }
  grep -vE '^[[:space:]]*#' "$s" | grep -q 'require_repo_identity' || missing="$missing $s"
done
ck "every DECLARED guarded script really calls the guard" \
   '[ -z "$missing" ] || { printf "not wired:%s\n" "$missing"; false; }'

actual="$(grep -rl 'require_repo_identity' scripts/ 2>/dev/null \
          | grep -v '^scripts/lib/repo-identity.sh$' \
          | while IFS= read -r f; do
              grep -vE '^[[:space:]]*#' "$f" | grep -q 'require_repo_identity' && printf '%s\n' "$f"
            done | sort)"
ck "and NO script outside the declared list calls it (the blast radius is bounded)" \
   '[ "$actual" = "$declared" ] || { printf "declared:\n%s\nactual:\n%s\n" "$declared" "$actual"; false; }'
# NON-VACUITY of that comparison: it must be able to see a caller that is not
# declared, or it would pass for any list at all.
mkdir -p "$TMP/radius/scripts"
printf 'require_repo_identity\n' > "$TMP/radius/scripts/undeclared.sh"
ck "...NON-VACUOUS: the same search finds a planted undeclared caller" \
   '[ -n "$( ( cd "$TMP/radius" && grep -rl require_repo_identity scripts/ ) )" ]'

# =============================================================================
# 9. ORDINARY CONTRIBUTORS ARE UNAFFECTED
# =============================================================================
# Not an assurance — a check. An ordinary contributor clones, builds, tests,
# lints and commits. None of those paths may reach the guard.
ck "the ordinary build/test entry points do not invoke the guard" \
   '! grep -vE "^[[:space:]]*#" tests/run-all.sh scripts/macro-validate.sh Makefile |
      grep -qE "require_repo_identity|repo-identity\.sh"'
ck "...nor do the git hooks a contributor installs" \
   '! grep -rqE "require_repo_identity|repo-identity\.sh" scripts/git-hooks/ .pre-commit-config.yaml'
ck "...nor does any guarded script sit on a Makefile or hook path" \
   '! grep -qE "prepare-release\.sh|runner-group-patch\.sh" Makefile .pre-commit-config.yaml'
ck "scripts/install-hooks.sh (the fork-facing bootstrap) is deliberately NOT guarded" \
   '! grep -q require_repo_identity scripts/install-hooks.sh &&
    ! printf "%s\n" "$declared" | grep -qx scripts/install-hooks.sh'
# The full ordinary-contributor shape, end to end: a clone that never registered
# a lane, with an uncommitted doc edit, run with no ZF_LANE in the environment.
mkfixture "$TMP/contributor" "$REAL_URL"
printf 'my change\n' >> "$TMP/contributor/README.md"
( cd "$TMP/contributor" && env -u ZF_LANE bash scripts/lib/repo-identity.sh check ) >"$TMP/contrib.out" 2>&1
rc_contrib=$?
ck "AN ORDINARY CLONE WITH NO LANE REGISTRATION PASSES UNIMPEDED" \
   '[ "$rc_contrib" -eq 0 ] || { cat "$TMP/contrib.out"; false; }'
ck "...and its ordinary git operations are untouched by the guard" \
   'git -C "$TMP/contributor" add README.md &&
    git -C "$TMP/contributor" commit -qm "contributor change" &&
    [ -z "$(git -C "$TMP/contributor" status --porcelain)" ]'

# =============================================================================
# 10. THE AMBIENT CHECKOUT IS UNTOUCHED
# =============================================================================
ck "no lane marker or registry was created in the real checkout" \
   '[ ! -e "$ROOT/.git/zf-lane" ] && [ ! -e "$ROOT/.git/zf-lanes" ]'
ck "the tracked tree is byte-identical to how this test found it" \
   '[ "$PRE_FINGERPRINT" = "$(fingerprint)" ]'

echo "----"
[ "$fail" -eq 0 ] && echo "test_repo_identity_guard: PASS" || echo "test_repo_identity_guard: FAIL"
exit "$fail"
