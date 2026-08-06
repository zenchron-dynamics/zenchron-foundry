#!/usr/bin/env bash
# Phase B — RC identity binding: validator + immutability probe + workflow shape.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

ck "validate-release-version self-test" 'bash scripts/validate-release-version.sh --self-test >/dev/null'
ck "registry-probe self-test"           'bash scripts/lib/registry-probe.sh --self-test >/dev/null'

# The four bound inputs (version, rc, expected_revision, confirmation) belonged
# to the RC publisher, which this change deleted. They return with the sealing
# path in PR B; the inventory in tests/release/test_disabled_paths_inventory.sh
# is the list that must come back with it.
# PR #65 replaced the per-version+rc+revision group with ONE literal org-wide
# cosign slot (self-hosted runners share $HOME; concurrent signing workflows
# raced each other's ~/.cosign install). Assert the serialized group instead.

# The reusable publisher that carried these call inputs was deleted. What
# replaces the binding they provided is stronger: the post-build authorizer
# takes the revision, run, attempt, repository, staging package and database
# snapshot as MANDATORY expectations and refuses if any is omitted.
ck "the post-build authorizer refuses without its bound expectations" \
   "grep -q 'every expectation is mandatory' scripts/release/authorize-staged-candidates.sh"
ck "the authorizer self-test passes" \
   "bash scripts/release/authorize-staged-candidates.sh --self-test >/dev/null 2>&1"

# --- PT-09: the ancestry gate must REFUSE an RC built from a non-master branch.
# Throwaway repo: an "origin" with master, a clone with a divergent local branch
# whose head is NOT reachable from origin/master. Run WITHOUT SKIP_ANCESTRY.
gtmp="$(mktemp -d)"
(
  set -e
  git init -q -b master "$gtmp/origin"
  git -C "$gtmp/origin" -c user.email=test@test -c user.name=test -c commit.gpgsign=false \
    commit -q --allow-empty -m "base on master"
  git clone -q "$gtmp/origin" "$gtmp/clone"
  git -C "$gtmp/clone" checkout -q -b divergent-feature
  git -C "$gtmp/clone" -c user.email=test@test -c user.name=test -c commit.gpgsign=false \
    commit -q --allow-empty -m "divergent commit, never merged"
) >/dev/null 2>&1
SIDE_SHA="$(git -C "$gtmp/clone" rev-parse HEAD)"
BASE_SHA="$(git -C "$gtmp/clone" rev-parse master)"
run_ancestry_gate() { # <sha>
  ( cd "$gtmp/clone" && \
    VERSION=v2026.07.03 RC=rc1 EXPECTED_REVISION="$1" GITHUB_SHA="$1" \
    CONFIRMATION="PUBLISH-v2026.07.03-rc1-$1" GITHUB_REF=refs/heads/master \
    bash "$ROOT/scripts/validate-release-version.sh" ) >/dev/null 2>&1
}
ck "ancestry gate accepts a master-reachable revision"    'run_ancestry_gate "$BASE_SHA"'
ck "ancestry gate REFUSES an RC from a non-master branch" '! run_ancestry_gate "$SIDE_SHA"'
rm -rf "$gtmp"

echo "----"; [ "$fail" -eq 0 ] && echo "test_rc_identity: PASS" || echo "test_rc_identity: FAIL"
exit $fail
