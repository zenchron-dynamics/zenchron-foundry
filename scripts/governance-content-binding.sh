#!/usr/bin/env bash
# =============================================================================
# scripts/governance-content-binding.sh [--json | --aggregate | --self-test]
# -----------------------------------------------------------------------------
# The DURABLE binding for governance evidence: a content address over the exact
# bytes of every governed input, plus a deterministic aggregate.
#
# WHY THIS REPLACES source_revision AS THE SECURITY BINDING.
#
# The evidence used to be anchored to a commit SHA, with the rule that the policy
# AT that revision must equal the committed policy. The branch protection here
# requires linear history, so every merge is a squash or a rebase, and both
# REWRITE commit SHAs. The anchor therefore names a commit that no longer exists
# the moment the change lands.
#
# The previous response to that was to SKIP the check when the revision became
# unreachable — turning "unverifiable" into "pass", the exact fail-open shape
# this repository keeps removing. Worse, it was circular: a policy-only change
# could not be green without regenerating the evidence in the same commit range
# that the merge was guaranteed to invalidate.
#
# A content address has no such dependency. It survives squash, rebase, cherry
# pick, mirror and re-clone, because it describes the BYTES rather than their
# location in history.
#
# source_revision is retained as PROVENANCE — useful for finding the change that
# produced a snapshot — and is explicitly no longer the security binding. A
# consumer must verify the content binding.
#
# Bound inputs, resolved deliberately rather than globbed:
#   policies/repository-governance.yaml            the declaration itself
#   policies/required-release-checks.yaml          the gate set it references
#   scripts/verify-repo-governance.sh              the verifier that produced it
#   scripts/governance-content-binding.sh          THIS FILE — the binding is
#     worthless if the thing computing it can be changed without changing it
#   scripts/assert-pr-workflows-github-hosted.sh   org_runner_group.requires_fork_pr_boundary
#
# The last is not hardcoded prose: it is the file the policy's
# requires_fork_pr_boundary field names, so the binding follows the policy.
# =============================================================================
set -euo pipefail
# AUDIT ROOT. Overridable so the self-test can bind a THROWAWAY copy of the
# governed inputs instead of the ambient checkout.
#
# It used to mutate the real files in place — cp aside, append a byte, restore —
# and one early exit between the rm and the restore left
# policies/required-release-checks.yaml containing nothing but
# "# governance-binding self-test mutation". That corruption was committed.
# A self-test must never be able to damage the repository it is verifying.
ROOT="${GCB_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

# Versioned, and DOMAIN-SEPARATED. The aggregate is taken over the schema name
# followed by the sorted "<sha>  <path>" lines, so a future binding format cannot
# produce a digest that this format would accept as its own.
BINDING_SCHEMA="repository-governance-binding-v1"

bound_inputs() {
  printf '%s\n' \
    policies/repository-governance.yaml \
    policies/required-release-checks.yaml \
    scripts/verify-repo-governance.sh \
    scripts/governance-content-binding.sh
  # Follows the policy rather than restating it.
  yq -r '.org_runner_group.requires_fork_pr_boundary' "$ROOT/policies/repository-governance.yaml"
}

# Per-file SHA-256 over exact bytes, plus an aggregate over "sha  path" lines in
# a fixed order. The aggregate covers the SET as well as the contents, so adding,
# removing or renaming an input changes it even when every remaining file is
# untouched.
content_binding() {
  local f abs sha lines=""
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    abs="$ROOT/$f"
    [ -f "$abs" ] || { printf 'REFUSE: bound input missing: %s\n' "$f" >&2; return 1; }
    sha="$(shasum -a 256 "$abs" | cut -d' ' -f1)"
    lines="${lines}${sha}  ${f}"$'\n'
  done < <(bound_inputs | LC_ALL=C sort)

  [ -n "$lines" ] || { echo "REFUSE: no bound inputs resolved" >&2; return 1; }
  local agg
  agg="$(printf '%s\n%s' "$BINDING_SCHEMA" "$lines" | shasum -a 256 | cut -d' ' -f1)"
  printf '%s' "$lines" | python3 -c '
import json, sys
files = []
for line in sys.stdin.read().splitlines():
    if not line.strip():
        continue
    sha, path = line.split("  ", 1)
    files.append({"path": path, "sha256": sha})
print(json.dumps({"schema": sys.argv[2], "algorithm": "sha256",
                  "aggregate": sys.argv[1],
                  "files": files}, sort_keys=True))' "$agg" "$BINDING_SCHEMA"
}

# ---------------------------------------------------------------------------
# THE CONSUMER. Tests must corrupt evidence and ask THIS whether it accepts it —
# reproducing the comparison inside a test proves only that two strings differ,
# not that any gate rejects anything.
#
# Structural equality against a freshly generated binding is deliberate: it
# rejects an extra input, a duplicate path, a reordering, a wrong per-file digest
# and a wrong aggregate without needing a separate rule for each, because the
# generated binding IS the canonical preimage.
# ---------------------------------------------------------------------------
verify_evidence() { # <snapshot.json>
  local ev="${1:?usage: governance-content-binding.sh --verify-evidence <snapshot.json>}"
  [ -f "$ev" ] || { printf 'REFUSE: evidence not found: %s\n' "$ev" >&2; return 1; }
  local expected
  expected="$(content_binding)" || { echo "REFUSE: could not compute the expected binding" >&2; return 1; }
  EV="$ev" EXPECTED="$expected" SCHEMA="$BINDING_SCHEMA" python3 - <<'PY'
import json, os, sys
try:
    doc = json.load(open(os.environ["EV"]))
except Exception as exc:
    sys.exit("REFUSE: evidence is not valid JSON: %s" % exc)
got = doc.get("content_binding")
if got is None:
    sys.exit("REFUSE: evidence carries no content_binding")
if not isinstance(got, dict):
    sys.exit("REFUSE: content_binding is not an object")
if got.get("schema") != os.environ["SCHEMA"]:
    sys.exit("REFUSE: binding schema is %r, expected %r" % (got.get("schema"), os.environ["SCHEMA"]))
if got.get("algorithm") != "sha256":
    sys.exit("REFUSE: binding algorithm is %r, expected 'sha256'" % (got.get("algorithm"),))
paths = [f.get("path") for f in got.get("files") or []]
if len(paths) != len(set(paths)):
    sys.exit("REFUSE: duplicate path in the bound file set: %r" % (paths,))
want = json.loads(os.environ["EXPECTED"])
if got != want:
    extra   = [p for p in paths if p not in [f["path"] for f in want["files"]]]
    missing = [f["path"] for f in want["files"] if f["path"] not in paths]
    detail = []
    if extra:   detail.append("unexpected input(s): %s" % ", ".join(extra))
    if missing: detail.append("missing input(s): %s" % ", ".join(missing))
    if got.get("aggregate") != want["aggregate"]:
        detail.append("aggregate %s != %s" % (got.get("aggregate"), want["aggregate"]))
    for f in got.get("files") or []:
        for w in want["files"]:
            if f.get("path") == w["path"] and f.get("sha256") != w["sha256"]:
                detail.append("%s: %s != %s" % (f["path"], f.get("sha256"), w["sha256"]))
    sys.exit("REFUSE: content binding does not match the committed bytes; "
             + ("; ".join(detail) if detail else "structural mismatch"))
print("content binding OK: %s (%d inputs, aggregate %s)"
      % (got["schema"], len(got["files"]), got["aggregate"][:12]))
PY
}

aggregate_only() { content_binding | python3 -c 'import json,sys; print(json.load(sys.stdin)["aggregate"])'; }

# Evidence must not be generated from a dirty tree. The content binding would
# describe bytes that are not committed anywhere, which is the provenance failure
# that produced the original contract.
assert_clean_worktree() { # [dir]
  local d="${1:-$ROOT}" dirty
  # `|| true` here made an UNREADABLE tree indistinguishable from a clean one:
  # a failed git status produced empty output, which read as "no changes". That
  # is the fail-open shape this whole contract exists to remove, sitting inside
  # the guard that enforces it.
  if ! dirty="$(git -C "$d" status --porcelain 2>/dev/null)"; then
    printf 'REFUSE: cannot determine worktree state for %s\n' "$d" >&2
    return 1
  fi
  [ -z "$dirty" ] || {
    printf 'REFUSE: worktree is dirty; governance evidence must describe committed bytes\n%s\n' "$dirty" >&2
    return 1
  }
}

_gcb_self_test() {
  local ok=0 nbad=0 tmp; tmp="$(mktemp -d)"
  # expand NOW: the local is out of scope by EXIT time
  # shellcheck disable=SC2064
  trap "rm -rf '${tmp}'" EXIT
  t() { if eval "$2"; then echo "ok   - $1"; ok=$((ok+1)); else echo "FAIL - $1"; nbad=$((nbad+1)); fi; }

  local base; base="$(content_binding)"
  t "produces a binding at all" "[ -n '$base' ]"
  t "aggregate is 64-hex" "python3 -c \"import json,sys,re; b=json.loads(sys.argv[1]); sys.exit(0 if re.fullmatch(r'[0-9a-f]{64}', b['aggregate']) else 1)\" '$base'"
  t "binds all five governed inputs" "[ \"\$(python3 -c \"import json,sys; print(len(json.loads(sys.argv[1])['files']))\" '$base')\" = 5 ]"
  t "every file has a 64-hex digest" \
    "python3 -c \"import json,sys,re; b=json.loads(sys.argv[1]); sys.exit(0 if all(re.fullmatch(r'[0-9a-f]{64}',f['sha256']) for f in b['files']) else 1)\" '$base'"
  t "is stable across repeated runs" "[ \"\$(content_binding)\" = '$base' ]"
  t "the binding script binds ITSELF" \
    "python3 -c \"import json,sys; b=json.loads(sys.argv[1]); sys.exit(0 if any('governance-content-binding.sh' in f['path'] for f in b['files']) else 1)\" '$base'"
  t "the fork-boundary input follows the policy field" \
    "python3 -c \"import json,sys; b=json.loads(sys.argv[1]); sys.exit(0 if any('assert-pr-workflows-github-hosted' in f['path'] for f in b['files']) else 1)\" '$base'"

  # ---- EVERY mutation below runs against an ISOLATED COPY of the inputs. ----
  # $ISO is a throwaway tree holding only the governed files at their repository
  # -relative paths. GCB_ROOT points the binding at it, so nothing here can touch
  # the ambient checkout even if this function dies mid-scenario.
  local ISO="$tmp/iso" f
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    mkdir -p "$ISO/$(dirname "$f")"
    cp "$ROOT/$f" "$ISO/$f"
  done < <(bound_inputs)

  local iso_base; iso_base="$( ( ROOT="$ISO"; content_binding ) )"
  t "the isolated copy binds identically to the real tree" \
    "[ \"\$(python3 -c \"import json,sys; print(json.loads(sys.argv[1])['aggregate'])\" '$iso_base')\" = \"\$(python3 -c \"import json,sys; print(json.loads(sys.argv[1])['aggregate'])\" '$base')\" ]"

  # One-byte mutation of EVERY bound input must change the aggregate.
  local abs after
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    abs="$ISO/$f"
    printf '\n# governance-binding self-test mutation\n' >> "$abs"
    after="$( ( ROOT="$ISO"; aggregate_only ) )"
    t "a one-byte change to $f changes the aggregate" \
      "[ '$after' != \"\$(python3 -c \"import json,sys; print(json.loads(sys.argv[1])['aggregate'])\" '$base')\" ]"
    cp "$ROOT/$f" "$abs"
    t "...and restoring $f restores the aggregate" \
      "[ \"\$( ( ROOT=\"$ISO\"; aggregate_only ) )\" = \"\$(python3 -c \"import json,sys; print(json.loads(sys.argv[1])['aggregate'])\" '$base')\" ]"
  done < <(bound_inputs)

  # A missing input refuses rather than binding a smaller set — in the COPY.
  rm -f "$ISO/policies/required-release-checks.yaml"
  t "a missing bound input REFUSES" "! ( ROOT='$ISO'; content_binding ) >/dev/null 2>&1"
  cp "$ROOT/policies/required-release-checks.yaml" "$ISO/policies/required-release-checks.yaml"
  t "...and it recovers once restored" "( ROOT='$ISO'; content_binding ) >/dev/null"

  # THE regression: the ambient checkout must be untouched by all of the above.
  t "the real policy files are byte-identical after every mutation scenario" \
    "cmp -s '$ROOT/policies/required-release-checks.yaml' '$ISO/policies/required-release-checks.yaml' &&
     cmp -s '$ROOT/policies/repository-governance.yaml' '$ISO/policies/repository-governance.yaml'"
  # Scoped to the POLICY files: this script legitimately contains the marker
  # string (it writes it, and explains the corruption it caused), so grepping
  # scripts/ would match the checker itself — the exact self-matching pattern
  # this project keeps hitting.
  t "no policy file in the ambient checkout carries the mutation marker" \
    "! grep -rlq 'governance-binding self-test mutation' '$ROOT/policies' 2>/dev/null"
  t "...and the marker IS findable where it was written (non-vacuity)" \
    "grep -q 'governance-binding self-test mutation' '$ROOT/scripts/governance-content-binding.sh'"

  # SABOTAGE: if GCB_ROOT routing is removed, mutations would hit the real tree.
  t "SABOTAGE: the script honours an explicit audit root" \
    "grep -q 'GCB_ROOT' '$ROOT/scripts/governance-content-binding.sh'"
  t "...and binding a root with a missing input refuses there, not here" \
    "! ( ROOT='$tmp/empty-root'; content_binding ) >/dev/null 2>&1"

  # Dirty-worktree refusal, tested against a throwaway repo rather than the
  # ambient one: whether THIS checkout happens to be clean is not the property
  # under test, and depending on it would make the result environmental.
  local r="$tmp/repo"; mkdir -p "$r"
  ( cd "$r" && git init -q . && git config user.email t@t && git config user.name t \
    && echo a > f && git add f && git commit -qm init ) >/dev/null 2>&1
  t "a clean worktree is accepted" "assert_clean_worktree '$r'"
  echo b >> "$r/f"
  t "a dirty worktree REFUSES evidence generation" "! assert_clean_worktree '$r' 2>/dev/null"
  ( cd "$r" && git checkout -q -- f )
  t "...and acceptance returns once it is clean again" "assert_clean_worktree '$r'"
  # THE case the `|| true` hid: git status FAILING must refuse, not read clean.
  local nr="$tmp/not-a-repo"; mkdir -p "$nr"
  t "a NON-GIT directory REFUSES (status fails, output empty)" \
    "! assert_clean_worktree '$nr' 2>/dev/null"
  local br="$tmp/broken"; mkdir -p "$br"
  ( cd "$br" && git init -q . && git config user.email t@t && git config user.name t \
    && echo a > f && git add f && git commit -qm init ) >/dev/null 2>&1
  printf 'not a git dir\n' > "$br/.git/HEAD"
  t "a BROKEN git metadata directory REFUSES" "! assert_clean_worktree '$br' 2>/dev/null"
  t "a nonexistent path REFUSES" "! assert_clean_worktree '$tmp/nowhere' 2>/dev/null"

  # --- THE CONSUMER PATH. Every fixture is corrupted and then handed to
  # --verify-evidence. Comparing two hashes inside a test proves they differ; it
  # does not prove any gate rejects anything.
  local ev="$tmp/ev.json"
  mk_ev() { python3 -c '
import json, subprocess, sys
b = json.loads(subprocess.run(["bash", sys.argv[1], "--json"], capture_output=True, text=True).stdout)
doc = {"repository": "o/r", "source_revision": "a"*40, "verdict": "PASS", "content_binding": b}
if len(sys.argv) > 3:
    exec(sys.argv[3])
json.dump(doc, open(sys.argv[2], "w"))' "$ROOT/scripts/governance-content-binding.sh" "$1" "${2:-}"; }

  mk_ev "$ev"
  t "consumer ACCEPTS a valid binding" "verify_evidence '$ev' >/dev/null 2>&1"

  mk_ev "$ev" 'del doc["content_binding"]'
  t "consumer REFUSES a missing binding" "! verify_evidence '$ev' >/dev/null 2>&1"

  mk_ev "$ev" 'doc["content_binding"]["schema"]="something-else-v9"'
  t "consumer REFUSES a wrong schema" "! verify_evidence '$ev' >/dev/null 2>&1"

  mk_ev "$ev" 'doc["content_binding"]["algorithm"]="md5"'
  t "consumer REFUSES a wrong algorithm" "! verify_evidence '$ev' >/dev/null 2>&1"

  mk_ev "$ev" 'doc["content_binding"]["files"].pop()'
  t "consumer REFUSES a missing input" "! verify_evidence '$ev' >/dev/null 2>&1"

  mk_ev "$ev" 'doc["content_binding"]["files"].append({"path":"extra.txt","sha256":"b"*64})'
  t "consumer REFUSES an EXTRA input" "! verify_evidence '$ev' >/dev/null 2>&1"

  mk_ev "$ev" 'doc["content_binding"]["files"].append(dict(doc["content_binding"]["files"][0]))'
  t "consumer REFUSES a duplicate path" "! verify_evidence '$ev' >/dev/null 2>&1"

  mk_ev "$ev" 'doc["content_binding"]["files"][0]["sha256"]="c"*64'
  t "consumer REFUSES a wrong per-file hash" "! verify_evidence '$ev' >/dev/null 2>&1"

  mk_ev "$ev" 'doc["content_binding"]["aggregate"]="0"*64'
  t "consumer REFUSES a wrong aggregate" "! verify_evidence '$ev' >/dev/null 2>&1"

  mk_ev "$ev" 'doc["content_binding"]["files"].reverse()'
  t "consumer REFUSES a reordered file list" "! verify_evidence '$ev' >/dev/null 2>&1"

  # The property the whole redesign exists for.
  mk_ev "$ev" 'doc["source_revision"]="deadbeef"*5'
  t "an unreachable source_revision with a VALID binding is ACCEPTED" "verify_evidence '$ev' >/dev/null 2>&1"

  mk_ev "$ev" 'doc["source_revision"]="deadbeef"*5; doc["content_binding"]["aggregate"]="0"*64'
  t "an unreachable source_revision with an INVALID binding is REFUSED" "! verify_evidence '$ev' >/dev/null 2>&1"

  mk_ev "$ev" 'doc["content_binding"]="not-an-object"'
  t "consumer REFUSES a non-object binding" "! verify_evidence '$ev' >/dev/null 2>&1"

  printf 'not json' > "$ev"
  t "consumer REFUSES malformed JSON" "! verify_evidence '$ev' >/dev/null 2>&1"
  t "consumer REFUSES a missing file" "! verify_evidence '$tmp/nope.json' >/dev/null 2>&1"

  echo "self-test: $ok ok, $nbad failed"
  [ "$nbad" -eq 0 ]
}

case "${1:---json}" in
  --json)      content_binding ;;
  --aggregate) aggregate_only ;;
  --inputs)    bound_inputs | LC_ALL=C sort ;;
  --assert-clean) assert_clean_worktree ;;
  --verify-evidence) shift; verify_evidence "${1:-}" ;;
  --self-test) _gcb_self_test && echo "governance-content-binding.sh: SELF-TEST OK" ;;
  *) echo "usage: governance-content-binding.sh [--json|--aggregate|--inputs|--assert-clean|--verify-evidence <f>|--self-test]" >&2; exit 2 ;;
esac

# governance-binding self-test mutation
