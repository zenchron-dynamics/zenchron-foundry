#!/usr/bin/env bash
# =============================================================================
# scripts/admin/assert-pr-issue-disposition.sh <pr-number>
# -----------------------------------------------------------------------------
# Every issue a pull request will close must be DECLARED, and every issue it
# declares it will close must actually be one GitHub closes.
#
# WHY THIS EXISTS. Three issues were closed by accident: #96, #97, and #100
# would have been. Not by a stray `Closes #N` — by headings written to explain
# the opposite:
#
#     ## Why this does not close #100
#
# GitHub's parser sees `close #100` and ignores every word around it. The prose
# saying an issue must stay open is what closed it. Two of those had to be
# reopened, leaving false completion events in a permanent audit timeline.
#
# The first attempt at a guard was a regex sweep for closing keywords. It missed
# exactly this case, because it searched for `closes` and the text said `close`.
# Approximating GitHub's parser is the wrong shape of solution: the parser is
# the authority on what it will close, so ASK IT.
#
# This compares two sets:
#
#   DECLARED  the `Closes:` lines in the pull request's `## Issue disposition`
#             footer — what the author says will happen
#   ACTUAL    GraphQL closingIssuesReferences — what GitHub will actually do
#
# They must be EQUAL. A declared issue GitHub will not close is a false promise;
# an issue GitHub will close that was never declared is the accident above.
#
# Expected footer:
#
#     ## Issue disposition
#
#     Closes: #122
#     Stays open: #100
#
# `Stays open:` is documentation for the reader — the guard proves those issues
# are NOT in the actual set, which is the property that matters.
#
# TWO CLOSURE PATHS, both checked:
#
#   1. The PULL REQUEST. GitHub derives closingIssuesReferences from the body
#      and from Development-panel links. Compared against the declared `Closes:`.
#
#   2. The COMMIT that lands on the default branch. This repository squashes
#      with `squash_merge_commit_message: COMMIT_MESSAGES`, so every original
#      commit message is concatenated into it, and the PR title normally becomes
#      its subject. GitHub parses closing keywords there INDEPENDENTLY of the
#      pull request. Path 1 can report "closes nothing" while path 2 closes an
#      issue — that is exactly what happened to #126 via #141.
#
#   Path 2 is handled STRICTLY: no closing keyword may appear in the title or
#   any commit message at all, even for an issue the footer declares. The footer
#   is then the only place closure intent can live.
#
# WHAT THIS CANNOT PREDICT. `gh pr merge --squash` accepts `--subject` and
# `--body`, which replace the squash commit message entirely. Those are operator
# inputs supplied at merge time, after every pre-merge check has run, so no
# guard can see them. If a custom subject or body is used, it must be checked by
# the operator; the safe default is to supply neither and let the checked title
# and commit messages stand.
#
# Usage:
#   assert-pr-issue-disposition.sh <pr-number>
#   assert-pr-issue-disposition.sh --self-test
#
# Env: REPO (default zenchron-dynamics/zenchron-foundry),
#      PR_BODY_FN / CLOSING_REFS_FN (injectable for offline tests)
# Exit: 0 declared and actual agree; 1 on any divergence.
# =============================================================================
set -euo pipefail

REPO="${REPO:-zenchron-dynamics/zenchron-foundry}"

_pr_body() { gh pr view "$1" --repo "$REPO" --json body --jq '.body'; }
pr_body() { "${PR_BODY_FN:-_pr_body}" "$1"; }

_closing_refs() {
  gh api graphql -f query="{repository(owner:\"${REPO%%/*}\",name:\"${REPO##*/}\"){pullRequest(number:$1){closingIssuesReferences(first:50){nodes{number}}}}}" \
    --jq '.data.repository.pullRequest.closingIssuesReferences.nodes[].number'
}
closing_refs() { "${CLOSING_REFS_FN:-_closing_refs}" "$1"; }

_pr_title() { gh pr view "$1" --repo "$REPO" --json title --jq '.title'; }
pr_title() { "${PR_TITLE_FN:-_pr_title}" "$1"; }

# Every commit as `<sha>\t<message-with-newlines-escaped>`, paginated. The SHA
# travels with the message so a diagnostic can name the offending commit.
_pr_commits() {
  gh api --paginate "repos/${REPO}/pulls/$1/commits?per_page=100" \
    --jq '.[] | "\(.sha)\t\(.commit.message | gsub("\n"; "\\n"))"'
}
pr_commits() { "${PR_COMMITS_FN:-_pr_commits}" "$1"; }

# ---------------------------------------------------------------------------
# check_disposition <declared-body> <actual-refs>
#
# Pure text/set logic, so the self-test drives it without network.
# ---------------------------------------------------------------------------
check_disposition() {
  BODY="$1" ACTUAL="$2" python3 - <<'PY'
import os, re, sys

body   = os.environ["BODY"]
actual = {int(x) for x in os.environ["ACTUAL"].split() if x.strip()}

# GitHub's closing keywords, in every form it accepts.
KEYWORD = re.compile(
    r"\b(close[sd]?|fix(e[sd])?|resolve[sd]?)\b\s*:?\s*#(\d+)", re.I)

# Fenced code blocks are BLANKED, not removed: a body that documents the
# expected footer, or quotes an offending heading to explain it, must not be
# parsed as if that were the real thing. Blanking preserves line numbering so
# section boundaries stay correct. Found by running this guard on its own pull
# request, which quoted both.
raw = body.split("\n")
lines, fence = [], None
for l in raw:
    m = re.match(r"^\s*(`{3,}|~{3,})", l)
    if fence is None and m:
        fence = m.group(1)[0] * 3
        lines.append("")
        continue
    if fence is not None:
        if m and m.group(1)[0] * 3 == fence:
            fence = None
        lines.append("")
        continue
    lines.append(l)

start = None
for i, l in enumerate(lines):
    if re.fullmatch(r"#{1,6}\s+Issue disposition\s*", l.strip()):
        start = i
        break
if start is None:
    sys.exit("REFUSE: no '## Issue disposition' section.\n"
             "  Every pull request must state which issues it closes and which\n"
             "  stay open, so the intent can be checked against what GitHub will\n"
             "  actually do.\n"
             "  Expected:\n"
             "    ## Issue disposition\n\n    Closes: #123\n    Stays open: #456")

# The section runs to the next heading of the same or higher level.
level = len(lines[start]) - len(lines[start].lstrip("#"))
end = len(lines)
for i in range(start + 1, len(lines)):
    m = re.match(r"^(#{1,6})\s+", lines[i])
    if m and len(m.group(1)) <= level:
        end = i
        break
section = lines[start:end]
section_text = "\n".join(section)

declared, stays = set(), set()
for l in section:
    m = re.match(r"^\s*Closes:\s*(.+)$", l, re.I)
    if m:
        declared |= {int(n) for n in re.findall(r"#(\d+)", m.group(1))}
    m = re.match(r"^\s*Stays open:\s*(.+)$", l, re.I)
    if m:
        stays |= {int(n) for n in re.findall(r"#(\d+)", m.group(1))}

# A closing keyword ANYWHERE else is the accident this exists to prevent —
# including inside prose explaining that an issue must NOT close.
outside = "\n".join(lines[:start] + lines[end:])
stray = sorted({int(m.group(3)) for m in KEYWORD.finditer(outside)})
if stray:
    print("REFUSE: closing keyword(s) outside the disposition footer: %s"
          % ", ".join("#%d" % n for n in stray), file=sys.stderr)
    for m in KEYWORD.finditer(outside):
        ctx = outside[max(0, m.start()-45):m.end()+25].replace("\n", " ")
        print("    …%s…" % ctx.strip(), file=sys.stderr)
    print("  GitHub parses these regardless of the surrounding words. A heading\n"
          "  such as 'Why this does not close #100' CLOSES #100.\n"
          "  Reword to avoid the verb, e.g. 'Why #100 stays open'.", file=sys.stderr)
    sys.exit(1)

problems = []
for n in sorted(declared - actual):
    problems.append("declared 'Closes: #%d' but GitHub will NOT close it — the "
                    "keyword is missing or malformed" % n)
for n in sorted(actual - declared):
    problems.append("GitHub WILL close #%d but it is not declared — this is how "
                    "an issue gets closed by accident" % n)
for n in sorted(stays & actual):
    problems.append("declared 'Stays open: #%d' but GitHub WILL close it" % n)
for n in sorted(stays & declared):
    problems.append("#%d is listed as both Closes and Stays open" % n)

def fmt(s):
    return ", ".join("#%d" % n for n in sorted(s)) if s else "(none)"

print("  declared Closes    : %s" % fmt(declared))
print("  GitHub will close  : %s" % fmt(actual))
print("  declared Stays open: %s" % fmt(stays))

if problems:
    print("REFUSE: issue disposition does not match GitHub:", file=sys.stderr)
    for p in problems:
        print("  %s" % p, file=sys.stderr)
    sys.exit(1)
print("DISPOSITION OK: declared and actual agree")
PY
}

# ---------------------------------------------------------------------------
# check_no_closing_keywords <pr-title> <commits: sha\tmessage per line>
#
# STRICT: the `## Issue disposition` footer is the SOLE authority on what a pull
# request closes. No closing keyword may appear in the PR TITLE or in any COMMIT
# SUBJECT OR BODY — not even for an issue the footer already declares.
#
# WHY, concretely. This repository squashes with
# `squash_merge_commit_message: COMMIT_MESSAGES`, so every original commit
# message is concatenated into the commit that lands on the default branch, and
# the PR title normally becomes its subject. GitHub parses closing keywords
# there independently of the pull-request body and of closingIssuesReferences.
#
# #141 proved it: the footer said `Stays open: #126`, GraphQL reported it would
# close nothing, the body-vs-GraphQL check passed — and #126 closed anyway,
# because the FIRST of three commits carried `Closes #126` from before the scope
# was narrowed. Squash 7ab8151 inherited it.
#
# Union semantics (allow the keyword, require the sets to agree) was rejected
# deliberately: it keeps two independent authorities, and lets historical
# implementation messages overrule the final disposition. Under strict, they
# cannot.
#
# Fenced blocks are NOT exempt here, unlike the body. A commit message is not a
# documentation page, and guessing whether GitHub honours markdown fencing in
# commit text would be approximating the parser again.
#
# Non-closing references stay allowed: Refs, Addresses, Partially addresses,
# Related to.
# ---------------------------------------------------------------------------
check_no_closing_keywords() {
  TITLE="$1" COMMITS="$2" python3 - <<'PY'
import os, re, sys

KEYWORD = re.compile(
    r"\b(close[sd]?|fix(?:e[sd])?|resolve[sd]?)\b\s*:?\s*#(\d+)", re.I)

title   = os.environ["TITLE"]
commits = os.environ["COMMITS"]

problems = []

for m in KEYWORD.finditer(title):
    problems.append(("PR title", title.strip(), m.group(0)))

seen = 0
for raw in commits.split("\n"):
    if not raw.strip():
        continue
    if "\t" not in raw:
        sys.exit("REFUSE: malformed commit record (no sha/message separator): %r"
                 % raw[:80])
    sha, msg = raw.split("\t", 1)
    if not re.fullmatch(r"[0-9a-f]{7,40}", sha):
        sys.exit("REFUSE: malformed commit sha: %r" % sha[:40])
    seen += 1
    msg = msg.replace("\\n", "\n")
    for line in msg.split("\n"):
        for m in KEYWORD.finditer(line):
            problems.append(("commit %s" % sha[:7], line.strip(), m.group(0)))

if seen == 0:
    sys.exit("REFUSE: the pull request reports no commits — an empty commit set "
             "cannot be checked, and treating it as clean would skip this gate")

if problems:
    print("REFUSE: closing keyword(s) outside the disposition footer.", file=sys.stderr)
    print("  The footer is the SOLE authority on what this pull request closes.",
          file=sys.stderr)
    print("  A squash merge copies the PR title and every commit message into the",
          file=sys.stderr)
    print("  commit that lands on the default branch, and GitHub parses closing",
          file=sys.stderr)
    print("  keywords there too — that is how #141 closed #126 while its footer",
          file=sys.stderr)
    print("  said 'Stays open: #126'.", file=sys.stderr)
    for src, line, hit in problems:
        print("", file=sys.stderr)
        print("    source: %s" % src, file=sys.stderr)
        print("    line:   %s" % (line[:150] or "(empty)"), file=sys.stderr)
        print("    match:  %s" % hit, file=sys.stderr)
    print("", file=sys.stderr)
    print("  Reword to a non-closing reference — Refs #N, Addresses #N,",
          file=sys.stderr)
    print("  Partially addresses #N, Related to #N — and keep closure intent",
          file=sys.stderr)
    print("  only in the '## Issue disposition' footer.", file=sys.stderr)
    sys.exit(1)

print("  no closing keyword in the PR title or any of %d commit message(s)" % seen)
PY
}

assert_pr() { # assert_pr <pr-number>
  local pr="$1"
  case "$pr" in ''|*[!0-9]*) echo "REFUSE: pr must be a number, got '$pr'" >&2; return 1 ;; esac
  local body refs
  body="$(pr_body "$pr")" || { echo "REFUSE: cannot read PR #${pr}" >&2; return 1; }
  # An unreadable API is a refusal, never an assumed-empty set: an empty
  # `actual` would make every undeclared closure invisible.
  refs="$(closing_refs "$pr")" || { echo "REFUSE: cannot read closingIssuesReferences for #${pr}" >&2; return 1; }
  local title commits
  title="$(pr_title "$pr")" || { echo "REFUSE: cannot read the title of PR #${pr}" >&2; return 1; }
  # An unreadable commit list is a refusal: an empty set would silently skip the
  # strict check, which is the surface that closed #126.
  commits="$(pr_commits "$pr")" || { echo "REFUSE: cannot read the commits of PR #${pr}" >&2; return 1; }

  echo "PR #${pr} (${REPO}):"
  check_no_closing_keywords "$title" "$commits" || return 1
  check_disposition "$body" "$refs"
}

# ---------------------------------------------------------------------------
_apid_self_test() {
  command -v python3 >/dev/null || { echo "SKIP - python3 absent"; return 0; }
  local ok=0 fail=0
  t() { # t <expect 0|1> <name> <body> <actual>
    local want="$1" name="$2" rc=0
    check_disposition "$3" "$4" >/dev/null 2>&1 || rc=$?
    if [ "$rc" -eq "$want" ]; then echo "  ok   $name"; ok=$((ok+1));
    else echo "  FAIL $name (rc=$rc want=$want)"; fail=$((fail+1)); fi
  }

  local GOOD='## Summary

Does things.

## Issue disposition

Closes: #122
Stays open: #100'

  t 0 "declared and actual agree"                  "$GOOD" "122"
  t 1 "GitHub closes an UNDECLARED issue"          "$GOOD" "122 999"
  t 1 "declared Closes that GitHub will not close" "$GOOD" ""
  t 1 "an issue declared to stay open IS closed"   "$GOOD" "122 100"

  # THE REGRESSION. This heading closed #96, #97 and would have closed #100.
  local NEGATED='## Summary

Work.

## Why this does not close #100

Because the evidence is unreviewed.

## Issue disposition

Closes: #122'
  t 1 "a NEGATED closing phrase in prose is refused" "$NEGATED" "122 100"
  t 1 "...and refused even when GitHub has not caught up yet" "$NEGATED" "122"

  # Every keyword form GitHub accepts.
  for kw in close closes closed fix fixes fixed resolve resolves resolved; do
    t 1 "stray '$kw #55' outside the footer is refused" \
      "## Notes
This $kw #55 somehow.

## Issue disposition

Closes: #122" "122"
  done
  t 1 "'Closes: #55' outside the footer is refused" \
    "## Notes
Closes: #55

## Issue disposition

Closes: #122" "122"

  t 1 "a missing disposition section is refused" \
    "## Summary
No footer here." "122"
  t 0 "an empty disposition (closes nothing) is fine" \
    "## Issue disposition

Stays open: #100" ""
  t 1 "...but not when GitHub will close something" \
    "## Issue disposition

Stays open: #100" "100"
  t 0 "multiple issues on one Closes line" \
    "## Issue disposition

Closes: #1, #2" "1 2"
  t 0 "multiple Closes lines" \
    "## Issue disposition

Closes: #1
Closes: #2" "1 2"
  t 1 "an issue in BOTH lists is refused" \
    "## Issue disposition

Closes: #7
Stays open: #7" "7"
  t 0 "the section ends at the next same-level heading" \
    "## Issue disposition

Closes: #1

## Later
Unrelated prose with no keywords." "1"
  t 0 "a deeper heading inside the section does not end it" \
    "## Issue disposition

### Detail
Closes: #1" "1"

  # --- fenced code blocks -----------------------------------------------------
  # Found by running this guard on its own pull request, which both DOCUMENTED
  # the expected footer and QUOTED an offending heading. Either would otherwise
  # be parsed as the real thing.
  t 0 "an EXAMPLE footer in a fence is not the real footer" \
    '## Expected format

```
## Issue disposition

Closes: #999
```

## Issue disposition

Closes: #122' "122"
  t 0 "a QUOTED offending heading in a fence is not a stray keyword" \
    '## Background

```
## Why this does not close #55
```

## Issue disposition

Closes: #122' "122"
  t 0 "tilde fences behave the same" \
    '## Background

~~~
close #55
~~~

## Issue disposition

Closes: #122' "122"
  t 1 "...but a real keyword OUTSIDE any fence is still caught" \
    '## Background

```
close #55
```

This really does close #77.

## Issue disposition

Closes: #122' "122"
  t 0 "an indented fence is handled" \
    '## Background

  ```
  close #55
  ```

## Issue disposition

Closes: #122' "122"

  # --- STRICT: title and commit messages ------------------------------------
  # k <expect 0|1> <name> <title> <commits>
  k() {
    local want="$1" name="$2" rc=0
    check_no_closing_keywords "$3" "$4" >/dev/null 2>&1 || rc=$?
    if [ "$rc" -eq "$want" ]; then echo "  ok   $name"; ok=$((ok+1));
    else echo "  FAIL $name (rc=$rc want=$want)"; fail=$((fail+1)); fi
  }
  local C1="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  local C2="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

  # THE #141 REGRESSION, exactly: footer says Stays open, GraphQL reports none,
  # but a commit carries the keyword.
  k 1 "#141 regression: commit closes an issue the footer keeps open" \
    "fix(ci): label RC builds with the canonical selector" \
    "$C1	fix(ci): derive the OCI version label\\n\\nCloses #126"
  # Strict differs from union here: refused even when declared.
  k 1 "a commit closure MATCHING declared Closes: is still refused" \
    "fix: thing" "$C1	fix: thing\\n\\nCloses #122"

  k 1 "closing keyword in a commit SUBJECT" \
    "fix: thing" "$C1	fix: closes #55"
  k 1 "closing keyword in a multiline commit BODY" \
    "fix: thing" "$C1	fix: thing\\n\\nSome prose.\\n\\nResolves #55\\n\\nMore."
  k 1 "closing keyword in the PR TITLE" \
    "fix: this closes #55" "$C1	fix: thing"

  for kw in close closes closed fix fixes fixed resolve resolves resolved; do
    k 1 "commit '$kw #55' refused" "t" "$C1	subject\\n\\n$kw #55"
  done
  k 1 "optional colon 'Closes: #55' refused" "t" "$C1	subject\\n\\nCloses: #55"

  # Non-closing references remain allowed.
  k 0 "'Refs #119' accepted"                  "t" "$C1	subject\\n\\nRefs #119"
  k 0 "'Addresses #126' accepted"             "t" "$C1	subject\\n\\nAddresses #126"
  k 0 "'Partially addresses #126' accepted"   "t" "$C1	subject\\n\\nPartially addresses #126"
  k 0 "'Related to #99' accepted"             "t" "$C1	subject\\n\\nRelated to #99"

  # Fenced blocks are deliberately NOT exempt in commit messages.
  k 1 "a fenced example inside a commit message is still refused" \
    "t" "$C1	subject\\n\\n~~~\\nCloses #55\\n~~~"
  k 1 "an indented (code-block) example is still refused" \
    "t" "$C1	subject\\n\\n    Closes #55"

  # Fail-closed retrieval.
  k 1 "an empty commit set is refused"        "t" ""
  k 1 "a malformed commit record is refused"  "t" "no-tab-here"
  k 1 "a malformed sha is refused"            "t" "zzz	subject"
  k 0 "multiple commits are ALL scanned"      "t" "$C1	one
$C2	two"
  k 1 "...and a keyword on the LAST of several is caught" \
    "t" "$C1	one
$C2	two\\n\\nCloses #55"

  echo "self-test: $ok ok, $fail failed"
  [ "$fail" -eq 0 ]
}

case "${1-}" in
  --self-test) _apid_self_test && echo "assert-pr-issue-disposition.sh: SELF-TEST OK" ;;
  "") echo "usage: assert-pr-issue-disposition.sh <pr-number> | --self-test" >&2; exit 2 ;;
  *) assert_pr "$1" ;;
esac
