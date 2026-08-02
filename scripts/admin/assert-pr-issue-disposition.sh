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

assert_pr() { # assert_pr <pr-number>
  local pr="$1"
  case "$pr" in ''|*[!0-9]*) echo "REFUSE: pr must be a number, got '$pr'" >&2; return 1 ;; esac
  local body refs
  body="$(pr_body "$pr")" || { echo "REFUSE: cannot read PR #${pr}" >&2; return 1; }
  # An unreadable API is a refusal, never an assumed-empty set: an empty
  # `actual` would make every undeclared closure invisible.
  refs="$(closing_refs "$pr")" || { echo "REFUSE: cannot read closingIssuesReferences for #${pr}" >&2; return 1; }
  echo "PR #${pr} (${REPO}):"
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

  echo "self-test: $ok ok, $fail failed"
  [ "$fail" -eq 0 ]
}

case "${1-}" in
  --self-test) _apid_self_test && echo "assert-pr-issue-disposition.sh: SELF-TEST OK" ;;
  "") echo "usage: assert-pr-issue-disposition.sh <pr-number> | --self-test" >&2; exit 2 ;;
  *) assert_pr "$1" ;;
esac
