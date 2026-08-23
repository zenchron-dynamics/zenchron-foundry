#!/usr/bin/env bash
# =============================================================================
# scripts/assert-no-identity-wildcards.sh
# -----------------------------------------------------------------------------
# Every runnable cosign identity in documentation and policy must EXACTLY equal
# one of the identities declared in policies/cosign-identities.yaml (#99).
#
# This is an ALLOWLIST, not a blacklist. The first implementation blacklisted a
# single shape — a bare `<repo>/.*` following a space-separated flag — and review
# proved it missed at least three equally broad runnable identities:
#
#   --certificate-identity-regexp='https://github.com/o/r/.*'          (= form)
#   '^https://github\.com/o/r/\.github/workflows/.*@refs/heads/master$'
#   '^https://github\.com/o/r/.+$'
#
# A blacklist cannot prove that every documented identity is safe; it only proves
# that one known-bad spelling is absent. The policy file is therefore the
# allowlist: any value that is not character-for-character a declared per-role
# identity is rejected, whatever shape it takes.
#
# Why it matters: a repository-wide identity accepts a signature from ANY
# workflow in the repo — including scheduled-rebuild.yml, whose candidate images
# must never satisfy the production identity, and any workflow a future
# compromise adds.
#
# Usage: assert-no-identity-wildcards.sh [<dir>]   (default: repo root)
#        assert-no-identity-wildcards.sh --self-test
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IDENTITIES="${IDENTITIES:-${ROOT}/policies/cosign-identities.yaml}"

# allowed_identities <policy> — the declared per-role identities, one per line.
allowed_identities() {
  IDENTITIES_PATH="$1" python3 - <<'PY'
import os, sys
try:
    import yaml
except ImportError:
    print("PyYAML is required", file=sys.stderr); sys.exit(2)
path = os.environ["IDENTITIES_PATH"]
try:
    doc = yaml.safe_load(open(path)) or {}
except Exception as exc:
    print("cannot read %s: %s" % (path, exc), file=sys.stderr); sys.exit(2)
roles = doc.get("roles") or {}
if not roles:
    print("no roles declared in %s" % path, file=sys.stderr); sys.exit(2)
for _name, role in roles.items():
    for key in ("identity_regexp", "identity"):
        if role.get(key):
            print(role[key])
PY
}

# extract_identities <file> — every runnable value handed to a cosign identity
# flag, as "<lineno>\t<value>". Handles `--flag value`, `--flag=value`, and a
# value pushed onto a shell continuation line, quoted or bare.
extract_identities() {
  FILE_PATH="$1" python3 - <<'PY'
import os, re, sys
path = os.environ["FILE_PATH"]
try:
    raw = open(path, encoding="utf-8", errors="replace").read()
except Exception:
    sys.exit(0)

# Only RUNNABLE context counts. A flag named in prose or in a comment is not an
# identity a consumer can copy — an earlier revision of this gate flagged its own
# explanatory comment. In Markdown that means fenced code blocks; in shell/YAML
# it means lines that are not comments.
ext = os.path.splitext(path)[1].lower()
raw_lines, keep = raw.splitlines(), []
in_fence = False
for line in raw_lines:
    stripped = line.strip()
    if ext in (".md", ".markdown"):
        # CommonMark allows backtick AND tilde fences, of three or more chars.
        # Only handling ``` let a ~~~ block hide a runnable example.
        if stripped.startswith("```") or stripped.startswith("~~~"):
            in_fence = not in_fence
            keep.append("")
            continue
        keep.append(line if in_fence else "")
    else:
        keep.append("" if stripped.startswith("#") else line)

lines = keep

# Rejoin shell line-continuations so a flag and its value reunite, keeping the
# first line's number for reporting.
joined, lineno_of, buf, start = [], [], "", 1
for i, line in enumerate(lines, 1):
    if not buf:
        start = i
    stripped_l = line.rstrip()
    if stripped_l.endswith("\\"):
        buf += stripped_l[:-1] + " "
        continue
    joined.append(buf + stripped_l); lineno_of.append(start); buf = ""
if buf:
    joined.append(buf); lineno_of.append(start)

FLAG = re.compile(r"--certificate-identity(?:-regexp)?\s*(?:=\s*|\s+)('[^']*'|\"[^\"]*\"|\S+)")
for text, ln in zip(joined, lineno_of):
    for m in FLAG.finditer(text):
        val = m.group(1).strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "'\"":
            val = val[1:-1]
        val = val.strip().rstrip("\\").strip()
        if val:
            print("%d\t%s" % (ln, val))
PY
}

# Files explicitly approved to hold a DYNAMIC cosign identity argument. Each
# must also assert policy membership at runtime (checked below), so approval
# alone is never sufficient. Paths are relative to the scanned directory.
DYNAMIC_IDENTITY_FILES="${DYNAMIC_IDENTITY_FILES:-scripts/verify-image-release-identity.sh}"

# Only this file may DEFINE the policy accessors. A second definition anywhere
# else shadows the real one — `identity_re_for_role() { printf .*; }` would make
# every call site resolve to a wildcard while still reading as policy-driven.
IDENTITY_ACCESSOR_HOME="${IDENTITY_ACCESSOR_HOME:-scripts/lib/cosign-identity.sh}"

# assert_no_accessor_shadowing <dir> -> 0 clean, 1 shadowed
assert_no_accessor_shadowing() {
  local dir="$1" hits=0 f rel
  while IFS= read -r f; do
    rel="${f#"$dir"/}"
    [ "$rel" = "$IDENTITY_ACCESSOR_HOME" ] && continue
    if grep -qE '^[[:space:]]*(function[[:space:]]+)?identity_(re_)?for_role[[:space:]]*\(\)' "$f"; then
      printf '%s: redefines the policy accessor identity_*_for_role — only %s may\n' \
        "$rel" "$IDENTITY_ACCESSOR_HOME" >&2
      printf '    define it; a shadow makes every call site resolve to whatever it returns\n' >&2
      hits=$((hits + 1))
    fi
  done < <(find "$dir" -name '*.sh' -not -path '*/.git/*' \
             -not -name 'assert-no-identity-wildcards.sh' | sort)
  [ "$hits" -eq 0 ]
}

scan() {
  local dir="$1" allowed hits=0 found=0 f
  if ! allowed="$(allowed_identities "$IDENTITIES")"; then
    echo "FAIL: cannot load declared identities from ${IDENTITIES}" >&2
    return 1
  fi

  while IFS= read -r f; do
    found=$((found + 1))
    while IFS=$'\t' read -r ln val; do
      [ -n "${val:-}" ] || continue
      # Documentation placeholders and template tokens are not runnable values.
      case "$val" in
        *'<'*'>'*)   continue ;;
        '{{'*)       continue ;;
        *'{{'*'}}'*) continue ;;
      esac

      # DYNAMIC arguments. Allow-listing variable NAMES (EXPECTED_IDENTITY,
      # IDENTITY_RE, COSIGN_ID, IDENTITY) recognised the name but proved nothing
      # about the VALUE, so a local reassignment still sailed through:
      #     IDENTITY_RE='^https://github\.com/o/r/.*$'
      #     cosign verify --certificate-identity-regexp "$IDENTITY_RE" IMAGE
      # and so did shadowing the accessor:
      #     identity_re_for_role() { printf '%s' '.*'; }
      #
      # Now: documentation may not use a dynamic identity at all, and a script
      # may only do so if it demonstrably resolves the value from the policy.
      case "$val" in
        '$'*|*'$('*)
          _rel="${f#"$dir"/}"
          case "$_rel" in
            *.md)
              printf '%s:%s: dynamic cosign identity in DOCUMENTATION — a reader cannot\n' \
                "$_rel" "$ln" >&2
              printf '    see where the value comes from. Show a literal identity from %s,\n' \
                "$(basename "$IDENTITIES")" >&2
              printf '    or the strict verifier command.\n        %s\n' "$val" >&2
              hits=$((hits + 1)); continue ;;
          esac

          # A direct call to the strict accessor carries its own provenance: it
          # reads the policy and dies on an unknown role.
          _bare="${val#\$}"; _bare="${_bare#\{}"; _bare="${_bare%\}}"
          case "$_bare" in
            '(identity_re_for_role'*|'(identity_for_role'*) continue ;;
          esac

          # Otherwise the file must be explicitly approved to hold a dynamic
          # identity AND must assert policy membership itself.
          if ! grep -qxF -- "$_rel" <<<"$DYNAMIC_IDENTITY_FILES"; then
            printf '%s:%s: dynamic cosign identity in a file not approved to hold one\n        %s\n' \
              "$_rel" "$ln" "$val" >&2
            hits=$((hits + 1)); continue
          fi
          if ! grep -qE 'assert_identity_(re|literal)_in_policy' "$f"; then
            printf '%s:%s: dynamic cosign identity, but the file never asserts the value is\n' \
              "$_rel" "$ln" >&2
            printf '    declared in %s (assert_identity_re_in_policy /\n' "$(basename "$IDENTITIES")" >&2
            printf '    assert_identity_literal_in_policy)\n        %s\n' "$val" >&2
            hits=$((hits + 1)); continue
          fi
          continue ;;
      esac
      if ! grep -qxF -- "$val" <<<"$allowed"; then
        printf '%s:%s: cosign identity is not one declared in %s\n    %s\n' \
          "${f#"$dir"/}" "$ln" "$(basename "$IDENTITIES")" "$val" >&2
        hits=$((hits + 1))
      fi
    done < <(extract_identities "$f")
  done < <(find "$dir" \( -name '*.md' -o -name '*.yaml' -o -name '*.yml' -o -name '*.sh' \) \
             -not -path '*/.git/*' -not -path '*/node_modules/*' \
             -not -name 'assert-no-identity-wildcards.sh' | sort)

  assert_no_accessor_shadowing "$dir" || hits=$((hits + 1))

  # Fail closed: scanning nothing must never look like success.
  if [ "$found" -eq 0 ]; then
    echo "FAIL: no files scanned under '${dir}' — gate would be vacuous" >&2
    return 1
  fi
  if [ "$hits" -gt 0 ]; then
    printf 'RESULT: FAIL (%d cosign identity value(s) not declared in %s)\n' \
      "$hits" "$(basename "$IDENTITIES")" >&2
    echo "        Every documented identity must EXACTLY equal a declared per-role identity." >&2
    echo "        Better still, document scripts/verify-image-release-identity.sh instead." >&2
    return 1
  fi
  printf 'RESULT: PASS (%d files; every cosign identity matches a declared role)\n' "$found"
}

self_test() {
  local tmp ok=0 bad=0
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '${tmp}'" EXIT
  t() { if eval "$2"; then ok=$((ok+1)); echo "  ok   $1"; else bad=$((bad+1)); echo "  FAIL $1"; fi; }

  cat > "$tmp/ids.yaml" <<'YAML'
roles:
  rc-publisher:
    identity_regexp: '^https://github\.com/o/r/\.github/workflows/publish-(ghcr|rc)\.yml@refs/heads/master$'
  release:
    identity_regexp: '^https://github\.com/o/r/\.github/workflows/release\.yml@refs/tags/v[0-9]{4}$'
YAML
  IDENTITIES="$tmp/ids.yaml"
  # Fixtures are RUNNABLE examples, i.e. fenced code — the same context the
  # scanner extracts from. Writing them as bare prose would make every negative
  # case pass for the wrong reason.
  mk() { mkdir -p "$tmp/$1"; { echo '```bash'; printf '%b' "$2"; echo '```'; } > "$tmp/$1/doc.md"; }

  # --- positives: each declared role, in both flag spellings ---------------
  mk good1 "cosign verify \\\\\n  --certificate-identity-regexp \\\\\n  '^https://github\\\\.com/o/r/\\\\.github/workflows/publish-(ghcr|rc)\\\\.yml@refs/heads/master\$' \\\\\n  img\n"
  t "declared rc-publisher identity passes"          "scan '$tmp/good1' >/dev/null"
  mk good2 "cosign verify --certificate-identity-regexp='^https://github\\\\.com/o/r/\\\\.github/workflows/release\\\\.yml@refs/tags/v[0-9]{4}\$' img\n"
  t "declared release identity passes (= form)"      "scan '$tmp/good2' >/dev/null"
  mk good3 "Pin by digest and verify; see the verifier script.\n"
  t "prose with no identity flag passes"             "scan '$tmp/good3' >/dev/null"

  # --- negatives: every shape the blacklist missed --------------------------
  mk bad1 "cosign verify --certificate-identity-regexp 'https://github.com/o/r/.*' img\n"
  t "bare repo wildcard rejected"                    "! scan '$tmp/bad1' >/dev/null 2>&1"
  mk bad2 "cosign verify --certificate-identity-regexp='https://github.com/o/r/.*' img\n"
  t "wildcard via = assignment rejected"             "! scan '$tmp/bad2' >/dev/null 2>&1"
  mk bad3 "cosign verify \\\\\n  --certificate-identity-regexp \\\\\n  '^https://github\\\\.com/o/r/\\\\.github/workflows/.*@refs/heads/master\$' \\\\\n  img\n"
  t "workflow-file wildcard rejected"                "! scan '$tmp/bad3' >/dev/null 2>&1"
  mk bad4 "cosign verify \\\\\n  --certificate-identity-regexp \\\\\n  '^https://github\\\\.com/o/r/.+\$' \\\\\n  img\n"
  t "'.+' catch-all rejected"                        "! scan '$tmp/bad4' >/dev/null 2>&1"
  mk bad5 "cosign verify --certificate-identity-regexp 'https://github\\\\.com/o/r/\\\\.github/workflows/publish-(ghcr|rc)\\\\.yml@refs/heads/master' img\n"
  t "missing anchors rejected"                       "! scan '$tmp/bad5' >/dev/null 2>&1"
  mk bad6 "cosign verify \\\\\n  --certificate-identity-regexp \\\\\n  '^https://github\\\\.com/o/r/\\\\.github/workflows/release\\\\.yml@refs/.*\$' \\\\\n  img\n"
  t "broader ref class (refs/.*) rejected"           "! scan '$tmp/bad6' >/dev/null 2>&1"
  mk bad7 "cosign verify --certificate-identity 'https://github.com/o/r/anything' img\n"
  t "non-regexp --certificate-identity checked too"  "! scan '$tmp/bad7' >/dev/null 2>&1"

  # --- fail-closed inputs ---------------------------------------------------
  # --- dynamic-argument bypass found in review -----------------------------
  # Skipping every $VAR proved nothing about the value behind it.
  mk dyn1 "BAD_IDENTITY='^https://github\\.com/o/r/.*\$'\ncosign verify --certificate-identity-regexp \"\$BAD_IDENTITY\" IMAGE\n"
  t "locally assigned wildcard variable rejected"    "! scan '$tmp/dyn1' >/dev/null 2>&1"
  mk dyn2 "cosign verify --certificate-identity-regexp \"\${SOME_VAR}\" IMAGE\n"
  t "unrecognised braced variable rejected"          "! scan '$tmp/dyn2' >/dev/null 2>&1"
  mk dyn3 "cosign verify --certificate-identity-regexp \"\$(echo bad)\" IMAGE\n"
  t "arbitrary command substitution rejected"        "! scan '$tmp/dyn3' >/dev/null 2>&1"
  # Name-based acceptance was the remaining hole: recognising IDENTITY_RE said
  # nothing about the value bound to it.
  mk dyn4 "cosign verify --certificate-identity-regexp \"\$IDENTITY_RE\" IMAGE\n"
  t "DOC: \$IDENTITY_RE rejected (name proves nothing)"  "! scan '$tmp/dyn4' >/dev/null 2>&1"
  mk dyn5 "cosign verify --certificate-identity-regexp \"\$(identity_re_for_role \"\$ROLE\")\" IMAGE\n"
  t "DOC: even the accessor call is rejected in prose"  "! scan '$tmp/dyn5' >/dev/null 2>&1"
  mk dyn6 "IDENTITY_RE='^https://github\\.com/o/r/.*\$'\ncosign verify --certificate-identity-regexp \"\$IDENTITY_RE\" IMAGE\n"
  t "DOC: locally reassigned IDENTITY_RE rejected"     "! scan '$tmp/dyn6' >/dev/null 2>&1"

  # --- scripts: dynamic allowed only with demonstrable provenance -----------
  mksh() { mkdir -p "$tmp/$1/$(dirname "$2")"; printf '%b' "$3" > "$tmp/$1/$2"; }

  # Approved file that asserts policy membership -> accepted.
  mksh sh_ok scripts/verify-image-release-identity.sh \
    "#!/usr/bin/env bash\nassert_identity_re_in_policy \"\$IDENTITY_RE\"\ncosign verify --certificate-identity-regexp \"\$IDENTITY_RE\" IMAGE\n"
  t "SCRIPT: approved file that asserts policy passes" \
    "DYNAMIC_IDENTITY_FILES='scripts/verify-image-release-identity.sh' scan '$tmp/sh_ok' >/dev/null"

  # Same file, assertion removed -> rejected. This is the local-reassignment
  # case: nothing proves the value came from the policy.
  mksh sh_noassert scripts/verify-image-release-identity.sh \
    "#!/usr/bin/env bash\nIDENTITY_RE='^https://github\\.com/o/r/.*\$'\ncosign verify --certificate-identity-regexp \"\$IDENTITY_RE\" IMAGE\n"
  t "SCRIPT: approved file WITHOUT the policy assertion is rejected" \
    "! DYNAMIC_IDENTITY_FILES='scripts/verify-image-release-identity.sh' scan '$tmp/sh_noassert' >/dev/null 2>&1"

  # Unapproved file -> rejected even with an assertion present.
  mksh sh_unapproved scripts/somewhere-else.sh \
    "#!/usr/bin/env bash\nassert_identity_re_in_policy \"\$IDENTITY_RE\"\ncosign verify --certificate-identity-regexp \"\$IDENTITY_RE\" IMAGE\n"
  t "SCRIPT: unapproved file is rejected" \
    "! DYNAMIC_IDENTITY_FILES='scripts/verify-image-release-identity.sh' scan '$tmp/sh_unapproved' >/dev/null 2>&1"

  # A direct accessor call carries its own provenance.
  mksh sh_accessor scripts/whatever.sh \
    "#!/usr/bin/env bash\ncosign verify --certificate-identity-regexp \"\$(identity_re_for_role rc-publisher)\" IMAGE\n"
  t "SCRIPT: direct accessor call passes anywhere" \
    "DYNAMIC_IDENTITY_FILES='' scan '$tmp/sh_accessor' >/dev/null"

  # …but not if the accessor itself is shadowed.
  mksh sh_shadow scripts/whatever.sh \
    "#!/usr/bin/env bash\nidentity_re_for_role() { printf '%s' '.*'; }\ncosign verify --certificate-identity-regexp \"\$(identity_re_for_role rc-publisher)\" IMAGE\n"
  t "SCRIPT: shadowing the policy accessor is rejected" \
    "! DYNAMIC_IDENTITY_FILES='' scan '$tmp/sh_shadow' >/dev/null 2>&1"
  mksh sh_shadow_fn scripts/whatever.sh \
    "#!/usr/bin/env bash\nfunction identity_for_role() { printf '%s' 'x'; }\ncosign verify --certificate-identity 'https://github.com/o/r/\\.github/workflows/publish-ghcr\\.yml@refs/heads/master' IMAGE\n"
  t "SCRIPT: 'function' keyword shadowing is rejected too" \
    "! DYNAMIC_IDENTITY_FILES='' scan '$tmp/sh_shadow_fn' >/dev/null 2>&1"

  # The real library must be allowed to define the accessor.
  mksh sh_home scripts/lib/cosign-identity.sh \
    "#!/usr/bin/env bash\nidentity_re_for_role() { yq -r .x policy; }\n"
  t "SCRIPT: the accessor's own home may define it" \
    "scan '$tmp/sh_home' >/dev/null"

  # --- alternate Markdown fence forms --------------------------------------
  mkdir -p "$tmp/fence1"
  { echo '~~~bash'; echo "cosign verify --certificate-identity-regexp 'https://github.com/o/r/.*' img"; echo '~~~'; } > "$tmp/fence1/doc.md"
  t "tilde-fenced wildcard is rejected"              "! scan '$tmp/fence1' >/dev/null 2>&1"
  mkdir -p "$tmp/fence2"
  { echo '````bash'; echo "cosign verify --certificate-identity-regexp 'https://github.com/o/r/.*' img"; echo '````'; } > "$tmp/fence2/doc.md"
  t "four-backtick fence is rejected"                "! scan '$tmp/fence2' >/dev/null 2>&1"

  mkdir -p "$tmp/empty"
  t "empty directory fails closed"                   "! scan '$tmp/empty' >/dev/null 2>&1"
  t "unreadable identity policy fails closed" \
    "! IDENTITIES='$tmp/missing.yaml' scan '$tmp/good1' >/dev/null 2>&1"

  IDENTITIES="${ROOT}/policies/cosign-identities.yaml"
  t "the repository itself passes"                   "scan '$ROOT' >/dev/null"

  echo "self-test: $ok ok, $bad failed"
  [ "$bad" -eq 0 ]
}

case "${1:-}" in
  --self-test) self_test ;;
  "")          scan "$ROOT" ;;
  *)           scan "$1" ;;
esac
