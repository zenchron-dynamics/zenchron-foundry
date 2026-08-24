#!/usr/bin/env bash
# Every fallback git hook must be EXECUTABLE.
#
# WHY. git silently skips a hook whose file is not executable — no warning to
# the committing developer, no non-zero exit, nothing. scripts/git-hooks/pre-commit
# was committed 100644 while its sibling pre-push was 100755, so the documented
# fallback (`git config core.hooksPath scripts/git-hooks`) installed a hook that
# never ran: no gitleaks secret scan, no >512KB block, no hadolint. The control
# was present in the tree and absent in effect — the vacuous-check class again.
#
# The MODE IN GIT is what matters, not the mode on this disk: a fresh clone gets
# the tracked mode, and a local chmod does not travel.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

hooks() { git ls-files -s scripts/git-hooks/; }

nonexec=""
badshebang=""
while read -r mode _rest; do
  path="${_rest##*$'\t'}"
  [ -n "$path" ] || continue
  [ "$mode" = "100755" ] || nonexec="$nonexec $path($mode)"
  head -n1 "$path" | grep -q '^#!' || badshebang="$badshebang $path"
done < <(hooks)

n_hooks="$(hooks | wc -l | tr -d ' ')"
ck "NON-VACUOUS: there are hooks to check" '[ "$n_hooks" -ge 2 ]'
ck "NON-VACUOUS: each hook path resolved to a real file" \
   'ok=1; while read -r _m _r; do p="${_r##*$'"'"'\t'"'"'}"; [ -f "$p" ] || ok=0; done < <(hooks); [ "$ok" = 1 ]'
ck "every tracked git hook is executable IN GIT (100755)" \
   '[ -z "$nonexec" ] || { printf "not executable:%s\n" "$nonexec"; false; }'
ck "every tracked git hook starts with a shebang" \
   '[ -z "$badshebang" ] || { printf "no shebang:%s\n" "$badshebang"; false; }'

echo "----"
[ "$fail" -eq 0 ] && echo "test_git_hooks: PASS" || echo "test_git_hooks: FAIL"
exit $fail
