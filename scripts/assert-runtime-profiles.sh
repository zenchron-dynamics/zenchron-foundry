#!/usr/bin/env bash
# =============================================================================
# scripts/assert-runtime-profiles.sh — confinement profiles, and the escape
# hatches that undo them (#129).
#
# Two jobs, kept apart on purpose:
#
#   STATIC   the shipped profiles parse, the seccomp profile is default-deny and
#            still denies the syscalls we claim, and NO shipped compose profile,
#            example or document tells a consumer to use an unconfining option.
#            Runs everywhere, offline.
#
#   EXECUTED the images actually run under the pinned seccomp profile, and the
#            forbidden options are shown to break the posture rather than merely
#            being discouraged. Needs docker.
#
# An environment that cannot execute a layer REPORTS that it did not execute it.
# It never reports the static result as if it were the executed one — evidence
# that cannot be produced must not be manufactured.
#
# Usage:
#   assert-runtime-profiles.sh                 static only (offline)
#   assert-runtime-profiles.sh --executed IMG  static + executed against IMG
#   assert-runtime-profiles.sh --self-test
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1
POLICY="$ROOT/policies/runtime-contract.yaml"
SECCOMP="$ROOT/security/seccomp/zenchron-default.json"
APPARMOR="$ROOT/security/apparmor/zenchron-container"

pass=0; fail=0
ck() { if eval "$2"; then pass=$((pass+1)); echo "ok   - $1"; else fail=$((fail+1)); echo "FAIL - $1"; fi; }

# --- static: the profiles exist and say what we claim ------------------------
ck "the seccomp profile is present and valid JSON" \
   "python3 -c \"import json;json.load(open('$SECCOMP'))\""
ck "the seccomp profile is DEFAULT-DENY" \
   "python3 -c \"
import json,sys
d=json.load(open('$SECCOMP'))
assert d['defaultAction']=='SCMP_ACT_ERRNO', d['defaultAction']\""
# The claim in security/README.md is that these are denied. Derive it from the
# profile rather than trusting the prose — a pinned copy can be replaced.
ck "the syscalls the README claims are denied really are not in the allowlist" \
   "python3 -c \"
import json
d=json.load(open('$SECCOMP'))
allowed=set()
for s in d['syscalls']:
    if s['action']=='SCMP_ACT_ALLOW' and not s.get('includes'):
        allowed.update(s.get('names',[]))
must_deny=['mount','umount2','pivot_root','setns','unshare','init_module',
           'finit_module','kexec_load','bpf','perf_event_open','ptrace',
           'reboot','swapon']
leaked=[s for s in must_deny if s in allowed]
assert not leaked, leaked\""
ck "the AppArmor reference profile is present" "test -s '$APPARMOR'"
ck "...and declares the profile name the docs tell consumers to load" \
   "grep -q '^profile zenchron-container' '$APPARMOR'"
ck "...and denies mount, raw kernel memory and the docker socket" \
   "grep -q 'deny mount' '$APPARMOR' && grep -q 'deny @{PROC}/kcore' '$APPARMOR' && grep -q 'docker.sock rwklx' '$APPARMOR'"
ck "SELinux behaviour is documented rather than shipped as a module" \
   "test -f security/selinux/README.md && ! find security/selinux -name '*.pp' -o -name '*.te' | grep -q ."

# --- static: nothing we ship teaches an unconfining option -------------------
# This is the half that actually protects a consumer: they copy our profiles and
# examples. Comment lines are excluded — the policy file NAMES these options in
# order to forbid them, and a bare grep would flag its own denylist.
scan_targets() { printf '%s\n' profiles/*.yml examples/*/compose*.yml examples/*/Dockerfile 2>/dev/null; }
code_only() { grep -vE '^[[:space:]]*#' "$1" 2>/dev/null; }

# Both spellings of every option. A consumer copies either a compose fragment or
# a `docker run` line out of our docs, and covering only one of the two is how a
# denylist looks complete while missing half the ways in.
#
# FORBIDDEN_TOKENS is the same list in plain form. The coverage check below reads
# THIS rather than re-deriving the regex in Python, whose `re` does not
# understand POSIX classes — two dialects of one denylist is the drift this check
# exists to prevent.
FORBIDDEN='seccomp=unconfined|apparmor=unconfined|label=disable|privileged:[[:space:]]*true|--privileged|pid:[[:space:]]*host|--pid[= ]host|ipc:[[:space:]]*host|--ipc[= ]host|network_mode:[[:space:]]*host|--network[= ]host|/var/run/docker\.sock|cap_add|--cap-add'
FORBIDDEN_TOKENS='seccomp=unconfined apparmor=unconfined label=disable privileged --pid ipc --ipc network_mode --network docker.sock cap_add --cap-add'
offenders() {
  local f
  for f in $(scan_targets); do
    [ -f "$f" ] || continue
    code_only "$f" | grep -nE "$FORBIDDEN" | sed "s|^|$f:|"
  done
}
ck "no shipped profile or example uses an unconfining option" '[ -z "$(offenders)" ]'

# The denylist must cover every option the POLICY forbids, so adding one there
# without teaching this scan about it cannot pass silently.
coverage_gaps() {
  FORBIDDEN_TOKENS="$FORBIDDEN_TOKENS" python3 - "$POLICY" <<'PYCOV'
import os, sys, yaml
tokens = os.environ["FORBIDDEN_TOKENS"].split()
pol = yaml.safe_load(open(sys.argv[1]))
opts = pol.get("forbidden_runtime_options") or []
if not opts:
    print("policy lists no forbidden options — the scan would be vacuous")
    raise SystemExit(0)
for e in opts:
    o = e["option"]
    if not any(t in o for t in tokens):
        print(o)
PYCOV
}
ck "every forbidden option in the policy is covered by this scan" \
   '[ -z "$(coverage_gaps)" ]'
ck "the policy actually lists forbidden options (not a vacuous scan)" \
   "python3 -c \"
import yaml
assert (yaml.safe_load(open('$POLICY')).get('forbidden_runtime_options') or [])\""

# --- executed ---------------------------------------------------------------
EXEC_IMG="${2:-}"
if [ "${1:-}" = "--executed" ] && [ -n "$EXEC_IMG" ]; then
  echo "--- executed layer (image: $EXEC_IMG)"
  ck "the image runs under the PINNED seccomp profile" \
     "docker run --rm --platform linux/amd64 --entrypoint sh \
        --read-only --cap-drop ALL --security-opt no-new-privileges \
        --security-opt seccomp='$SECCOMP' --tmpfs /tmp:mode=1777 \
        '$EXEC_IMG' -c 'grep -q \"^Seccomp:.*2\" /proc/self/status'"

  # The negative direction: the escape hatch must be SHOWN to remove the control.
  # A denylist nobody has ever seen fire is a denylist nobody knows works.
  ck "seccomp=unconfined demonstrably removes the filter" \
     "docker run --rm --platform linux/amd64 --entrypoint sh \
        --security-opt seccomp=unconfined '$EXEC_IMG' \
        -c 'grep -q \"^Seccomp:.*0\" /proc/self/status'"
  # CapBnd, not CapEff, and the difference is instructive. These images run as
  # uid 10001, and a non-root process has no EFFECTIVE capabilities whatever the
  # container was started with — so checking CapEff would have concluded that
  # `--privileged` is harmless here. The BOUNDING set is what actually changes:
  # 0000000000000000 under the contract profile, 000001ffffffffff privileged.
  # That is the whole escalation surface handed back, waiting for anything that
  # gains uid 0 inside the container.
  ck "--privileged demonstrably restores the capability BOUNDING set" \
     "docker run --rm --platform linux/amd64 --entrypoint sh --privileged '$EXEC_IMG' \
        -c 'grep \"^CapBnd:\" /proc/self/status | grep -qv \"0000000000000000\"'"
  ck "...which the contract profile keeps empty" \
     "docker run --rm --platform linux/amd64 --entrypoint sh \
        --read-only --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp:mode=1777 \
        '$EXEC_IMG' -c 'grep -q \"^CapBnd:.*0000000000000000\" /proc/self/status'"
  # ...and the contract profile is what prevents both.
  ck "the contract profile keeps capabilities empty" \
     "docker run --rm --platform linux/amd64 --entrypoint sh \
        --read-only --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp:mode=1777 \
        '$EXEC_IMG' -c 'grep -q \"^CapEff:.*0000000000000000\" /proc/self/status'"

  # AppArmor: only where the host actually enforces it.
  if [ -d /sys/kernel/security/apparmor ]; then
    ck "the AppArmor profile parses on this host" \
       "apparmor_parser -Q '$APPARMOR'"
    echo "note: AppArmor enforcement EXECUTED on this host"
  else
    echo "note: AppArmor NOT executed — no /sys/kernel/security/apparmor on this host."
    echo "      Syntax is still checked above; enforcement evidence is not claimed."
  fi
fi

if [ "${1:-}" = "--self-test" ]; then
  # The offenders() scan must actually fire. A denylist that has never matched
  # anything is indistinguishable from a broken regex.
  t="$(mktemp -d)/compose.bad.yml"
  mkdir -p "$(dirname "$t")"
  printf 'services:\n  x:\n    privileged: true\n' > "$t"
  if code_only "$t" | grep -qE "$FORBIDDEN"; then
    pass=$((pass+1)); echo "ok   - the denylist matches a real offending file"
  else
    fail=$((fail+1)); echo "FAIL - the denylist matches a real offending file"
  fi
  printf '# privileged: true is forbidden here\nservices:\n  x:\n    image: y\n' > "$t"
  if code_only "$t" | grep -qE "$FORBIDDEN"; then
    fail=$((fail+1)); echo "FAIL - a COMMENT naming the option is not an offence"
  else
    pass=$((pass+1)); echo "ok   - a COMMENT naming the option is not an offence"
  fi
fi

echo "----"
printf 'assert-runtime-profiles: %d ok, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
