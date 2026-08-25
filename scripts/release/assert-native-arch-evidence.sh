#!/usr/bin/env bash
# =============================================================================
# scripts/release/assert-native-arch-evidence.sh
# -----------------------------------------------------------------------------
# Fail-closed gate for the QEMU/native boundary (#111).
#
# Given a directory of child evidence records, this refuses when a NATIVE arm64
# claim is not backed by natively-executed children. It is deliberately usable
# in two modes:
#
#   default                     — report the split; refuse only if the policy
#                                 says native is required
#   --require-native <arch>     — refuse unless every child of that architecture
#                                 ran natively, whatever the policy says
#
# An emulated child can never satisfy a native requirement. That is the whole
# point: QEMU evidence is real evidence about packages and findings, and is not
# evidence about runtime behaviour.
#
# Usage:
#   assert-native-arch-evidence.sh <records-dir> [--require-native linux/arm64]
#   assert-native-arch-evidence.sh --self-test
# Exit: 0 satisfied, 1 refused or unreadable. Empty discovery is NEVER success.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
POLICY="${POLICY:-$ROOT/policies/native-arch-requirements.yaml}"

die() { echo "REFUSE: $*" >&2; exit 1; }

policy_requires_native() {
  python3 - "$POLICY" <<'PY'
import sys, yaml
try:
    d = yaml.safe_load(open(sys.argv[1]))
except Exception as e:
    print("policy-unreadable: %s" % e); raise SystemExit(2)
print("true" if (d.get("release_gate") or {}).get("require_native_arm64") else "false")
PY
}

check() {
  local dir="${1:?usage: assert-native-arch-evidence.sh <records-dir>}"
  local require_arch="${2:-}"
  [ -d "$dir" ] || die "records directory not found: $dir"

  local n
  n="$(find "$dir" -maxdepth 1 -name '*.json' | wc -l | tr -d ' ')"
  # Empty discovery is not success. A gate that passes because it found nothing
  # is the failure mode this whole project keeps hitting.
  [ "$n" -gt 0 ] || die "no child records in '$dir' — empty discovery is never success"

  python3 - "$dir" "$require_arch" <<'PY'
import json, glob, os, sys, collections
d, require = sys.argv[1], sys.argv[2]
recs = []
for f in sorted(glob.glob(os.path.join(d, "*.json"))):
    try:
        r = json.load(open(f))
    except Exception as e:
        print("REFUSE: %s is not valid JSON: %s" % (os.path.basename(f), e), file=sys.stderr)
        raise SystemExit(1)
    if "platform" in r and "execution_mode" in r:
        recs.append(r)
if not recs:
    print("REFUSE: no records carrying platform+execution_mode", file=sys.stderr)
    raise SystemExit(1)

by = collections.defaultdict(lambda: collections.Counter())
for r in recs:
    by[r["platform"]][r["execution_mode"]] += 1

for plat in sorted(by):
    modes = by[plat]
    print("  %-14s %s" % (plat, dict(modes)))

problems = []
# An unknown execution_mode is refused rather than assumed native.
for r in recs:
    if r["execution_mode"] not in ("native", "qemu"):
        problems.append("%s: unknown execution_mode %r" %
                        (r.get("child_key", "?"), r["execution_mode"]))
    # A native claim must agree with the host architecture it ran on.
    if r["execution_mode"] == "native":
        want = r["platform"].split("/")[1]
        got = r.get("host_architecture")
        if got != want:
            problems.append("%s claims execution_mode=native but host_architecture=%r "
                            "does not match platform %r" % (r.get("child_key", "?"), got, r["platform"]))

if require:
    emulated = [r.get("child_key", "?") for r in recs
                if r["platform"] == require and r["execution_mode"] != "native"]
    missing = not [r for r in recs if r["platform"] == require]
    if missing:
        problems.append("native evidence required for %s but no child of that platform exists" % require)
    if emulated:
        problems.append("native evidence required for %s but %d child(ren) ran emulated: %s"
                        % (require, len(emulated), ", ".join(sorted(emulated)[:4])))

if problems:
    print("REFUSE: native-architecture evidence contract not satisfied:", file=sys.stderr)
    for p in problems:
        print("  - %s" % p, file=sys.stderr)
    raise SystemExit(1)
print("native-arch evidence OK%s" % (" (native required for %s)" % require if require else ""))
PY
}

_self_test() {
  local tmp ok=0 bad=0
  tmp="$(mktemp -d)"
  # expand NOW: the local is out of scope by EXIT time
  # shellcheck disable=SC2064
  trap "rm -rf '${tmp}'" EXIT
  t() { if eval "$2"; then echo "  ok   $1"; ok=$((ok+1)); else echo "  FAIL $1"; bad=$((bad+1)); fi; }
  # check() can die(), and die() exits. Without a subshell the first die-path
  # kills the self-test and every later assertion silently never executes.
  chk() { ( check "$@" ); }

  mk() { # mk <dir> <platform> <mode> <hostarch> [name]
    mkdir -p "$1"
    jq -n --arg p "$2" --arg m "$3" --arg h "$4" --arg k "${5:-c}" \
      '{child_key:$k, platform:$p, execution_mode:$m, host_architecture:$h}' \
      > "$1/${5:-c}.json"
  }

  local d="$tmp/native"; mk "$d" linux/arm64 native arm64 a
  t "native arm64 satisfies a native requirement" \
    "chk '$d' linux/arm64 >/dev/null 2>&1"

  d="$tmp/emul"; mk "$d" linux/arm64 qemu amd64 a
  t "QEMU arm64 does NOT satisfy a native requirement" \
    "! chk '$d' linux/arm64 >/dev/null 2>&1"
  # Captured to a file first: `check ... | grep` under pipefail reports CHECK's
  # status, and check fails here ON PURPOSE. Sixth occurrence in this project;
  # documented in AGENTS.md.
  chk "$d" linux/arm64 > "$tmp/emul.out" 2>&1
  t "...and the refusal says the children ran emulated" \
    "grep -q 'ran emulated' '$tmp/emul.out'"
  t "...while the same evidence passes with no native requirement" \
    "chk '$d' >/dev/null 2>&1"

  d="$tmp/lying"; mk "$d" linux/arm64 native amd64 a
  t "a child claiming native on a mismatched host is REFUSED" \
    "! chk '$d' >/dev/null 2>&1"
  chk "$d" > "$tmp/lying.out" 2>&1
  t "...naming the host_architecture disagreement" \
    "grep -q 'host_architecture' '$tmp/lying.out'"

  d="$tmp/unknown"; mk "$d" linux/arm64 emulated-ish arm64 a
  t "an unknown execution_mode is refused, not assumed native" \
    "! chk '$d' >/dev/null 2>&1"

  d="$tmp/absent"; mk "$d" linux/amd64 native amd64 a
  t "requiring native arm64 with no arm64 child at all refuses" \
    "! chk '$d' linux/arm64 >/dev/null 2>&1"

  mkdir -p "$tmp/empty"
  t "empty discovery refuses, never passes" \
    "! chk '$tmp/empty' >/dev/null 2>&1"
  t "a missing directory refuses" \
    "! chk '$tmp/nope' >/dev/null 2>&1"

  d="$tmp/broken"; mkdir -p "$d"; printf 'not json' > "$d/c.json"
  t "unreadable evidence refuses, never counts as clean" \
    "! chk '$d' >/dev/null 2>&1"

  # Was: "currently does NOT require native arm64". It does now — a hosted
  # ubuntu-24.04-arm runner produces native evidence, so the gate is armed. The
  # assertion is kept on the READ, not on the value, so it still catches an
  # unreadable or malformed policy.
  t "the policy is readable and states a native-arm64 requirement either way" \
    "case \"\$(policy_requires_native)\" in true|false) true ;; *) false ;; esac"
  t "...and it currently DOES require native arm64" \
    "[ \"\$(policy_requires_native)\" = true ]"

  echo "self-test: $ok ok, $bad failed"
  [ "$bad" -eq 0 ]
}

case "${1:-}" in
  --self-test) _self_test && echo "assert-native-arch-evidence.sh: SELF-TEST OK" ;;
  "") echo "usage: assert-native-arch-evidence.sh <records-dir> [--require-native <platform>] | --self-test" >&2; exit 2 ;;
  *)
    dir="$1"; shift
    req=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --require-native) req="${2:?--require-native needs a platform}"; shift 2 ;;
        *) die "unknown argument: $1" ;;
      esac
    done
    if [ -z "$req" ] && [ "$(policy_requires_native)" = true ]; then req="linux/arm64"; fi
    check "$dir" "$req"
    ;;
esac
