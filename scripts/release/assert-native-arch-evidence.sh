#!/usr/bin/env bash
# =============================================================================
# scripts/release/assert-native-arch-evidence.sh
# -----------------------------------------------------------------------------
# Fail-closed gate for the QEMU/native boundary (#111).
#
# Given a directory of evidence records, this refuses when a NATIVE arm64 claim
# is not backed by natively-executed children. It has three modes:
#
#   default                     — report the split; refuse only if the policy
#                                 says native is required
#   --require-native <platform> — refuse unless every child of that platform ran
#                                 natively, whatever the policy says
#   --gate-release              — the RELEASE binding. Everything above, plus:
#                                 the evidence must IDENTIFY what it is about
#                                 (host architecture, platform, runner kind,
#                                 source revision, immutable manifest digest),
#                                 that identity must match the candidate being
#                                 authorized, and every required production
#                                 image must be covered. Evidence for another
#                                 digest, another source revision or another
#                                 platform REFUSES.
#
# TWO THINGS THIS DELIBERATELY REFUSES TO INFER.
#
#   1. Architecture from a runner label. `runs-on: ubuntu-24.04-arm` is a
#      REQUEST, and what a job lands on is a fact only `uname -m` can report.
#      In --gate-release a record must carry `architecture_source: measured`
#      and a `uname_m` that corresponds to the host architecture it claims.
#      A record whose architecture came from the label is refused BY NAME.
#
#   2. Nativeness from the absence of the word "qemu". Emulation is spelled
#      both `qemu` and `emulated` in this tree (the PHP 8.5 experimental cohort
#      in docs/audits/experimental-php-8.5-linux-amd64/ uses `emulated`). Both
#      are emulation, neither satisfies a native requirement, and any OTHER
#      value is refused rather than assumed native.
#
# Usage:
#   assert-native-arch-evidence.sh <records-dir> [--require-native <platform>]
#        [--gate-release --expect-revision <40hex> --expect-digests <file.json>]
#        [--allow-non-authoritative]
#   assert-native-arch-evidence.sh --self-test
#
# --expect-digests takes a JSON object mapping canonical image label to the
# immutable manifest digest of the candidate child on the required platform:
#   {"php-fpm/8.4": "sha256:<64-hex>", ...}
# Its key set IS the required production image set: covering fewer of them is a
# refusal, so 9 of 10 native results can never read as a pass.
#
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

# The runner kinds the policy accepts. Read from the policy rather than hardcoded
# so a record cannot name a runner shape nobody agreed to.
policy_runner_kinds() {
  python3 - "$POLICY" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1])) or {}
print(",".join(r["kind"] for r in (d.get("accepted_runners") or [])))
PY
}

check() {
  local dir="${1:?usage: assert-native-arch-evidence.sh <records-dir>}"
  local require_arch="${2:-}" gate="${3:-0}" expect_rev="${4:-}" expect_digests="${5:-}"
  local allow_non_auth="${6:-0}"
  [ -d "$dir" ] || die "records directory not found: $dir"

  local n
  n="$(find "$dir" -maxdepth 1 -name '*.json' | wc -l | tr -d ' ')"
  # Empty discovery is not success. A gate that passes because it found nothing
  # is the failure mode this whole project keeps hitting.
  [ "$n" -gt 0 ] || die "no child records in '$dir' — empty discovery is never success"

  if [ "$gate" = 1 ]; then
    # --gate-release cannot be vacuous: without the candidate identity it would
    # "gate" against nothing at all, which is the exact shape of a decorative
    # control. Both expectations are mandatory.
    [ -n "$require_arch" ]   || die "--gate-release requires --require-native <platform>"
    [ -n "$expect_rev" ]     || die "--gate-release requires --expect-revision <40-hex>"
    [ -n "$expect_digests" ] || die "--gate-release requires --expect-digests <file.json>"
    printf '%s' "$expect_rev" | grep -Eq '^[0-9a-f]{40}$' \
      || die "--expect-revision '$expect_rev' is not a 40-hex source revision"
    [ -f "$expect_digests" ] || die "--expect-digests file not found: $expect_digests"
  fi

  local kinds; kinds="$(policy_runner_kinds)" || kinds=""

  NAE_KINDS="$kinds" python3 - "$dir" "$require_arch" "$gate" "$expect_rev" \
      "$expect_digests" "$allow_non_auth" <<'PY'
import json, glob, os, sys, collections

d, require, gate_s, expect_rev, expect_digests, allow_non_auth_s = sys.argv[1:7]
gate = gate_s == "1"
allow_non_auth = allow_non_auth_s == "1"
accepted_kinds = [k for k in os.environ.get("NAE_KINDS", "").split(",") if k]

# Every spelling of "this did not run on the hardware it claims". Recognised on
# purpose: an unrecognised mode is refused, but emulation must be diagnosed AS
# emulation, not as a typo.
EMULATION_MODES = {"qemu", "emulated", "emulation"}
KNOWN_MODES = EMULATION_MODES | {"native"}
# uname -m as reported by the kernel -> the architecture name this tree uses.
UNAME_TO_ARCH = {"aarch64": "arm64", "arm64": "arm64",
                 "x86_64": "amd64", "amd64": "amd64"}
# Identity a native record must carry before it may gate anything.
REQUIRED_IDENTITY = ["image_label", "platform", "host_architecture",
                     "execution_mode", "runner_kind", "source_revision",
                     "manifest_digest"]

recs = []
for f in sorted(glob.glob(os.path.join(d, "*.json"))):
    try:
        r = json.load(open(f))
    except Exception as e:
        print("REFUSE: %s is not valid JSON: %s" % (os.path.basename(f), e), file=sys.stderr)
        raise SystemExit(1)
    if isinstance(r, dict) and "platform" in r and "execution_mode" in r:
        r["_file"] = os.path.basename(f)
        recs.append(r)
if not recs:
    print("REFUSE: no records carrying platform+execution_mode", file=sys.stderr)
    raise SystemExit(1)

by = collections.defaultdict(lambda: collections.Counter())
for r in recs:
    by[r["platform"]][r["execution_mode"]] += 1

for plat in sorted(by):
    print("  %-14s %s" % (plat, dict(by[plat])))

problems = []


def ident(r):
    return r.get("child_key") or r.get("image_label") or r.get("_file") or "?"


# --- shape that holds in every mode -----------------------------------------
for r in recs:
    if r["execution_mode"] not in KNOWN_MODES:
        problems.append("%s: unknown execution_mode %r — an unrecognised mode is "
                        "refused, never assumed native" % (ident(r), r["execution_mode"]))
    # A native claim must agree with the host architecture it ran on.
    if r["execution_mode"] == "native":
        want = r["platform"].split("/")[-1]
        got = r.get("host_architecture")
        if got != want:
            problems.append("%s claims execution_mode=native but host_architecture=%r "
                            "does not match platform %r" % (ident(r), got, r["platform"]))

# --- the native requirement --------------------------------------------------
if require:
    emulated = [ident(r) for r in recs
                if r["platform"] == require and r["execution_mode"] in EMULATION_MODES]
    other_mode = [ident(r) for r in recs
                  if r["platform"] == require and r["execution_mode"] not in KNOWN_MODES]
    if not [r for r in recs if r["platform"] == require]:
        problems.append("native evidence required for %s but no child of that platform "
                        "exists" % require)
    if emulated:
        problems.append("native evidence required for %s but %d child(ren) ran emulated: %s"
                        % (require, len(emulated), ", ".join(sorted(emulated)[:4])))
    if other_mode:
        problems.append("native evidence required for %s but %d child(ren) did not record "
                        "a native execution_mode: %s"
                        % (require, len(other_mode), ", ".join(sorted(other_mode)[:4])))

# --- --gate-release: the evidence must identify the candidate ----------------
if gate:
    try:
        want_digests = json.load(open(expect_digests))
    except Exception as e:
        print("REFUSE: --expect-digests is not readable JSON: %s" % e, file=sys.stderr)
        raise SystemExit(1)
    if not isinstance(want_digests, dict) or not want_digests:
        print("REFUSE: --expect-digests must be a non-empty {image_label: digest} object; "
              "an empty candidate set would gate nothing", file=sys.stderr)
        raise SystemExit(1)

    covered = {}
    for r in recs:
        who = ident(r)

        # Only records offered as native evidence for the required platform can
        # cover a required image. Everything else is checked for honesty and
        # then explicitly refused as coverage, never silently ignored.
        for field in REQUIRED_IDENTITY:
            if not r.get(field):
                problems.append("%s: native evidence does not identify %s — evidence "
                                "that cannot say what it is about cannot authorize "
                                "anything" % (who, field))

        # 1. THE LABEL IS A CLAIM, THE MEASUREMENT IS THE FACT.
        src = r.get("architecture_source")
        if src != "measured":
            problems.append("%s: architecture_source is %r, not 'measured' — the runner "
                            "label %r is a claim about where the job was REQUESTED, and "
                            "execution_mode must never be inferred from it"
                            % (who, src, r.get("runner_label")))
        uname = r.get("uname_m")
        if uname is not None:
            mapped = UNAME_TO_ARCH.get(str(uname))
            if mapped is None:
                problems.append("%s: uname_m %r is not a recognised machine name"
                                % (who, uname))
            elif mapped != r.get("host_architecture"):
                problems.append("%s: uname -m reported %r (%s) but the record claims "
                                "host_architecture %r — the measurement and the claim "
                                "disagree" % (who, uname, mapped, r.get("host_architecture")))

        # 2. The runner shape must be one the policy accepted.
        kind = r.get("runner_kind")
        if accepted_kinds and kind and kind not in accepted_kinds:
            problems.append("%s: runner_kind %r is not an accepted runner kind (%s)"
                            % (who, kind, ", ".join(accepted_kinds)))

        # 3. Provenance: a branch run is real evidence about a branch, and is
        #    not authorization for a release.
        if r.get("authoritative") is False and not allow_non_auth:
            problems.append("%s: evidence is marked authoritative=false — it was produced "
                            "on a non-default ref and cannot gate a release" % who)

        # 4. Another source revision cannot authorize this one.
        rev = r.get("source_revision")
        if rev and rev != expect_rev:
            problems.append("%s: source_revision %r is not the candidate revision %r — "
                            "evidence for another source cannot authorize this one"
                            % (who, rev, expect_rev))

        # 5. Another platform cannot satisfy the requirement.
        if r["platform"] != require:
            problems.append("%s: platform %r is not the required platform %r — evidence "
                            "for another platform cannot satisfy it"
                            % (who, r["platform"], require))
            continue

        # 6. Another digest cannot authorize this one.
        label = r.get("image_label")
        dig = r.get("manifest_digest")
        if label and label not in want_digests:
            problems.append("%s: image_label %r is not among the candidate images being "
                            "authorized — evidence for another image cannot authorize "
                            "this candidate" % (who, label))
        elif label and dig and dig != want_digests[label]:
            problems.append("%s: manifest_digest %r is not the authorized candidate digest "
                            "%r for %s — evidence for another digest cannot authorize "
                            "this one" % (who, dig, want_digests[label], label))

        # 7. The reference must actually name the digest it claims.
        ref = r.get("digest_reference")
        if ref and dig and not ref.endswith("@" + dig):
            problems.append("%s: digest_reference %r does not end in the manifest digest "
                            "%r" % (who, ref, dig))

        # 8. The smoke must have passed. Native evidence of a FAILING run is
        #    evidence, and it is not authorization.
        smoke = r.get("runtime_smoke")
        if smoke != "PASS":
            problems.append("%s: runtime_smoke is %r — native evidence must record a "
                            "passing runtime smoke" % (who, smoke))

        if r["execution_mode"] == "native" and label:
            covered[label] = dig

    # 9. COMPLETENESS. 9 of 10 is a refusal, not a pass.
    missing = sorted(set(want_digests) - set(covered))
    if missing:
        problems.append("native %s evidence covers %d of %d required production images; "
                        "missing: %s — a partial native result is a refusal, not a pass"
                        % (require, len(covered), len(want_digests), ", ".join(missing)))

if problems:
    print("REFUSE: native-architecture evidence contract not satisfied:", file=sys.stderr)
    for p in problems:
        print("  - %s" % p, file=sys.stderr)
    raise SystemExit(1)
if gate:
    print("native-arch evidence OK: %d of %d required production images carry native %s "
          "runtime evidence bound to the candidate digests at %s"
          % (len(covered), len(want_digests), require, expect_rev))
else:
    print("native-arch evidence OK%s" % (" (native required for %s)" % require if require else ""))
PY
}

# shellcheck disable=SC2317  # invoked through eval in the assertion helper
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

  # `emulated` is the spelling the real PHP 8.5 cohort uses. It must be
  # diagnosed as emulation, not as an unknown mode.
  d="$tmp/emulated"; mk "$d" linux/arm64 emulated amd64 a
  chk "$d" linux/arm64 > "$tmp/emulated.out" 2>&1
  t "execution_mode 'emulated' is recognised AS emulation, not as a typo" \
    "grep -q 'ran emulated' '$tmp/emulated.out'"

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

  # ---- --gate-release ------------------------------------------------------
  local REV=1111111111111111111111111111111111111111
  local OTHER=2222222222222222222222222222222222222222
  local DA DB
  DA="sha256:$(printf 'a%.0s' $(seq 64))"
  DB="sha256:$(printf 'b%.0s' $(seq 64))"
  printf '{"php-cli/8.3":"%s","nginx/prod":"%s"}\n' "$DA" "$DB" > "$tmp/want.json"

  gmk() { # gmk <dir> <label> <digest> [k=v ...]
    local dir="$1" label="$2" dig="$3"; shift 3
    mkdir -p "$dir"
    jq -n --arg l "$label" --arg dg "$dig" --arg rev "$REV" \
      '{record_type:"native-arch-runtime-evidence",
        child_key:($l+"/linux/arm64"), image_label:$l,
        platform:"linux/arm64", host_architecture:"arm64",
        execution_mode:"native", architecture_source:"measured", uname_m:"aarch64",
        runner_kind:"ephemeral-hosted", runner_label:"ubuntu-24.04-arm",
        source_revision:$rev, manifest_digest:$dg,
        digest_reference:("ghcr.io/o/p@"+$dg),
        runtime_smoke:"PASS", authoritative:true}' \
      > "$dir/$(printf '%s' "$label" | tr '/' '-').json"
    local f kv
    f="$dir/$(printf '%s' "$label" | tr '/' '-').json"
    for kv in "$@"; do
      jq --arg k "${kv%%=*}" --argjson v "${kv#*=}" '.[$k]=$v' "$f" > "$f.t" && mv "$f.t" "$f"
    done
  }
  gate() { ( check "$1" linux/arm64 1 "$REV" "$tmp/want.json" ); }

  d="$tmp/g-ok"; gmk "$d" php-cli/8.3 "$DA"; gmk "$d" nginx/prod "$DB"
  gate "$d" > "$tmp/g-ok.out" 2>&1
  t "GATE: complete, measured, digest-bound native evidence AUTHORIZES" \
    "gate '$d' >/dev/null 2>&1"
  t "...and says how many required images it covered" \
    "grep -q '2 of 2 required production images' '$tmp/g-ok.out'"

  d="$tmp/g-partial"; gmk "$d" php-cli/8.3 "$DA"
  gate "$d" > "$tmp/g-partial.out" 2>&1
  t "GATE: partial coverage REFUSES" "! gate '$d' >/dev/null 2>&1"
  t "...saying a partial native result is a refusal, not a pass" \
    "grep -q 'a partial native result is a refusal, not a pass' '$tmp/g-partial.out'"

  d="$tmp/g-rev"; gmk "$d" php-cli/8.3 "$DA" "source_revision=\"$OTHER\""; gmk "$d" nginx/prod "$DB"
  gate "$d" > "$tmp/g-rev.out" 2>&1
  t "GATE: evidence for another source revision REFUSES" "! gate '$d' >/dev/null 2>&1"
  t "...saying evidence for another source cannot authorize this one" \
    "grep -q 'evidence for another source cannot authorize this one' '$tmp/g-rev.out'"

  d="$tmp/g-dig"; gmk "$d" php-cli/8.3 "$DB"; gmk "$d" nginx/prod "$DB"
  gate "$d" > "$tmp/g-dig.out" 2>&1
  t "GATE: evidence for another digest REFUSES" "! gate '$d' >/dev/null 2>&1"
  t "...saying evidence for another digest cannot authorize this one" \
    "grep -q 'evidence for another digest cannot authorize this one' '$tmp/g-dig.out'"

  d="$tmp/g-plat"; gmk "$d" php-cli/8.3 "$DA" 'platform="linux/amd64"' 'host_architecture="amd64"'
  gmk "$d" nginx/prod "$DB"
  gate "$d" > "$tmp/g-plat.out" 2>&1
  t "GATE: evidence for another platform REFUSES" "! gate '$d' >/dev/null 2>&1"
  t "...saying evidence for another platform cannot satisfy it" \
    "grep -q 'evidence for another platform cannot satisfy it' '$tmp/g-plat.out'"

  d="$tmp/g-label"; gmk "$d" php-cli/8.3 "$DA"; gmk "$d" nginx/prod "$DB"
  gmk "$d" php-fpm/8.4 "$DA"
  gate "$d" > "$tmp/g-label.out" 2>&1
  t "GATE: evidence for an image outside the candidate set REFUSES" \
    "! gate '$d' >/dev/null 2>&1"
  t "...saying evidence for another image cannot authorize this candidate" \
    "grep -q 'evidence for another image cannot authorize this candidate' '$tmp/g-label.out'"

  d="$tmp/g-label-src"; gmk "$d" php-cli/8.3 "$DA" 'architecture_source="runner-label"'
  gmk "$d" nginx/prod "$DB"
  gate "$d" > "$tmp/g-label-src.out" 2>&1
  t "GATE: architecture taken from the runner label REFUSES" "! gate '$d' >/dev/null 2>&1"
  t "...saying the label is a claim and must never be inferred from" \
    "grep -q 'execution_mode must never be inferred from it' '$tmp/g-label-src.out'"

  d="$tmp/g-uname"; gmk "$d" php-cli/8.3 "$DA" 'uname_m="x86_64"'; gmk "$d" nginx/prod "$DB"
  gate "$d" > "$tmp/g-uname.out" 2>&1
  t "GATE: a uname -m that contradicts the claimed host REFUSES" \
    "! gate '$d' >/dev/null 2>&1"
  t "...saying the measurement and the claim disagree" \
    "grep -q 'the measurement and the claim disagree' '$tmp/g-uname.out'"

  d="$tmp/g-ident"; gmk "$d" php-cli/8.3 "$DA"; gmk "$d" nginx/prod "$DB"
  jq 'del(.manifest_digest)' "$d/php-cli-8.3.json" > "$d/t" && mv "$d/t" "$d/php-cli-8.3.json"
  gate "$d" > "$tmp/g-ident.out" 2>&1
  t "GATE: evidence that does not identify a manifest digest REFUSES" \
    "! gate '$d' >/dev/null 2>&1"
  t "...naming the field it failed to identify" \
    "grep -q 'native evidence does not identify manifest_digest' '$tmp/g-ident.out'"

  d="$tmp/g-emul"; gmk "$d" php-cli/8.3 "$DA" 'execution_mode="emulated"' 'host_architecture="amd64"'
  gmk "$d" nginx/prod "$DB"
  gate "$d" > "$tmp/g-emul.out" 2>&1
  t "GATE: QEMU evidence cannot satisfy the release native requirement" \
    "! gate '$d' >/dev/null 2>&1"
  t "...diagnosed as emulation" "grep -q 'ran emulated' '$tmp/g-emul.out'"

  d="$tmp/g-auth"; gmk "$d" php-cli/8.3 "$DA" 'authoritative=false'; gmk "$d" nginx/prod "$DB"
  gate "$d" > "$tmp/g-auth.out" 2>&1
  t "GATE: non-authoritative (branch) evidence cannot gate a release" \
    "! gate '$d' >/dev/null 2>&1"
  t "...saying it was produced on a non-default ref" \
    "grep -q 'produced on a non-default ref and cannot gate a release' '$tmp/g-auth.out'"

  d="$tmp/g-smoke"; gmk "$d" php-cli/8.3 "$DA" 'runtime_smoke="FAIL"'; gmk "$d" nginx/prod "$DB"
  gate "$d" > "$tmp/g-smoke.out" 2>&1
  t "GATE: a failing native smoke is evidence, not authorization" \
    "! gate '$d' >/dev/null 2>&1"
  t "...saying native evidence must record a passing runtime smoke" \
    "grep -q 'must record a passing runtime smoke' '$tmp/g-smoke.out'"

  # A gate with no candidate identity would gate nothing at all.
  d="$tmp/g-ok"
  ( check "$d" linux/arm64 1 "" "$tmp/want.json" ) > "$tmp/g-vac.out" 2>&1
  t "GATE: --gate-release without a candidate revision REFUSES rather than passing" \
    "grep -q 'requires --expect-revision' '$tmp/g-vac.out'"
  printf '{}' > "$tmp/empty.json"
  ( check "$d" linux/arm64 1 "$REV" "$tmp/empty.json" ) > "$tmp/g-vac2.out" 2>&1
  t "GATE: an EMPTY candidate set REFUSES rather than vacuously passing" \
    "grep -q 'an empty candidate set would gate nothing' '$tmp/g-vac2.out'"

  # ---- the real, committed emulated cohort as a negative fixture -----------
  # docs/audits/experimental-php-8.5-linux-amd64/ is genuine emulated evidence:
  # execution_mode "emulated", host_architecture arm64, platform linux/amd64. It
  # is exactly the shape that must never read as native arm64 evidence.
  local COHORT="$ROOT/docs/audits/experimental-php-8.5-linux-amd64"
  if [ -d "$COHORT" ]; then
    d="$tmp/real-emul"; mkdir -p "$d"
    local ff
    for ff in "$COHORT"/*.child-facts.json; do
      cp "$ff" "$d/$(basename "$ff")"
    done
    # child-facts carry no `platform` key, so give them the platform their
    # child_key names — otherwise the gate would not even see them, and a gate
    # that cannot see the fixture proves nothing.
    for ff in "$d"/*.json; do
      jq '. + {platform:"linux/amd64"}' "$ff" > "$ff.t" && mv "$ff.t" "$ff"
    done
    ( check "$d" linux/arm64 ) > "$tmp/real-emul.out" 2>&1
    t "REAL FIXTURE: the PHP 8.5 emulated cohort cannot satisfy native arm64" \
      "! ( check '$d' linux/arm64 ) >/dev/null 2>&1"
    t "...refused because no child of that platform exists, not by accident" \
      "grep -q 'no child of that platform exists' '$tmp/real-emul.out'"
    ( check "$d" linux/amd64 ) > "$tmp/real-emul2.out" 2>&1
    t "REAL FIXTURE: ...and it cannot satisfy native linux/amd64 either" \
      "! ( check '$d' linux/amd64 ) >/dev/null 2>&1"
    t "...diagnosed as emulation, in its own spelling" \
      "grep -q 'ran emulated' '$tmp/real-emul2.out'"
  fi

  # Was: "currently does NOT require native arm64". It does now — a hosted
  # ubuntu-24.04-arm runner produces native evidence, so the gate is armed. The
  # assertion is kept on the READ, not on the value, so it still catches an
  # unreadable or malformed policy.
  t "the policy is readable and states a native-arm64 requirement either way" \
    "case \"\$(policy_requires_native)\" in true|false) true ;; *) false ;; esac"
  t "...and it currently DOES require native arm64" \
    "[ \"\$(policy_requires_native)\" = true ]"
  t "the accepted runner kinds are read from policy, not hardcoded" \
    "[ -n \"\$(policy_runner_kinds)\" ]"

  echo "self-test: $ok ok, $bad failed"
  [ "$bad" -eq 0 ]
}

case "${1:-}" in
  --self-test) _self_test && echo "assert-native-arch-evidence.sh: SELF-TEST OK" ;;
  "") echo "usage: assert-native-arch-evidence.sh <records-dir> [--require-native <platform>]" \
           "[--gate-release --expect-revision <40hex> --expect-digests <file>]" \
           "[--allow-non-authoritative] | --self-test" >&2; exit 2 ;;
  *)
    dir="$1"; shift
    req=""; gate=0; exp_rev=""; exp_dig=""; allow_non_auth=0
    while [ $# -gt 0 ]; do
      case "$1" in
        --require-native) req="${2:?--require-native needs a platform}"; shift 2 ;;
        --gate-release)   gate=1; shift ;;
        --expect-revision) exp_rev="${2:?--expect-revision needs a 40-hex revision}"; shift 2 ;;
        --expect-digests)  exp_dig="${2:?--expect-digests needs a file}"; shift 2 ;;
        --allow-non-authoritative) allow_non_auth=1; shift ;;
        *) die "unknown argument: $1" ;;
      esac
    done
    if [ -z "$req" ] && [ "$(policy_requires_native)" = true ]; then req="linux/arm64"; fi
    check "$dir" "$req" "$gate" "$exp_rev" "$exp_dig" "$allow_non_auth"
    ;;
esac
