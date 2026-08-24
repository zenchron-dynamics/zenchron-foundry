#!/usr/bin/env bash
# =============================================================================
# scripts/experimental/experimental-plan.sh
# -----------------------------------------------------------------------------
# THE single enumeration of EXPERIMENTAL cohort children, and the single place
# that says what an experimental cohort may be invoked FOR.
#
# WHY THIS EXISTS.
#
# Four PHP 8.5 image definitions exist under images/php-{cli,fpm,worker,
# frankenphp}/8.5 and build on linux/amd64. Production is MATRIX_IMAGES in
# scripts/lib/common.sh and must not change. The only thing that recorded 8.5's
# status was `used_by: []` in policies/lifecycle.yaml, which says "no shipping
# image consumes this line" and NOTHING about the four Dockerfiles. They were
# therefore unreachable dead configuration: nothing enumerated them, nothing
# built them, nothing scanned them, and a fifth could have appeared unnoticed.
#
# This is the analogue of scripts/release/build-acceptance-matrix.sh for
# experimental cohorts, and it is DELIBERATELY A SEPARATE FILE. Merging the two
# enumerations is the one change that could put an experimental child into a
# production acceptance run.
#
# REACHABILITY AND ISOLATION ARE BOTH ENFORCED HERE, and they fail in opposite
# directions:
#
#   reachable  every registered cohort image resolves to a context on disk, and
#              every 8.5 directory on disk is registered. An unregistered
#              directory is a REFUSAL, not a silent omission.
#   isolated   no cohort image may appear in MATRIX_IMAGES, the cohort's
#              lifecycle line must carry the experimental release state, and the
#              production capabilities (acceptance, release-manifest, promotion,
#              seal, sign, publish, governance-selector) are refused by name,
#              each with its own diagnostic.
#
# IDENTITY IS NOT REDEFINED. child_key()/child_slug() come from
# scripts/lib/common.sh, the ONE identity derivation in this repository. A
# second one would let two spellings of the same child diverge — the defect
# behind cancelled run 32123758374.
#
# TWO ROOTS, deliberately separate, mirroring assert-evidence-class.sh:
#   EXP_ROOT        where the identity derivation lives. Always this checkout.
#   EXP_AUDIT_ROOT  the tree whose REGISTRY, LIFECYCLE, MATRIX and IMAGE
#                   DIRECTORIES are read. Defaults to EXP_ROOT. It exists so the
#                   sabotage tests can mutate a disposable COPY instead of the
#                   checkout (tests/lib/test_no_ambient_mutation.sh).
#
# Usage:
#   experimental-plan.sh --list
#   experimental-plan.sh plan <cohort> <platform-list>
#   experimental-plan.sh --count <cohort> <platform-list>
#   experimental-plan.sh capability <cohort> <capability>
#   experimental-plan.sh --self-test
# =============================================================================
set -uo pipefail
_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
. "$_d/../lib/common.sh"
# common.sh sets -e for its callers. This script deliberately runs commands that
# exit non-zero (every refusal path is one), and inherits errexit would abort the
# run at the first intentional refusal instead of reporting it.
set +e

EXP_ROOT="${EXP_ROOT:-$(cd "$_d/../.." && pwd)}"
EXP_AUDIT_ROOT="${EXP_AUDIT_ROOT:-$EXP_ROOT}"
REGISTRY="$EXP_AUDIT_ROOT/policies/experimental-cohorts.yaml"
LIFECYCLE="$EXP_AUDIT_ROOT/policies/lifecycle.yaml"

_need() {
  command -v jq >/dev/null || { echo "REFUSE: jq required" >&2; return 1; }
  python3 -c 'import yaml' 2>/dev/null \
    || { echo "REFUSE: python3 with PyYAML is required" >&2; return 1; }
}

# The PRODUCTION matrix as the AUDITED tree defines it. Read by executing that
# tree's own library rather than re-parsing it, so the two can never disagree
# about what a matrix token is.
_audited_matrix() {
  bash -c '. "$1/scripts/lib/common.sh"; matrix_images' _ "$EXP_AUDIT_ROOT" 2>/dev/null
}

# -----------------------------------------------------------------------------
# The whole contract lives in one python module: bash dispatches, python decides.
# It emits ONE JSON object per line for `entries`, or a plain verdict otherwise.
# -----------------------------------------------------------------------------
_exp() { # _exp <subcommand> [args...]
  _need || return 1
  MATRIX="$(_audited_matrix)" python3 - "$REGISTRY" "$LIFECYCLE" "$EXP_AUDIT_ROOT" "$@" <<'PY'
import hashlib, json, os, sys
import yaml

reg_path, life_path, root, sub = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
args = sys.argv[5:]

def refuse(msg):
    print("REFUSE: " + msg, file=sys.stderr)
    sys.exit(1)

def load_yaml(p, what):
    if not os.path.exists(p):
        refuse(f"{what} not found at {p}")
    try:
        return yaml.safe_load(open(p))
    except yaml.YAMLError as e:
        refuse(f"{what} is not valid YAML: {p}: {e}")

reg = load_yaml(reg_path, "experimental cohort registry")
life = load_yaml(life_path, "lifecycle inventory")

COHORTS = {c["id"]: c for c in (reg.get("cohorts") or [])}
CAPS = reg.get("capabilities") or {}
ALLOWED_VOCAB = CAPS.get("allowed") or {}
FORBIDDEN = CAPS.get("forbidden") or {}
LIFE_LINES = {x["id"]: x for x in (life.get("lines") or [])}

# MATRIX tokens as the audited tree's own library produces them.
MATRIX = [t for t in (os.environ.get("MATRIX") or "").split() if t]
if not MATRIX:
    refuse("the production matrix came back EMPTY. MATRIX_IMAGES in "
           "scripts/lib/common.sh is what proves an experimental cohort is "
           "disjoint from production; an empty matrix would make that check "
           "pass vacuously, so it is a refusal rather than a free pass")

def get_cohort(cid):
    if cid not in COHORTS:
        refuse(f"{cid!r} is not a registered experimental cohort. Known: "
               f"{sorted(COHORTS) or '(none)'}. A cohort is declared in "
               f"policies/experimental-cohorts.yaml and nowhere else — there is "
               f"deliberately no inferred default, because 'an images/ directory "
               f"that nothing lists is experimental' is exactly the dead "
               f"configuration this plan exists to abolish")
    return COHORTS[cid]

def check_lifecycle(c):
    """The cohort's release state is AUTHORIZED BY policies/lifecycle.yaml."""
    line_id = c["lifecycle_line"]
    want = c["requires_foundry_release_state"]
    if line_id not in LIFE_LINES:
        refuse(f"cohort {c['id']!r} names lifecycle line {line_id!r}, which does "
               f"not exist in policies/lifecycle.yaml. A cohort cannot authorize "
               f"its own release state")
    got = LIFE_LINES[line_id].get("foundry_release_state")
    if got != want:
        refuse(f"cohort {c['id']!r} requires foundry_release_state {want!r} on "
               f"lifecycle line {line_id!r}, but the lifecycle inventory says "
               f"{got!r}. The registry says WHICH DIRECTORIES are in the cohort; "
               f"policies/lifecycle.yaml says WHAT STATE the line is in. Neither "
               f"file can move an image on its own")

def check_disjoint(c):
    """No cohort image may be a PRODUCTION matrix image, in either direction."""
    sel = str(c["selector"])
    fams = [i["family"] for i in c["images"]]
    for tok in MATRIX:
        fam, _, ver = tok.partition(":")
        if ver == sel:
            refuse(f"production matrix token {tok!r} carries the experimental "
                   f"selector {sel!r}. An experimental cohort and MATRIX_IMAGES "
                   f"must stay DISJOINT: production acceptance derives its "
                   f"expected child count from MATRIX_COUNT, so an experimental "
                   f"family inside it fails the authorizer for a defect rather "
                   f"than a finding. Promoting {sel!r} requires a lifecycle "
                   f"authorization change, not a matrix edit")
        if fam in fams and ver == sel:
            refuse(f"cohort image {fam}:{sel} is also a production matrix image")

def check_registration(c):
    """Every 8.5 directory on disk is registered; every registration exists."""
    sel = str(c["selector"])
    registered = {i["family"]: i for i in c["images"]}
    for fam, img in registered.items():
        ctx = os.path.join(root, img["context"])
        if not os.path.isdir(ctx):
            refuse(f"cohort {c['id']!r} registers {fam} at {img['context']}, but "
                   f"that directory does not exist. A registration with no "
                   f"context is a plan that cannot be executed")
        if not os.path.isfile(os.path.join(ctx, "Dockerfile")):
            refuse(f"cohort {c['id']!r}: {img['context']} has no Dockerfile")
    images_dir = os.path.join(root, "images")
    found = []
    if os.path.isdir(images_dir):
        for fam in sorted(os.listdir(images_dir)):
            d = os.path.join(images_dir, fam, sel)
            if os.path.isdir(d):
                found.append(fam)
    unregistered = sorted(set(found) - set(registered))
    if unregistered:
        refuse(f"UNREGISTERED experimental image director"
               f"{'ies' if len(unregistered) > 1 else 'y'}: "
               + ", ".join(f"images/{f}/{sel}" for f in unregistered)
               + f". A {sel} image directory that no cohort lists is unreachable "
               f"dead configuration: nothing builds it, nothing smokes it, "
               f"nothing scans it, and nothing notices when it rots. Register it "
               f"in policies/experimental-cohorts.yaml under cohort "
               f"{c['id']!r}, or delete the directory")

def context_digest(rel):
    """Digest of the build CONTEXT, so two artifacts from the same revision but a
    different context are distinguishable. Path-and-content, sorted, so it does
    not depend on directory order."""
    base = os.path.join(root, rel)
    h = hashlib.sha256()
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames.sort()
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            relp = os.path.relpath(full, base)
            h.update(relp.encode())
            h.update(b"\0")
            h.update(hashlib.sha256(open(full, "rb").read()).hexdigest().encode())
            h.update(b"\n")
    return "sha256:" + h.hexdigest()

def validate_platforms(c, raw):
    if not raw:
        refuse("no platforms requested")
    if raw.startswith(",") or raw.endswith(",") or ",," in raw:
        refuse(f"malformed platform list {raw!r} (empty element)")
    seen, out = [], []
    for p in raw.split(","):
        if not p.startswith("linux/") or p == "linux/":
            refuse(f"{p!r} is not a linux/<arch> platform")
        if p in seen:
            refuse(f"platform {p!r} requested twice")
        seen.append(p)
        if p not in c["platforms"]:
            refuse(f"cohort {c['id']!r} is authorized for {c['platforms']} only, "
                   f"and {p!r} is not among them. No {p} child of this cohort has "
                   f"ever been built: there is no digest, no installed inventory "
                   f"and no finding set for it, so an amd64 result must not be "
                   f"allowed to speak for it")
        out.append(p)
    return out

# --------------------------------------------------------------------------
if sub == "list":
    for cid, c in sorted(COHORTS.items()):
        check_lifecycle(c); check_disjoint(c); check_registration(c)
        print(f"{cid}\tselector={c['selector']}\tplatforms={','.join(c['platforms'])}"
              f"\timages={len(c['images'])}\tclass={c['evidence_class']}")

elif sub == "entries":
    cid, plats = args[0], args[1]
    c = get_cohort(cid)
    check_lifecycle(c); check_disjoint(c); check_registration(c)
    prov = c.get("opcache_provenance") or {}
    for p in validate_platforms(c, plats):
        for img in c["images"]:
            fam = img["family"]
            print(json.dumps({
                "cohort": cid,
                "fam": fam,
                "ver": str(c["selector"]),
                "ctx": img["context"],
                "platform": p,
                "evidence_class": c["evidence_class"],
                "evidence_dir": c["evidence_dir"],
                "build_input_digest": context_digest(img["context"]),
                "required_extensions": " ".join(img["required_extensions"].split()),
                "forbidden_tools": img["forbidden_tools"],
                "opcache_provenance": prov.get(fam),
                "capabilities": c["capabilities"],
            }, sort_keys=True))

elif sub == "capability":
    cid, cap = args[0], args[1]
    c = get_cohort(cid)
    check_lifecycle(c); check_disjoint(c); check_registration(c)
    if cap in FORBIDDEN:
        refuse(f"capability {cap!r} is FORBIDDEN for experimental cohort "
               f"{cid!r}: {' '.join(FORBIDDEN[cap].split())}")
    if cap not in ALLOWED_VOCAB:
        refuse(f"capability {cap!r} is not in the closed capability vocabulary. "
               f"Allowed: {sorted(ALLOWED_VOCAB)}. Forbidden: {sorted(FORBIDDEN)}. "
               f"A verb that is neither is a refusal, so inventing a new one "
               f"cannot silently succeed")
    if cap not in (c.get("capabilities") or []):
        refuse(f"cohort {cid!r} does not carry capability {cap!r}; it carries "
               f"{c['capabilities']}")
    print(f"ok - cohort {cid}: capability {cap} permitted "
          f"({' '.join(ALLOWED_VOCAB[cap].split())})")

elif sub == "meta":
    cid = args[0]
    c = get_cohort(cid)
    check_lifecycle(c); check_disjoint(c); check_registration(c)
    print(json.dumps({
        "cohort": cid,
        "selector": str(c["selector"]),
        "platforms": c["platforms"],
        "capabilities": c["capabilities"],
        "forbidden_capabilities": sorted(FORBIDDEN),
        "evidence_class": c["evidence_class"],
        "evidence_dir": c["evidence_dir"],
    }, sort_keys=True))

else:
    refuse(f"unknown subcommand {sub!r}")
PY
}

# build_plan <cohort> <platform-list>
#
# Identity (child_key/child_slug) is attached HERE, in bash, from
# scripts/lib/common.sh — the one derivation. Python never spells a child name.
build_plan() {
  local cid="${1-}" plats="${2-}" entries meta line fam ver plat ck cs out=""
  [ -n "$cid" ] || { echo "REFUSE: no cohort named" >&2; return 1; }
  meta="$(_exp meta "$cid")" || return 1
  entries="$(_exp entries "$cid" "$plats")" || return 1
  [ -n "$entries" ] || { echo "REFUSE: cohort '$cid' enumerated no children" >&2; return 1; }
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    fam="$(printf '%s' "$line" | jq -r .fam)"
    ver="$(printf '%s' "$line" | jq -r .ver)"
    plat="$(printf '%s' "$line" | jq -r .platform)"
    ck="$(child_key  "$fam" "$ver" "$plat")" || return 1
    cs="$(child_slug "$fam" "$ver" "$plat")" || return 1
    out="${out}$(printf '%s' "$line" | jq -c --arg k "$ck" --arg s "$cs" \
      '. + {child_key:$k, child_slug:$s}')"$'\n'
  done <<< "$entries"
  printf '%s' "$out" | jq -sc --argjson meta "$meta" '$meta + {include: .}'
}

plan_count() {
  local m; m="$(build_plan "${1-}" "${2-}")" || return 1
  printf '%s' "$m" | jq '.include|length'
}

# --- self-test ---------------------------------------------------------------
# Writes ONLY inside a disposable fixture it creates. Never a repository-rooted
# path — see tests/lib/test_no_ambient_mutation.sh for the class of defect that
# rule exists for.
self_test() {
  local pass=0 fail=0 tmp copy out
  tmp="$(mktemp -d)"
  # EXIT, never RETURN: a RETURN trap fires on the return of every inner
  # function under `bash -T` and would delete the fixture after the first
  # assertion (tests/lib/test_functrace_safety.sh).
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" EXIT
  ck() { if eval "$2"; then pass=$((pass+1)); echo "ok   - $1"; else fail=$((fail+1)); echo "FAIL - $1"; fi; }

  if ! python3 -c 'import yaml' 2>/dev/null || ! command -v jq >/dev/null; then
    echo "SKIP - jq/pyyaml absent"; return 0
  fi

  # --- reachability --------------------------------------------------------
  ck "the registry lists php-8.5"            "$0 --list | grep -q '^php-8.5'"
  ck "the plan enumerates all four families" \
     "[ \"\$($0 --count php-8.5 linux/amd64)\" = 4 ]"
  out="$(build_plan php-8.5 linux/amd64)"
  ck "every enumerated context exists on disk" \
     "printf '%s' \"\$out\" | jq -r '.include[].ctx' | while read -r c; do
        [ -f \"$EXP_AUDIT_ROOT/\$c/Dockerfile\" ] || exit 1; done"
  ck "each child carries the canonical child_key from common.sh" \
     "[ \"\$(printf '%s' \"\$out\" | jq -r '.include[]|select(.fam==\"php-fpm\").child_key')\" \
        = \"\$(child_key php-fpm 8.5 linux/amd64)\" ]"
  ck "each child carries a build-context digest" \
     "printf '%s' \"\$out\" | jq -e 'all(.include[]; .build_input_digest|test(\"^sha256:[0-9a-f]{64}\$\"))' >/dev/null"
  ck "context digests are DISTINCT per family (not one constant)" \
     "[ \"\$(printf '%s' \"\$out\" | jq -r '[.include[].build_input_digest]|unique|length')\" = 4 ]"
  ck "the plan declares the reused foundry-child evidence class" \
     "[ \"\$(printf '%s' \"\$out\" | jq -r .evidence_class)\" = foundry-child ]"

  # --- isolation from production ------------------------------------------
  ck "no experimental child appears in the PRODUCTION acceptance plan" \
     "[ \"\$(bash '$EXP_ROOT/scripts/release/build-acceptance-matrix.sh' linux/amd64,linux/arm64 \
              | jq -r '[.include[]|select(.ver==\"8.5\")]|length')\" = 0 ]"
  ck "the production plan still yields exactly 2 x MATRIX_COUNT children" \
     "[ \"\$(bash '$EXP_ROOT/scripts/release/build-acceptance-matrix.sh' --count linux/amd64,linux/arm64)\" \
        = \"$(( MATRIX_COUNT * 2 ))\" ]"
  ck "the experimental and production enumerations are disjoint" \
     "[ -z \"\$(comm -12 \
         <(printf '%s' \"\$out\" | jq -r '.include[]|\"\\(.fam):\\(.ver)\"' | sort -u) \
         <(matrix_images | sort -u))\" ]"

  # --- capabilities: allowed ----------------------------------------------
  local c
  for c in build smoke extensions sbom scan evidence; do
    ck "capability '$c' is permitted" "$0 capability php-8.5 $c >/dev/null"
  done

  # --- capabilities, forbidden, each for its OWN reason -------------------
  # `|| true` IS LOAD-BEARING. `set -o pipefail` is still on (only errexit was
  # cleared), so under a pipeline bash reports the status of ANY failing member —
  # and these commands fail ON PURPOSE. Without the `|| true` a perfectly
  # matching grep still reads as a failed assertion. This is the fifth place in
  # this repository that trap has bitten; the shape is always an assertion about
  # a deliberately-failing command, so every refusal-diagnostic probe below is
  # funnelled through one of these two helpers rather than written inline.
  # OUTPUT IS CAPTURED, NEVER PIPED INTO A MATCHER. Two traps meet here, and
  # the second is a RACE that passes until it does not:
  #   * `set -o pipefail` reports a pipeline as failed when ANY member fails,
  #     and every command below fails ON PURPOSE;
  #   * a quiet matcher exits at the FIRST hit and closes the pipe, so the
  #     producer dies of SIGPIPE and the pipeline exits 141 however well the
  #     match went — and `|| true` cannot catch a signal.
  # Whether that fires depends on how much the producer had already written.
  # Substitution plus a case glob has neither problem, so every refusal
  # DIAGNOSTIC below goes through one of these three helpers.
  why()        { "$0" capability php-8.5 "$1" 2>&1; }
  says()       { case "$(why "$1")" in *"$2"*) return 0 ;; *) return 1 ;; esac; }
  sab_says()   { case "$(EXP_AUDIT_ROOT="$copy" "$0" --count php-8.5 linux/amd64 2>&1)" in
                   *"$1"*) return 0 ;; *) return 1 ;; esac; }
  arm64_says() { case "$("$0" --count php-8.5 linux/arm64 2>&1)" in
                   *"$1"*) return 0 ;; *) return 1 ;; esac; }
  ck "capability 'acceptance' is refused"       "says acceptance FORBIDDEN"
  ck "...naming production acceptance"          "says acceptance MATRIX_COUNT"
  ck "capability 'release-manifest' is refused" "says release-manifest FORBIDDEN"
  ck "capability 'promotion' is refused"        "says promotion 'never published'"
  ck "capability 'seal' is refused"             "says seal required-release-checks"
  ck "capability 'sign' is refused"             "says sign indistinguishable"
  ck "capability 'publish' is refused"          "says publish 'no support commitment'"
  ck "capability 'governance-selector' refused" "says governance-selector php-8.3-8.4"
  ck "an INVENTED capability is refused, not defaulted" \
     "says teleport 'closed capability vocabulary'"

  # --- platform authority --------------------------------------------------
  ck "linux/arm64 is refused for this cohort"   "! $0 --count php-8.5 linux/arm64 >/dev/null 2>&1"
  ck "...and the refusal says no arm64 child exists" \
     "arm64_says 'has ever been built'"
  ck "an unknown cohort is refused"             "! $0 --count php-9.9 linux/amd64 >/dev/null 2>&1"
  ck "an empty platform list is refused"        "! $0 --count php-8.5 '' >/dev/null 2>&1"
  ck "a duplicate platform is refused"          "! $0 --count php-8.5 linux/amd64,linux/amd64 >/dev/null 2>&1"

  # --- SABOTAGE, on a disposable COPY of the audited tree -----------------
  copy="$tmp/tree"
  mkdir -p "$copy"
  ( cd "$EXP_AUDIT_ROOT" && tar cf - policies scripts images ) | ( cd "$copy" && tar xf - )
  ck "the disposable copy reproduces the clean verdict (sabotage baseline)" \
     "EXP_AUDIT_ROOT='$copy' $0 --count php-8.5 linux/amd64 >/dev/null 2>&1"

  # 1. an experimental image directory that nobody registered
  mkdir -p "$copy/images/php-unregistered/8.5"
  printf 'FROM scratch\nUSER 10001:10001\n' > "$copy/images/php-unregistered/8.5/Dockerfile"
  ck "SABOTAGE: an UNREGISTERED 8.5 image directory is REFUSED" \
     "! EXP_AUDIT_ROOT='$copy' $0 --count php-8.5 linux/amd64 >/dev/null 2>&1"
  ck "...and the refusal NAMES the unregistered directory" \
     "sab_says 'images/php-unregistered/8.5'"
  ck "...and calls it what it is: dead configuration" \
     "sab_says 'dead configuration'"
  rm -rf "$copy/images/php-unregistered"
  ck "...and removing it restores the clean verdict (the refusal was the change)" \
     "EXP_AUDIT_ROOT='$copy' $0 --count php-8.5 linux/amd64 >/dev/null 2>&1"

  # 2. an experimental image promoted into PRODUCTION without lifecycle authority
  sed -i.bak 's|^MATRIX_IMAGES="|MATRIX_IMAGES="php-cli:8.5 |' "$copy/scripts/lib/common.sh"
  sed -i.bak 's|^MATRIX_COUNT=10|MATRIX_COUNT=11|' "$copy/scripts/lib/common.sh"
  rm -f "$copy/scripts/lib/common.sh.bak"
  ck "SABOTAGE: an 8.5 image added to MATRIX_IMAGES is REFUSED" \
     "! EXP_AUDIT_ROOT='$copy' $0 --count php-8.5 linux/amd64 >/dev/null 2>&1"
  ck "...and the refusal says promotion needs lifecycle authorization, not a matrix edit" \
     "sab_says 'not a matrix edit'"

  # 3. the lifecycle authorization removed underneath a registered cohort
  ( cd "$EXP_AUDIT_ROOT" && tar cf - policies scripts ) | ( cd "$copy" && tar xf - )
  python3 - "$copy/policies/lifecycle.yaml" <<'PYS'
import sys, yaml
p = sys.argv[1]
d = yaml.safe_load(open(p))
for line in d["lines"]:
    if line["id"] == "php-8.5":
        line["foundry_release_state"] = "production"
yaml.safe_dump(d, open(p, "w"), sort_keys=False, allow_unicode=True)
PYS
  ck "SABOTAGE: a lifecycle release-state change alone is REFUSED" \
     "! EXP_AUDIT_ROOT='$copy' $0 --count php-8.5 linux/amd64 >/dev/null 2>&1"
  ck "...and the refusal names both files, so neither can move an image alone" \
     "sab_says 'Neither file can move an image on its own'"

  # 4. NON-VACUITY of the disjointness proof: an EMPTY matrix must not pass
  ( cd "$EXP_AUDIT_ROOT" && tar cf - policies scripts ) | ( cd "$copy" && tar xf - )
  sed -i.bak 's|^MATRIX_IMAGES=.*|MATRIX_IMAGES=""|' "$copy/scripts/lib/common.sh"
  rm -f "$copy/scripts/lib/common.sh.bak"
  ck "SABOTAGE: an EMPTY production matrix is refused, not passed vacuously" \
     "sab_says 'came back EMPTY'"

  echo "----"
  printf 'self-test: %d ok, %d failed\n' "$pass" "$fail"
  [ "$fail" -eq 0 ]
}

# NO ARGUMENT is a usage error; an EMPTY argument is a refusal. They are
# different, and the difference is what tells a caller whether they mistyped a
# command or passed an empty variable.
if [ "$#" -eq 0 ]; then
  cat >&2 <<USAGE
usage: $(basename "$0") --list
       $(basename "$0") plan <cohort> <platform-list>
       $(basename "$0") --count <cohort> <platform-list>
       $(basename "$0") capability <cohort> <capability>
       $(basename "$0") --self-test
USAGE
  exit 64
fi
case "$1" in
  --list)      _exp list ;;
  --self-test) self_test ;;
  --count)     shift; plan_count "${1-}" "${2-}" ;;
  capability)  shift; [ "$#" -eq 2 ] || { echo "REFUSE: capability needs <cohort> <capability>" >&2; exit 1; }; _exp capability "$1" "$2" ;;
  plan)        shift; build_plan "${1-}" "${2-}" ;;
  *)           echo "REFUSE: unknown subcommand '$1'" >&2; exit 1 ;;
esac
