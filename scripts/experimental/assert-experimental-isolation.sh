#!/usr/bin/env bash
# =============================================================================
# scripts/experimental/assert-experimental-isolation.sh
# -----------------------------------------------------------------------------
# THE PRODUCTION-SIDE HALF of the experimental cohort contract.
#
# scripts/experimental/experimental-plan.sh proves an experimental cohort is
# REACHABLE — all four PHP 8.5 definitions are enumerated, and an unregistered
# 8.5 directory is refused. That is only half a guarantee. The other half is
# that nothing in PRODUCTION can reach BACK, and it must be checked from the
# production side, because the plan is not what a release run executes.
#
# WHAT IS ASSERTED, and why each one is structural rather than a text search:
#
#   1. DISJOINT ENUMERATIONS. No cohort selector appears in MATRIX_IMAGES.
#      MATRIX_IMAGES is the ONE production enumeration and every production
#      path — acceptance, manifest, promotion, seal, sign, publish — derives
#      from it. If the cohort is not in it, none of them can name a cohort
#      child, and this is the assertion that actually carries that weight.
#
#   2. THE ACCEPTANCE PLAN YIELDS ZERO COHORT CHILDREN, on every platform, and
#      still yields exactly MATRIX_COUNT per platform. Checked by RUNNING the
#      production planner, not by reading it.
#
#   3. NO PRODUCTION CONTRACT. contracts/ is the production contract directory
#      and its file count is asserted against MATRIX_COUNT elsewhere. A cohort
#      image with a file there would both break that count and quietly claim
#      production support.
#
#   4. NO GOVERNANCE SELECTOR NAMES THE COHORT, in EITHER list of
#      policies/vulnerability-exceptions.yaml. The PHP selectors are bound to
#      the immutable php-8.3-8.4 cohort (in_scope(), scripts/reconcile-
#      vulnerabilities.sh); this refuses the static shape that would widen them.
#
#   5. NO PRODUCTION WORKFLOW ENUMERATES THE COHORT. Executable lines only:
#      this repository has repeatedly shipped checks that matched their own
#      explanatory prose and reported a correct file as broken.
#
#   6. EVERY FORBIDDEN CAPABILITY IS STILL REFUSED by the plan.
#
# EVERY ONE OF THESE IS PROVED NON-VACUOUS in --self-test, against a disposable
# copy: a check that has never failed is indistinguishable from a check that
# cannot fail.
#
# Roots follow scripts/experimental/experimental-plan.sh: EXP_ROOT is this
# checkout (the contract), EXP_AUDIT_ROOT is the tree being audited.
#
# Usage:
#   assert-experimental-isolation.sh
#   assert-experimental-isolation.sh --self-test
# =============================================================================
set -uo pipefail
_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
. "$_d/../lib/common.sh"
# Sourcing common.sh imports `set -e`. Every refusal below is a deliberately
# non-zero command; errexit would abort at the first one and report nothing.
set +e

EXP_ROOT="${EXP_ROOT:-$(cd "$_d/../.." && pwd)}"
EXP_AUDIT_ROOT="${EXP_AUDIT_ROOT:-$EXP_ROOT}"
PLAN="$EXP_ROOT/scripts/experimental/experimental-plan.sh"

_rc=0
_refuse() { printf 'REFUSE: %s\n' "$*" >&2; _rc=1; }
_ok()     { printf 'ok   - %s\n' "$*"; }

# cohort_selectors — every registered experimental selector, from the registry.
cohort_selectors() {
  python3 - "$EXP_AUDIT_ROOT/policies/experimental-cohorts.yaml" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
for c in (d.get("cohorts") or []):
    print(str(c["selector"]))
PY
}

cohort_ids() {
  python3 - "$EXP_AUDIT_ROOT/policies/experimental-cohorts.yaml" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
for c in (d.get("cohorts") or []):
    print(c["id"])
PY
}

audited_matrix() { bash -c '. "$1/scripts/lib/common.sh"; matrix_images' _ "$EXP_AUDIT_ROOT" 2>/dev/null; }

# workflow_hits <selector> — executable-line occurrences of a selector in the
# production workflows. Comments stripped FIRST, so this check cannot be
# satisfied or broken by its own documentation.
workflow_hits() {
  local sel="$1" f out
  for f in "$EXP_AUDIT_ROOT"/.github/workflows/*.yml; do
    [ -f "$f" ] || continue
    out="$(grep -vE '^[[:space:]]*#' "$f" | grep -nF "$sel")"
    [ -n "$out" ] && printf '%s: %s\n' "${f##*/}" "$(printf '%s' "$out" | head -1)"
  done
  return 0
}

ledger_hits() {
  python3 - "$EXP_AUDIT_ROOT/policies/vulnerability-exceptions.yaml" "$@" <<'PY'
import sys, yaml
led = yaml.safe_load(open(sys.argv[1]))
sels = sys.argv[2:]
rows = (led.get("exceptions") or []) + (led.get("not_affected") or [])
if not rows:
    print("EMPTY-LEDGER")
    raise SystemExit(0)
for e in rows:
    img = str(e.get("image", ""))
    for s in sels:
        if s in img:
            print(f"{e.get('cve')}: image={img!r}")
PY
}

run_checks() {
  _rc=0
  local sels ids sel matrix tok n_prod plat

  sels="$(cohort_selectors)"
  ids="$(cohort_ids)"
  if [ -z "$sels" ] || [ -z "$ids" ]; then
    _refuse "the experimental cohort registry enumerated NOTHING. Every check
below is a statement about registered cohorts, so an empty registry would pass
all of them vacuously. If there are genuinely no experimental cohorts, delete
policies/experimental-cohorts.yaml and this gate together."
    return "$_rc"
  fi

  # --- 1. disjoint enumerations -------------------------------------------
  matrix="$(audited_matrix)"
  if [ -z "$matrix" ]; then
    _refuse "MATRIX_IMAGES came back empty; disjointness cannot be proved against nothing"
    return "$_rc"
  fi
  for sel in $sels; do
    for tok in $matrix; do
      if [ "${tok##*:}" = "$sel" ]; then
        _refuse "production matrix token '$tok' carries experimental selector '$sel'.
        Production is MATRIX_IMAGES and must not contain an experimental cohort:
        promotion requires a lifecycle authorization change in
        policies/lifecycle.yaml, not an edit to scripts/lib/common.sh."
      fi
    done
  done
  [ "$_rc" -eq 0 ] && _ok "MATRIX_IMAGES carries no experimental selector ($(printf '%s' "$sels" | tr '\n' ' '))"

  # --- 2. the production acceptance plan cannot reach a cohort child ------
  # RUN the production planner. Reading it would prove only what it says.
  local acc
  acc="$(bash "$EXP_ROOT/scripts/release/build-acceptance-matrix.sh" linux/amd64,linux/arm64 2>/dev/null)"
  if [ -z "$acc" ]; then
    _refuse "the production acceptance planner produced no matrix; cannot prove exclusion"
  else
    for sel in $sels; do
      n_prod="$(printf '%s' "$acc" | jq -r --arg v "$sel" '[.include[]|select(.ver==$v)]|length')"
      if [ "$n_prod" != 0 ]; then
        _refuse "the production acceptance plan enumerates $n_prod child(ren) with selector '$sel'"
      fi
    done
    for plat in linux/amd64 linux/arm64; do
      n_prod="$(printf '%s' "$acc" | jq -r --arg p "$plat" '[.include[]|select(.platform==$p)]|length')"
      if [ "$n_prod" != "$MATRIX_COUNT" ]; then
        _refuse "the production acceptance plan yields $n_prod children on $plat, expected \$MATRIX_COUNT=$MATRIX_COUNT"
      fi
    done
  fi
  [ "$_rc" -eq 0 ] && _ok "the production acceptance plan yields MATRIX_COUNT children per platform and zero experimental ones"

  # --- 3. no production contract claims an experimental image -------------
  for sel in $sels; do
    local hits
    hits="$(ls "$EXP_AUDIT_ROOT"/contracts/images/*-"$sel".yaml \
                "$EXP_AUDIT_ROOT"/contracts/php-extensions/*-"$sel".txt 2>/dev/null)"
    if [ -n "$hits" ]; then
      _refuse "contracts/ holds PRODUCTION contracts for experimental selector '$sel':
$(printf '%s' "$hits" | sed 's|^|        |')
        Their count is asserted against MATRIX_COUNT, and a contract there
        claims production support the cohort does not have."
    fi
  done
  [ "$_rc" -eq 0 ] && _ok "contracts/ holds no experimental-selector contract"

  # --- 4. no governance selector names the cohort -------------------------
  local lhits
  lhits="$(ledger_hits $sels $ids)"
  if [ "$lhits" = "EMPTY-LEDGER" ]; then
    _refuse "policies/vulnerability-exceptions.yaml has no entries at all; a selector
        check against an empty ledger proves nothing"
  elif [ -n "$lhits" ]; then
    _refuse "a vulnerability-ledger selector names an experimental cohort:
$(printf '%s' "$lhits" | sed 's|^|        |')
        PHP selectors are bound to the IMMUTABLE php-8.3-8.4 cohort. Widening
        one to an experimental cohort would retroactively govern an artifact
        the decision was never made from."
  else
    _ok "no vulnerability-ledger selector (either list) names an experimental cohort"
  fi

  # --- 5. no production workflow enumerates a cohort ----------------------
  for sel in $sels; do
    local whits
    whits="$(workflow_hits "$sel")"
    if [ -n "$whits" ]; then
      _refuse "a production workflow enumerates experimental selector '$sel':
$(printf '%s' "$whits" | sed 's|^|        |')"
    fi
  done
  [ "$_rc" -eq 0 ] && _ok "no .github/workflows/ executable line enumerates an experimental selector"

  # --- 6. every forbidden capability is still refused ---------------------
  local cid cap
  for cid in $ids; do
    for cap in acceptance release-manifest promotion seal sign publish governance-selector; do
      if bash "$PLAN" capability "$cid" "$cap" >/dev/null 2>&1; then
        _refuse "cohort '$cid' PERMITS forbidden capability '$cap'"
      fi
    done
    for cap in build smoke extensions sbom scan evidence; do
      if ! bash "$PLAN" capability "$cid" "$cap" >/dev/null 2>&1; then
        _refuse "cohort '$cid' refuses ALLOWED capability '$cap' — the cohort is
        unreachable, which is the dead configuration this contract abolishes"
      fi
    done
  done
  [ "$_rc" -eq 0 ] && _ok "every forbidden capability refuses and every allowed capability permits"

  return "$_rc"
}

# --- self-test ---------------------------------------------------------------
# Writes ONLY inside a disposable fixture. Never a repository-rooted path.
self_test() {
  local pass=0 fail=0 tmp copy
  tmp="$(mktemp -d)"
  # EXIT, never RETURN — a RETURN trap fires on every inner function return
  # under `bash -T` (tests/lib/test_functrace_safety.sh).
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" EXIT
  ck() { if eval "$2"; then pass=$((pass+1)); echo "ok   - $1"; else fail=$((fail+1)); echo "FAIL - $1"; fi; }

  ck "the checkout PASSES isolation today" "run_checks >/dev/null 2>&1"

  copy="$tmp/tree"; mkdir -p "$copy"
  ( cd "$EXP_AUDIT_ROOT" && tar cf - policies scripts contracts images .github ) | ( cd "$copy" && tar xf - )
  reset_copy() { ( cd "$EXP_AUDIT_ROOT" && tar cf - policies scripts contracts .github ) | ( cd "$copy" && tar xf - ); }
  # OUTPUT IS CAPTURED, NEVER PIPED INTO A MATCHER. Two traps meet here and the
  # second one is a RACE, so it passes until it does not:
  #   * `set -o pipefail` reports a pipeline as failed when ANY member fails,
  #     and the audited command fails ON PURPOSE — hence the usual `|| true`;
  #   * a quiet matcher exits at the FIRST hit and closes the pipe, so the
  #     producer is killed by SIGPIPE and the pipeline exits 141 however well
  #     the match went. `|| true` cannot catch a signal. Whether it fires
  #     depends on how much the producer had already written, which is why half
  #     these assertions passed and half failed on identical code.
  # Substitution plus a case glob has neither problem.
  sab() { EXP_AUDIT_ROOT="$copy" run_checks 2>&1; }
  sab_says() { case "$(sab)" in *"$1"*) return 0 ;; *) return 1 ;; esac; }

  ck "the disposable copy reproduces the PASS (baseline for every sabotage below)" \
     "EXP_AUDIT_ROOT='$copy' run_checks >/dev/null 2>&1"

  # 1. an experimental image promoted into the production matrix
  sed -i.bak 's|^MATRIX_IMAGES="|MATRIX_IMAGES="php-cli:8.5 |' "$copy/scripts/lib/common.sh"
  rm -f "$copy/scripts/lib/common.sh.bak"
  ck "SABOTAGE: 8.5 in MATRIX_IMAGES is REFUSED" "! EXP_AUDIT_ROOT='$copy' run_checks >/dev/null 2>&1"
  ck "...and the refusal says promotion needs a lifecycle change, not a matrix edit" \
     "sab_says 'not an edit to scripts/lib/common.sh'"
  reset_copy
  ck "...and reverting it restores the PASS (the sabotage was the cause)" \
     "EXP_AUDIT_ROOT='$copy' run_checks >/dev/null 2>&1"

  # 2. a production contract that claims an experimental image
  cp "$copy/contracts/images/php-cli-8.4.yaml" "$copy/contracts/images/php-cli-8.5.yaml"
  ck "SABOTAGE: a contracts/ entry for 8.5 is REFUSED" "! EXP_AUDIT_ROOT='$copy' run_checks >/dev/null 2>&1"
  ck "...and the refusal says it claims production support" \
     "sab_says 'claims production support'"
  reset_copy; rm -f "$copy/contracts/images/php-cli-8.5.yaml"
  ck "...and removing it restores the PASS" "EXP_AUDIT_ROOT='$copy' run_checks >/dev/null 2>&1"

  # 3. a governance selector widened to reach the cohort
  python3 - "$copy/policies/vulnerability-exceptions.yaml" <<'PYS'
import sys, yaml
p = sys.argv[1]
d = yaml.safe_load(open(p))
for e in d["exceptions"]:
    if e["image"] == "php-8.3-8.4":
        e["image"] = "php-8.3-8.4-8.5"
        break
yaml.safe_dump(d, open(p, "w"), sort_keys=False, allow_unicode=True)
PYS
  ck "SABOTAGE: a ledger selector widened to 8.5 is REFUSED" \
     "! EXP_AUDIT_ROOT='$copy' run_checks >/dev/null 2>&1"
  ck "...and the refusal says the decision was never made from that artifact" \
     "sab_says 'decision was never made from'"
  reset_copy
  ck "...and reverting the ledger restores the PASS" "EXP_AUDIT_ROOT='$copy' run_checks >/dev/null 2>&1"

  # 4. a production workflow that enumerates the cohort
  printf '\n# a comment mentioning 8.5 must NOT trip this check\n        run: echo build-8.5\n' \
    >> "$copy/.github/workflows/scan-images.yml"
  ck "SABOTAGE: a workflow line naming 8.5 is REFUSED" \
     "! EXP_AUDIT_ROOT='$copy' run_checks >/dev/null 2>&1"
  ck "...and the refusal names the workflow" "sab_says 'scan-images.yml'"
  reset_copy
  # The comment-only case must NOT refuse: a check that matches its own prose
  # has condemned correct files in this repository before.
  printf '\n# scan-images does not build php 8.5; this comment says so\n' \
    >> "$copy/.github/workflows/scan-images.yml"
  ck "...but a COMMENT mentioning 8.5 does NOT trip it" \
     "EXP_AUDIT_ROOT='$copy' run_checks >/dev/null 2>&1"
  reset_copy

  # 5. NON-VACUITY of the registry-driven loop: an empty registry must refuse
  printf 'schema_version: 1\ncapabilities:\n  allowed: {}\n  forbidden: {}\ncohorts: []\n' \
    > "$copy/policies/experimental-cohorts.yaml"
  ck "SABOTAGE: an EMPTY cohort registry is refused, not passed vacuously" \
     "sab_says 'enumerated NOTHING'"
  reset_copy
  ck "...and restoring the registry restores the PASS" "EXP_AUDIT_ROOT='$copy' run_checks >/dev/null 2>&1"

  echo "----"
  printf 'self-test: %d ok, %d failed\n' "$pass" "$fail"
  [ "$fail" -eq 0 ]
}

case "${1-}" in
  --self-test) self_test ;;
  "")          run_checks && echo "EXPERIMENTAL ISOLATION OK" ;;
  *)           echo "usage: $(basename "$0") [--self-test]" >&2; exit 64 ;;
esac
