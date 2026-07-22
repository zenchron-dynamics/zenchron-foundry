#!/usr/bin/env bash
# Phase E — two-phase promotion + compensating rollback, against the mock
# registry backend. Proves: full success; mutation failure at first / middle /
# final-canonical alias each triggers a full reverse-order restore; and an
# unrestorable rollback yields the emergency exit code 99 + incident artifact.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

# registry-ops for seeding the mock
# shellcheck source=/dev/null
. scripts/lib/registry-ops.sh
# shellcheck source=/dev/null
. scripts/lib/registry-aliases.sh
set +e   # the sourced libs enable `set -e`; this harness checks exit codes itself

ck "promote-stable self-test"          'bash scripts/promote-stable.sh --self-test >/dev/null'
ck "rollback-stable self-test"         'bash scripts/rollback-stable.sh --self-test >/dev/null'
ck "verify-promotion-state self-test"  'bash scripts/verify-promotion-state.sh --self-test >/dev/null'

R=7b4985a1234567890abcdef1234567890abcdef1
mkey() { case "$2" in prod) printf '%s' "$1" ;; *) printf '%s-%s' "$1" "$2" ;; esac; }

# Build a signed(LOCAL) RC manifest with known per-image digests.
build_manifest() { # <out>
  R="$R" OUT="$1" python3 - <<'PY'
import os, yaml, hashlib
R=os.environ["R"]
keys=[f"php-{f}-{v}" for f in ("cli","fpm","worker","frankenphp") for v in ("8.3","8.4")]+["nginx","caddy"]
def repo(k): return "ghcr.io/zenchron-dynamics/%s" % (k.rsplit("-",1)[0] if k.startswith("php-") else k)
def dig(k): return "sha256:"+hashlib.sha256(("rc:"+k).encode()).hexdigest()
imgs={k:{"repository":repo(k),"immutable_tag":"t-"+k,"digest":dig(k),"reference":repo(k)+"@"+dig(k),
         "revision":R,"platforms":["linux/amd64","linux/arm64"]} for k in keys}
m={"schema_version":1,"release":"v2026.07.03","candidate":"rc1","revision":R,
   "source_repository":"zenchron-dynamics/zenchron-foundry","source_ref":"refs/heads/master",
   "workflow_run_id":"1","created_at":"2026-07-03T12:00:00Z","images":imgs}
yaml.safe_dump(m,open(os.environ["OUT"],"w"),sort_keys=True)
PY
}
rcdig_for() { python3 -c "import hashlib,sys;print('sha256:'+hashlib.sha256(('rc:'+sys.argv[1]).encode()).hexdigest())" "$1"; }
priordig_for() { python3 -c "import hashlib,sys;print('sha256:'+hashlib.sha256(('prior:'+sys.argv[1]).encode()).hexdigest())" "$1"; }

# Seed the mock registry: every stable alias gets a PRIOR digest, except caddy's
# aliases are left absent (NONE -> tests new-alias creation + untag-on-rollback).
seed_priors() {
  REG_RETAG_COUNT=0
  for t in $MATRIX_IMAGES; do
    fam="${t%:*}"; sel="${t#*:}"
    for suf in $(stable_aliases "$sel" 2026.07.03); do
      ref="$(full_ref "$fam" "$suf")"
      case "$fam" in caddy) continue ;; esac   # leave caddy aliases as NONE
      reg_retag "$ref" "$(priordig_for "$ref")"
    done
  done
}
all_at_rc() { # every alias resolves to its image RC digest?
  for t in $MATRIX_IMAGES; do
    fam="${t%:*}"; sel="${t#*:}"; want="$(rcdig_for "$(mkey "$fam" "$sel")")"
    for suf in $(stable_aliases "$sel" 2026.07.03); do
      got="$(reg_digest "$(full_ref "$fam" "$suf")" 2>/dev/null || echo '')"
      [ "$got" = "$want" ] || return 1
    done
  done
}
priors_restored() { # non-caddy aliases back at prior; caddy aliases absent
  for t in $MATRIX_IMAGES; do
    fam="${t%:*}"; sel="${t#*:}"
    for suf in $(stable_aliases "$sel" 2026.07.03); do
      ref="$(full_ref "$fam" "$suf")"; got="$(reg_digest "$ref" 2>/dev/null || echo NONE)"
      case "$fam" in
        caddy) [ "$got" = NONE ] || return 1 ;;
        *)     [ "$got" = "$(priordig_for "$ref")" ] || return 1 ;;
      esac
    done
  done
}

run_promo() { # <mock-dir> <artdir> [REG_FAIL_AT]
  ( export REG_BACKEND=mock REG_MOCK_DIR="$1" ARTDIR="$2" LOCAL=1
    [ -n "${3:-}" ] && export REG_FAIL_AT="$3"
    bash scripts/promote-stable.sh v2026.07.03 rc1 --manifest "$2/rc.yaml" ) >/dev/null 2>&1
}

setup() { # -> echoes "mockdir artdir"
  local d; d="$(mktemp -d)"; mkdir -p "$d/mock" "$d/art"
  build_manifest "$d/art/rc.yaml"; LOCAL=1 bash scripts/sign-release-manifest.sh "$d/art/rc.yaml" >/dev/null 2>&1
  REG_BACKEND=mock REG_MOCK_DIR="$d/mock" seed_priors
  printf '%s %s' "$d/mock" "$d/art"
}

# --- success ---
read -r MK AR <<<"$(setup)"
run_promo "$MK" "$AR"; rc=$?
ck "full promotion succeeds" "[ $rc -eq 0 ]"
ck "all aliases at RC digest"  'REG_BACKEND=mock REG_MOCK_DIR="'"$MK"'" all_at_rc'
ck "rollback manifest written" "test -f '$AR/rollback-v2026.07.03.yaml'"
ck "journal written"           "test -f '$AR/promotion-journal-v2026.07.03.txt'"
ck "promotion manifest written" "test -f '$AR/promotion-v2026.07.03.yaml'"
rm -rf "$(dirname "$MK")"

# --- fail at first / middle / final alias -> rollback restores priors ---
for FA in 1 14 28; do
  read -r MK AR <<<"$(setup)"
  run_promo "$MK" "$AR" "$FA"; rc=$?
  ck "fail@$FA aborts promotion (rc!=0)" "[ $rc -ne 0 ]"
  ck "fail@$FA restores priors (reverse rollback)" 'REG_BACKEND=mock REG_MOCK_DIR="'"$MK"'" priors_restored'
  rm -rf "$(dirname "$MK")"
done

# --- unrestorable rollback -> emergency exit 99 + incident ---
d="$(mktemp -d)"; mkdir -p "$d/mock" "$d/art"
# journal claims an alias was mutated; rollback manifest says restore to a prior,
# but the registry retag is forced to fail -> incident + 99.
ref="ghcr.io/zenchron-dynamics/php-cli:8.4-prod"
cat > "$d/art/rb.yaml" <<YAML
schema_version: 1
release: v2026.07.03
candidate: rc1
revision: $R
created_at: 2026-07-03T12:00:00Z
aliases:
  - ref: $ref
    prior_digest: sha256:$(printf p | shasum -a256 | cut -c1-64)
YAML
printf '%s\n' "$ref" > "$d/art/journal.txt"
( export REG_BACKEND=mock REG_MOCK_DIR="$d/mock" REG_FAIL_AT=1 ARTDIR="$d/art"
  bash scripts/rollback-stable.sh "$d/art/rb.yaml" "$d/art/journal.txt" ) >/dev/null 2>&1
rc=$?
ck "unrestorable rollback -> exit 99" "[ $rc -eq 99 ]"
ck "incident artifact written"        "test -f '$d/art/ROLLBACK-INCIDENT.txt'"
rm -rf "$d"

# --- PT-11 (negative #35): rollback with an ABSENT rollback manifest must
# refuse cleanly — a plain die, neither success nor the emergency exit 99.
d="$(mktemp -d)"; mkdir -p "$d/mock" "$d/art"
printf '%s\n' "ghcr.io/zenchron-dynamics/php-cli:8.4-prod" > "$d/art/journal.txt"
( export REG_BACKEND=mock REG_MOCK_DIR="$d/mock" ARTDIR="$d/art"
  bash scripts/rollback-stable.sh "$d/art/no-such-rollback.yaml" "$d/art/journal.txt" ) >/dev/null 2>&1
rc=$?
ck "absent rollback manifest -> refused (rc!=0)" "[ $rc -ne 0 ]"
ck "absent rollback manifest -> not emergency 99" "[ $rc -ne 99 ]"
rm -rf "$d"

echo "----"; [ "$fail" -eq 0 ] && echo "test_promotion: PASS" || echo "test_promotion: FAIL"
exit $fail
