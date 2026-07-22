#!/usr/bin/env bash
# =============================================================================
# scripts/rollback-stable.sh <rollback-manifest.yaml> <journal>
# -----------------------------------------------------------------------------
# Compensating rollback for a failed stable promotion. Replays the mutation
# journal in REVERSE, restoring each changed alias to the prior digest recorded
# in the rollback manifest (or removing an alias that was newly created, prior
# = NONE). Verifies each restoration.
#
# Exit codes:
#   0   every mutated alias restored + verified
#   99  EMERGENCY — one or more aliases could not be restored; writes a critical
#       incident artifact listing every inconsistent alias, so release sealing
#       is blocked.
# =============================================================================
# Deliberately `-e`-less: the restore loop must visit EVERY journaled alias and
# accumulate failures into the incident artifact — an errexit abort on the
# first bad alias would leave the rest unexamined and the incident incomplete.
set -uo pipefail
_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/registry-ops.sh
. "$_d/lib/registry-ops.sh"
set +e   # registry-ops.sh sets -e; re-disable it (see header comment)

rollback_stable() {
  local ROLLBACK="${1:?usage: rollback-stable.sh <rollback-manifest> <journal>}"
  local JOURNAL="${2:?usage: rollback-stable.sh <rollback-manifest> <journal>}"
  [ -f "$ROLLBACK" ] || die "rollback manifest not found: $ROLLBACK"
  [ -f "$JOURNAL" ]  || { warn "no journal ($JOURNAL) — nothing was mutated"; return 0; }

  local ARTDIR="${ARTDIR:-$(dirname "$ROLLBACK")}"
  local INCIDENT="$ARTDIR/ROLLBACK-INCIDENT.txt"
  # mktemp, not a predictable "$INCIDENT.tmp": a fixed path could be pre-created
  # or symlinked by an earlier failed run and is race-prone.
  local SCRATCH; SCRATCH="$(mktemp "$ARTDIR/.rollback-incident.XXXXXX")" || { warn "cannot create incident scratch"; return 99; }

  prior_of() { yq -r ".aliases[] | select(.ref==\"$1\") | .prior_digest" "$ROLLBACK" 2>/dev/null | head -1; }

  # Reverse the journal (last mutated is restored first).
  local mutated
  mutated="$(tail -r "$JOURNAL" 2>/dev/null || tac "$JOURNAL" 2>/dev/null || sed '1!G;h;$!d' "$JOURNAL")"

  local bad=0 restored=0 left=0 ref prior got
  for ref in $mutated; do
    [ -n "$ref" ] || continue
    prior="$(prior_of "$ref")"
    if [ -z "$prior" ] || [ "$prior" = "null" ]; then
      warn "no prior recorded for $ref — cannot restore"; echo "UNRESTORABLE $ref (no prior)" >> "$SCRATCH"; bad=$((bad+1)); continue
    fi
    if [ "$prior" = "NONE" ]; then
      reg_untag "$ref" || { echo "FAILED-UNTAG $ref" >> "$SCRATCH"; bad=$((bad+1)); continue; }
      if reg_digest "$ref" >/dev/null 2>&1; then
        # A NONE-prior alias was newly CREATED by this promotion (no prior state to
        # restore to). On the real GHCR backend a single tag cannot be deleted from
        # CI (reg_untag is a no-op), so it stays pointing at the just-promoted
        # digest. Record it as a non-fatal LEFT-TAGGED note — rollback still fully
        # restores every alias that HAD a prior. The mock backend MUST remove it.
        case "${REG_BACKEND:-real}" in
          mock) echo "STILL-PRESENT $ref (expected removed)" >> "$SCRATCH"; bad=$((bad+1)) ;;
          *)    echo "LEFT-TAGGED $ref (new alias; real GHCR backend cannot untag from CI — non-fatal)" >> "$SCRATCH"; left=$((left+1)) ;;
        esac
      else restored=$((restored+1)); fi
    else
      if reg_retag "$ref" "$prior" 2>/dev/null; then
        got="$(reg_digest "$ref" 2>/dev/null || echo '')"
        if [ "$got" = "$prior" ]; then restored=$((restored+1)); else echo "VERIFY-MISMATCH $ref got=$got want=$prior" >> "$SCRATCH"; bad=$((bad+1)); fi
      else
        echo "FAILED-RESTORE $ref want=$prior" >> "$SCRATCH"; bad=$((bad+1))
      fi
    fi
  done

  echo "rollback: ${restored} restored, ${left} left-tagged (new aliases), ${bad} failed"
  if [ "$bad" -gt 0 ]; then
    {
      echo "CRITICAL ROLLBACK INCIDENT"
      echo "rollback-manifest: $ROLLBACK"
      echo "journal: $JOURNAL"
      echo "inconsistent aliases:"
      cat "$SCRATCH" 2>/dev/null
    } > "$INCIDENT"
    rm -f "$SCRATCH"
    warn "wrote incident artifact: $INCIDENT"
    return 99
  fi
  # Non-fatal: preserve the LEFT-TAGGED note (new aliases the real backend cannot
  # untag from CI) as rollback evidence when there were any.
  if [ "$left" -gt 0 ]; then
    { echo "ROLLBACK NOTE (non-fatal): new aliases left tagged (real backend cannot untag from CI)"
      echo "rollback-manifest: $ROLLBACK"; cat "$SCRATCH" 2>/dev/null; } > "$INCIDENT"
    warn "wrote non-fatal rollback note: $INCIDENT"
  fi
  rm -f "$SCRATCH"
  echo "ROLLBACK OK: all prior-having aliases restored${left:+; $left new alias(es) left tagged (recorded)}"
  return 0
}

# --- self-test (mock backend + stubbed-docker real backend) ------------------
_rs_self_test() {
  command -v yq >/dev/null 2>&1 || { echo "SKIP - yq absent"; return 0; }
  local fail=0 tmp; tmp="$(mktemp -d)"
  _t() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }
  local REF=ghcr.io/zenchron-dynamics/php-cli:8.4-prod
  local PRIOR=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  local PROMOTED=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb

  _manifest() { # <file> <prior_digest>
    cat > "$1" <<YAML
schema_version: 1
release: v2026.07.03
candidate: rc1
revision: 7b4985a1234567890abcdef1234567890abcdef1
created_at: 2026-07-03T12:00:00Z
aliases:
  - ref: $REF
    prior_digest: $2
YAML
  }
  _run() { # <dir> <manifest> <journal> [env...] -> $rc
    local d="$1" m="$2" j="$3"; shift 3
    ( env "$@" REG_BACKEND=mock REG_MOCK_DIR="$d" ARTDIR="$(dirname "$m")" \
        bash "${BASH_SOURCE[0]}" "$m" "$j" ) >/dev/null 2>&1
  }

  # restore-success: alias sits at the promoted digest, journaled; prior recorded
  local d1="$tmp/c1"; mkdir -p "$d1/art" "$d1/mock"
  _manifest "$d1/art/rb.yaml" "$PRIOR"
  printf '%s\n' "$REF" > "$d1/art/j.txt"
  ( export REG_BACKEND=mock REG_MOCK_DIR="$d1/mock"; reg_retag "$REF" "$PROMOTED" )
  _run "$d1/mock" "$d1/art/rb.yaml" "$d1/art/j.txt"; local rc=$?
  _t "restore-success exits 0" '[ "$rc" -eq 0 ]'
  _t "alias restored to prior digest" \
     '[ "$(REG_BACKEND=mock REG_MOCK_DIR="$d1/mock" reg_digest "$REF")" = "$PRIOR" ]'

  # VERIFY-MISMATCH: retag ACKs but stores the wrong digest -> 99 + incident
  local d2="$tmp/c2"; mkdir -p "$d2/art" "$d2/mock"
  _manifest "$d2/art/rb.yaml" "$PRIOR"
  printf '%s\n' "$REF" > "$d2/art/j.txt"
  ( export REG_BACKEND=mock REG_MOCK_DIR="$d2/mock"; reg_retag "$REF" "$PROMOTED" )
  _run "$d2/mock" "$d2/art/rb.yaml" "$d2/art/j.txt" REG_WRITE_WRONG_AT=1; rc=$?
  _t "VERIFY-MISMATCH exits 99"          '[ "$rc" -eq 99 ]'
  _t "incident artifact written"         'test -f "$d2/art/ROLLBACK-INCIDENT.txt"'
  _t "incident lists the mismatch alias" 'grep -q "VERIFY-MISMATCH $REF" "$d2/art/ROLLBACK-INCIDENT.txt"'
  _t "no predictable .tmp scratch left"  '! test -e "$d2/art/ROLLBACK-INCIDENT.txt.tmp"'

  # prior=NONE on the REAL backend (docker stubbed): untag is impossible from CI
  # -> LEFT-TAGGED note, NON-fatal exit 0
  local d3="$tmp/c3"; mkdir -p "$d3/art" "$d3/store" "$d3/bin"
  cat > "$d3/bin/docker" <<'EOF'
#!/usr/bin/env bash
# Minimal `docker buildx imagetools` stub backed by $DOCKER_STORE.
key() { printf '%s' "$1" | tr '/:@' '___'; }
case "${2:-} ${3:-}" in
  "imagetools inspect") f="$DOCKER_STORE/$(key "$4")"; [ -f "$f" ] && cat "$f" || exit 1 ;;
  "imagetools create")  src="$6"; printf '%s' "${src##*@}" > "$DOCKER_STORE/$(key "$5")" ;;
  *) exit 1 ;;
esac
EOF
  chmod +x "$d3/bin/docker"
  _manifest "$d3/art/rb.yaml" "NONE"
  printf '%s\n' "$REF" > "$d3/art/j.txt"
  printf '%s' "$PROMOTED" > "$d3/store/$(printf '%s' "$REF" | tr '/:@' '___')"
  ( PATH="$d3/bin:$PATH" DOCKER_STORE="$d3/store" ARTDIR="$d3/art" \
      bash "${BASH_SOURCE[0]}" "$d3/art/rb.yaml" "$d3/art/j.txt" ) >/dev/null 2>&1; rc=$?
  _t "prior=NONE real backend: non-fatal (exit 0)" '[ "$rc" -eq 0 ]'
  _t "LEFT-TAGGED note written" 'grep -q "LEFT-TAGGED $REF" "$d3/art/ROLLBACK-INCIDENT.txt"'

  # missing journal -> clean exit 0, nothing mutated
  local d4="$tmp/c4"; mkdir -p "$d4/art" "$d4/mock"
  _manifest "$d4/art/rb.yaml" "$PRIOR"
  local out
  # shellcheck disable=SC2034  # out consumed inside the eval'd assertion below
  out="$( ( REG_BACKEND=mock REG_MOCK_DIR="$d4/mock" ARTDIR="$d4/art" \
      bash "${BASH_SOURCE[0]}" "$d4/art/rb.yaml" "$d4/art/no-such-journal.txt" ) 2>&1 )"; rc=$?
  _t "missing journal: clean exit 0"      '[ "$rc" -eq 0 ]'
  _t "missing journal: says not mutated"  'printf "%s" "$out" | grep -q "nothing was mutated"'

  # missing rollback manifest -> die (negative test #35): nonzero, NOT 99
  local d5="$tmp/c5"; mkdir -p "$d5/art" "$d5/mock"
  printf '%s\n' "$REF" > "$d5/art/j.txt"
  ( REG_BACKEND=mock REG_MOCK_DIR="$d5/mock" ARTDIR="$d5/art" \
      bash "${BASH_SOURCE[0]}" "$d5/art/no-such-manifest.yaml" "$d5/art/j.txt" ) >/dev/null 2>&1; rc=$?
  if [ "$rc" -ne 0 ]; then echo "ok   - missing rollback manifest refuses (nonzero)"
  else echo "FAIL - missing rollback manifest refuses (nonzero)"; fail=1; fi
  if [ "$rc" -ne 99 ]; then echo "ok   - missing rollback manifest is NOT the emergency code"
  else echo "FAIL - missing rollback manifest is NOT the emergency code"; fail=1; fi

  rm -rf "$tmp"; return $fail
}

case "${1:-}" in
  --self-test) _rs_self_test && echo "rollback-stable.sh: SELF-TEST OK"; exit ;;
esac
rollback_stable "$@"
exit $?
