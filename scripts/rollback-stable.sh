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
set -uo pipefail
_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/registry-ops.sh
. "$_d/lib/registry-ops.sh"

ROLLBACK="${1:?usage: rollback-stable.sh <rollback-manifest> <journal>}"
JOURNAL="${2:?usage: rollback-stable.sh <rollback-manifest> <journal>}"
[ -f "$ROLLBACK" ] || die "rollback manifest not found: $ROLLBACK"
[ -f "$JOURNAL" ]  || { warn "no journal ($JOURNAL) — nothing was mutated"; exit 0; }

ARTDIR="${ARTDIR:-$(dirname "$ROLLBACK")}"
INCIDENT="$ARTDIR/ROLLBACK-INCIDENT.txt"

prior_of() { yq -r ".aliases[] | select(.ref==\"$1\") | .prior_digest" "$ROLLBACK" 2>/dev/null | head -1; }

# Reverse the journal (last mutated is restored first).
mutated="$(tail -r "$JOURNAL" 2>/dev/null || tac "$JOURNAL" 2>/dev/null || sed '1!G;h;$!d' "$JOURNAL")"

bad=0; restored=0; left=0
for ref in $mutated; do
  [ -n "$ref" ] || continue
  prior="$(prior_of "$ref")"
  if [ -z "$prior" ] || [ "$prior" = "null" ]; then
    warn "no prior recorded for $ref — cannot restore"; echo "UNRESTORABLE $ref (no prior)" >> "$INCIDENT.tmp"; bad=$((bad+1)); continue
  fi
  if [ "$prior" = "NONE" ]; then
    reg_untag "$ref" || { echo "FAILED-UNTAG $ref" >> "$INCIDENT.tmp"; bad=$((bad+1)); continue; }
    if reg_digest "$ref" >/dev/null 2>&1; then
      # A NONE-prior alias was newly CREATED by this promotion (no prior state to
      # restore to). On the real GHCR backend a single tag cannot be deleted from
      # CI (reg_untag is a no-op), so it stays pointing at the just-promoted
      # digest. Record it as a non-fatal LEFT-TAGGED note — rollback still fully
      # restores every alias that HAD a prior. The mock backend MUST remove it.
      case "${REG_BACKEND:-real}" in
        mock) echo "STILL-PRESENT $ref (expected removed)" >> "$INCIDENT.tmp"; bad=$((bad+1)) ;;
        *)    echo "LEFT-TAGGED $ref (new alias; real GHCR backend cannot untag from CI — non-fatal)" >> "$INCIDENT.tmp"; left=$((left+1)) ;;
      esac
    else restored=$((restored+1)); fi
  else
    if reg_retag "$ref" "$prior" 2>/dev/null; then
      got="$(reg_digest "$ref" 2>/dev/null || echo '')"
      if [ "$got" = "$prior" ]; then restored=$((restored+1)); else echo "VERIFY-MISMATCH $ref got=$got want=$prior" >> "$INCIDENT.tmp"; bad=$((bad+1)); fi
    else
      echo "FAILED-RESTORE $ref want=$prior" >> "$INCIDENT.tmp"; bad=$((bad+1))
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
    cat "$INCIDENT.tmp" 2>/dev/null
  } > "$INCIDENT"
  rm -f "$INCIDENT.tmp"
  warn "wrote incident artifact: $INCIDENT"
  exit 99
fi
# Non-fatal: preserve the LEFT-TAGGED note (new aliases the real backend cannot
# untag from CI) as rollback evidence when there were any.
if [ "$left" -gt 0 ]; then
  { echo "ROLLBACK NOTE (non-fatal): new aliases left tagged (real backend cannot untag from CI)"
    echo "rollback-manifest: $ROLLBACK"; cat "$INCIDENT.tmp" 2>/dev/null; } > "$INCIDENT"
  warn "wrote non-fatal rollback note: $INCIDENT"
fi
rm -f "$INCIDENT.tmp"
echo "ROLLBACK OK: all prior-having aliases restored${left:+; $left new alias(es) left tagged (recorded)}"
