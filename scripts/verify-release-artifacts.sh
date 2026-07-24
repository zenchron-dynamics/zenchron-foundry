#!/usr/bin/env bash
# =============================================================================
# scripts/verify-release-artifacts.sh
# -----------------------------------------------------------------------------
# THIN ORCHESTRATOR. Verifies the 10 stable images by delegating every
# per-image trust check to the single authoritative verifier
# scripts/verify-image-release-identity.sh (signature, exact per-role identity,
# issuer, SBOM, SLSA provenance, provenance repo+revision, OCI revision label,
# amd64+arm64). No verification logic is reimplemented here — this file only
# fans out over the matrix, pins each image to its digest, and enforces 10/10.
#
# SC-09: for each image, EVERY stable alias from stable_aliases (canonical
# prod, prod-<rel>, and the PHP -debian alias) must resolve to ONE shared
# digest. The full artifact/identity verification then runs ONCE per unique
# digest: cosign signatures and attestations attach to the DIGEST, which the
# equality check has just proven all aliases share — re-verifying the same
# digest once per alias adds cost, not assurance.
#
# SC-19: alias enumeration goes through lib/registry-aliases.sh
# (stable_aliases/full_ref) and digest resolution through lib/registry-ops.sh
# (reg_digest) — no local stable_ref/digest_of copies.
#
# After the loop it writes a machine-readable results file (RESULTS_JSON) with
# per-check-class pass counts, REAL counts observed in the loop — the release
# evidence package derives its verification fields from this file instead of
# hardcoded literals (RA-01/WF-02).
#
# Env:
#   VERSION            release tag vYYYY.MM.DD[.N] (required unless LOCAL=1) —
#                      needed to enumerate the version-bound prod-<rel> aliases
#   EXPECTED_REVISION  40-hex release revision (required unless LOCAL=1)
#   EXPECTED_REPO      default zenchron-dynamics/zenchron-foundry
#   EXPECTED_ROLE      default rc-publisher (stable digests are promoted RC digests)
#   REGISTRY/NAMESPACE default ghcr.io / zenchron-dynamics
#   RESULTS_JSON       results file path (default release-verify-results.json)
#   LOCAL=1            cosign/registry absent -> SKIP, exit 0
# =============================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
# shellcheck source=lib/registry-aliases.sh
. "$ROOT/scripts/lib/registry-aliases.sh"
# shellcheck source=lib/registry-ops.sh
. "$ROOT/scripts/lib/registry-ops.sh"

VERIFIER="$ROOT/scripts/verify-image-release-identity.sh"
RESULTS_JSON="${RESULTS_JSON:-release-verify-results.json}"

# SC-09: every stable alias for an image must resolve to ONE shared digest.
# Echoes that digest; nonzero if any alias is unresolved or disagrees.
aliases_shared_digest() { # <fam> <sel> <rel>
  local fam="$1" sel="$2" rel="$3" suf ref d shared=""
  for suf in $(stable_aliases "$sel" "$rel"); do
    ref="$(full_ref "$fam" "$suf")"
    d="$(reg_digest "$ref" 2>/dev/null || true)"
    [ -n "$d" ] || { warn "  $ref: digest unresolved"; return 1; }
    if [ -z "$shared" ]; then shared="$d"
    elif [ "$d" != "$shared" ]; then warn "  $ref: $d != $shared (alias divergence)"; return 1; fi
  done
  [ -n "$shared" ] || return 1
  printf '%s' "$shared"
}

# The verifier runs its checks in a FIXED order and fails fast, so its failure
# message tells us exactly how many check classes the image really passed:
#   0=none  1=signature  2=+sbom  3=+provenance  4=+oci_revision  (5=all incl. arch)
# Unknown failure text credits NOTHING (fail closed).
classify_pass_count() { # <verifier stderr> -> 0..4
  case "$1" in
    *"signature/identity/issuer"*)  echo 0 ;;
    *"SBOM attestation"*)           echo 1 ;;
    *"provenance attestation"*|*"provenance predicate"*|*"no source revision"*|\
    *"provenance revision"*|*"provenance repo"*) echo 2 ;;
    *"OCI revision label"*|*"image config"*)     echo 3 ;;
    *"missing platform"*|*"image index"*)        echo 4 ;;
    *) echo 0 ;;
  esac
}

c_sig=0 c_sbom=0 c_prov=0 c_oci=0 c_arch=0
credit() { # <classes-passed 0..5>
  if [ "$1" -ge 1 ]; then c_sig=$((c_sig+1)); fi
  if [ "$1" -ge 2 ]; then c_sbom=$((c_sbom+1)); fi
  if [ "$1" -ge 3 ]; then c_prov=$((c_prov+1)); fi
  if [ "$1" -ge 4 ]; then c_oci=$((c_oci+1)); fi
  if [ "$1" -ge 5 ]; then c_arch=$((c_arch+1)); fi
}

write_results() { # <path> <images>
  command -v jq >/dev/null 2>&1 || die "jq required to write $1"
  jq -n --argjson n "$2" \
    --arg sig "$c_sig/$2" --arg sbom "$c_sbom/$2" --arg prov "$c_prov/$2" \
    --arg oci "$c_oci/$2" --arg arch "$c_arch/$2" \
    '{images: $n, signature: $sig, sbom: $sbom, provenance: $prov,
      oci_revision: $oci, architecture: $arch}' > "$1"
}

# --- self-test (offline: classification, alias equality, results emission) ---
_vra_self_test() {
  command -v jq >/dev/null 2>&1 || { echo "SKIP - jq absent"; return 0; }
  local fail=0 tmp; tmp="$(mktemp -d)"
  _t() { if [ "$2" = "$3" ]; then echo "ok   - $1"; else echo "FAIL - $1: got '$2' want '$3'"; fail=1; fi; }
  # --- SC-09 alias equality (mock registry backend) --------------------------
  local D1=sha256:1111111111111111111111111111111111111111111111111111111111111111
  local D2=sha256:2222222222222222222222222222222222222222222222222222222222222222
  mkdir -p "$tmp/mock"
  ( export REG_BACKEND=mock REG_MOCK_DIR="$tmp/mock"
    for suf in $(stable_aliases 8.4 2026.07.03); do reg_retag "$(full_ref php-cli "$suf")" "$D1"; done )
  _t "all aliases agree -> shared digest" \
     "$(REG_BACKEND=mock REG_MOCK_DIR="$tmp/mock" aliases_shared_digest php-cli 8.4 2026.07.03)" "$D1"
  ( export REG_BACKEND=mock REG_MOCK_DIR="$tmp/mock"
    reg_retag "$(full_ref php-cli 8.4-debian)" "$D2" )   # non-canonical alias drifts
  if ( REG_BACKEND=mock REG_MOCK_DIR="$tmp/mock" aliases_shared_digest php-cli 8.4 2026.07.03 ) >/dev/null 2>&1
    then echo "FAIL - alias divergence rejected"; fail=1; else echo "ok   - alias divergence rejected"; fi
  if ( REG_BACKEND=mock REG_MOCK_DIR="$tmp/mock" aliases_shared_digest caddy prod 2026.07.03 ) >/dev/null 2>&1
    then echo "FAIL - unresolved alias rejected"; fail=1; else echo "ok   - unresolved alias rejected"; fi
  # Fixture messages are HARDCODED (not generated by the verifier) on purpose.
  _t "sig failure credits nothing"   "$(classify_pass_count 'IDENTITY FAIL [x]: signature/identity/issuer verify failed')" 0
  _t "sbom failure credits sig"      "$(classify_pass_count 'IDENTITY FAIL [x]: SBOM attestation missing/invalid')" 1
  _t "prov attest credits sig+sbom"  "$(classify_pass_count 'IDENTITY FAIL [x]: provenance attestation missing/invalid')" 2
  _t "prov revision credits 2"       "$(classify_pass_count 'IDENTITY FAIL [x]: provenance revision aaa != expected bbb')" 2
  _t "oci label credits 3"           "$(classify_pass_count "IDENTITY FAIL [x]: OCI revision label '' != expected bbb")" 3
  _t "platform credits 4"            "$(classify_pass_count 'IDENTITY FAIL [x]: missing platform linux/arm64')" 4
  _t "unknown text credits nothing"  "$(classify_pass_count 'something unexpected exploded')" 0
  # results emission: partial counts survive verbatim (9/10 stays 9/10)
  c_sig=9 c_sbom=10 c_prov=10 c_oci=10 c_arch=10
  write_results "$tmp/r.json" 10
  _t "results images count"       "$(jq -r '.images' "$tmp/r.json")" 10
  _t "results partial signature"  "$(jq -r '.signature' "$tmp/r.json")" "9/10"
  _t "results sbom"               "$(jq -r '.sbom' "$tmp/r.json")" "10/10"
  _t "results provenance"         "$(jq -r '.provenance' "$tmp/r.json")" "10/10"
  _t "results oci_revision"       "$(jq -r '.oci_revision' "$tmp/r.json")" "10/10"
  _t "results architecture"       "$(jq -r '.architecture' "$tmp/r.json")" "10/10"
  c_sig=0 c_sbom=0 c_prov=0 c_oci=0 c_arch=0
  rm -rf "$tmp"; return $fail
}

case "${1:-}" in
  --self-test) _vra_self_test && echo "verify-release-artifacts.sh: SELF-TEST OK"; exit ;;
esac

export EXPECTED_REPO="${EXPECTED_REPO:-zenchron-dynamics/zenchron-foundry}"
export EXPECTED_ROLE="${EXPECTED_ROLE:-rc-publisher}"

if [ "${LOCAL:-0}" = 1 ] || ! command -v cosign >/dev/null 2>&1; then
  [ "${LOCAL:-0}" = 1 ] || die "cosign not installed (set LOCAL=1 to skip for non-release use)"
  echo "SKIPPED: LOCAL=1 — release artifact verification not run"; exit 0
fi
[ -n "${EXPECTED_REVISION:-}" ] || die "EXPECTED_REVISION required (40-hex release revision)"
export EXPECTED_REVISION
# SC-09: the version-bound prod-<rel> aliases can only be enumerated from the
# release tag — fail closed rather than silently verifying a subset.
[ -n "${VERSION:-}" ] || die "VERSION required (release tag vYYYY.MM.DD[.N]) to enumerate all stable aliases"
require_calver "$VERSION"
REL="${VERSION#v}"

n=0 ok=0
for t in $MATRIX_IMAGES; do
  n=$((n+1)); fam="${t%:*}"; sel="${t#*:}"
  # SC-09: all stable aliases must share one digest; identity checks then run
  # once on that shared digest (attestations attach to the digest).
  if ! dg="$(aliases_shared_digest "$fam" "$sel" "$REL")"; then
    echo "FAIL $fam ($sel): stable aliases unresolved or diverged"; continue
  fi
  if out="$("$VERIFIER" "${NS}/${fam}@${dg}" 2>&1)"; then
    echo "PASS $fam ($sel) @ $dg (all aliases agree)"; ok=$((ok+1)); credit 5
  else
    echo "FAIL $fam ($sel) @ $dg (identity verification failed)"
    credit "$(classify_pass_count "$out")"
  fi
done

# Machine-readable per-class results — written even when the gate below dies,
# so a partial run leaves honest counts (e.g. 9/10) that the evidence
# validator will REFUSE.
write_results "$RESULTS_JSON" "$n"
echo "wrote $RESULTS_JSON (signature=$c_sig/$n sbom=$c_sbom/$n provenance=$c_prov/$n oci_revision=$c_oci/$n architecture=$c_arch/$n)"

echo "RELEASE VERIFY: ${ok}/${n} images fully verified"
assert_full_matrix "$n"
[ "$ok" -eq "$MATRIX_COUNT" ] || die "not all images passed (${ok}/${MATRIX_COUNT})"
echo "ALL CHECKS PASSED (${MATRIX_COUNT}/${MATRIX_COUNT})"
