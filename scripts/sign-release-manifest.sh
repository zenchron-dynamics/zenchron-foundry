#!/usr/bin/env bash
# =============================================================================
# scripts/sign-release-manifest.sh <manifest.yaml>
# -----------------------------------------------------------------------------
# Checksums and cosign-blob-signs the RC manifest, producing the immutable
# evidence trio consumed by promotion:
#     <manifest>.sha256   sha256 checksum
#     <manifest>.sig      cosign blob signature (keyless)
#     <manifest>.pem      signing certificate
#
# LOCAL=1 (or cosign absent) writes the checksum only and SKIPS signing — for
# offline dry-runs. A real RC publish must sign (cosign present, LOCAL unset).
#
# COSIGN_BIN is injectable (self-test only; defaults to `cosign`).
# =============================================================================
set -euo pipefail
_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/release-manifest.sh
. "$_d/lib/release-manifest.sh"

sign_release_manifest() {
  local MANIFEST="${1:?usage: sign-release-manifest.sh <manifest.yaml>}"
  local cosign="${COSIGN_BIN:-cosign}"
  [ -f "$MANIFEST" ] || die "manifest not found: $MANIFEST"

  checksum_file "$MANIFEST" > "${MANIFEST}.sha256"
  log "wrote ${MANIFEST}.sha256"

  if ! command -v "$cosign" >/dev/null 2>&1; then
    [ "${LOCAL:-0}" = 1 ] || die "cosign not installed (set LOCAL=1 for an unsigned offline manifest)"
    warn "LOCAL: cosign absent — manifest checksummed but NOT signed"
    return 0
  fi

  "$cosign" sign-blob --yes \
    --output-signature "${MANIFEST}.sig" \
    --output-certificate "${MANIFEST}.pem" \
    "$MANIFEST"
  log "signed: ${MANIFEST}.sig + ${MANIFEST}.pem"
}

# --- self-test (stub cosign via COSIGN_BIN; offline) -------------------------
_srm_self_test() {
  local fail=0 tmp; tmp="$(mktemp -d)"
  _t() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

  # Stub cosign: honors --output-signature/--output-certificate like the real one.
  cat > "$tmp/cosign" <<'EOF'
#!/usr/bin/env bash
sig="" pem="" prev=""
for a in "$@"; do
  [ "$prev" = "--output-signature" ] && sig="$a"
  [ "$prev" = "--output-certificate" ] && pem="$a"
  prev="$a"
done
printf 'stub-signature\n' > "$sig"
printf 'stub-certificate\n' > "$pem"
EOF
  chmod +x "$tmp/cosign"

  printf 'release: v2026.07.03\n' > "$tmp/m.yaml"

  # happy path: stub cosign present -> sha256 + sig + pem all written
  if ( COSIGN_BIN="$tmp/cosign" sign_release_manifest "$tmp/m.yaml" ) >/dev/null 2>&1; then
    echo "ok   - signing with stub cosign succeeds"
  else
    echo "FAIL - signing with stub cosign succeeds"; fail=1
  fi
  _t ".sha256 written"        '[ -s "$tmp/m.yaml.sha256" ]'
  _t ".sig written"           '[ -s "$tmp/m.yaml.sig" ]'
  _t ".pem written"           '[ -s "$tmp/m.yaml.pem" ]'
  _t "checksum matches file"  '[ "$(cat "$tmp/m.yaml.sha256")" = "$(checksum_file "$tmp/m.yaml")" ]'

  # missing cosign, LOCAL unset -> refuse (no unsigned manifest on a real publish)
  rm -f "$tmp/m.yaml.sig" "$tmp/m.yaml.pem"
  if ( COSIGN_BIN="$tmp/no-such-cosign" LOCAL=0 sign_release_manifest "$tmp/m.yaml" ) >/dev/null 2>&1; then
    echo "FAIL - missing cosign must refuse without LOCAL=1"; fail=1
  else
    echo "ok   - missing cosign refuses without LOCAL=1"
  fi
  _t "refusal leaves no .sig"  '[ ! -e "$tmp/m.yaml.sig" ]'

  # missing cosign, LOCAL=1 -> checksum-only success
  if ( COSIGN_BIN="$tmp/no-such-cosign" LOCAL=1 sign_release_manifest "$tmp/m.yaml" ) >/dev/null 2>&1; then
    echo "ok   - LOCAL=1 tolerates absent cosign (checksum only)"
  else
    echo "FAIL - LOCAL=1 tolerates absent cosign (checksum only)"; fail=1
  fi
  _t "LOCAL path writes no .sig" '[ ! -e "$tmp/m.yaml.sig" ]'

  # missing manifest -> refuse
  if ( COSIGN_BIN="$tmp/cosign" sign_release_manifest "$tmp/absent.yaml" ) >/dev/null 2>&1; then
    echo "FAIL - missing manifest must refuse"; fail=1
  else
    echo "ok   - missing manifest refuses"
  fi

  rm -rf "$tmp"
  return $fail
}

case "${1:-}" in
  --self-test) _srm_self_test && echo "sign-release-manifest.sh: SELF-TEST OK" ;;
  "") die "usage: sign-release-manifest.sh <manifest.yaml> | --self-test" ;;
  *) sign_release_manifest "$@" ;;
esac
