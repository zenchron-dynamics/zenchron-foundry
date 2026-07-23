#!/usr/bin/env bash
# =============================================================================
# scripts/verify-signatures.sh <image-ref> [<image-ref> ...]
# -----------------------------------------------------------------------------
# THIN ORCHESTRATOR. Delegates each image ref to the single authoritative
# verifier scripts/verify-image-release-identity.sh. This replaces the previous
# weaker path (bare signature + best-effort SBOM warning) so every caller gets
# the full trust check: signature, exact per-role identity, issuer, SBOM,
# provenance repo+revision, OCI revision label, and amd64+arm64.
#
# Env: EXPECTED_REVISION (40-hex, required unless LOCAL=1), EXPECTED_REPO
#      (default zenchron-dynamics/zenchron-foundry), EXPECTED_ROLE
#      (default rc-publisher), LOCAL=1 to skip when cosign is absent.
#      COSIGN_BIN / VERIFIER_BIN are injectable (self-test only).
# =============================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/common.sh
. "$ROOT/scripts/lib/common.sh"

verify_signatures() {
  [ "$#" -ge 1 ] || { echo "usage: verify-signatures.sh <image-ref> [...]" >&2; return 2; }
  export EXPECTED_REPO="${EXPECTED_REPO:-zenchron-dynamics/zenchron-foundry}"
  export EXPECTED_ROLE="${EXPECTED_ROLE:-rc-publisher}"
  local cosign="${COSIGN_BIN:-cosign}"
  local verifier="${VERIFIER_BIN:-$ROOT/scripts/verify-image-release-identity.sh}"

  if [ "${LOCAL:-0}" = 1 ] || ! command -v "$cosign" >/dev/null 2>&1; then
    [ "${LOCAL:-0}" = 1 ] || die "cosign not installed (set LOCAL=1 to skip)"
    echo "SKIPPED: LOCAL=1 — signature verification not run"; return 0
  fi
  [ -n "${EXPECTED_REVISION:-}" ] || die "EXPECTED_REVISION required"
  export EXPECTED_REVISION

  local rc=0 image
  for image in "$@"; do
    echo "==> verify identity: $image"
    "$verifier" "$image" || rc=1
  done
  [ "$rc" -eq 0 ] || die "one or more images failed identity verification"
  echo "==> Verification complete."
}

# --- self-test (stub cosign + stub verifier; offline) ------------------------
_vs_self_test() {
  local fail=0 tmp; tmp="$(mktemp -d)"
  _t() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }
# shellcheck disable=SC2034  # R consumed inside the single-quoted eval'd assertions below
  local R=7b4985a1234567890abcdef1234567890abcdef1

  printf '#!/usr/bin/env bash\nexit 0\n' > "$tmp/cosign"; chmod +x "$tmp/cosign"
  # Stub verifier: logs each ref; fails any ref containing "bad".
  cat > "$tmp/verifier" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$1" >> "$tmp/seen"
case "\$1" in *bad*) exit 1 ;; *) exit 0 ;; esac
EOF
  chmod +x "$tmp/verifier"

  # LOCAL=1 -> explicit skip, exit 0, verifier never invoked
  : > "$tmp/seen"
  _t "LOCAL=1 skips (exit 0)" \
    '( LOCAL=1 COSIGN_BIN="$tmp/cosign" VERIFIER_BIN="$tmp/verifier" verify_signatures ghcr.io/x/a@sha256:0 ) 2>/dev/null | grep -q SKIPPED'
  _t "LOCAL=1 never delegates" '[ ! -s "$tmp/seen" ]'

  # cosign absent, LOCAL unset -> refuse
  _t "missing cosign refuses" \
    '! ( LOCAL=0 COSIGN_BIN="$tmp/no-such-cosign" VERIFIER_BIN="$tmp/verifier" EXPECTED_REVISION="$R" verify_signatures ghcr.io/x/a@sha256:0 ) >/dev/null 2>&1'

  # EXPECTED_REVISION missing -> refuse
  _t "missing EXPECTED_REVISION refuses" \
    '! ( LOCAL=0 COSIGN_BIN="$tmp/cosign" VERIFIER_BIN="$tmp/verifier" EXPECTED_REVISION="" verify_signatures ghcr.io/x/a@sha256:0 ) >/dev/null 2>&1'

  # all refs pass -> exit 0, every ref delegated
  : > "$tmp/seen"
  _t "all-pass exits 0" \
    '( LOCAL=0 COSIGN_BIN="$tmp/cosign" VERIFIER_BIN="$tmp/verifier" EXPECTED_REVISION="$R" verify_signatures ghcr.io/x/a@sha256:0 ghcr.io/x/b@sha256:1 ) >/dev/null 2>&1'
  _t "every ref delegated" '[ "$(wc -l < "$tmp/seen" | tr -d " ")" = 2 ]'

  # one failing ref -> nonzero, but ALL refs still attempted (aggregation)
  : > "$tmp/seen"
  _t "one failure is nonzero" \
    '! ( LOCAL=0 COSIGN_BIN="$tmp/cosign" VERIFIER_BIN="$tmp/verifier" EXPECTED_REVISION="$R" verify_signatures ghcr.io/x/bad@sha256:0 ghcr.io/x/ok@sha256:1 ) >/dev/null 2>&1'
  _t "failure still visits all refs" '[ "$(wc -l < "$tmp/seen" | tr -d " ")" = 2 ]'

  # no args -> usage error
  _t "no refs is a usage error" '! ( verify_signatures ) >/dev/null 2>&1'

  rm -rf "$tmp"
  return $fail
}

case "${1:-}" in
  --self-test) _vs_self_test && echo "verify-signatures.sh: SELF-TEST OK" ;;
  *) verify_signatures "$@" ;;
esac
