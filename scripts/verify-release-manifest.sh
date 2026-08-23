#!/usr/bin/env bash
# =============================================================================
# scripts/verify-release-manifest.sh <manifest.yaml> [<sig> <cert>]
# -----------------------------------------------------------------------------
# Verifies the RC manifest before promotion trusts it:
#   1. checksum matches <manifest>.sha256 — the sidecar is REQUIRED
#   2. cosign blob signature verifies against the pinned role identity
#   3. schema + policy validation (delegates to validate-release-manifest.sh)
#
# EXPECTED_ROLE (default rc-publisher) selects the cosign identity from
# policies/cosign-identities.yaml. LOCAL=1 skips step 2 only (offline dry-run,
# loud warning). cosign absent WITHOUT LOCAL=1 is a hard failure — a missing
# tool must never silently downgrade the gate.
# =============================================================================
set -euo pipefail
_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/release-manifest.sh
. "$_d/lib/release-manifest.sh"
# shellcheck source=lib/cosign-identity.sh
. "$_d/lib/cosign-identity.sh"

verify_manifest() {
  local MANIFEST="${1:?usage: verify-release-manifest.sh <manifest.yaml> [<sig> <cert>]}"
  local SIG="${2:-${MANIFEST}.sig}"
  local CERT="${3:-${MANIFEST}.pem}"
  local ROLE="${EXPECTED_ROLE:-rc-publisher}"

  [ -f "$MANIFEST" ] || die "manifest not found: $MANIFEST"

  # 1. checksum — sidecar required (a missing .sha256 must not skip the check)
  [ -f "${MANIFEST}.sha256" ] || die "checksum sidecar missing: ${MANIFEST}.sha256"
  local want got
  want="$(awk '{print $1}' "${MANIFEST}.sha256")"
  got="$(checksum_file "$MANIFEST")"
  [ "$want" = "$got" ] || die "checksum mismatch: $got != $want"
  log "checksum OK"

  # 2. signature — skipped ONLY by an explicit LOCAL=1; a missing cosign
  #    without LOCAL=1 refuses instead of silently downgrading to schema-only.
  if [ "${LOCAL:-0}" = 1 ]; then
    warn "LOCAL=1: signature verification SKIPPED — checksum+schema only (offline dry-run)"
  else
    command -v cosign >/dev/null 2>&1 || die "cosign required to verify the manifest signature (set LOCAL=1 for offline)"
    [ -f "$SIG" ]  || die "signature not found: $SIG"
    [ -f "$CERT" ] || die "certificate not found: $CERT"
    cosign verify-blob \
      --certificate "$CERT" --signature "$SIG" \
      --certificate-identity-regexp "$(identity_re_for_role "$ROLE")" \
      --certificate-oidc-issuer "$(issuer_from_policy)" \
      "$MANIFEST" >/dev/null || die "manifest signature verification failed"
    log "signature OK (role $ROLE)"
  fi

  # 3. schema + policy
  bash "$_d/validate-release-manifest.sh" "$MANIFEST"
  log "manifest verified: $MANIFEST"
}

# --- self-test ---------------------------------------------------------------
_vrm_self_test() {
  command -v yq >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1 \
    || { echo "SKIP - yq/python3 absent"; return 0; }
  python3 -c 'import yaml, jsonschema' 2>/dev/null || { echo "SKIP - pyyaml/jsonschema absent"; return 0; }
  local fail=0 tmp; tmp="$(mktemp -d)"
  local R=7b4985a1234567890abcdef1234567890abcdef1
  _t() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

  # Schema-valid 10-image manifest fixture (independent of any live manifest).
  R="$R" OUT="$tmp/m.yaml" python3 - <<'PY'
import os, yaml, hashlib
R = os.environ["R"]
keys = [f"php-{f}-{v}" for f in ("cli","fpm","worker","frankenphp") for v in ("8.3","8.4")] + ["nginx","caddy"]
def repo(k): return "ghcr.io/zenchron-dynamics/%s" % (k.rsplit("-",1)[0] if k.startswith("php-") else k)
def dig(k): return "sha256:" + hashlib.sha256(k.encode()).hexdigest()
imgs = {k: {"repository": repo(k), "immutable_tag": "t-"+k, "digest": dig(k),
            "reference": repo(k)+"@"+dig(k), "revision": R,
            "platforms": ["linux/amd64","linux/arm64"]} for k in keys}
m = {"schema_version":1, "release":"v2026.07.03", "candidate":"rc1", "revision":R,
     "source_repository":"zenchron-dynamics/zenchron-foundry", "source_ref":"refs/heads/master",
     "workflow_run_id":"1", "created_at":"2026-07-03T12:00:00Z", "images":imgs}
yaml.safe_dump(m, open(os.environ["OUT"],"w"), sort_keys=True)
PY

  # missing .sha256 -> REFUSE even with LOCAL=1 (checksum is never optional)
  _t "missing .sha256 sidecar refused" \
     '! ( LOCAL=1 verify_manifest "$tmp/m.yaml" ) >/dev/null 2>&1'

  checksum_file "$tmp/m.yaml" > "$tmp/m.yaml.sha256"

  # LOCAL=1 without .sig/.pem -> passes checksum+schema, warns about the skip
  local out rc
  out="$( ( LOCAL=1 verify_manifest "$tmp/m.yaml" ) 2>&1 )"; rc=$?
  if [ "$rc" -eq 0 ]; then echo "ok   - LOCAL=1 without sidecars passes (schema-only)"
  else echo "FAIL - LOCAL=1 without sidecars passes (schema-only)"; fail=1; fi
  if printf '%s' "$out" | grep -q "SKIPPED"; then echo "ok   - LOCAL=1 skip is loud (warning printed)"
  else echo "FAIL - LOCAL=1 skip is loud (warning printed)"; fail=1; fi

  # cosign absent WITHOUT LOCAL=1 -> REFUSE (stub PATH with every tool but cosign)
  local stub="$tmp/bin"; mkdir -p "$stub"
  local c p
  for c in bash sh awk grep sed cat yq python3 mktemp shasum sha256sum dirname; do
    p="$(command -v "$c" 2>/dev/null || true)"; [ -n "$p" ] && ln -s "$p" "$stub/$c"
  done
  if ( PATH="$stub" bash "${BASH_SOURCE[0]}" "$tmp/m.yaml" ) >/dev/null 2>&1; then
    echo "FAIL - cosign absent without LOCAL=1 must refuse"; fail=1
  else
    echo "ok   - cosign absent without LOCAL=1 refuses"
  fi

  # checksum tamper -> REFUSE
  printf '\n# tampered\n' >> "$tmp/m.yaml"
  _t "checksum tamper refused" '! ( LOCAL=1 verify_manifest "$tmp/m.yaml" ) >/dev/null 2>&1'

  rm -rf "$tmp"; return $fail
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-}" in
    --self-test) _vrm_self_test && echo "verify-release-manifest.sh: SELF-TEST OK" ;;
    "") echo "usage: verify-release-manifest.sh <manifest.yaml> [<sig> <cert>] | --self-test" >&2; exit 2 ;;
    *) verify_manifest "$@" ;;
  esac
fi
