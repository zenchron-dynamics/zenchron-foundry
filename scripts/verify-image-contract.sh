#!/usr/bin/env bash
# =============================================================================
# scripts/verify-image-contract.sh <image-ref> <contract.yaml>
# -----------------------------------------------------------------------------
# Data-driven check of a built image's CONFIG metadata against its machine-
# readable runtime contract (contracts/images/*.yaml): non-root user, exposed
# ports, healthcheck presence, and the OCI revision label. Complements the smoke
# scripts (which exercise runtime BEHAVIOUR) with a static contract assertion.
#
# Env: INSPECT_FN (injectable; default `docker inspect`) -> emits the image
#      config JSON ({Config:{User,ExposedPorts,Healthcheck,Labels}}). Enables
#      offline self-test without a real image.
# =============================================================================
set -euo pipefail
_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
. "$_d/lib/common.sh"

_default_inspect() { docker inspect "$1" --format '{{json .Config}}' 2>/dev/null | jq '{Config: .}'; }

verify_contract() {
  local ref="$1" contract="$2" fetch="${INSPECT_FN:-_default_inspect}"
  command -v yq >/dev/null || die "yq required"; command -v jq >/dev/null || die "jq required"
  [ -f "$contract" ] || die "contract not found: $contract"
  local cfg; cfg="$("$fetch" "$ref")"; [ -n "$cfg" ] || die "could not inspect $ref"

  local want_user; want_user="$(yq -r '.user // ""' "$contract")"
  local nonroot; nonroot="$(yq -r '.non_root // false' "$contract")"
  local hc; hc="$(yq -r '.healthcheck // false' "$contract")"
  local ocirev; ocirev="$(yq -r '.oci_revision_label // "optional"' "$contract")"

  local user; user="$(jq -r '.Config.User // ""' <<<"$cfg")"
  [ -n "$want_user" ] && { [ "$user" = "$want_user" ] || die "$ref user '$user' != contract '$want_user'"; }
  if [ "$nonroot" = true ]; then
    case "$user" in ""|0|0:0|root|root:*) die "$ref must be non-root (user='$user')";; esac
  fi
  # exposed ports
  local p
  for p in $(yq -r '.ports // [] | .[]' "$contract"); do
    jq -e --arg port "${p}/tcp" '.Config.ExposedPorts | has($port)' >/dev/null 2>&1 <<<"$cfg" \
      || die "$ref does not expose port $p"
  done
  if [ "$hc" = true ]; then
    jq -e '.Config.Healthcheck.Test // empty | length > 0' >/dev/null 2>&1 <<<"$cfg" \
      || die "$ref has no healthcheck (contract requires one)"
  fi
  # The OCI revision label is stamped at publish time (VCS_REF build-arg), so a
  # local cold build legitimately lacks it — SKIP_OCI_LABEL=1 relaxes just that.
  if [ "$ocirev" = required ] && [ "${SKIP_OCI_LABEL:-0}" != 1 ]; then
    local rev; rev="$(jq -r '.Config.Labels["org.opencontainers.image.revision"] // ""' <<<"$cfg")"
    is_hex40 "$rev" || die "$ref missing/invalid org.opencontainers.image.revision label ('$rev')"
  fi
  echo "CONTRACT OK [$ref] per $(basename "$contract")"
}

_vic_self_test() {
  command -v jq >/dev/null && command -v yq >/dev/null || { echo "SKIP - jq/yq absent"; return 0; }
  local fail=0 tmp; tmp="$(mktemp -d)"
  local REV=7b4985a1234567890abcdef1234567890abcdef1
  cat > "$tmp/c.yaml" <<YAML
image: php-fpm
user: "10001:10001"
non_root: true
ports: [9000]
healthcheck: true
oci_revision_label: required
YAML
  _cfg() { cat <<JSON
{"Config":{"User":"$1","ExposedPorts":$2,"Healthcheck":$3,"Labels":{"org.opencontainers.image.revision":"$4"}}}
JSON
  }
  _M=""; _mk() { printf '%s' "$_M"; }
  _run() { ( INSPECT_FN=_mk verify_contract x "$tmp/c.yaml" ) >/dev/null 2>&1; }
  _ok() { _M="$2"; if _run; then echo "ok   - $1"; else echo "FAIL - $1 (want pass)"; fail=1; fi; }
  _no() { _M="$2"; if _run; then echo "FAIL - $1 (want reject)"; fail=1; else echo "ok   - $1"; fi; }
  _ok "good config passes"         "$(_cfg 10001:10001 '{"9000/tcp":{}}' '{"Test":["CMD","x"]}' "$REV")"
  _no "root user rejected"         "$(_cfg 0:0 '{"9000/tcp":{}}' '{"Test":["CMD","x"]}' "$REV")"
  _no "wrong user rejected"        "$(_cfg 999:999 '{"9000/tcp":{}}' '{"Test":["CMD","x"]}' "$REV")"
  _no "missing port rejected"      "$(_cfg 10001:10001 '{}' '{"Test":["CMD","x"]}' "$REV")"
  _no "missing healthcheck reject" "$(_cfg 10001:10001 '{"9000/tcp":{}}' 'null' "$REV")"
  _no "missing revision label"     "$(_cfg 10001:10001 '{"9000/tcp":{}}' '{"Test":["CMD","x"]}' '')"
  rm -rf "$tmp"; return $fail
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-}" in
    --self-test) _vic_self_test && echo "verify-image-contract.sh: SELF-TEST OK" ;;
    "") echo "usage: verify-image-contract.sh <image-ref> <contract.yaml> | --self-test" >&2; exit 2 ;;
    *) verify_contract "$1" "$2" ;;
  esac
fi
