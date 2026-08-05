#!/usr/bin/env bash
# =============================================================================
# scripts/release/verify-oci-metadata.sh <image-ref> <contract.yaml> <labels-out.json>
# -----------------------------------------------------------------------------
# Validate the FULL OCI label map of a staged image against its contract (#126).
#
# WHY THIS IS NOT verify-image-contract.sh. That script checks runtime posture —
# user, ports, healthcheck — and exactly one label, the revision. Everything else
# #126 names went unchecked, so a wrong licence, a stale base image, a missing
# support status or a bogus created timestamp all produced a clean pass. The
# metadata_contract field in the authorization record then said PASS while saying
# nothing about most of the metadata.
#
# Two classes of value, checked differently:
#
#   STATIC  — title, description, vendor, source, base.name, licences and the
#             com.zenchron.* set. Compared against contracts/images/<image>.yaml,
#             which is the REVIEWED EXPECTATION. A Dockerfile edit that changes a
#             licence or base image without the matching contract change fails
#             here; that drift is the whole point.
#
#   DYNAMIC — version, revision, created, ref.name. There is no fixed expected
#             value; they must equal what THIS RUN actually is. Passed in, and
#             compared against the run's own facts.
#
# The inspected label map is written out as evidence, so the record is derived
# from something a reviewer can read rather than from a bare PASS.
#
# Env (all REQUIRED — an omitted expectation would silently stop checking):
#   EXPECT_REVISION   40-hex source revision this run built from
#   EXPECT_CREATED    RFC3339 UTC build timestamp, frozen once per run
#   EXPECT_REF_NAME   the staging tag the image was pushed as
#
# INSPECT_FN is injectable for offline self-test; it must emit the image config
# JSON as {Config:{Labels:{...}}}.
# =============================================================================
set -euo pipefail
_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
. "$_d/../lib/common.sh"

# The static keys EVERY image must declare and every contract must pin. The
# check used to be "iterate whatever oci_static happens to contain, then require
# at least six keys" — so a contract that simply omitted a dimension validated
# cleanly against an image that also omitted it. Caddy was in exactly that state:
# no base.name in the Dockerfile, none in the contract, and #126 requires base
# metadata on every child. Six other keys being present is not sufficient.
REQUIRED_STATIC_KEYS="\
org.opencontainers.image.title
org.opencontainers.image.description
org.opencontainers.image.vendor
org.opencontainers.image.source
org.opencontainers.image.base.name
org.opencontainers.image.licenses
com.zenchron.runtime
com.zenchron.support"

_default_inspect() { docker inspect "$1" --format '{{json .Config}}' 2>/dev/null | jq '{Config: .}'; }

verify_oci_metadata() { # <ref> <contract> <labels-out>
  local ref="${1:?usage: verify-oci-metadata.sh <image-ref> <contract.yaml> <labels-out.json>}"
  local contract="${2:?contract required}"
  local out="${3:?labels output path required}"
  local fetch="${INSPECT_FN:-_default_inspect}"
  local bad=()

  command -v yq >/dev/null || die "yq required"
  command -v jq >/dev/null || die "jq required"
  [ -f "$contract" ] || die "contract not found: $contract"

  local e
  for e in EXPECT_REVISION EXPECT_CREATED EXPECT_REF_NAME; do
    [ -n "${!e:-}" ] || die "$e is required"
  done
  is_hex40 "$EXPECT_REVISION" || die "EXPECT_REVISION is not 40-hex"
  printf '%s' "$EXPECT_CREATED" | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' \
    || die "EXPECT_CREATED is not RFC3339 UTC: '$EXPECT_CREATED'"

  local cfg labels
  cfg="$("$fetch" "$ref")" || die "could not inspect $ref"
  [ -n "$cfg" ] || die "could not inspect $ref"
  labels="$(jq -c '.Config.Labels // {}' <<<"$cfg")"
  [ "$labels" != "null" ] || labels='{}'

  mkdir -p "$(dirname "$out")"
  jq -n --arg ref "$ref" --argjson l "$labels" \
    '{image_reference:$ref, labels:$l}' > "$out"

  # An image with no labels at all must not pass by vacuity.
  [ "$(jq 'length' <<<"$labels")" -gt 0 ] || bad+=("image carries no labels at all")

  # --- static ---------------------------------------------------------------
  local key want got
  while IFS= read -r key; do
    [ -n "$key" ] || continue
    want="$(yq -r ".oci_static.\"${key}\"" "$contract")"
    got="$(jq -r --arg k "$key" '.[$k] // ""' <<<"$labels")"
    [ "$got" = "$want" ] || bad+=("$key: image has '${got:-<missing>}', contract requires '$want'")
  done < <(yq -r '.oci_static // {} | keys | .[]' "$contract")

  # Every mandatory dimension must be pinned by the contract AND present on the
  # image. Counting keys is not the same as requiring the right ones.
  local rk
  while IFS= read -r rk; do
    [ -n "$rk" ] || continue
    local pinned; pinned="$(yq -r ".oci_static.\"${rk}\" // \"\"" "$contract")"
    if [ -z "$pinned" ] || [ "$pinned" = null ]; then
      bad+=("$rk: MANDATORY but the contract does not pin it")
      continue
    fi
    local present; present="$(jq -r --arg k "$rk" '.[$k] // ""' <<<"$labels")"
    [ -n "$present" ] || bad+=("$rk: MANDATORY but the image does not carry it")
  done <<<"$REQUIRED_STATIC_KEYS"

  # --- dynamic: must equal what this run is ---------------------------------
  want="$(yq -r '.oci_version_label' "$contract")"
  [ -n "$want" ] && [ "$want" != null ] || bad+=("contract declares no oci_version_label")
  got="$(jq -r '.["org.opencontainers.image.version"] // ""' <<<"$labels")"
  [ "$got" = "$want" ] || bad+=("version: image has '${got:-<missing>}', contract requires '$want'")

  got="$(jq -r '.["org.opencontainers.image.revision"] // ""' <<<"$labels")"
  [ "$got" = "$EXPECT_REVISION" ] || bad+=("revision: image has '${got:-<missing>}', this run built '$EXPECT_REVISION'")

  got="$(jq -r '.["org.opencontainers.image.created"] // ""' <<<"$labels")"
  [ "$got" = "$EXPECT_CREATED" ] || bad+=("created: image has '${got:-<missing>}', this run froze '$EXPECT_CREATED'")

  got="$(jq -r '.["org.opencontainers.image.ref.name"] // ""' <<<"$labels")"
  [ "$got" = "$EXPECT_REF_NAME" ] || bad+=("ref.name: image has '${got:-<missing>}', this run pushed '$EXPECT_REF_NAME'")

  if [ "${#bad[@]}" -gt 0 ]; then
    printf 'REFUSE: OCI metadata contract failed for %s\n' "$ref" >&2
    printf '  - %s\n' "${bad[@]}" >&2
    return 1
  fi
  log "OCI metadata OK: $ref ($(jq 'length' <<<"$labels") labels checked against $(basename "$contract"))"
}

# ---------------------------------------------------------------------------
_vom_self_test() {
  local ok=0 nbad=0 tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  local REV="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  export EXPECT_REVISION="$REV" EXPECT_CREATED="2026-08-06T00:00:00Z" \
         EXPECT_REF_NAME="nginx-prod-r1-a1-saaaaaaa-amd64"

  local C="$tmp/c.yaml"
  cat > "$C" <<'YAML'
oci_static:
  "org.opencontainers.image.title": "zenchron-nginx"
  "org.opencontainers.image.description": "d"
  "org.opencontainers.image.vendor": "Zenchron Dynamics"
  "org.opencontainers.image.source": "https://github.com/zenchron-dynamics/zenchron-foundry"
  "org.opencontainers.image.base.name": "docker.io/nginxinc/nginx-unprivileged:1.27-bookworm"
  "org.opencontainers.image.licenses": "LicenseRef-Zenchron-Internal"
  "com.zenchron.runtime": "nginx"
  "com.zenchron.support": "supported"
oci_version_label: "prod"
YAML

  _labels() { # _labels [jq-mutation]
    local filt="${1:-.}"
    jq -c "$filt" <<JSON
{"org.opencontainers.image.title":"zenchron-nginx",
 "org.opencontainers.image.description":"d",
 "org.opencontainers.image.vendor":"Zenchron Dynamics",
 "org.opencontainers.image.source":"https://github.com/zenchron-dynamics/zenchron-foundry",
 "org.opencontainers.image.base.name":"docker.io/nginxinc/nginx-unprivileged:1.27-bookworm",
 "org.opencontainers.image.licenses":"LicenseRef-Zenchron-Internal",
 "com.zenchron.runtime":"nginx",
 "com.zenchron.support":"supported",
 "org.opencontainers.image.version":"prod",
 "org.opencontainers.image.revision":"$REV",
 "org.opencontainers.image.created":"2026-08-06T00:00:00Z",
 "org.opencontainers.image.ref.name":"nginx-prod-r1-a1-saaaaaaa-amd64"}
JSON
  }

  t() { # t <name> <pass|fail> <jq-mutation>
    local name="$1" expect="$2" filt="${3:-.}"
    local L; L="$(_labels "$filt")"
    _stub() { jq -n --argjson l "$L" '{Config:{Labels:$l}}'; }
    if ( INSPECT_FN=_stub verify_oci_metadata img "$C" "$tmp/out.json" ) >/dev/null 2>&1; then
      [ "$expect" = pass ] && { echo "ok   - $name"; ok=$((ok+1)); return; }
    else
      [ "$expect" = fail ] && { echo "ok   - $name"; ok=$((ok+1)); return; }
    fi
    echo "FAIL - $name (expected $expect)"; nbad=$((nbad+1))
  }

  t "a fully conformant label map passes" pass
  t "a wrong licence refuses"        fail '.["org.opencontainers.image.licenses"]="MIT"'
  t "a wrong source refuses"         fail '.["org.opencontainers.image.source"]="https://example.invalid"'
  t "a drifted base image refuses"   fail '.["org.opencontainers.image.base.name"]="docker.io/library/nginx:latest"'
  t "a missing title refuses"        fail 'del(.["org.opencontainers.image.title"])'
  t "a missing support status refuses" fail 'del(.["com.zenchron.support"])'
  t "a wrong vendor refuses"         fail '.["org.opencontainers.image.vendor"]="Someone Else"'
  t "prod-prod refuses"              fail '.["org.opencontainers.image.version"]="prod-prod"'
  t "a revision from another commit refuses" fail '.["org.opencontainers.image.revision"]="0000000000000000000000000000000000000000"'
  t "a created timestamp that is not the run's refuses" fail '.["org.opencontainers.image.created"]="2020-01-01T00:00:00Z"'
  t "a ref.name that is not the pushed tag refuses" fail '.["org.opencontainers.image.ref.name"]="something-else"'
  t "an image with no labels refuses"  fail '{}'
  t "a missing created label refuses"  fail 'del(.["org.opencontainers.image.created"])'

  # The gap this closed: a contract that simply OMITS a dimension used to
  # validate cleanly against an image that also omits it. Caddy was in exactly
  # that state for base.name. Removing the key from BOTH sides must still fail.
  local C2="$tmp/c2.yaml"
  grep -v 'base.name' "$C" > "$C2"
  local L2; L2="$(_labels 'del(.["org.opencontainers.image.base.name"])')"
  _stub2() { jq -n --argjson l "$L2" '{Config:{Labels:$l}}'; }
  if ( INSPECT_FN=_stub2 verify_oci_metadata img "$C2" "$tmp/o2.json" ) >/dev/null 2>&1; then
    echo "FAIL - a mandatory key absent from BOTH contract and image should refuse"; nbad=$((nbad+1))
  else
    echo "ok   - a mandatory key absent from BOTH contract and image still refuses"; ok=$((ok+1))
  fi

  # ...and every mandatory dimension, one at a time
  local rk
  while IFS= read -r rk; do
    [ -n "$rk" ] || continue
    local Cx="$tmp/cx.yaml" Lx
    grep -vF "\"$rk\"" "$C" > "$Cx"
    Lx="$(_labels "del(.[\"$rk\"])")"
    _stubx() { jq -n --argjson l "$Lx" '{Config:{Labels:$l}}'; }
    if ( INSPECT_FN=_stubx verify_oci_metadata img "$Cx" "$tmp/ox.json" ) >/dev/null 2>&1; then
      echo "FAIL - dropping mandatory $rk should refuse"; nbad=$((nbad+1))
    else
      echo "ok   - dropping mandatory $rk refuses"; ok=$((ok+1))
    fi
  done <<<"$REQUIRED_STATIC_KEYS"

  # the label map is written out as evidence even though the run passed
  local L; L="$(_labels)"; _stub() { jq -n --argjson l "$L" '{Config:{Labels:$l}}'; }
  ( INSPECT_FN=_stub verify_oci_metadata img "$C" "$tmp/ev.json" ) >/dev/null 2>&1
  if [ -s "$tmp/ev.json" ] && [ "$(jq -r '.labels["com.zenchron.support"]' "$tmp/ev.json")" = supported ]; then
    echo "ok   - the inspected label map is saved as evidence"; ok=$((ok+1))
  else echo "FAIL - label map evidence"; nbad=$((nbad+1)); fi

  # omitted expectations refuse (die exits, so capture with if)
  local m
  for m in EXPECT_REVISION EXPECT_CREATED EXPECT_REF_NAME; do
    if ( unset "$m"; INSPECT_FN=_stub verify_oci_metadata img "$C" "$tmp/o.json" ) >/dev/null 2>&1; then
      echo "FAIL - omitting $m should refuse"; nbad=$((nbad+1))
    else echo "ok   - omitting $m refuses"; ok=$((ok+1)); fi
  done

  echo "self-test: $ok ok, $nbad failed"
  [ "$nbad" -eq 0 ]
}

case "${1:-}" in
  --self-test) _vom_self_test && echo "verify-oci-metadata.sh: SELF-TEST OK" ;;
  "") echo "usage: verify-oci-metadata.sh <image-ref> <contract.yaml> <labels-out.json> | --self-test" >&2; exit 2 ;;
  *) verify_oci_metadata "$@" ;;
esac
