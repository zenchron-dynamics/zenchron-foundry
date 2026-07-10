#!/usr/bin/env bash
# =============================================================================
# Canonical per-image RELEASE IDENTITY verifier (Workstream 2).
#
# Verifies ONE image reference's full trust identity and binds it to an expected
# source revision. Intended to be the single verifier reused by RC verification,
# stable promotion, release sealing and manual verification — do not maintain a
# weaker parallel implementation.
#
# Checks (all must hold):
#   1. cosign signature      (exact identity if EXPECTED_IDENTITY set, else regexp)
#   2. OIDC issuer           (--certificate-oidc-issuer)
#   3. SPDX SBOM attestation present + verifies
#   4. SLSA provenance attestation present + verifies
#   5. provenance source REPO  == EXPECTED_REPO
#   6. provenance source REVISION == EXPECTED_REVISION (40-hex)
#   7. OCI revision label      == EXPECTED_REVISION
#   8. image index advertises every EXPECTED_PLATFORM (default amd64+arm64)
#
# Usage:
#   verify-image-release-identity.sh <image-ref>
#   verify-image-release-identity.sh --self-test
#
# Required env (real runs):
#   EXPECTED_REVISION   40-hex source commit
#   EXPECTED_REPO       owner/repo (e.g. zenchron-dynamics/zenchron-foundry)
# Optional env:
#   EXPECTED_IDENTITY   exact cosign cert identity (narrow pin; preferred)
#   IDENTITY_RE         fallback identity regexp (default broad repo regex)
#   ISSUER              OIDC issuer (default GitHub Actions)
#   EXPECTED_PLATFORMS  comma list (default linux/amd64,linux/arm64)
#   LOCAL=1             if cosign/crane missing, print SKIPPED and exit 0
# =============================================================================
set -euo pipefail

REGISTRY="${REGISTRY:-ghcr.io}"
NAMESPACE="${NAMESPACE:-zenchron-dynamics}"
IDENTITY_RE="${IDENTITY_RE:-https://github.com/zenchron-dynamics/zenchron-foundry/.*}"
ISSUER="${ISSUER:-https://token.actions.githubusercontent.com}"
EXPECTED_PLATFORMS="${EXPECTED_PLATFORMS:-linux/amd64,linux/arm64}"
SHA_RE='^[0-9a-f]{40}$'

# Narrow the accepted identity to an explicit per-role policy when EXPECTED_ROLE
# is set (rc-publisher / release / scheduled-rebuild). This replaces the broad
# `…/zenchron-foundry/.*` default so a scheduled-rebuild signature can never pass
# production verification. An explicit EXPECTED_IDENTITY still takes precedence.
if [ -n "${EXPECTED_ROLE:-}" ] && [ -z "${EXPECTED_IDENTITY:-}" ]; then
  _virid_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  # shellcheck source=lib/cosign-identity.sh
  . "$_virid_dir/lib/cosign-identity.sh"
  IDENTITY_RE="$(identity_re_for_role "$EXPECTED_ROLE")"
  ISSUER="$(issuer_from_policy)"
fi

fail() { echo "IDENTITY FAIL [${IMG:-}]: $*" >&2; exit 1; }

# ---- Pure extraction/comparison logic (unit-tested; no network) -------------

# Extract a 40-hex source revision from an in-toto/SLSA provenance statement.
# Handles SLSA v1 (buildDefinition.resolvedDependencies[].digest.gitCommit) and
# v0.2 (materials[].digest.sha1, invocation.configSource.digest.sha1).
prov_revision() {
  jq -r '
    [ (.predicate.buildDefinition.resolvedDependencies[]?.digest.gitCommit // empty),
      (.predicate.materials[]?.digest.sha1 // empty),
      (.predicate.invocation.configSource.digest.sha1 // empty) ]
    | map(select(test("^[0-9a-f]{40}$"))) | (.[0] // "")
  ' 2>/dev/null || true
}

# Extract owner/repo from the provenance source URI (git+https://…/OWNER/REPO[@ref][.git]).
prov_repo() {
  jq -r '
    [ (.predicate.buildDefinition.resolvedDependencies[]?.uri // empty),
      (.predicate.materials[]?.uri // empty),
      (.predicate.invocation.configSource.uri // empty) ]
    | map(select(test("github.com"))) | (.[0] // "")
  ' 2>/dev/null \
  | sed -E 's#^git\+##; s#^https?://##; s#^github.com/##; s#\.git$##; s#@.*$##'
}

# Extract the OCI revision label from an image config JSON.
oci_revision() {
  jq -r '.config.Labels["org.opencontainers.image.revision"] // ""' 2>/dev/null || true
}

# Does an index manifest JSON advertise a given os/arch pair?
index_has_platform() { # <index-json> <linux/amd64>
  local os="${2%%/*}" arch="${2##*/}"
  jq -e --arg os "$os" --arg arch "$arch" '
    (.manifests // []) | any(.platform.os == $os and .platform.architecture == $arch)
  ' >/dev/null 2>&1 <<<"$1"
}

# ---- Runtime wrappers (cosign / registry) -----------------------------------

# Populate the COSIGN_ID array with the identity flag+value. An array is safe for
# a regex value containing shell/regex metachars (incl. the '|' in the
# publish-(ghcr|rc) alternation). An exact EXPECTED_IDENTITY wins over the role
# regexp. (The previous `printf '%s\0%s' | read -d '' a1 a2` dropped the value:
# read -d '' stops at the FIRST null, so a2 was always empty and cosign received
# an empty --certificate-identity-regexp — matching nothing.)
_set_cosign_id() {
  if [ -n "${EXPECTED_IDENTITY:-}" ]; then COSIGN_ID=(--certificate-identity "$EXPECTED_IDENTITY")
  else COSIGN_ID=(--certificate-identity-regexp "$IDENTITY_RE"); fi
}
_cosign_verify() {
  local ref="$1"; _set_cosign_id
  cosign verify "${COSIGN_ID[@]}" --certificate-oidc-issuer "$ISSUER" "$ref" >/dev/null 2>&1
}
_cosign_attest() {
  local ref="$1" ptype="$2"; _set_cosign_id
  cosign verify-attestation --type "$ptype" "${COSIGN_ID[@]}" --certificate-oidc-issuer "$ISSUER" "$ref" >/dev/null 2>&1
}
_prov_predicate_json() { # emit the decoded provenance statement JSON
  local ref="$1"; _set_cosign_id
  cosign verify-attestation --type slsaprovenance "${COSIGN_ID[@]}" --certificate-oidc-issuer "$ISSUER" "$ref" 2>/dev/null \
    | jq -r '.payload' 2>/dev/null | base64 -d 2>/dev/null || true
}
# Image CONFIG JSON (has .config.Labels). crane handles multi-arch; the buildx
# fallback does NOT — `{{json .Image}}` on an OCI index returns a platform-keyed
# MAP ({"linux/amd64":{...}}), not {"config":{...}}, so the OCI-label read comes
# back empty. Resolve a linux platform child manifest first, then inspect that
# single-platform image (whose .Image IS the config). Single-arch refs have no
# child list and are read directly.
_config_json() {
  local ref="$1" child repo
  crane config "$ref" 2>/dev/null && return 0
  child="$(docker buildx imagetools inspect "$ref" \
    --format '{{range .Manifest.Manifests}}{{if eq .Platform.OS "linux"}}{{println .Digest}}{{end}}{{end}}' 2>/dev/null \
    | grep -m1 '^sha256:')"
  if [ -n "$child" ]; then repo="${ref%%@*}"; repo="${repo%:*}"; ref="$repo@$child"; fi
  docker buildx imagetools inspect "$ref" --format '{{json .Image}}' 2>/dev/null || true
}
_index_json()  { crane manifest "$1" 2>/dev/null || docker buildx imagetools inspect "$1" --format '{{json .Manifest}}' 2>/dev/null || true; }

verify_image() {
  IMG="$1"
  [ -n "$IMG" ] || fail "no image ref given"
  [[ "${EXPECTED_REVISION:-}" =~ $SHA_RE ]] || fail "EXPECTED_REVISION must be 40-hex (got '${EXPECTED_REVISION:-}')"
  [ -n "${EXPECTED_REPO:-}" ] || fail "EXPECTED_REPO required"

  if ! command -v cosign >/dev/null 2>&1; then
    if [ "${LOCAL:-0}" = 1 ]; then echo "SKIPPED: cosign missing ($IMG)"; return 0; fi
    fail "cosign not installed (strict). Set LOCAL=1 to skip for non-release use."
  fi
  command -v jq >/dev/null || fail "jq required"

  _cosign_verify "$IMG"                 || fail "signature/identity/issuer verify failed"
  _cosign_attest "$IMG" spdxjson        || fail "SBOM attestation missing/invalid"
  _cosign_attest "$IMG" slsaprovenance  || fail "provenance attestation missing/invalid"

  local pj rev repo cfg ocirev idx plat
  pj="$(_prov_predicate_json "$IMG")"; [ -n "$pj" ] || fail "could not decode provenance predicate"
  rev="$(prov_revision <<<"$pj")";  [ -n "$rev" ]  || fail "no source revision in provenance"
  repo="$(prov_repo <<<"$pj")"
  [ "$rev" = "$EXPECTED_REVISION" ] || fail "provenance revision $rev != expected $EXPECTED_REVISION"
  [ "$repo" = "$EXPECTED_REPO" ]    || fail "provenance repo '$repo' != expected '$EXPECTED_REPO'"

  cfg="$(_config_json "$IMG")"; [ -n "$cfg" ] || fail "could not fetch image config for OCI label"
  ocirev="$(oci_revision <<<"$cfg")"
  [ "$ocirev" = "$EXPECTED_REVISION" ] || fail "OCI revision label '$ocirev' != expected $EXPECTED_REVISION"

  idx="$(_index_json "$IMG")"; [ -n "$idx" ] || fail "could not fetch image index for platform check"
  IFS=',' read -ra plat <<<"$EXPECTED_PLATFORMS"
  for p in "${plat[@]}"; do index_has_platform "$idx" "$p" || fail "missing platform $p"; done

  echo "IDENTITY OK [$IMG]: sig+sbom+prov, revision=$rev repo=$repo, OCI label ok, platforms=$EXPECTED_PLATFORMS"
}

# ---- Self-test (pure logic, synthetic fixtures) -----------------------------
self_test() {
  command -v jq >/dev/null || { echo "jq required for self-test"; return 1; }
  local ok=0 bad=0
  eq() { if [ "$2" = "$3" ]; then ok=$((ok+1)); echo "  ok   $1"; else bad=$((bad+1)); echo "  FAIL $1: '$2' != '$3'"; fi; }
  local REV=1234567890abcdef1234567890abcdef12345678

  local v1='{"predicate":{"buildDefinition":{"resolvedDependencies":[{"uri":"git+https://github.com/zenchron-dynamics/zenchron-foundry@refs/heads/master","digest":{"gitCommit":"'"$REV"'"}}]}}}'
  eq "v1 revision"  "$(prov_revision <<<"$v1")" "$REV"
  eq "v1 repo"      "$(prov_repo     <<<"$v1")" "zenchron-dynamics/zenchron-foundry"

  local v02='{"predicate":{"materials":[{"uri":"git+https://github.com/zenchron-dynamics/zenchron-foundry.git","digest":{"sha1":"'"$REV"'"}}],"invocation":{"configSource":{"uri":"git+https://github.com/zenchron-dynamics/zenchron-foundry@refs/heads/master","digest":{"sha1":"'"$REV"'"}}}}}'
  eq "v0.2 revision" "$(prov_revision <<<"$v02")" "$REV"
  eq "v0.2 repo"     "$(prov_repo     <<<"$v02")" "zenchron-dynamics/zenchron-foundry"

  eq "no revision -> empty" "$(prov_revision <<<'{"predicate":{}}')" ""
  eq "short sha rejected"   "$(prov_revision <<<'{"predicate":{"materials":[{"digest":{"sha1":"deadbeef"}}]}}')" ""

  eq "oci label present" "$(oci_revision <<<'{"config":{"Labels":{"org.opencontainers.image.revision":"'"$REV"'"}}}')" "$REV"
  eq "oci label absent"  "$(oci_revision <<<'{"config":{"Labels":{}}}')" ""

  local idx='{"manifests":[{"platform":{"os":"linux","architecture":"amd64"}},{"platform":{"os":"linux","architecture":"arm64"}}]}'
  if index_has_platform "$idx" "linux/amd64"; then ok=$((ok+1)); echo "  ok   has amd64"; else bad=$((bad+1)); echo "  FAIL has amd64"; fi
  if index_has_platform "$idx" "linux/arm64"; then ok=$((ok+1)); echo "  ok   has arm64"; else bad=$((bad+1)); echo "  FAIL has arm64"; fi
  if index_has_platform "$idx" "linux/s390x"; then bad=$((bad+1)); echo "  FAIL s390x should be absent"; else ok=$((ok+1)); echo "  ok   s390x absent"; fi

  # a single-arch index must fail the arm64 requirement
  local single='{"manifests":[{"platform":{"os":"linux","architecture":"amd64"}}]}'
  if index_has_platform "$single" "linux/arm64"; then bad=$((bad+1)); echo "  FAIL single-arch arm64"; else ok=$((ok+1)); echo "  ok   single-arch missing arm64 detected"; fi

  echo "self-test: $ok ok, $bad failed"
  [ "$bad" -eq 0 ]
}

if [ "${1:-}" = "--self-test" ]; then self_test; else verify_image "${1:-}"; fi
