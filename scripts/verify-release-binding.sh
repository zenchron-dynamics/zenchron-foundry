#!/usr/bin/env bash
# =============================================================================
# scripts/verify-release-binding.sh <manifest.yaml> <tag> <tag-commit>
# -----------------------------------------------------------------------------
# Enforces the release equality chain so a stable release can only seal the
# exact commit the approved RC manifest and every promoted image represent:
#
#   tag_commit == manifest.revision
#   tag        == manifest.release
#   for each of the 10 images:
#       stable_alias_digest == manifest_image_digest        (this script)
#       provenance_revision == OCI_revision == tag_commit    (delegated to
#           verify-image-release-identity.sh, unless LOCAL)
#
# Env: REGISTRY/NAMESPACE, RESOLVE_DIGEST_FN (injectable), EXPECTED_REPO,
#      LOCAL=1 to skip the cosign identity delegation (offline).
# =============================================================================
set -euo pipefail
_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/registry-aliases.sh
. "$_d/lib/registry-aliases.sh"
# shellcheck source=lib/release-manifest.sh
. "$_d/lib/release-manifest.sh"

REL="${REL:-}"  # placeholder to satisfy set -u in some shells

digest_of() { docker buildx imagetools inspect "$1" --format '{{.Manifest.Digest}}' 2>/dev/null; }

# canonical stable ref per matrix image (the human-facing prod alias)
stable_ref() { case "$2" in prod) printf '%s/%s:prod' "$NS" "$1" ;; *) printf '%s/%s:%s-prod' "$NS" "$1" "$2" ;; esac; }
# manifest key per matrix image
mkey() { case "$2" in prod) printf '%s' "$1" ;; *) printf '%s-%s' "$1" "$2" ;; esac; }

verify_binding() {
  local manifest="$1" tag="$2" commit="$3"
  [ -f "$manifest" ] || die "manifest not found: $manifest"
  require_calver "$tag"; require_hex40 "$commit"
  local resolver="${RESOLVE_DIGEST_FN:-digest_of}"

  local mrel mrev; mrel="$(manifest_field "$manifest" '.release')"; mrev="$(manifest_field "$manifest" '.revision')"
  [ "$mrel" = "$tag" ]    || die "manifest release '$mrel' != tag '$tag'"
  [ "$mrev" = "$commit" ] || die "manifest revision '$mrev' != tag commit '$commit'"

  local n=0 ok=0
  for t in $MATRIX_IMAGES; do
    n=$((n+1)); local fam="${t%:*}" sel="${t#*:}" key ref mdig sdig
    key="$(mkey "$fam" "$sel")"
    mdig="$(manifest_image_field "$manifest" "$key" digest)"
    ref="$(stable_ref "$fam" "$sel")"
    sdig="$("$resolver" "$ref" || true)"
    [ -n "$sdig" ] || { echo "FAIL $ref: stable digest unresolved"; continue; }
    if [ "$sdig" = "$mdig" ]; then
      echo "PASS $key: stable == RC digest ($sdig)"; ok=$((ok+1))
    else
      echo "FAIL $key: stable $sdig != manifest $mdig"
    fi
  done
  assert_full_matrix "$n"
  [ "$ok" -eq "$MATRIX_COUNT" ] || die "digest equality failed (${ok}/${MATRIX_COUNT})"

  # Provenance + OCI revision equality per image (delegated). Offline: skipped.
  if [ "${LOCAL:-0}" != 1 ] && command -v cosign >/dev/null 2>&1; then
    export EXPECTED_REVISION="$commit" EXPECTED_ROLE="rc-publisher"
    export EXPECTED_REPO="${EXPECTED_REPO:-zenchron-dynamics/zenchron-foundry}"
    for t in $MATRIX_IMAGES; do
      local fam="${t%:*}" sel="${t#*:}" ref dig
      ref="$(stable_ref "$fam" "$sel")"; dig="$("$resolver" "$ref")"
      bash "$_d/verify-image-release-identity.sh" "$NS/$fam@$dig"
    done
  else
    warn "LOCAL/cosign-absent: skipped provenance+OCI revision delegation"
  fi
  log "RELEASE BINDING OK: tag $tag == commit $commit across ${MATRIX_COUNT}/${MATRIX_COUNT} images"
}

# --- self-test ---------------------------------------------------------------
_vrb_self_test() {
  command -v yq >/dev/null && command -v python3 >/dev/null || { echo "SKIP - yq/python3 absent"; return 0; }
  local fail=0 tmp; tmp="$(mktemp -d)"
  local R=7b4985a1234567890abcdef1234567890abcdef1
  # Build a good manifest with deterministic per-family digests.
  R="$R" OUT="$tmp/m.yaml" python3 - <<'PY'
import os, yaml, hashlib
R=os.environ["R"]
keys=[f"php-{f}-{v}" for f in ("cli","fpm","worker","frankenphp") for v in ("8.3","8.4")]+["nginx","caddy"]
def repo(k): return "ghcr.io/zenchron-dynamics/%s" % (k.rsplit("-",1)[0] if k.startswith("php-") else k)
def dig(k): return "sha256:"+hashlib.sha256(k.encode()).hexdigest()
imgs={k:{"repository":repo(k),"immutable_tag":"t-"+k,"digest":dig(k),
         "reference":repo(k)+"@"+dig(k),"revision":R,
         "platforms":["linux/amd64","linux/arm64"]} for k in keys}
m={"schema_version":1,"release":"v2026.07.03","candidate":"rc1","revision":R,
   "source_repository":"zenchron-dynamics/zenchron-foundry","source_ref":"refs/heads/master",
   "workflow_run_id":"1","created_at":"2026-07-03T12:00:00Z","images":imgs}
yaml.safe_dump(m,open(os.environ["OUT"],"w"),sort_keys=True)
PY
  # mock resolver: stable ref -> the manifest digest for that family (agreement).
  # Portable key parse (no BSD-sed `t`): ghcr.io/ns/<fam>:<suffix>.
  cat > "$tmp/mock.sh" <<'EOF'
#!/usr/bin/env bash
ref="$1"; tag="${ref##*:}"; rest="${ref%:*}"; fam="${rest##*/}"
case "$tag" in prod) key="$fam" ;; *-prod) key="$fam-${tag%-prod}" ;; *) key="$fam" ;; esac
python3 -c "import hashlib,sys;print('sha256:'+hashlib.sha256(sys.argv[1].encode()).hexdigest())" "$key"
EOF
  chmod +x "$tmp/mock.sh"
  _run() { ( RESOLVE_DIGEST_FN="$tmp/mock.sh" LOCAL=1 verify_binding "$1" "$2" "$3" ) >/dev/null 2>&1; }
  _ok() { if _run "$@"; then echo "ok   - $4"; else echo "FAIL - $4 (want pass)"; fail=1; fi; }
  _no() { if _run "$1" "$2" "$3"; then echo "FAIL - $4 (want reject)"; fail=1; else echo "ok   - $4"; fi; }

  _ok "$tmp/m.yaml" v2026.07.03 "$R" "good binding passes"
  _no "$tmp/m.yaml" v2026.07.04 "$R" "wrong tag rejects"
  _no "$tmp/m.yaml" v2026.07.03 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "wrong commit rejects"
  # one stable digest mismatch: mock returns bogus for caddy
  cat > "$tmp/mockbad.sh" <<'EOF'
#!/usr/bin/env bash
ref="$1"
case "$ref" in *caddy*) echo "sha256:$(printf deadbeef | shasum -a256 | cut -c1-64)"; exit 0;; esac
tag="${ref##*:}"; rest="${ref%:*}"; fam="${rest##*/}"
case "$tag" in prod) key="$fam" ;; *-prod) key="$fam-${tag%-prod}" ;; *) key="$fam" ;; esac
python3 -c "import hashlib,sys;print('sha256:'+hashlib.sha256(sys.argv[1].encode()).hexdigest())" "$key"
EOF
  chmod +x "$tmp/mockbad.sh"
  if ( RESOLVE_DIGEST_FN="$tmp/mockbad.sh" LOCAL=1 verify_binding "$tmp/m.yaml" v2026.07.03 "$R" ) >/dev/null 2>&1
    then echo "FAIL - one digest mismatch rejects (want reject)"; fail=1; else echo "ok   - one digest mismatch rejects"; fi
  rm -rf "$tmp"; return $fail
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-}" in
    --self-test) _vrb_self_test && echo "verify-release-binding.sh: SELF-TEST OK" ;;
    "") echo "usage: verify-release-binding.sh <manifest.yaml> <tag> <tag-commit> | --self-test" >&2; exit 2 ;;
    *) verify_binding "$@" ;;
  esac
fi
