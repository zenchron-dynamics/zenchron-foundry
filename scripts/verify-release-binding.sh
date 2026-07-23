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
#       EVERY stable alias digest == manifest_image_digest    (this script;
#           SC-09: canonical prod, prod-<rel> AND the PHP -debian alias — the
#           full stable_aliases inventory, not just the canonical alias)
#       provenance_revision == OCI_revision == tag_commit     (delegated to
#           verify-image-release-identity.sh, unless LOCAL)
#
# Identity delegation runs ONCE per image, on the shared digest: cosign
# signatures/attestations attach to the DIGEST, and the loop above has already
# proven every alias resolves to that same digest — re-verifying the identical
# digest once per alias would add cost, not assurance.
#
# SC-19: no local digest_of/stable_ref copies — alias enumeration goes through
# lib/registry-aliases.sh (stable_aliases/full_ref) and digest resolution
# through lib/registry-ops.sh (reg_digest). RESOLVE_DIGEST_FN stays as the
# injectable resolver seam for offline tests.
#
# Env: REGISTRY/NAMESPACE, RESOLVE_DIGEST_FN (injectable), EXPECTED_REPO,
#      LOCAL=1 to skip the cosign identity delegation (offline).
# =============================================================================
set -euo pipefail
_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/registry-aliases.sh
. "$_d/lib/registry-aliases.sh"
# shellcheck source=lib/registry-ops.sh
. "$_d/lib/registry-ops.sh"
# shellcheck source=lib/release-manifest.sh
. "$_d/lib/release-manifest.sh"

REL="${REL:-}"  # placeholder to satisfy set -u in some shells

# manifest key per matrix image
mkey() { case "$2" in prod) printf '%s' "$1" ;; *) printf '%s-%s' "$1" "$2" ;; esac; }

verify_binding() {
  local manifest="$1" tag="$2" commit="$3"
  [ -f "$manifest" ] || die "manifest not found: $manifest"
  require_calver "$tag"; require_hex40 "$commit"
  local resolver="${RESOLVE_DIGEST_FN:-reg_digest}"
  local rel="${tag#v}"

  local mrel mrev; mrel="$(manifest_field "$manifest" '.release')"; mrev="$(manifest_field "$manifest" '.revision')"
  [ "$mrel" = "$tag" ]    || die "manifest release '$mrel' != tag '$tag'"
  [ "$mrev" = "$commit" ] || die "manifest revision '$mrev' != tag commit '$commit'"

  local n=0 img_ok=0 na=0 na_ok=0
  for t in $MATRIX_IMAGES; do
    n=$((n+1)); local fam="${t%:*}" sel="${t#*:}" key mdig suf ref sdig this_ok=1
    key="$(mkey "$fam" "$sel")"
    mdig="$(manifest_image_field "$manifest" "$key" digest)"
    is_digest "$mdig" || die "manifest digest for $key is not sha256: '$mdig'"
    # SC-09: the FULL alias inventory, not just the canonical prod alias.
    for suf in $(stable_aliases "$sel" "$rel"); do
      ref="$(full_ref "$fam" "$suf")"
      na=$((na+1))
      sdig="$("$resolver" "$ref" 2>/dev/null || true)"
      if [ -z "$sdig" ]; then
        echo "FAIL $ref: stable digest unresolved"; this_ok=0; continue
      fi
      if [ "$sdig" = "$mdig" ]; then
        echo "PASS $ref == RC digest ($sdig)"; na_ok=$((na_ok+1))
      else
        echo "FAIL $ref: stable $sdig != manifest $mdig"; this_ok=0
      fi
    done
    [ "$this_ok" -eq 1 ] && img_ok=$((img_ok+1))
  done
  assert_full_matrix "$n"
  [ "$na_ok" -eq "$na" ] && [ "$img_ok" -eq "$MATRIX_COUNT" ] \
    || die "digest equality failed (${na_ok}/${na} aliases, ${img_ok}/${MATRIX_COUNT} images)"

  # Provenance + OCI revision equality per image (delegated). Offline: skipped.
  # Runs once per image on the manifest digest: every alias was just proven to
  # resolve to that exact digest, and attestations attach to the digest itself.
  if [ "${LOCAL:-0}" != 1 ] && command -v cosign >/dev/null 2>&1; then
    export EXPECTED_REVISION="$commit" EXPECTED_ROLE="rc-publisher"
    export EXPECTED_REPO="${EXPECTED_REPO:-zenchron-dynamics/zenchron-foundry}"
    for t in $MATRIX_IMAGES; do
      local fam="${t%:*}" sel="${t#*:}" key mdig
      key="$(mkey "$fam" "$sel")"
      mdig="$(manifest_image_field "$manifest" "$key" digest)"
      bash "$_d/verify-image-release-identity.sh" "$NS/$fam@$mdig"
    done
  else
    warn "LOCAL/cosign-absent: skipped provenance+OCI revision delegation"
  fi
  log "RELEASE BINDING OK: tag $tag == commit $commit across ${na}/${na} aliases (${MATRIX_COUNT}/${MATRIX_COUNT} images)"
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
  # mock resolver: EVERY stable alias (canonical, prod-<rel>, -debian) -> the
  # manifest digest for its image key (agreement across the full inventory).
  cat > "$tmp/mock.sh" <<'EOF'
#!/usr/bin/env bash
ref="$1"; tag="${ref##*:}"; rest="${ref%:*}"; fam="${rest##*/}"
case "$tag" in
  prod|prod-*)     key="$fam" ;;                  # edge: prod / prod-<rel>
  *-debian)        key="$fam-${tag%-debian}" ;;   # php provider-explicit alias
  *-prod|*-prod-*) key="$fam-${tag%%-prod*}" ;;   # php canonical / version-bound
  *) key="$fam" ;;
esac
python3 -c "import hashlib,sys;print('sha256:'+hashlib.sha256(sys.argv[1].encode()).hexdigest())" "$key"
EOF
  chmod +x "$tmp/mock.sh"
  _run() { ( RESOLVE_DIGEST_FN="$tmp/mock.sh" LOCAL=1 verify_binding "$1" "$2" "$3" ) >/dev/null 2>&1; }
  _ok() { if _run "$@"; then echo "ok   - $4"; else echo "FAIL - $4 (want pass)"; fail=1; fi; }
  _no() { if _run "$1" "$2" "$3"; then echo "FAIL - $4 (want reject)"; fail=1; else echo "ok   - $4"; fi; }

  _ok "$tmp/m.yaml" v2026.07.03 "$R" "good binding passes (all aliases)"
  _no "$tmp/m.yaml" v2026.07.04 "$R" "wrong tag rejects"
  _no "$tmp/m.yaml" v2026.07.03 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "wrong commit rejects"
  # one stable digest mismatch: mock returns bogus for caddy (edge canonical)
  cat > "$tmp/mockbad.sh" <<'EOF'
#!/usr/bin/env bash
ref="$1"
case "$ref" in *caddy*) echo "sha256:$(printf deadbeef | shasum -a256 | cut -c1-64)"; exit 0;; esac
exec "$(dirname "$0")/mock.sh" "$ref"
EOF
  chmod +x "$tmp/mockbad.sh"
  if ( RESOLVE_DIGEST_FN="$tmp/mockbad.sh" LOCAL=1 verify_binding "$tmp/m.yaml" v2026.07.03 "$R" ) >/dev/null 2>&1
    then echo "FAIL - one digest mismatch rejects (want reject)"; fail=1; else echo "ok   - one digest mismatch rejects"; fi
  # SC-09: a NON-canonical alias drifting alone must also reject — the bogus
  # digest is returned ONLY for php-cli:8.3-debian; every canonical alias agrees.
  cat > "$tmp/mockbad2.sh" <<'EOF'
#!/usr/bin/env bash
ref="$1"
case "$ref" in */php-cli:8.3-debian) echo "sha256:$(printf drifted | shasum -a256 | cut -c1-64)"; exit 0;; esac
exec "$(dirname "$0")/mock.sh" "$ref"
EOF
  chmod +x "$tmp/mockbad2.sh"
  if ( RESOLVE_DIGEST_FN="$tmp/mockbad2.sh" LOCAL=1 verify_binding "$tmp/m.yaml" v2026.07.03 "$R" ) >/dev/null 2>&1
    then echo "FAIL - non-canonical alias drift rejects (want reject)"; fail=1; else echo "ok   - non-canonical alias drift rejects"; fi
  # SC-09: an UNRESOLVED non-canonical alias must also reject (empty resolver).
  cat > "$tmp/mockgone.sh" <<'EOF'
#!/usr/bin/env bash
ref="$1"
case "$ref" in */nginx:prod-*) exit 1;; esac
exec "$(dirname "$0")/mock.sh" "$ref"
EOF
  chmod +x "$tmp/mockgone.sh"
  if ( RESOLVE_DIGEST_FN="$tmp/mockgone.sh" LOCAL=1 verify_binding "$tmp/m.yaml" v2026.07.03 "$R" ) >/dev/null 2>&1
    then echo "FAIL - unresolved version-bound alias rejects (want reject)"; fail=1; else echo "ok   - unresolved version-bound alias rejects"; fi
  rm -rf "$tmp"; return $fail
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-}" in
    --self-test) _vrb_self_test && echo "verify-release-binding.sh: SELF-TEST OK" ;;
    "") echo "usage: verify-release-binding.sh <manifest.yaml> <tag> <tag-commit> | --self-test" >&2; exit 2 ;;
    *) verify_binding "$@" ;;
  esac
fi
