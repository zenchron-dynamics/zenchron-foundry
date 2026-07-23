#!/usr/bin/env bash
# =============================================================================
# scripts/lib/release-manifest.sh
# -----------------------------------------------------------------------------
# Read/emit helpers for the signed RC release manifest. Uses a REAL YAML parser
# (yq v4) — never grep/sed — so malformed YAML fails loudly instead of being
# silently mis-parsed. Shared by generate/validate/verify-release-manifest.sh.
#
# Manifest shape (schema_version 1) is defined by
# schemas/release-manifest.schema.json. Helpers here are format-only; policy
# checks (digest syntax, revision equality, 10/10 coverage) live in the
# validator that sources this file.
# =============================================================================
set -euo pipefail

_rm_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
[ -n "${_COMMON_SOURCED:-}" ] || . "$_rm_dir/common.sh"
_COMMON_SOURCED=1

_yq() { command -v yq >/dev/null 2>&1 || die "yq (v4) is required to read manifests"; yq "$@"; }

# manifest_field <file> <yq-expression>   e.g. '.release'
manifest_field() { _yq -r "${2}" "$1"; }

# manifest_image_keys <file>  -> one image key per line, sorted
manifest_image_keys() { _yq -r '.images | keys | .[]' "$1" | sort; }

# manifest_image_field <file> <key> <subfield>  e.g. digest / reference / revision
manifest_image_field() { _yq -r ".images.\"$2\".$3" "$1"; }

# manifest_image_platforms <file> <key>  -> one platform per line
# (SC-23: arg order matches the doc comment and the manifest_image_* siblings)
manifest_image_platforms() { _yq -r ".images.\"$2\".platforms // [] | .[]" "$1" 2>/dev/null || true; }

# manifest_key <family> <selector>  -> manifest image key for a matrix token:
# the versionless "prod" selector collapses to the bare family (nginx, caddy);
# everything else is <family>-<selector> (php-cli-8.4). The ONE key-derivation
# rule shared by generate/validate/promote/verify (SC-18).
manifest_key() { case "${2:-}" in prod) printf '%s' "$1" ;; *) printf '%s-%s' "$1" "${2:-}" ;; esac; }

# checksum_file <path>  -> sha256 hex (portable: sha256sum or shasum)
checksum_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# atomic_write <dest>  (stdin -> temp -> mv); deterministic, never a partial file
atomic_write() {
  local dest="$1" tmp; tmp="$(mktemp "${dest}.XXXXXX")"
  cat > "$tmp"
  mv -f "$tmp" "$dest"
}

# --- self-test (offline, uses a fixture) -------------------------------------
_rm_self_test() {
  command -v yq >/dev/null 2>&1 || { echo "SKIP - yq absent"; return 0; }
  local fail=0 tmp; tmp="$(mktemp -d)"
  cat > "$tmp/m.yaml" <<'YAML'
schema_version: 1
release: v2026.07.03
candidate: rc1
revision: 7b4985a1234567890abcdef1234567890abcdef1
images:
  php-cli-8.4:
    digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    platforms: [linux/amd64, linux/arm64]
YAML
  _t() { if [ "$2" = "$3" ]; then echo "ok   - $1"; else echo "FAIL - $1: '$2' != '$3'"; fail=1; fi; }
  _t "read release"   "$(manifest_field "$tmp/m.yaml" '.release')" "v2026.07.03"
  _t "read schema"    "$(manifest_field "$tmp/m.yaml" '.schema_version')" "1"
  _t "image keys"     "$(manifest_image_keys "$tmp/m.yaml")" "php-cli-8.4"
  _t "image digest"   "$(manifest_image_field "$tmp/m.yaml" php-cli-8.4 digest)" \
     "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  _t "platforms count" "$(manifest_image_platforms "$tmp/m.yaml" php-cli-8.4 | wc -l | tr -d ' ')" "2"
  _t "manifest_key prod -> family"  "$(manifest_key nginx prod)" "nginx"
  _t "manifest_key sel -> fam-sel"  "$(manifest_key php-cli 8.4)" "php-cli-8.4"
  printf 'hello' | atomic_write "$tmp/a.txt"
  _t "atomic write"   "$(cat "$tmp/a.txt")" "hello"
  _t "checksum stable" "$(checksum_file "$tmp/a.txt")" "$(checksum_file "$tmp/a.txt")"
  rm -rf "$tmp"
  return $fail
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-}" in
    --self-test) _rm_self_test && echo "release-manifest.sh: SELF-TEST OK" ;;
    *) echo "usage: release-manifest.sh --self-test" >&2; exit 2 ;;
  esac
fi
