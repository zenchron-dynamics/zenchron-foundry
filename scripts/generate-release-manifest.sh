#!/usr/bin/env bash
# =============================================================================
# scripts/generate-release-manifest.sh <version> --rc <rcN> [options]
# -----------------------------------------------------------------------------
# Emits the AUTHORITATIVE, schema-valid RC release manifest (schema_version 1):
# for each of the 10 canonical images, its immutable RC tag, the resolved index
# digest, the digest-pinned reference, the bound source revision, and the real
# advertised platforms. This manifest — signed — is the ONLY input promotion
# consumes; promotion never rediscovers candidates from mutable tags.
#
# Options / env:
#   --rc <rcN>          required
#   --revision <40hex>  default: git rev-parse HEAD
#   --created-at <ts>   default: now (or SOURCE_DATE_EPOCH)
#   REGISTRY/NAMESPACE  default ghcr.io / zenchron-dynamics
#   RESOLVE_DIGEST_FN   <ref> -> sha256:… (default crane/buildx); injectable
#   RESOLVE_PLATFORMS_FN <ref> -> csv of os/arch (default buildx); injectable
#   LOCAL=1             tolerate offline: digest "UNRESOLVED", platforms default
# Writes release-artifacts/release-manifest.yaml when that dir exists, and
# self-validates the result with validate-release-manifest.sh.
# =============================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
# shellcheck source=lib/registry-aliases.sh
. "$ROOT/scripts/lib/registry-aliases.sh"
# shellcheck source=lib/release-manifest.sh
. "$ROOT/scripts/lib/release-manifest.sh"

_default_digest() { crane digest "$1" 2>/dev/null || \
  docker buildx imagetools inspect "$1" --format '{{.Manifest.Digest}}' 2>/dev/null; }
_default_platforms() {
  docker buildx imagetools inspect "$1" --format '{{json .Manifest}}' 2>/dev/null \
    | jq -r '[ (.manifests // [])[] | select(.platform.os=="linux") | .platform.os+"/"+.platform.architecture ] | unique | join(",")' 2>/dev/null
}
RESOLVE_DIGEST_FN="${RESOLVE_DIGEST_FN:-_default_digest}"
RESOLVE_PLATFORMS_FN="${RESOLVE_PLATFORMS_FN:-_default_platforms}"

# Gather one TSV row per image: key repo immutable_tag digest reference revision platforms
gather() {
  for t in $MATRIX_IMAGES; do
    local fam="${t%:*}" sel="${t#*:}" key repo imm ref dig plats
    key="$(manifest_key "$fam" "$sel")"   # shared key rule (SC-18)
    repo="$NS/$fam"
    imm="$(immutable_rc_suffix "$sel" "$VERSION" "$RC" "$REVISION")"
    dig="$("$RESOLVE_DIGEST_FN" "$repo:$imm" || true)"
    plats="$("$RESOLVE_PLATFORMS_FN" "$repo:$imm" || true)"
    if [ -z "$dig" ]; then
      [ "$LOCAL" = 1 ] || die "could not resolve digest for $repo:$imm (set LOCAL=1 for offline)"
      dig="UNRESOLVED"
    fi
    [ -n "$plats" ] || plats="linux/amd64,linux/arm64"
    ref="$repo@$dig"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$key" "$repo" "$imm" "$dig" "$ref" "$REVISION" "$plats"
  done
}

emit() {  # <rows-file>
  ROWS="$1" VERSION="$VERSION" RC="$RC" REVISION="$REVISION" CREATED_AT="$CREATED_AT" \
  REPO="${SOURCE_REPO:-zenchron-dynamics/zenchron-foundry}" \
  SREF="${GITHUB_REF:-refs/heads/master}" \
  WF="${GITHUB_WORKFLOW:-publish-rc}" RUNID="${GITHUB_RUN_ID:-0}" ATTEMPT="${GITHUB_RUN_ATTEMPT:-1}" \
  python3 - <<'PY'
import os, sys, yaml
rows = [l.rstrip("\n").split("\t") for l in open(os.environ["ROWS"]) if l.strip()]
imgs = {}
for key, repo, imm, dig, ref, rev, plats in rows:
    imgs[key] = {"repository": repo, "immutable_tag": imm, "digest": dig,
                 "reference": ref, "revision": rev,
                 "platforms": [p for p in plats.split(",") if p]}
m = {"schema_version": 1, "release": os.environ["VERSION"], "candidate": os.environ["RC"],
     "revision": os.environ["REVISION"], "source_repository": os.environ["REPO"],
     "source_ref": os.environ["SREF"], "workflow_name": os.environ["WF"],
     "workflow_run_id": os.environ["RUNID"], "workflow_run_attempt": os.environ["ATTEMPT"],
     "created_at": os.environ["CREATED_AT"], "images": imgs}
yaml.safe_dump(m, sys.stdout, sort_keys=True)
PY
}

main() {
  RC="" REVISION="" CREATED_AT="" VERSION="" LOCAL="${LOCAL:-0}"
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --rc) shift; RC="${1:?--rc needs a value}" ;;
      --revision) shift; REVISION="${1:?--revision needs a value}" ;;
      --created-at) shift; CREATED_AT="${1:?--created-at needs a value}" ;;
      -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
      -*) die "unknown option: $1" ;;
      *) [ -z "$VERSION" ] && VERSION="$1" || die "unexpected arg: $1" ;;
    esac
    shift
  done

  require_calver "$VERSION"
  require_rc "$RC"
  [ -n "$REVISION" ] || REVISION="$(git rev-parse HEAD)"
  require_hex40 "$REVISION"
  if [ -z "$CREATED_AT" ]; then
    if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
      CREATED_AT="$(date -u -r "$SOURCE_DATE_EPOCH" +%FT%TZ 2>/dev/null || date -u -d "@$SOURCE_DATE_EPOCH" +%FT%TZ)"
    else CREATED_AT="$(date -u +%FT%TZ)"; fi
  fi

  local _rows MANIFEST tmp
  _rows="$(mktemp)"; gather > "$_rows"
  MANIFEST="$(emit "$_rows")"
  rm -f "$_rows"
  printf '%s' "$MANIFEST"

  # SKIP_ARTIFACT_WRITE=1 is set ONLY by the self-test so a recursive test run
  # can never clobber a live release-artifacts/ directory.
  if [ -d release-artifacts ] && [ "${SKIP_ARTIFACT_WRITE:-0}" != 1 ]; then
    # atomic write + checksum sidecar
    tmp="$(mktemp release-artifacts/rm.XXXXXX)"; printf '%s' "$MANIFEST" > "$tmp"
    mv -f "$tmp" release-artifacts/release-manifest.yaml
    ( cd release-artifacts && { sha256sum release-manifest.yaml 2>/dev/null || shasum -a 256 release-manifest.yaml; } > release-manifest.yaml.sha256 )
    echo "Wrote release-artifacts/release-manifest.yaml (+ .sha256)" >&2
    # self-validate unless offline placeholders are present
    if [ "$LOCAL" != 1 ]; then bash scripts/validate-release-manifest.sh release-artifacts/release-manifest.yaml >&2; fi
  fi
}

# --- self-test (injected resolver mocks, offline) ----------------------------
_grm_self_test() {
  command -v python3 >/dev/null 2>&1 && command -v yq >/dev/null 2>&1 \
    || { echo "SKIP - python3/yq absent"; return 0; }
  python3 -c 'import yaml, jsonschema' 2>/dev/null || { echo "SKIP - pyyaml/jsonschema absent"; return 0; }
  local fail=0 tmp; tmp="$(mktemp -d)"
  local R=7b4985a1234567890abcdef1234567890abcdef1
  _t() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

  # Injected resolver mocks via the RESOLVE_*_FN seams (deterministic per ref).
  mkdir -p "$tmp/bin"
  cat > "$tmp/bin/mockdig" <<'EOF'
#!/usr/bin/env bash
printf 'sha256:%s\n' "$(printf '%s' "$1" | shasum -a 256 | cut -c1-64)"
EOF
  printf '#!/usr/bin/env bash\necho linux/amd64,linux/arm64\n' > "$tmp/bin/mockplat"
  printf '#!/usr/bin/env bash\nexit 1\n' > "$tmp/bin/mockfail"
  chmod +x "$tmp/bin/"*

  ( cd "$tmp" && SKIP_ARTIFACT_WRITE=1 \
      RESOLVE_DIGEST_FN="$tmp/bin/mockdig" RESOLVE_PLATFORMS_FN="$tmp/bin/mockplat" \
      bash "$ROOT/scripts/generate-release-manifest.sh" v2026.07.03 --rc rc1 \
        --revision "$R" --created-at 2026-07-03T12:00:00Z ) > "$tmp/m.yaml" 2>/dev/null
  _t "generation succeeds with mock resolvers" "[ $? -eq 0 ]"
  _t "manifest lists 10 images" '[ "$(yq -r ".images | keys | length" "$tmp/m.yaml")" = 10 ]'
  _t "manifest revision bound"  '[ "$(yq -r ".revision" "$tmp/m.yaml")" = "$R" ]'
  _t "digests are anchored"     '! yq -r ".images[].digest" "$tmp/m.yaml" | grep -Ev "^sha256:[0-9a-f]{64}$" | grep -q .'
  _t "manifest schema-validates" 'bash "$ROOT/scripts/validate-release-manifest.sh" "$tmp/m.yaml" >/dev/null 2>&1'

  # resolver failure without LOCAL=1 -> refuse (no UNRESOLVED placeholders)
  if ( cd "$tmp" && SKIP_ARTIFACT_WRITE=1 \
        RESOLVE_DIGEST_FN="$tmp/bin/mockfail" RESOLVE_PLATFORMS_FN="$tmp/bin/mockplat" \
        bash "$ROOT/scripts/generate-release-manifest.sh" v2026.07.03 --rc rc1 \
          --revision "$R" ) >/dev/null 2>&1; then
    echo "FAIL - unresolvable digest must refuse without LOCAL=1"; fail=1
  else
    echo "ok   - unresolvable digest refuses without LOCAL=1"
  fi

  rm -rf "$tmp"; return $fail
}

case "${1:-}" in
  --self-test) _grm_self_test && echo "generate-release-manifest.sh: SELF-TEST OK" ;;
  *) main "$@" ;;
esac
