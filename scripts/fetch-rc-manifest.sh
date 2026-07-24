#!/usr/bin/env bash
# =============================================================================
# scripts/fetch-rc-manifest.sh <rc-run-id> <version> <rc> <dest-dir>
# -----------------------------------------------------------------------------
# The ONLY supported way to obtain the signed RC manifest for stable promotion
# and release sealing: download it from the publish-rc.yml workflow run that
# produced and signed it.
#
# The manifest is deliberately NEVER committed to the source tree. Committing
# generated RC evidence creates a new commit AFTER the RC images were built,
# which breaks the release equality chain:
#
#   release tag commit == manifest.revision == provenance revision == OCI revision
#
# Fail-closed checks, in order, before the manifest is trusted:
#   1. run exists and belongs to EXPECTED_REPO
#   2. run is .github/workflows/publish-rc.yml (not some other workflow)
#   3. run conclusion == success
#   4. run head_sha == EXPECTED_REVISION (the release tag commit)
#   5. artifact rc-manifest-<version>-<rc> downloads, all four files present
#   6. checksum + cosign signature + schema/policy (verify-release-manifest.sh)
#   7. .release == <version>, .candidate == <rc>, .revision == EXPECTED_REVISION
#
# There is no fallback to locally committed evidence — by design.
#
# Env:
#   EXPECTED_REVISION  40-hex release tag commit (required)
#   EXPECTED_REPO      default zenchron-dynamics/zenchron-foundry
#   EXPECTED_ROLE      default rc-publisher (cosign identity for the manifest)
#   GH_BIN             injectable `gh` binary (fixture tests)
#   LOCAL=1            skip the cosign signature step only (offline)
# =============================================================================
set -euo pipefail
_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/release-manifest.sh
. "$_d/lib/release-manifest.sh"

# The one workflow allowed to mint a signed RC manifest.
RC_WORKFLOW_PATH=".github/workflows/publish-rc.yml"

fetch_rc_manifest() {
  local run_id="${1:-}" version="${2:-}" rc="${3:-}" dest="${4:-}"
  local repo="${EXPECTED_REPO:-zenchron-dynamics/zenchron-foundry}"
  local rev="${EXPECTED_REVISION:-}"
  local gh="${GH_BIN:-gh}"

  [ -n "$dest" ] || die "usage: fetch-rc-manifest.sh <run-id> <version> <rc> <dest-dir>"
  [ -n "$run_id" ] || die "rc manifest run id is required (publish-rc run that built this RC)"
  printf '%s' "$run_id" | grep -Eq '^[0-9]+$' || die "run id '$run_id' is not a numeric run id"
  require_calver "$version"; require_rc "$rc"
  [ -n "$rev" ] || die "EXPECTED_REVISION required (release tag commit)"
  require_hex40 "$rev"
  command -v jq >/dev/null 2>&1 || die "jq is required to inspect the publish-rc run"

  # --- 1-4: provenance of the run that produced the artifact ------------------
  local meta
  meta="$("$gh" api "repos/${repo}/actions/runs/${run_id}" 2>/dev/null)" \
    || die "publish-rc run ${run_id} not found in ${repo}"
  local got
  got="$(printf '%s' "$meta" | jq -r '.repository.full_name // ""')"
  [ "$got" = "$repo" ] || die "run ${run_id} belongs to '${got}', not '${repo}'"
  got="$(printf '%s' "$meta" | jq -r '.path // ""')"
  [ "$got" = "$RC_WORKFLOW_PATH" ] || die "run ${run_id} is '${got}', not ${RC_WORKFLOW_PATH}"
  got="$(printf '%s' "$meta" | jq -r '.conclusion // ""')"
  [ "$got" = "success" ] || die "run ${run_id} concluded '${got}', not success"
  got="$(printf '%s' "$meta" | jq -r '.head_sha // ""')"
  [ "$got" = "$rev" ] || die "run ${run_id} built ${got}, not the release revision ${rev}"

  # --- 5: the artifact --------------------------------------------------------
  local name="rc-manifest-${version}-${rc}"
  mkdir -p "$dest"
  "$gh" run download "$run_id" --repo "$repo" -n "$name" -D "$dest" \
    || die "artifact '${name}' not found in run ${run_id}"
  local m="$dest/release-manifest.yaml" f
  for f in "$m" "$m.sha256" "$m.sig" "$m.pem"; do
    [ -f "$f" ] || die "artifact '${name}' incomplete: missing $(basename "$f")"
  done

  # --- 6: checksum + signature + schema/policy (10/10 images, digests, revs) ---
  EXPECTED_ROLE="${EXPECTED_ROLE:-rc-publisher}" bash "$_d/verify-release-manifest.sh" "$m"

  # --- 7: the manifest describes exactly this release ------------------------
  got="$(manifest_field "$m" '.release')"
  [ "$got" = "$version" ] || die "manifest release '${got}' != release version '${version}'"
  got="$(manifest_field "$m" '.candidate')"
  [ "$got" = "$rc" ] || die "manifest candidate '${got}' != selected rc '${rc}'"
  got="$(manifest_field "$m" '.revision')"
  [ "$got" = "$rev" ] || die "manifest revision '${got}' != release tag commit '${rev}'"

  log "RC MANIFEST OK: ${name} from run ${run_id} @ ${rev} -> ${m}"
}

# --- self-test (offline; fixture `gh`, LOCAL=1 skips cosign) -----------------
_frm_self_test() {
  command -v yq >/dev/null 2>&1 && command -v jq >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1 \
    || { echo "SKIP - yq/jq/python3 absent"; return 0; }
  python3 -c 'import yaml, jsonschema' 2>/dev/null || { echo "SKIP - pyyaml/jsonschema absent"; return 0; }
  local fail=0 tmp; tmp="$(mktemp -d)"
  local REV=3635459c4d6eb2602ad5bcdc0a927d716c615a39
  local REPO=zenchron-dynamics/zenchron-foundry
  local SRC="$tmp/src"; mkdir -p "$SRC"

  # A valid signed-shape RC manifest (sig/pem are placeholders; LOCAL=1 skips cosign).
  # SC-20: this fixture's image list INTENTIONALLY duplicates MATRIX_IMAGES
  # instead of deriving from it — an independent copy makes the self-test a
  # drift tripwire for accidental edits to the authoritative matrix
  # (owner-accepted duplication; do not centralize).
  REV="$REV" OUT="$SRC/release-manifest.yaml" python3 - <<'PY'
import os, yaml, hashlib
R = os.environ["REV"]
keys = [f"php-{f}-{v}" for f in ("cli","fpm","worker","frankenphp") for v in ("8.3","8.4")] + ["nginx","caddy"]
def repo(k): return "ghcr.io/zenchron-dynamics/%s" % (k.rsplit("-",1)[0] if k.startswith("php-") else k)
def dig(k): return "sha256:" + hashlib.sha256(k.encode()).hexdigest()
imgs = {k: {"repository": repo(k), "immutable_tag": "t-"+k, "digest": dig(k),
            "reference": repo(k)+"@"+dig(k), "revision": R,
            "platforms": ["linux/amd64","linux/arm64"]} for k in keys}
m = {"schema_version":1, "release":"v2026.07.04", "candidate":"rc1", "revision":R,
     "source_repository":"zenchron-dynamics/zenchron-foundry", "source_ref":"refs/heads/master",
     "workflow_run_id":"99", "created_at":"2026-07-04T12:00:00Z", "images":imgs}
yaml.safe_dump(m, open(os.environ["OUT"],"w"), sort_keys=True)
PY
  : > "$SRC/release-manifest.yaml.sig"; : > "$SRC/release-manifest.yaml.pem"
  _sum() { checksum_file "$1/release-manifest.yaml" > "$1/release-manifest.yaml.sha256"; }
  _sum "$SRC"

  # Fixture gh: MOCK_META drives `gh api`, MOCK_SRC drives `gh run download`.
  cat > "$tmp/gh" <<'EOF'
#!/usr/bin/env bash
case "$1" in
  api)
    [ "${MOCK_NORUN:-0}" = 1 ] && exit 1
    printf '%s' "$MOCK_META" ;;
  run)
    [ "${MOCK_NOART:-0}" = 1 ] && exit 1
    d=""; prev=""
    for a in "$@"; do [ "$prev" = "-D" ] && d="$a"; prev="$a"; done
    mkdir -p "$d" && cp "$MOCK_SRC"/release-manifest.yaml* "$d"/ ;;
esac
EOF
  chmod +x "$tmp/gh"

  _meta() { # <repo> <path> <conclusion> <sha>
    printf '{"repository":{"full_name":"%s"},"path":"%s","conclusion":"%s","head_sha":"%s"}' "$@"
  }
  local GOOD; GOOD="$(_meta "$REPO" "$RC_WORKFLOW_PATH" success "$REV")"

  # _run <meta> <src> <run-id> <version> <rc> [extra-env...]
  _run() {
    local meta="$1" src="$2" rid="$3" ver="$4" rc="$5"; shift 5
    ( rm -rf "$tmp/out"; env "$@" GH_BIN="$tmp/gh" MOCK_META="$meta" MOCK_SRC="$src" \
        LOCAL=1 EXPECTED_REVISION="$REV" EXPECTED_REPO="$REPO" \
        bash "$_d/fetch-rc-manifest.sh" "$rid" "$ver" "$rc" "$tmp/out" ) >/dev/null 2>&1
  }
  _ok() { local d="$1"; shift; if _run "$@"; then echo "ok   - $d"; else echo "FAIL - $d (want pass)"; fail=1; fi; }
  _no() { local d="$1"; shift; if _run "$@"; then echo "FAIL - $d (want reject)"; fail=1; else echo "ok   - $d"; fi; }

  _ok "good RC artifact accepted"     "$GOOD" "$SRC" 99 v2026.07.04 rc1
  _no "empty run id rejected"         "$GOOD" "$SRC" "" v2026.07.04 rc1
  _no "non-numeric run id rejected"   "$GOOD" "$SRC" "abc" v2026.07.04 rc1
  _no "missing run rejected"          "$GOOD" "$SRC" 99 v2026.07.04 rc1 MOCK_NORUN=1
  _no "wrong repository rejected"     "$(_meta evil/repo "$RC_WORKFLOW_PATH" success "$REV")" "$SRC" 99 v2026.07.04 rc1
  _no "wrong workflow rejected"       "$(_meta "$REPO" .github/workflows/ci.yml success "$REV")" "$SRC" 99 v2026.07.04 rc1
  _no "failed RC run rejected"        "$(_meta "$REPO" "$RC_WORKFLOW_PATH" failure "$REV")" "$SRC" 99 v2026.07.04 rc1
  _no "run head_sha mismatch reject"  "$(_meta "$REPO" "$RC_WORKFLOW_PATH" success 0000000000000000000000000000000000000000)" "$SRC" 99 v2026.07.04 rc1
  _no "missing artifact rejected"     "$GOOD" "$SRC" 99 v2026.07.04 rc1 MOCK_NOART=1

  # incomplete artifact: signature file absent
  cp -R "$SRC" "$tmp/nosig"; rm -f "$tmp/nosig/release-manifest.yaml.sig"
  _no "incomplete artifact rejected"  "$GOOD" "$tmp/nosig" 99 v2026.07.04 rc1

  # checksum mismatch: manifest body edited after the .sha256 was written
  cp -R "$SRC" "$tmp/badsum"; printf '\n# tampered\n' >> "$tmp/badsum/release-manifest.yaml"
  _no "checksum mismatch rejected"    "$GOOD" "$tmp/badsum" 99 v2026.07.04 rc1

  # manifest describes a different release / rc / revision
  _no "manifest version mismatch"     "$GOOD" "$SRC" 99 v2026.07.05 rc1
  _no "manifest rc mismatch"          "$GOOD" "$SRC" 99 v2026.07.04 rc2
  cp -R "$SRC" "$tmp/otherrev"
  python3 - "$tmp/otherrev/release-manifest.yaml" <<'PY'
import sys, yaml
f = sys.argv[1]; m = yaml.safe_load(open(f))
r = "a" * 40
m["revision"] = r
for img in m["images"].values(): img["revision"] = r
yaml.safe_dump(m, open(f, "w"), sort_keys=True)
PY
  _sum "$tmp/otherrev"
  _no "manifest revision mismatch"    "$GOOD" "$tmp/otherrev" 99 v2026.07.04 rc1

  # malformed / incomplete image set (delegated to validate-release-manifest.sh)
  cp -R "$SRC" "$tmp/badimgs"
  python3 - "$tmp/badimgs/release-manifest.yaml" <<'PY'
import sys, yaml
f = sys.argv[1]; m = yaml.safe_load(open(f))
del m["images"]["nginx"]
yaml.safe_dump(m, open(f, "w"), sort_keys=True)
PY
  _sum "$tmp/badimgs"
  _no "missing image rejected"        "$GOOD" "$tmp/badimgs" 99 v2026.07.04 rc1

  cp -R "$SRC" "$tmp/extraimg"
  python3 - "$tmp/extraimg/release-manifest.yaml" <<'PY'
import sys, yaml
f = sys.argv[1]; m = yaml.safe_load(open(f))
m["images"]["php-cli-9.9"] = dict(m["images"]["nginx"])
yaml.safe_dump(m, open(f, "w"), sort_keys=True)
PY
  _sum "$tmp/extraimg"
  _no "extra image rejected"          "$GOOD" "$tmp/extraimg" 99 v2026.07.04 rc1

  cp -R "$SRC" "$tmp/baddig"
  python3 - "$tmp/baddig/release-manifest.yaml" <<'PY'
import sys, yaml
f = sys.argv[1]; m = yaml.safe_load(open(f))
m["images"]["caddy"]["digest"] = "sha256:xyz"
yaml.safe_dump(m, open(f, "w"), sort_keys=True)
PY
  _sum "$tmp/baddig"
  _no "malformed digest rejected"     "$GOOD" "$tmp/baddig" 99 v2026.07.04 rc1

  rm -rf "$tmp"
  return $fail
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-}" in
    --self-test) _frm_self_test && echo "fetch-rc-manifest.sh: SELF-TEST OK" ;;
    "") echo "usage: fetch-rc-manifest.sh <run-id> <version> <rc> <dest-dir> | --self-test" >&2; exit 2 ;;
    *) fetch_rc_manifest "$@" ;;
  esac
fi
