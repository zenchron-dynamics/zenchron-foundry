#!/usr/bin/env bash
# =============================================================================
# scripts/verify-promotion-state.sh <rc-manifest.yaml> <version>
# -----------------------------------------------------------------------------
# Phase 3 of promotion. For every stable alias, asserts it resolves to the exact
# RC digest from the signed manifest; when cosign is present (and not LOCAL),
# also runs the full identity verification per alias. Emits a schema-valid
# promotion manifest (aliases[] ref/digest/verified) to stdout. Nonzero if any
# alias fails. Every failure path inside the loop is explicitly guarded, and
# the python emit's exit status is checked so a failed emit can never leave
# empty stdout for promote-stable.sh to capture as the promotion manifest.
# =============================================================================
set -euo pipefail
_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/registry-aliases.sh
. "$_d/lib/registry-aliases.sh"
# shellcheck source=lib/registry-ops.sh
. "$_d/lib/registry-ops.sh"
# shellcheck source=lib/release-manifest.sh
. "$_d/lib/release-manifest.sh"

verify_promotion_state() {
  local MANIFEST="${1:?usage: verify-promotion-state.sh <rc-manifest> <version>}"
  local VERSION="${2:?usage: verify-promotion-state.sh <rc-manifest> <version>}"
  local REL="${VERSION#v}"
  local RC REV
  RC="$(manifest_field "$MANIFEST" '.candidate')"
  REV="$(manifest_field "$MANIFEST" '.revision')"

  local ROWS bad=0 t fam sel key rcdig suf ref got verified
  ROWS="$(mktemp)"
  for t in $MATRIX_IMAGES; do
    fam="${t%:*}"; sel="${t#*:}"; key="$(manifest_key "$fam" "$sel")"
    rcdig="$(manifest_image_field "$MANIFEST" "$key" digest)"
    # SC-24: bash-layer digest anchoring, independent of any schema validation.
    is_digest "$rcdig" || { rm -f "$ROWS"; die "bash-layer digest anchor: manifest digest for $key is not sha256:<64-hex>: '$rcdig'"; }
    for suf in $(stable_aliases "$sel" "$REL"); do
      ref="$(full_ref "$fam" "$suf")"
      got="$(reg_digest "$ref" 2>/dev/null || echo '')"
      verified=true
      if [ "$got" != "$rcdig" ]; then verified=false; bad=$((bad+1)); warn "MISMATCH $ref: $got != $rcdig"; fi
      if [ "$verified" = true ] && [ "${LOCAL:-0}" != 1 ] && command -v cosign >/dev/null 2>&1; then
        EXPECTED_REVISION="$REV" EXPECTED_ROLE=rc-publisher \
        EXPECTED_REPO="${EXPECTED_REPO:-${GITHUB_REPOSITORY:-zenchron-dynamics/zenchron-foundry}}" \
          bash "$_d/verify-image-release-identity.sh" "$NS/$fam@$got" >/dev/null 2>&1 \
          || { verified=false; bad=$((bad+1)); warn "IDENTITY FAIL $ref"; }
      fi
      printf '%s\t%s\t%s\n' "$ref" "${got:-UNRESOLVED}" "$verified" >> "$ROWS"
    done
  done

  # Emit the promotion manifest; a failed emit MUST fail this script loudly —
  # promote-stable.sh captures our stdout as the promotion manifest, and an
  # unguarded emit failure would hand it an empty file.
  if ! REL="$REL" VERSION="$VERSION" RC="$RC" REV="$REV" ROWS="$ROWS" python3 - <<'PY'
import os, yaml
rows=[l.rstrip("\n").split("\t") for l in open(os.environ["ROWS"]) if l.strip()]
m={"schema_version":1,"release":os.environ["VERSION"],"candidate":os.environ["RC"],
   "revision":os.environ["REV"],"created_at":__import__("datetime").datetime.now(__import__("datetime").timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
   "aliases":[{"ref":r,"digest":d,"verified":(v=="true")} for r,d,v in rows]}
import sys; yaml.safe_dump(m, sys.stdout, sort_keys=True)
PY
  then
    rm -f "$ROWS"; die "promotion manifest emit failed"
  fi
  rm -f "$ROWS"
  [ "$bad" -eq 0 ] || { warn "promotion verification failed ($bad aliases)"; return 1; }
}

# --- self-test (mock registry backend, offline) ------------------------------
_vps_self_test() {
  command -v yq >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1 \
    || { echo "SKIP - yq/python3 absent"; return 0; }
  python3 -c 'import yaml' 2>/dev/null || { echo "SKIP - pyyaml absent"; return 0; }
  local fail=0 tmp; tmp="$(mktemp -d)"; mkdir -p "$tmp/mock"
  local R=7b4985a1234567890abcdef1234567890abcdef1

  # Fixture manifest: per-image digests derived from an independent seed.
  # SC-20: the fixture's image list INTENTIONALLY duplicates MATRIX_IMAGES —
  # an independent copy is a drift tripwire for the authoritative matrix
  # (owner-accepted duplication; do not centralize).
  R="$R" OUT="$tmp/rc.yaml" python3 - <<'PY'
import os, yaml, hashlib
R = os.environ["R"]
keys = [f"php-{f}-{v}" for f in ("cli","fpm","worker","frankenphp") for v in ("8.3","8.4","8.5")] + ["nginx","caddy"]
def repo(k): return "ghcr.io/zenchron-dynamics/%s" % (k.rsplit("-",1)[0] if k.startswith("php-") else k)
def dig(k): return "sha256:" + hashlib.sha256(("vps:"+k).encode()).hexdigest()
imgs = {k: {"repository": repo(k), "immutable_tag": "t-"+k, "digest": dig(k),
            "reference": repo(k)+"@"+dig(k), "revision": R,
            "platforms": ["linux/amd64","linux/arm64"]} for k in keys}
m = {"schema_version":1, "release":"v2026.07.03", "candidate":"rc1", "revision":R,
     "source_repository":"zenchron-dynamics/zenchron-foundry", "source_ref":"refs/heads/master",
     "workflow_run_id":"1", "created_at":"2026-07-03T12:00:00Z", "images":imgs}
yaml.safe_dump(m, open(os.environ["OUT"],"w"), sort_keys=True)
PY
  _dig() { python3 -c "import hashlib,sys;print('sha256:'+hashlib.sha256(('vps:'+sys.argv[1]).encode()).hexdigest())" "$1"; }

  # Seed every stable alias with its exact RC digest.
  local t fam sel suf ref
  ( export REG_BACKEND=mock REG_MOCK_DIR="$tmp/mock"
    for t in $MATRIX_IMAGES; do
      fam="${t%:*}"; sel="${t#*:}"
      for suf in $(stable_aliases "$sel" 2026.07.03); do
        reg_retag "$(full_ref "$fam" "$suf")" "$(_dig "$(manifest_key "$fam" "$sel")")"
      done
    done )

  local out rc
  out="$( ( REG_BACKEND=mock REG_MOCK_DIR="$tmp/mock" LOCAL=1 \
            bash "${BASH_SOURCE[0]}" "$tmp/rc.yaml" v2026.07.03 ) 2>/dev/null )"; rc=$?
  if [ "$rc" -eq 0 ]; then echo "ok   - all-match passes"; else echo "FAIL - all-match passes (rc=$rc)"; fail=1; fi
  printf '%s' "$out" > "$tmp/promo.yaml"
  if yq -e '.aliases | length > 0' "$tmp/promo.yaml" >/dev/null 2>&1 \
     && [ "$(yq -r '[.aliases[].verified] | all' "$tmp/promo.yaml")" = "true" ]; then
    echo "ok   - promotion manifest emitted, every alias verified"
  else
    echo "FAIL - promotion manifest emitted, every alias verified"; fail=1
  fi

  # one alias drifts -> nonzero
  ( export REG_BACKEND=mock REG_MOCK_DIR="$tmp/mock"
    reg_retag "$(full_ref caddy prod)" "sha256:$(printf 'x%.0s' {1..64} | tr x 0)" )
  if ( REG_BACKEND=mock REG_MOCK_DIR="$tmp/mock" LOCAL=1 \
       bash "${BASH_SOURCE[0]}" "$tmp/rc.yaml" v2026.07.03 ) >/dev/null 2>&1; then
    echo "FAIL - one mismatch must be nonzero"; fail=1
  else
    echo "ok   - one mismatch is nonzero"
  fi
  ( export REG_BACKEND=mock REG_MOCK_DIR="$tmp/mock"
    reg_retag "$(full_ref caddy prod)" "$(_dig caddy)" )   # restore

  # unanchored manifest digest -> rejected by the bash layer
  cp "$tmp/rc.yaml" "$tmp/bad.yaml"
  python3 - "$tmp/bad.yaml" <<'PY'
import sys, yaml
f = sys.argv[1]; m = yaml.safe_load(open(f))
m["images"]["caddy"]["digest"] = "sha256:xyz"
yaml.safe_dump(m, open(f, "w"), sort_keys=True)
PY
  out="$( ( REG_BACKEND=mock REG_MOCK_DIR="$tmp/mock" LOCAL=1 \
            bash "${BASH_SOURCE[0]}" "$tmp/bad.yaml" v2026.07.03 ) 2>&1 >/dev/null )"; rc=$?
  if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q "bash-layer digest anchor"; then
    echo "ok   - sha256:xyz rejected by the bash layer"
  else
    echo "FAIL - sha256:xyz rejected by the bash layer (rc=$rc: $out)"; fail=1
  fi

  # python emit failure -> nonzero, stdout must not look like a manifest
  local stub="$tmp/bin"; mkdir -p "$stub"
  printf '#!/usr/bin/env bash\nexit 1\n' > "$stub/python3"; chmod +x "$stub/python3"
  out="$( ( PATH="$stub:$PATH" REG_BACKEND=mock REG_MOCK_DIR="$tmp/mock" LOCAL=1 \
            bash "${BASH_SOURCE[0]}" "$tmp/rc.yaml" v2026.07.03 ) 2>/dev/null )"; rc=$?
  if [ "$rc" -ne 0 ] && ! printf '%s' "$out" | grep -q "aliases:"; then
    echo "ok   - python emit failure is nonzero (no manifest on stdout)"
  else
    echo "FAIL - python emit failure is nonzero (rc=$rc)"; fail=1
  fi

  rm -rf "$tmp"; return $fail
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-}" in
    --self-test) _vps_self_test && echo "verify-promotion-state.sh: SELF-TEST OK" ;;
    "") echo "usage: verify-promotion-state.sh <rc-manifest> <version> | --self-test" >&2; exit 2 ;;
    *) verify_promotion_state "$@" ;;
  esac
fi
