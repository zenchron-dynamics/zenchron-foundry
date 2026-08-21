#!/usr/bin/env bash
# =============================================================================
# scripts/validate-release-manifest.sh <manifest.yaml>
# -----------------------------------------------------------------------------
# Strict RC-manifest validator. Uses a REAL parser (PyYAML) + JSON Schema
# (jsonschema), never grep/sed. Enforces, beyond the schema:
#   * exactly the 10 canonical matrix image keys — no missing, no extra, no dup
#   * every image.revision == the top-level revision (no mixed revisions)
#   * every image.reference == <repository>@<digest> (digest-pinned, consistent)
#   * source_repository is the expected repo
#
# Runs offline. --self-test exercises the good manifest and every reject case.
# =============================================================================
set -euo pipefail
_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/release-manifest.sh
. "$_d/lib/release-manifest.sh"
SCHEMA="$_d/../schemas/release-manifest.schema.json"

# Expected image keys, derived from the ONE matrix source of truth via the
# shared manifest_key rule (SC-18).
expected_keys() {
  for t in $MATRIX_IMAGES; do
    manifest_key "${t%:*}" "${t#*:}"; printf '\n'
  done | sort
}

validate_manifest() {
  local file="$1" exprepo="${2:-zenchron-dynamics/zenchron-foundry}"
  [ -f "$file" ] || die "manifest not found: $file"
  # Bash-layer digest anchoring (SC-24): every digest is re-checked against
  # DIGEST_RE from common.sh, INDEPENDENT of the JSON schema — defense in depth
  # so a schema regression can never admit an unanchored digest.
  command -v yq >/dev/null 2>&1 || die "yq required for bash-layer digest anchoring"
  local dg
  while IFS= read -r dg; do
    [ -n "$dg" ] || continue
    is_digest "$dg" || die "bash-layer digest anchor: '$dg' does not match sha256:<64-hex>"
  done < <(yq -r '(.images // {})[] | .digest // ""' "$file")
  local keys; keys="$(expected_keys | tr '\n' ',' )"
  EXPECTED_KEYS="$keys" EXPECTED_REPO="$exprepo" SCHEMA="$SCHEMA" MANIFEST="$file" python3 - <<'PY'
import os, sys, json, yaml
from jsonschema import Draft202012Validator

manifest = yaml.safe_load(open(os.environ["MANIFEST"]))
schema = json.load(open(os.environ["SCHEMA"]))
errs = []

v = Draft202012Validator(schema)
for e in sorted(v.iter_errors(manifest), key=lambda e: list(e.path)):
    errs.append("schema: %s at %s" % (e.message, "/".join(map(str, e.path)) or "<root>"))

if not errs:  # structural policy only meaningful once the shape is valid
    exp = set(k for k in os.environ["EXPECTED_KEYS"].split(",") if k)
    got = set((manifest.get("images") or {}).keys())
    for miss in sorted(exp - got): errs.append("missing image: %s" % miss)
    for extra in sorted(got - exp): errs.append("unexpected image: %s" % extra)
    rev = manifest.get("revision")
    repo = manifest.get("source_repository")
    if repo != os.environ["EXPECTED_REPO"]:
        errs.append("source_repository '%s' != expected '%s'" % (repo, os.environ["EXPECTED_REPO"]))
    for k, img in (manifest.get("images") or {}).items():
        if img.get("revision") != rev:
            errs.append("%s: revision %s != manifest revision %s" % (k, img.get("revision"), rev))
        ref, dig, r = img.get("reference",""), img.get("digest",""), img.get("repository","")
        if ref != "%s@%s" % (r, dig):
            errs.append("%s: reference '%s' != '%s@%s'" % (k, ref, r, dig))

if errs:
    print("MANIFEST INVALID (%d):" % len(errs), file=sys.stderr)
    for e in errs: print("  - " + e, file=sys.stderr)
    sys.exit(1)
print("MANIFEST VALID: %s" % os.environ["MANIFEST"])
PY
}

# --- self-test ---------------------------------------------------------------
_vrm_self_test() {
  command -v python3 >/dev/null || { echo "SKIP - python3 absent"; return 0; }
  python3 -c 'import yaml, jsonschema' 2>/dev/null || { echo "SKIP - pyyaml/jsonschema absent"; return 0; }
  local fail=0 tmp; tmp="$(mktemp -d)"
  local R=7b4985a1234567890abcdef1234567890abcdef1
  local D=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  # Build a GOOD manifest with all 10 keys via python (deterministic).
  # SC-20: this fixture's image list INTENTIONALLY duplicates MATRIX_IMAGES
  # instead of deriving from it — an independent copy makes the self-test a
  # drift tripwire for accidental edits to the authoritative matrix
  # (owner-accepted duplication; do not centralize).
  R="$R" D="$D" OUT="$tmp/good.yaml" python3 - <<'PY'
import os, yaml
R, D = os.environ["R"], os.environ["D"]
keys = [f"php-{f}-{v}" for f in ("cli","fpm","worker","frankenphp") for v in ("8.3","8.4","8.5")] + ["nginx","caddy"]
def repo(k):
    fam = k.rsplit("-",1)[0] if k.startswith("php-") else k
    return "ghcr.io/zenchron-dynamics/%s" % fam
imgs = {}
for k in keys:
    r = repo(k)
    imgs[k] = {"repository": r, "immutable_tag": "t-"+k, "digest": D,
               "reference": r+"@"+D, "revision": R,
               "platforms": ["linux/amd64","linux/arm64"]}
m = {"schema_version":1, "release":"v2026.07.03","candidate":"rc1","revision":R,
     "source_repository":"zenchron-dynamics/zenchron-foundry","source_ref":"refs/heads/master",
     "workflow_run_id":"123","created_at":"2026-07-03T12:00:00Z","images":imgs}
yaml.safe_dump(m, open(os.environ["OUT"],"w"), sort_keys=True)
PY
  # subshell: the bash-layer digest anchor die()s; contain the exit per case
  _ok() { if ( validate_manifest "$1" ) >/dev/null 2>&1; then echo "ok   - $2"; else echo "FAIL - $2 (expected valid)"; fail=1; fi; }
  _no() { if ( validate_manifest "$1" ) >/dev/null 2>&1; then echo "FAIL - $2 (expected reject)"; fail=1; else echo "ok   - $2"; fi; }
  _mut() { python3 - "$1" "$2" <<'PY'    # apply a python expr `m` mutation
import sys, yaml
f, expr = sys.argv[1], sys.argv[2]
m = yaml.safe_load(open(f)); exec(expr); yaml.safe_dump(m, open(f,"w"))
PY
  }
  _ok "$tmp/good.yaml" "good manifest valid"
  cp "$tmp/good.yaml" "$tmp/miss.yaml";   _mut "$tmp/miss.yaml" 'del m["images"]["nginx"]';                     _no "$tmp/miss.yaml"  "missing image"
  cp "$tmp/good.yaml" "$tmp/extra.yaml";  _mut "$tmp/extra.yaml" 'm["images"]["php-cli-9.9"]=dict(m["images"]["nginx"])'; _no "$tmp/extra.yaml" "extra image"
  cp "$tmp/good.yaml" "$tmp/dig.yaml";    _mut "$tmp/dig.yaml" 'm["images"]["caddy"]["digest"]="sha256:xyz"';   _no "$tmp/dig.yaml"   "malformed digest"
  cp "$tmp/good.yaml" "$tmp/abbr.yaml";   _mut "$tmp/abbr.yaml" 'm["revision"]="7b4985a"';                       _no "$tmp/abbr.yaml"  "abbreviated revision"
  cp "$tmp/good.yaml" "$tmp/mix.yaml";    _mut "$tmp/mix.yaml" 'm["images"]["nginx"]["revision"]="0"*40';       _no "$tmp/mix.yaml"   "mixed revision"
  cp "$tmp/good.yaml" "$tmp/repo.yaml";   _mut "$tmp/repo.yaml" 'm["source_repository"]="evil/repo"';            _no "$tmp/repo.yaml"  "wrong source_repository"
  cp "$tmp/good.yaml" "$tmp/sv.yaml";     _mut "$tmp/sv.yaml" 'm["schema_version"]=2';                           _no "$tmp/sv.yaml"    "unsupported schema_version"
  cp "$tmp/good.yaml" "$tmp/ref.yaml";    _mut "$tmp/ref.yaml" 'm["images"]["caddy"]["reference"]="ghcr.io/x/caddy@"+"sha256:"+"b"*64'; _no "$tmp/ref.yaml" "reference/digest mismatch"
  # SC-24: the malformed digest must be rejected by the BASH layer (is_digest),
  # before the python/schema stage even runs — assert the error message source.
  local err
  err="$( ( validate_manifest "$tmp/dig.yaml" ) 2>&1 >/dev/null || true )"
  if printf '%s' "$err" | grep -q "bash-layer digest anchor"; then
    echo "ok   - malformed digest rejected by the bash layer (schema bypassed)"
  else
    echo "FAIL - malformed digest not caught by the bash layer: $err"; fail=1
  fi
  rm -rf "$tmp"
  return $fail
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-}" in
    --self-test) _vrm_self_test && echo "validate-release-manifest.sh: SELF-TEST OK" ;;
    "") echo "usage: validate-release-manifest.sh <manifest.yaml> | --self-test" >&2; exit 2 ;;
    *) validate_manifest "$@" ;;
  esac
fi
