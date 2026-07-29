#!/usr/bin/env bash
# =============================================================================
# scripts/ci/assert-no-stale-exceptions.sh
# -----------------------------------------------------------------------------
# Fail when an ACTIVE exception matched no finding anywhere in the shipping
# image matrix (#102/#103).
#
# scripts/reconcile-vulnerabilities.sh emits `matched_exceptions` per image and
# its header claimed "the aggregate stale check across the whole matrix consumes
# this". Review found no such consumer existed — the claim was documentation
# without an implementation. This is it.
#
# Why it matters: an exception whose finding has disappeared (package removed,
# base rebuilt, advisory withdrawn) keeps sitting in the ledger with an owner, an
# approver and an expiry, describing a risk that is no longer being taken. It
# then quietly re-suppresses the advisory if it ever comes back, and it inflates
# the accepted-risk count that release evidence reports to auditors.
#
# A stale record is a documentation defect, not an exposure, so this runs as a
# matrix-wide aggregate rather than blocking any single image build.
#
# Usage:
#   assert-no-stale-exceptions.sh <reconciliation-dir> [<ledger>]
#   assert-no-stale-exceptions.sh --self-test
#
# The directory must contain one reconciliation JSON per shipping image. A short
# count is a FAILURE: a partial matrix would report exceptions as stale purely
# because the image that uses them was not scanned.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LEDGER_DEFAULT="${ROOT}/policies/vulnerability-exceptions.yaml"
# The full shipping matrix. Derived from MATRIX_IMAGES in scripts/lib/common.sh
# (10 images) — kept explicit so a short run cannot look complete.
EXPECTED_IMAGES="${EXPECTED_IMAGES:-10}"

check() {
  RECON_DIR="$1" LEDGER="${2:-$LEDGER_DEFAULT}" EXPECTED="$EXPECTED_IMAGES" python3 - <<'PY'
import glob, json, os, sys

try:
    import yaml
except ImportError:
    print("FAIL: PyYAML is required", file=sys.stderr); sys.exit(1)

recon_dir = os.environ["RECON_DIR"]
ledger    = os.environ["LEDGER"]
expected  = int(os.environ["EXPECTED"])

files = sorted(glob.glob(os.path.join(recon_dir, "*.json")))
if not files:
    print("FAIL: no reconciliation files under '%s' — the check would be vacuous"
          % recon_dir, file=sys.stderr)
    sys.exit(1)
if len(files) < expected:
    print("FAIL: %d reconciliation file(s) but the matrix has %d images. A partial "
          "matrix would report live exceptions as stale." % (len(files), expected),
          file=sys.stderr)
    sys.exit(1)

matched = set()
for path in files:
    try:
        doc = json.load(open(path))
    except Exception as exc:
        print("FAIL: cannot read %s: %s" % (path, exc), file=sys.stderr); sys.exit(1)
    for key in doc.get("matched_exceptions") or []:
        matched.add(key)

try:
    led = yaml.safe_load(open(ledger)) or {}
except Exception as exc:
    print("FAIL: cannot read ledger %s: %s" % (ledger, exc), file=sys.stderr); sys.exit(1)

entries = led.get("exceptions")
if not isinstance(entries, list):
    print("FAIL: ledger has no 'exceptions' list", file=sys.stderr); sys.exit(1)

stale = []
for e in entries:
    key = "%s@%s" % (e.get("cve"), e.get("image"))
    if key not in matched:
        stale.append(key)

if stale:
    print("FAIL: %d active exception(s) matched no finding in the %d-image matrix:"
          % (len(stale), len(files)), file=sys.stderr)
    for key in sorted(stale):
        print("  %s" % key, file=sys.stderr)
    print("  -> the finding is gone: delete the record, or narrow its scope to the "
          "images where it still applies.", file=sys.stderr)
    sys.exit(1)

print("OK: all %d exceptions matched a real finding across %d images"
      % (len(entries), len(files)))
PY
}

self_test() {
  local tmp ok=0 bad=0
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '${tmp}'" RETURN
  t() { if eval "$2"; then ok=$((ok+1)); echo "  ok   $1"; else bad=$((bad+1)); echo "  FAIL $1"; fi; }

  cat > "$tmp/led.yaml" <<'YAML'
schema_version: 1
exceptions:
  - {cve: CVE-2099-1, image: caddy}
  - {cve: CVE-2099-2, image: nginx}
YAML
  mkrecon() { # mkrecon <dir> <n-files> <matched-json-array>
    mkdir -p "$1"; local i
    for i in $(seq 1 "$2"); do printf '{"matched_exceptions": %s}\n' "$3" > "$1/img$i.json"; done
  }

  mkrecon "$tmp/full" 10 '["CVE-2099-1@caddy","CVE-2099-2@nginx"]'
  t "every exception matched -> pass"        "EXPECTED_IMAGES=10 check '$tmp/full' '$tmp/led.yaml' >/dev/null"

  mkrecon "$tmp/stale" 10 '["CVE-2099-1@caddy"]'
  t "an unmatched exception is stale"        "! EXPECTED_IMAGES=10 check '$tmp/stale' '$tmp/led.yaml' >/dev/null 2>&1"
  t "…and it is named in the output" \
    "out=\"\$(EXPECTED_IMAGES=10 check '$tmp/stale' '$tmp/led.yaml' 2>&1 || true)\"; grep -q 'CVE-2099-2@nginx' <<<\"\$out\""

  mkrecon "$tmp/partial" 3 '["CVE-2099-1@caddy","CVE-2099-2@nginx"]'
  t "a partial matrix fails closed"          "! EXPECTED_IMAGES=10 check '$tmp/partial' '$tmp/led.yaml' >/dev/null 2>&1"

  mkdir -p "$tmp/empty"
  t "no reconciliation files fails closed"   "! EXPECTED_IMAGES=10 check '$tmp/empty' '$tmp/led.yaml' >/dev/null 2>&1"

  mkdir -p "$tmp/broken"; printf 'not json' > "$tmp/broken/a.json"
  for i in $(seq 2 10); do printf '{"matched_exceptions": []}' > "$tmp/broken/img$i.json"; done
  t "unreadable reconciliation fails closed" "! EXPECTED_IMAGES=10 check '$tmp/broken' '$tmp/led.yaml' >/dev/null 2>&1"

  echo "self-test: $ok ok, $bad failed"
  [ "$bad" -eq 0 ]
}

case "${1:-}" in
  --self-test) self_test ;;
  "")          echo "usage: $(basename "$0") <reconciliation-dir> [<ledger>]" >&2; exit 1 ;;
  *)           check "$@" ;;
esac
