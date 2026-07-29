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
# shellcheck source=../lib/common.sh
. "${ROOT}/scripts/lib/common.sh"

# The canonical shipping matrix, derived from the SINGLE source of truth
# (MATRIX_IMAGES in scripts/lib/common.sh) and rendered as the image labels
# reconcile-vulnerabilities.sh actually emits: "family/version", or bare
# "family" for the unversioned images. Counting files was not enough — eleven
# files, or ten files that were all the same image, both passed.
canonical_images() {
  local t fam ver
  while read -r t; do
    fam="${t%:*}"; ver="${t##*:}"
    case "$ver" in prod) printf '%s\n' "$fam" ;; *) printf '%s/%s\n' "$fam" "$ver" ;; esac
  done < <(matrix_images)
}

check() {
  # ${VAR-} not ${VAR:-}: an explicitly EMPTY override must stay empty and fail
  # closed in the check below, not silently expand back to the full matrix.
  RECON_DIR="$1" LEDGER="${2:-$LEDGER_DEFAULT}" \
  CANONICAL="${CANONICAL_IMAGES-$(canonical_images | paste -sd, -)}" python3 - <<'PY'
import glob, json, os, sys

try:
    import yaml
except ImportError:
    print("FAIL: PyYAML is required", file=sys.stderr); sys.exit(1)

recon_dir = os.environ["RECON_DIR"]
ledger    = os.environ["LEDGER"]
canonical = [i for i in os.environ["CANONICAL"].split(",") if i]

if not canonical:
    print("FAIL: canonical image matrix is empty — the check would be vacuous",
          file=sys.stderr)
    sys.exit(1)

files = sorted(glob.glob(os.path.join(recon_dir, "*.json")))
if not files:
    print("FAIL: no reconciliation files under '%s' — the check would be vacuous"
          % recon_dir, file=sys.stderr)
    sys.exit(1)

# --- the matrix must be EXACTLY the shipping matrix -------------------------
# Each file must declare which image it reconciled, and the set of declared
# images must equal the canonical set. A count alone let a partial run pass by
# duplicating one image, and let an unknown image count towards coverage.
VALID_VERDICTS = {"PASS", "FAIL"}
seen = {}
for path in files:
    try:
        doc = json.load(open(path))
    except Exception as exc:
        print("FAIL: cannot read %s: %s" % (path, exc), file=sys.stderr); sys.exit(1)
    if not isinstance(doc, dict):
        print("FAIL: %s is not a JSON object" % path, file=sys.stderr); sys.exit(1)

    image = doc.get("image")
    if not isinstance(image, str) or not image:
        print("FAIL: %s declares no 'image' — it cannot be counted towards matrix "
              "coverage" % path, file=sys.stderr)
        sys.exit(1)
    if image in seen:
        print("FAIL: image '%s' reconciled twice (%s and %s) — duplicate selectors "
              "inflate coverage and hide a missing image"
              % (image, seen[image], path), file=sys.stderr)
        sys.exit(1)
    seen[image] = path

    # An unrecognised or missing verdict means the reconciliation did not
    # complete as this check understands it. Treating that as coverage would
    # let a malformed run stand in for a real one.
    verdict = doc.get("verdict")
    if verdict not in VALID_VERDICTS:
        print("FAIL: %s has verdict %r, expected one of %s"
              % (path, verdict, sorted(VALID_VERDICTS)), file=sys.stderr)
        sys.exit(1)

    for key in ("matched_exception_ids", "shadowed_exception_ids"):
        val = doc.get(key)
        if val is None:
            print("FAIL: %s has no '%s' — it predates the stable-ID scheme and "
                  "cannot be reconciled against the ledger" % (path, key),
                  file=sys.stderr)
            sys.exit(1)
        if not isinstance(val, list) or not all(isinstance(x, str) for x in val):
            print("FAIL: %s: '%s' must be a list of strings" % (path, key),
                  file=sys.stderr)
            sys.exit(1)

got, want = set(seen), set(canonical)
if got != want:
    if want - got:
        print("FAIL: reconciliation missing for %d image(s): %s"
              % (len(want - got), ", ".join(sorted(want - got))), file=sys.stderr)
    if got - want:
        print("FAIL: reconciliation present for %d image(s) not in the shipping "
              "matrix: %s" % (len(got - want), ", ".join(sorted(got - want))),
              file=sys.stderr)
    sys.exit(1)

matched, shadowed = set(), set()
for path in seen.values():
    doc = json.load(open(path))
    matched.update(doc["matched_exception_ids"])
    shadowed.update(doc["shadowed_exception_ids"])

# --- ledger ------------------------------------------------------------------
try:
    led = yaml.safe_load(open(ledger)) or {}
except Exception as exc:
    print("FAIL: cannot read ledger %s: %s" % (ledger, exc), file=sys.stderr); sys.exit(1)

entries = led.get("exceptions")
if not isinstance(entries, list):
    print("FAIL: ledger has no 'exceptions' list", file=sys.stderr); sys.exit(1)


def exc_id(e):
    """Must stay identical to exc_id() in scripts/reconcile-vulnerabilities.sh."""
    def part(v):
        if v is None:
            return "*"
        if isinstance(v, (list, tuple)):
            return ",".join(sorted(str(x) for x in v))
        return str(v)
    return "|".join(part(e.get(k)) for k in
                    ("cve", "image", "package", "installed_version"))


stale, redundant = [], []
for i, e in enumerate(entries):
    if not isinstance(e, dict):
        print("FAIL: exceptions[%d] is not a mapping" % i, file=sys.stderr); sys.exit(1)
    key = exc_id(e)
    if key in matched:
        continue
    (redundant if key in shadowed else stale).append(key)

if redundant:
    print("FAIL: %d exception(s) are redundant — another record already governs "
          "the same finding:" % len(redundant), file=sys.stderr)
    for key in sorted(redundant):
        print("  %s" % key, file=sys.stderr)
    print("  -> the finding is real, but this record never governs it. Merge it "
          "into the governing record or narrow one of the two.", file=sys.stderr)

if stale:
    print("FAIL: %d active exception(s) matched no finding in the %d-image matrix:"
          % (len(stale), len(seen)), file=sys.stderr)
    for key in sorted(stale):
        print("  %s" % key, file=sys.stderr)
    print("  -> the finding is gone: delete the record, or narrow its scope to the "
          "images where it still applies.", file=sys.stderr)

if stale or redundant:
    sys.exit(1)

print("OK: all %d exceptions matched a real finding across the full %d-image matrix"
      % (len(entries), len(seen)))
PY
}

self_test() {
  local tmp ok=0 bad=0
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '${tmp}'" RETURN
  t() { if eval "$2"; then ok=$((ok+1)); echo "  ok   $1"; else bad=$((bad+1)); echo "  FAIL $1"; fi; }

  # Two records that BOTH name CVE-2099-3 on nginx and differ only by package —
  # the pair the old "cve@image" key collapsed into one.
  cat > "$tmp/led.yaml" <<'YAML'
schema_version: 1
exceptions:
  - {cve: CVE-2099-1, image: caddy,  package: libfoo, installed_version: "1.0"}
  - {cve: CVE-2099-2, image: nginx,  package: libbar, installed_version: "2.0"}
  - {cve: CVE-2099-3, image: nginx,  package: libbaz, installed_version: "3.0"}
  - {cve: CVE-2099-3, image: nginx,  package: libqux, installed_version: "3.0"}
YAML
  local ID1='CVE-2099-1|caddy|libfoo|1.0'
  local ID2='CVE-2099-2|nginx|libbar|2.0'
  local ID3='CVE-2099-3|nginx|libbaz|3.0'
  local ID4='CVE-2099-3|nginx|libqux|3.0'
  local CANON; CANON="$(canonical_images | paste -sd, -)"

  # mkmatrix <dir> <matched-json> [shadowed-json] — one file per canonical image
  mkmatrix() {
    local dir="$1" m="$2" sh="${3:-[]}" img n=0
    mkdir -p "$dir"
    while read -r img; do
      n=$((n+1))
      printf '{"image":"%s","verdict":"PASS","matched_exception_ids":%s,"shadowed_exception_ids":%s}\n' \
        "$img" "$m" "$sh" > "$dir/img$n.json"
    done < <(canonical_images)
  }

  local ALL="[\"$ID1\",\"$ID2\",\"$ID3\",\"$ID4\"]"

  mkmatrix "$tmp/full" "$ALL"
  t "every exception matched -> pass" \
    "CANONICAL_IMAGES='$CANON' check '$tmp/full' '$tmp/led.yaml' >/dev/null"

  mkmatrix "$tmp/stale" "[\"$ID1\",\"$ID2\",\"$ID3\"]"
  t "an unmatched exception is stale" \
    "! CANONICAL_IMAGES='$CANON' check '$tmp/stale' '$tmp/led.yaml' >/dev/null 2>&1"
  t "...and the stale record is named by its full ID" \
    "out=\"\$(CANONICAL_IMAGES='$CANON' check '$tmp/stale' '$tmp/led.yaml' 2>&1 || true)\"; grep -q '$ID4' <<<\"\$out\""
  t "...and the same-CVE sibling is NOT reported stale" \
    "out=\"\$(CANONICAL_IMAGES='$CANON' check '$tmp/stale' '$tmp/led.yaml' 2>&1 || true)\"; ! grep -q '$ID3' <<<\"\$out\""

  # REGRESSION for the old key: under "cve@image" both CVE-2099-3 records
  # collapsed to "CVE-2099-3@nginx", so matching either marked both live.
  t "a same-cve same-image pair is tracked separately" \
    "out=\"\$(CANONICAL_IMAGES='$CANON' check '$tmp/stale' '$tmp/led.yaml' 2>&1 || true)\"; grep -q '1 active exception' <<<\"\$out\""

  mkmatrix "$tmp/shadow" "[\"$ID1\",\"$ID2\",\"$ID3\"]" "[\"$ID4\"]"
  t "a shadowed record is reported redundant, not stale" \
    "out=\"\$(CANONICAL_IMAGES='$CANON' check '$tmp/shadow' '$tmp/led.yaml' 2>&1 || true)\"; grep -q 'redundant' <<<\"\$out\" && ! grep -q 'matched no finding' <<<\"\$out\""
  t "a redundant record still fails the check" \
    "! CANONICAL_IMAGES='$CANON' check '$tmp/shadow' '$tmp/led.yaml' >/dev/null 2>&1"

  # --- matrix coverage ------------------------------------------------------
  mkmatrix "$tmp/partial" "$ALL"; rm -f "$tmp/partial/img1.json"
  t "a missing image fails closed" \
    "! CANONICAL_IMAGES='$CANON' check '$tmp/partial' '$tmp/led.yaml' >/dev/null 2>&1"
  t "...and the missing image is named" \
    "out=\"\$(CANONICAL_IMAGES='$CANON' check '$tmp/partial' '$tmp/led.yaml' 2>&1 || true)\"; grep -q 'missing for 1 image' <<<\"\$out\""

  # THE gap a count-only check could not see: right number of files, but one
  # image reconciled twice and another not at all.
  mkmatrix "$tmp/dup" "$ALL"
  python3 - "$tmp/dup" <<'PYD'
import json, sys, pathlib
d = pathlib.Path(sys.argv[1])
f = sorted(d.glob("*.json"))
doc = json.load(open(f[1])); doc["image"] = json.load(open(f[0]))["image"]
json.dump(doc, open(f[1], "w"))
PYD
  t "the right file COUNT with a duplicate image fails" \
    "! CANONICAL_IMAGES='$CANON' check '$tmp/dup' '$tmp/led.yaml' >/dev/null 2>&1"
  t "...and it is reported as a duplicate, not as missing" \
    "out=\"\$(CANONICAL_IMAGES='$CANON' check '$tmp/dup' '$tmp/led.yaml' 2>&1 || true)\"; grep -q 'reconciled twice' <<<\"\$out\""

  mkmatrix "$tmp/extra" "$ALL"
  printf '{"image":"not-a-shipping-image","verdict":"PASS","matched_exception_ids":[],"shadowed_exception_ids":[]}' \
    > "$tmp/extra/extra.json"
  t "an image outside the shipping matrix fails" \
    "! CANONICAL_IMAGES='$CANON' check '$tmp/extra' '$tmp/led.yaml' >/dev/null 2>&1"

  mkmatrix "$tmp/noimage" "$ALL"
  printf '{"verdict":"PASS","matched_exception_ids":[],"shadowed_exception_ids":[]}' \
    > "$tmp/noimage/img1.json"
  t "a file with no image selector fails closed" \
    "! CANONICAL_IMAGES='$CANON' check '$tmp/noimage' '$tmp/led.yaml' >/dev/null 2>&1"

  # --- verdict --------------------------------------------------------------
  mkmatrix "$tmp/noverdict" "$ALL"
  printf '{"image":"caddy","matched_exception_ids":[],"shadowed_exception_ids":[]}' \
    > "$tmp/noverdict/img1.json"
  t "a missing verdict fails closed" \
    "! CANONICAL_IMAGES='$CANON' check '$tmp/noverdict' '$tmp/led.yaml' >/dev/null 2>&1"

  mkmatrix "$tmp/badverdict" "$ALL"
  printf '{"image":"caddy","verdict":"UNKNOWN","matched_exception_ids":[],"shadowed_exception_ids":[]}' \
    > "$tmp/badverdict/img1.json"
  t "an unknown verdict fails closed" \
    "! CANONICAL_IMAGES='$CANON' check '$tmp/badverdict' '$tmp/led.yaml' >/dev/null 2>&1"

  # --- malformed input ------------------------------------------------------
  mkdir -p "$tmp/empty"
  t "no reconciliation files fails closed" \
    "! CANONICAL_IMAGES='$CANON' check '$tmp/empty' '$tmp/led.yaml' >/dev/null 2>&1"

  mkmatrix "$tmp/broken" "$ALL"; printf 'not json' > "$tmp/broken/img1.json"
  t "unreadable reconciliation fails closed" \
    "! CANONICAL_IMAGES='$CANON' check '$tmp/broken' '$tmp/led.yaml' >/dev/null 2>&1"

  mkmatrix "$tmp/oldschema" "$ALL"
  printf '{"image":"caddy","verdict":"PASS","matched_exceptions":["CVE-2099-1@caddy"]}' \
    > "$tmp/oldschema/img1.json"
  t "a pre-stable-ID reconciliation fails closed" \
    "! CANONICAL_IMAGES='$CANON' check '$tmp/oldschema' '$tmp/led.yaml' >/dev/null 2>&1"

  t "an empty canonical matrix fails closed" \
    "! CANONICAL_IMAGES='' check '$tmp/full' '$tmp/led.yaml' >/dev/null 2>&1"

  t "the canonical matrix really is the 10 shipping images" \
    "[ \"\$(canonical_images | grep -c .)\" = 10 ] && canonical_images | grep -qx nginx && canonical_images | grep -qx php-cli/8.3"

  echo "self-test: $ok ok, $bad failed"
  [ "$bad" -eq 0 ]
}

case "${1:-}" in
  --self-test) self_test ;;
  "")          echo "usage: $(basename "$0") <reconciliation-dir> [<ledger>]" >&2; exit 1 ;;
  *)           check "$@" ;;
esac
