#!/usr/bin/env bash
# =============================================================================
# scripts/license/license-inventory.sh — normalise licence facts out of SBOMs.
# -----------------------------------------------------------------------------
# Reads every SPDX-JSON and CycloneDX-JSON SBOM in a directory (the shape
# scripts/generate-sbom.sh writes) and produces ONE normalised inventory.
#
# It deliberately does not decide anything. It records, per component:
#   * every licence identifier any SBOM asserted, and WHICH field asserted it
#   * whether the component's licence is UNKNOWN (absent, NOASSERTION, NONE)
#   * whether the SBOMs CONFLICT — two sources asserting different licences for
#     the same component version
#
# Why the provenance of each assertion is kept: SPDX carries both
# `licenseDeclared` (what the package says about itself) and `licenseConcluded`
# (what the scanner decided). When those disagree, the disagreement IS the
# finding, and an inventory that flattened them to one string would erase it.
#
# Usage:
#   scripts/license/license-inventory.sh --sbom-dir DIR [--out FILE]
#   scripts/license/license-inventory.sh --self-test
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

usage() {
  sed -n '17,20p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 64
}

# -----------------------------------------------------------------------------
# build <sbom_dir> <out_or_dash>
# -----------------------------------------------------------------------------
build() {
  SBOM_DIR="$1" OUT="$2" python3 <<'PY'
import json, os, sys, glob, hashlib

sbom_dir = os.environ["SBOM_DIR"]
out      = os.environ["OUT"]

if not os.path.isdir(sbom_dir):
    sys.stderr.write("REFUSE: sbom directory %r does not exist\n" % sbom_dir)
    raise SystemExit(1)

# NOASSERTION/NONE are SPDX's way of saying "nobody established this". They are
# not licences and must never normalise onto one.
UNKNOWN_TOKENS = {"", "noassertion", "none", "unknown", "null"}


def norm(v):
    """Normalise one raw licence assertion to a list of identifiers."""
    if v is None:
        return []
    s = str(v).strip()
    if s.lower() in UNKNOWN_TOKENS:
        return []
    # An SPDX expression is kept whole when it is a real choice/conjunction:
    # splitting "MIT OR Apache-2.0" into two components would misrepresent it as
    # dual obligations when it is a choice, so the expression is the identifier.
    return [s]


records = {}   # (name, version) -> record


def add(name, version, ident, source_file, fmt, field, raw):
    key = (name or "", version or "")
    r = records.setdefault(key, {
        "name": key[0], "version": key[1],
        "licenses": [], "sources": [], "purls": [],
    })
    r["sources"].append({
        "file": os.path.basename(source_file), "format": fmt,
        "field": field, "value": raw if raw is not None else "",
        "normalised": ident,
    })
    for i in ident:
        if i not in r["licenses"]:
            r["licenses"].append(i)


files = sorted(glob.glob(os.path.join(sbom_dir, "*.json")))
parsed = []
for f in files:
    try:
        with open(f) as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as e:
        sys.stderr.write("REFUSE: %s is not readable JSON: %s\n" % (f, e))
        raise SystemExit(1)

    # --- SPDX ---------------------------------------------------------------
    if "spdxVersion" in doc or "SPDXID" in doc:
        parsed.append((f, "spdx"))
        for p in doc.get("packages") or []:
            nm, ver = p.get("name"), p.get("versionInfo")
            for field in ("licenseConcluded", "licenseDeclared"):
                raw = p.get(field)
                add(nm, ver, norm(raw), f, "spdx", field, raw)
            for ref in p.get("externalRefs") or []:
                if ref.get("referenceType") == "purl":
                    key = (nm or "", ver or "")
                    if ref["referenceLocator"] not in records[key]["purls"]:
                        records[key]["purls"].append(ref["referenceLocator"])

    # --- CycloneDX ----------------------------------------------------------
    elif doc.get("bomFormat") == "CycloneDX" or "components" in doc:
        parsed.append((f, "cyclonedx"))
        for c in doc.get("components") or []:
            nm, ver = c.get("name"), c.get("version")
            lic = c.get("licenses") or []
            if not lic:
                add(nm, ver, [], f, "cyclonedx", "licenses", None)
            for entry in lic:
                if "expression" in entry:
                    raw = entry["expression"]
                    add(nm, ver, norm(raw), f, "cyclonedx", "expression", raw)
                else:
                    lo = entry.get("license") or {}
                    raw = lo.get("id") or lo.get("name")
                    add(nm, ver, norm(raw), f, "cyclonedx", "license", raw)
            if c.get("purl"):
                key = (nm or "", ver or "")
                if c["purl"] not in records[key]["purls"]:
                    records[key]["purls"].append(c["purl"])
    else:
        sys.stderr.write("REFUSE: %s is neither SPDX nor CycloneDX\n" % f)
        raise SystemExit(1)

if not parsed:
    sys.stderr.write(
        "REFUSE: no SBOM found in %s — an empty licence inventory is not a\n"
        "        clean licence inventory, and must never be treated as one\n" % sbom_dir)
    raise SystemExit(1)

components = []
for key in sorted(records):
    r = records[key]
    # UNKNOWN: nothing anywhere asserted a licence for this component.
    r["unknown"] = not r["licenses"]
    # CONFLICT: two assertions that each named something, naming different
    # things. One source being silent is not a conflict — it is just silence.
    asserted = set()
    for s in r["sources"]:
        if s["normalised"]:
            asserted.add(tuple(s["normalised"]))
    r["conflict"] = len(asserted) > 1
    r["licenses"] = sorted(r["licenses"])
    components.append(r)

doc = {
    "schema": "foundry.license-inventory/v1",
    "sbom_files": [os.path.basename(f) for f, _ in parsed],
    "sbom_formats": sorted({fmt for _, fmt in parsed}),
    "component_count": len(components),
    "unknown_count": sum(1 for c in components if c["unknown"]),
    "conflict_count": sum(1 for c in components if c["conflict"]),
    "components": components,
}
blob = json.dumps(doc, indent=2, sort_keys=True) + "\n"
doc["inventory_sha256"] = hashlib.sha256(blob.encode()).hexdigest()
blob = json.dumps(doc, indent=2, sort_keys=True) + "\n"

if out == "-":
    sys.stdout.write(blob)
else:
    with open(out, "w") as fh:
        fh.write(blob)
    print("inventory written: %s" % out)
print("components: %d, unknown: %d, conflicting: %d"
      % (doc["component_count"], doc["unknown_count"], doc["conflict_count"]))
PY
}

# -----------------------------------------------------------------------------
# self-test — fixtures only, in a scratch dir. Never touches the checkout.
# -----------------------------------------------------------------------------
self_test() {
  local fail=0 tmp
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" EXIT

  ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

  mkdir -p "$tmp/sbom"
  cat >"$tmp/sbom/a.spdx.json" <<'JSON'
{"spdxVersion":"SPDX-2.3","packages":[
 {"name":"libfoo","versionInfo":"1.0","licenseConcluded":"MIT","licenseDeclared":"MIT",
  "externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:deb/libfoo@1.0"}]},
 {"name":"libmystery","versionInfo":"2.0","licenseConcluded":"NOASSERTION","licenseDeclared":"NOASSERTION"},
 {"name":"libsplit","versionInfo":"3.0","licenseConcluded":"MIT","licenseDeclared":"GPL-3.0-only"}
]}
JSON
  cat >"$tmp/sbom/a.cdx.json" <<'JSON'
{"bomFormat":"CycloneDX","components":[
 {"name":"libfoo","version":"1.0","purl":"pkg:deb/libfoo@1.0",
  "licenses":[{"license":{"id":"MIT"}}]},
 {"name":"libchoice","version":"4.0","licenses":[{"expression":"MIT OR Apache-2.0"}]}
]}
JSON

  ck "an SBOM directory produces an inventory" \
     "build '$tmp/sbom' '$tmp/inv.json' >/dev/null 2>&1"
  ck "both SBOM formats were parsed" \
     "python3 -c \"import json;d=json.load(open('$tmp/inv.json'));assert d['sbom_formats']==['cyclonedx','spdx'],d['sbom_formats']\""
  ck "a plainly-licensed component is neither unknown nor conflicting" \
     "python3 -c \"import json;d=json.load(open('$tmp/inv.json'));c=[x for x in d['components'] if x['name']=='libfoo'][0];assert c['licenses']==['MIT'] and not c['unknown'] and not c['conflict'],c\""
  ck "NOASSERTION is recorded as UNKNOWN, not as a licence" \
     "python3 -c \"import json;d=json.load(open('$tmp/inv.json'));c=[x for x in d['components'] if x['name']=='libmystery'][0];assert c['unknown'] and c['licenses']==[],c\""
  ck "declared-vs-concluded disagreement is recorded as a CONFLICT" \
     "python3 -c \"import json;d=json.load(open('$tmp/inv.json'));c=[x for x in d['components'] if x['name']=='libsplit'][0];assert c['conflict'],c\""
  ck "an SPDX choice expression is kept whole, not split into two licences" \
     "python3 -c \"import json;d=json.load(open('$tmp/inv.json'));c=[x for x in d['components'] if x['name']=='libchoice'][0];assert c['licenses']==['MIT OR Apache-2.0'],c\""
  ck "every assertion keeps the field that made it" \
     "python3 -c \"import json;d=json.load(open('$tmp/inv.json'));c=[x for x in d['components'] if x['name']=='libsplit'][0];assert {s['field'] for s in c['sources']}=={'licenseConcluded','licenseDeclared'},c\""

  # --- fail-closed behaviour -------------------------------------------------
  mkdir -p "$tmp/empty"
  ck "an EMPTY sbom directory is refused, not reported as clean" \
     "! build '$tmp/empty' - >/dev/null 2>&1"
  # NB: `build ... | grep` would inherit build's non-zero status under
  # `set -o pipefail`, so even a MATCHING grep reads as a failure. Capture the
  # diagnostic first, assert against it second.
  cap() { build "$1" - >"$tmp/out" 2>&1 || true; }
  ck "...and says why" \
     "cap '$tmp/empty'; grep -q 'an empty licence inventory is not a' '$tmp/out'"
  ck "a missing sbom directory is refused" \
     "! build '$tmp/nope' - >/dev/null 2>&1"
  mkdir -p "$tmp/bad" && echo 'not json' >"$tmp/bad/x.json"
  ck "unparseable JSON is refused rather than skipped" \
     "! build '$tmp/bad' - >/dev/null 2>&1"
  mkdir -p "$tmp/alien" && echo '{"hello":"world"}' >"$tmp/alien/x.json"
  ck "a JSON file that is not an SBOM is refused" \
     "! build '$tmp/alien' - >/dev/null 2>&1"

  echo "----"
  if [ "$fail" -eq 0 ]; then echo "license-inventory: SELF-TEST OK"; else echo "license-inventory: SELF-TEST FAILED"; fi
  return "$fail"
}

main() {
  local dir="" out="-"
  case "${1:-}" in
    --self-test) self_test; exit $? ;;
    "") usage ;;
  esac
  while [ $# -gt 0 ]; do
    case "$1" in
      --sbom-dir) dir="${2:-}"; shift 2 ;;
      --out)      out="${2:-}"; shift 2 ;;
      *) usage ;;
    esac
  done
  [ -n "$dir" ] || usage
  cd "$ROOT" || exit 1
  build "$dir" "$out"
}

main "$@"
