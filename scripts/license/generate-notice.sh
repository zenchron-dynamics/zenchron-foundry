#!/usr/bin/env bash
# =============================================================================
# scripts/license/generate-notice.sh — third-party NOTICE *candidate* (#120).
# -----------------------------------------------------------------------------
# Renders a normalised licence inventory into an attribution notice.
#
# It emits a CANDIDATE, and the word is load-bearing. Which notices Foundry must
# actually ship — or whether it ships any at all — depends on how #98 resolves
# the contradiction between a public repository and a LICENSE forbidding public
# distribution. Until an owner records that decision, this file is a draft for
# review and says so on its own first line, so it cannot be mistaken later for
# an approved legal artefact.
#
# It refuses to render at all while the inventory still contains unknown or
# conflicting licences: a notice file built over "we could not tell" would
# publish a claim about attribution that nobody verified.
#
# Usage:
#   generate-notice.sh --inventory FILE [--out FILE] [--policy FILE]
#   generate-notice.sh --self-test
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

usage() {
  sed -n '19,21p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 64
}

render() {
  INVENTORY="$1" OUT="$2" POLICY="$3" python3 <<'PY'
import json, os, sys

inv_path, out, pol_path = os.environ["INVENTORY"], os.environ["OUT"], os.environ["POLICY"]

try:
    import yaml
except ImportError:
    sys.stderr.write("REFUSE: PyYAML is required to read the licence policy\n")
    raise SystemExit(2)

def refuse(msg):
    sys.stderr.write("REFUSE: %s\n" % msg)
    raise SystemExit(1)

try:
    with open(inv_path) as fh:
        inv = json.load(fh)
except (OSError, ValueError) as e:
    refuse("licence inventory %s is unreadable: %s" % (inv_path, e))

if inv.get("schema") != "foundry.license-inventory/v1":
    refuse("%s is not a foundry.license-inventory/v1 document" % inv_path)

comps = inv.get("components") or []
if not comps:
    refuse("inventory lists no components — an empty NOTICE is not a complete NOTICE")

unknown = sorted("%s@%s" % (c.get("name", ""), c.get("version", ""))
                 for c in comps if c.get("unknown"))
conflict = sorted("%s@%s" % (c.get("name", ""), c.get("version", ""))
                  for c in comps if c.get("conflict"))
if unknown or conflict:
    lines = ["cannot render a NOTICE over an unresolved inventory:"]
    if unknown:
        lines.append("  %d component(s) with NO established licence:" % len(unknown))
        lines += ["    - %s" % u for u in unknown]
    if conflict:
        lines.append("  %d component(s) with CONFLICTING licences:" % len(conflict))
        lines += ["    - %s" % c for c in conflict]
    lines.append("  Attribution nobody verified is not attribution.")
    refuse("\n".join(lines))

try:
    with open(pol_path) as fh:
        pol = yaml.safe_load(fh) or {}
except (OSError, ValueError) as e:
    refuse("licence policy %s is unreadable: %s" % (pol_path, e))

publication = pol.get("publication") or {}
approved = bool(publication.get("notices_approved_for_distribution"))
decision = publication.get("decision")
issue = publication.get("tracked_issue")

by_license = {}
for c in comps:
    for lic in c.get("licenses") or []:
        by_license.setdefault(lic, []).append(
            "%s %s" % (c.get("name", ""), c.get("version", "")))

head = []
if approved and decision != "undetermined":
    head.append("THIRD-PARTY NOTICES")
    head.append("Distribution decision: %s (recorded in %s)" % (decision, os.path.basename(pol_path)))
else:
    head.append("THIRD-PARTY NOTICE CANDIDATE — DRAFT, NOT APPROVED FOR DISTRIBUTION")
    head.append("")
    head.append("This file was generated from SBOM evidence. It is NOT a legal artefact and")
    head.append("has NOT been approved for publication. How Zenchron Foundry may be")
    head.append("distributed is undetermined and tracked in issue %s; until that is" % issue)
    head.append("decided by the owner, this document exists for review only.")
    head.append("")
    head.append("  publication.decision                         : %s" % decision)
    head.append("  publication.notices_approved_for_distribution: %s" % approved)

body = [
    "",
    "Generated from : %s" % ", ".join(inv.get("sbom_files") or []),
    "Components     : %d" % len(comps),
    "Distinct licences: %d" % len(by_license),
    "",
    "=" * 78,
    "",
]
for lic in sorted(by_license):
    body.append(lic)
    body.append("-" * len(lic))
    for item in sorted(set(by_license[lic])):
        body.append("  %s" % item)
    body.append("")

text = "\n".join(head + body) + "\n"
if out == "-":
    sys.stdout.write(text)
else:
    with open(out, "w") as fh:
        fh.write(text)
    print("notice candidate written: %s" % out)
print("licences: %d, components: %d%s"
      % (len(by_license), len(comps), "" if approved else "  (CANDIDATE — not approved)"))
PY
}

self_test() {
  local fail=0 tmp
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" EXIT

  ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

  cat >"$tmp/pol.yaml" <<'YAML'
publication:
  decision: undetermined
  tracked_issue: 98
  notices_approved_for_distribution: false
YAML
  cat >"$tmp/pol-approved.yaml" <<'YAML'
publication:
  decision: B
  tracked_issue: 98
  notices_approved_for_distribution: true
YAML

  printf '%s\n' '{"schema":"foundry.license-inventory/v1","sbom_files":["a.spdx.json"],"components":[
    {"name":"libfoo","version":"1.0","licenses":["MIT"],"unknown":false,"conflict":false,"sources":[]},
    {"name":"libbar","version":"2.0","licenses":["MIT"],"unknown":false,"conflict":false,"sources":[]}]}' >"$tmp/clean.json"

  ck "a resolved inventory renders a notice" \
     "render '$tmp/clean.json' '$tmp/NOTICE.txt' '$tmp/pol.yaml' >/dev/null 2>&1"
  ck "the notice is labelled a CANDIDATE while #98 is undetermined" \
     "head -1 '$tmp/NOTICE.txt' | grep -q 'DRAFT, NOT APPROVED FOR DISTRIBUTION'"
  ck "...and does not claim approval anywhere" \
     "! grep -q '^THIRD-PARTY NOTICES$' '$tmp/NOTICE.txt'"
  ck "components are grouped under their licence" \
     "grep -q '^MIT$' '$tmp/NOTICE.txt' && grep -q 'libfoo 1.0' '$tmp/NOTICE.txt' && grep -q 'libbar 2.0' '$tmp/NOTICE.txt'"
  ck "an owner-approved policy renders the non-draft heading" \
     "render '$tmp/clean.json' '$tmp/NOTICE2.txt' '$tmp/pol-approved.yaml' >/dev/null 2>&1 && head -1 '$tmp/NOTICE2.txt' | grep -q '^THIRD-PARTY NOTICES$'"

  printf '%s\n' '{"schema":"foundry.license-inventory/v1","components":[
    {"name":"libmystery","version":"9.0","licenses":[],"unknown":true,"conflict":false,"sources":[]}]}' >"$tmp/unknown.json"
  ck "an inventory with an UNKNOWN licence refuses to render" \
     "! render '$tmp/unknown.json' '$tmp/x.txt' '$tmp/pol.yaml' >/dev/null 2>&1"
  # `render ... | grep` would inherit render's non-zero status under
  # `set -o pipefail`, so a matching grep on a refusal still reads as failure.
  ck "...naming the component" \
     "render '$tmp/unknown.json' '$tmp/x.txt' '$tmp/pol.yaml' >'$tmp/out' 2>&1 || true; grep -q 'libmystery@9.0' '$tmp/out'"
  ck "...and no file is produced" \
     "test ! -f '$tmp/x.txt'"

  printf '%s\n' '{"schema":"foundry.license-inventory/v1","components":[
    {"name":"libsplit","version":"3.0","licenses":["MIT","GPL-3.0-only"],"unknown":false,"conflict":true,"sources":[]}]}' >"$tmp/conflict.json"
  ck "an inventory with a CONFLICT refuses to render" \
     "! render '$tmp/conflict.json' '$tmp/y.txt' '$tmp/pol.yaml' >/dev/null 2>&1"

  printf '%s\n' '{"schema":"foundry.license-inventory/v1","components":[]}' >"$tmp/empty.json"
  ck "an EMPTY inventory refuses rather than emitting an empty NOTICE" \
     "! render '$tmp/empty.json' '$tmp/z.txt' '$tmp/pol.yaml' >/dev/null 2>&1"
  ck "a non-inventory document is refused" \
     "echo '{\"schema\":\"nope\"}' >'$tmp/w.json'; ! render '$tmp/w.json' '$tmp/w.txt' '$tmp/pol.yaml' >/dev/null 2>&1"

  echo "----"
  if [ "$fail" -eq 0 ]; then echo "generate-notice: SELF-TEST OK"; else echo "generate-notice: SELF-TEST FAILED"; fi
  return "$fail"
}

main() {
  local inv="" out="-" pol="$ROOT/policies/license-policy.yaml"
  case "${1:-}" in
    --self-test) self_test; exit $? ;;
    "") usage ;;
  esac
  while [ $# -gt 0 ]; do
    case "$1" in
      --inventory) inv="${2:-}"; shift 2 ;;
      --out)       out="${2:-}"; shift 2 ;;
      --policy)    pol="${2:-}"; shift 2 ;;
      *) usage ;;
    esac
  done
  [ -n "$inv" ] || usage
  render "$inv" "$out" "$pol"
}

main "$@"
