#!/usr/bin/env bash
# =============================================================================
# scripts/assert-publish-platforms-reconciled.sh <platforms-csv> [ledger]
# -----------------------------------------------------------------------------
# Refuses to publish any platform whose vulnerability findings have never been
# reconciled.
#
# Why this exists: reconcile-vulnerabilities.sh runs per architecture and takes
# a mandatory --arch. Every acceptance record therefore records the exact
# architectures it was evidenced against, in `verified_architectures`. Nothing
# previously connected that to publication, so a multi-arch push could ship
# linux/arm64 while every record in the ledger had only ever been evidenced on
# linux/amd64 — the arm64 layers would carry CRITICAL/HIGH findings that no
# human had classified and no gate had seen.
#
# The rule enforced here is deliberately conservative: a platform is publishable
# only if EVERY active acceptance record declares it. A record that omits the
# platform is a record whose reasoning was never checked against that
# architecture's package set, and it is not knowable without scanning that
# architecture whether that record would have been needed there. Unverified is
# therefore treated as unreconciled, never as "probably the same".
#
# WHAT THIS DOES NOT PROVE. It is a ledger-coverage check, not scan evidence.
# It asserts that every acceptance record claims the platform; it does NOT prove
# that a scan of that architecture was ever run, nor that it passed. Today that
# gap is not reachable — every record is linux/amd64 only, so arm64 is refused
# outright — but it becomes load-bearing the moment anyone adds
# `linux/arm64` to verified_architectures.
#
# BEFORE ARM64 PUBLICATION IS ENABLED, this check must be replaced by, or paired
# with, one that consumes real reconciliation evidence bound to:
#     child manifest digest, architecture, source revision,
#     image family/version, and the Trivy database snapshot
# so that "reconciled for arm64" means an arm64 scan of the exact digest being
# published, not a line of YAML asserting it. Adding arm64 to the ledger without
# that evidence would turn this gate from conservative into decorative.
#
# The per-architecture Trivy gate remains what proves a given scan passed.
#
# Env: LEDGER (default policies/vulnerability-exceptions.yaml)
# Exit: 0 every requested platform is reconciled; 1 otherwise.
# =============================================================================
set -euo pipefail
_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
. "$_d/lib/common.sh"

LEDGER="${LEDGER:-$_d/../policies/vulnerability-exceptions.yaml}"

# assert_platforms_reconciled <platforms-csv> <ledger>
assert_platforms_reconciled() {
  local csv="$1" ledger="$2"
  [ -n "$csv" ] || die "no platforms given: refusing to publish an unspecified platform set"
  [ -f "$ledger" ] || die "ledger not found: $ledger"
  command -v python3 >/dev/null || die "python3 required"

  PLATFORMS_CSV="$csv" LEDGER_PATH="$ledger" python3 - <<'PY'
import os, sys, yaml

csv = os.environ["PLATFORMS_CSV"]
path = os.environ["LEDGER_PATH"]

plats = [p.strip() for p in csv.split(",")]
if any(p == "" for p in plats):
    sys.exit("REFUSE: empty entry in platform list %r" % csv)
for p in plats:
    # os/arch shape. A bare "arm64" or a stray "--platform" must never be
    # silently treated as reconciled because it matches nothing.
    if p.count("/") != 1 or not all(part.strip() for part in p.split("/")):
        sys.exit("REFUSE: %r is not a valid os/arch platform" % p)
if len(set(plats)) != len(plats):
    sys.exit("REFUSE: duplicate platform in %r" % csv)

try:
    doc = yaml.safe_load(open(path)) or {}
except yaml.YAMLError as e:
    sys.exit("REFUSE: ledger is not valid YAML: %s" % e)
if not isinstance(doc, dict):
    sys.exit("REFUSE: ledger root is not a mapping")

records = []
for section in ("exceptions", "not_affected"):
    got = doc.get(section)
    if got is None:
        continue
    if not isinstance(got, list):
        sys.exit("REFUSE: ledger section %r is not a list" % section)
    for i, r in enumerate(got):
        if not isinstance(r, dict):
            sys.exit("REFUSE: %s[%d] is not a mapping" % (section, i))
        records.append((section, i, r))

# An empty ledger means nothing has been accepted. That is a legitimate,
# fully-remediated state (#122) and every platform is trivially reconciled.
if not records:
    print("PUBLISH-PLATFORMS OK: ledger holds no acceptance records; "
          "nothing is accepted on any platform (%s)" % ", ".join(plats))
    sys.exit(0)

def rid(section, i, r):
    # Identify a record the way the ledger does. `package` is optional (a
    # record may govern a CVE across every package in an image), so it is
    # shown only when present rather than rendered as a misleading "?".
    bits = ["%s[%d]" % (section, i), str(r.get("cve") or r.get("advisory") or "?")]
    img = r.get("image") or r.get("affected_images")
    if img:
        bits.append("image=%s" % (",".join(img) if isinstance(img, list) else img))
    pkg = r.get("package")
    if pkg:
        bits.append("pkg=%s" % (",".join(pkg) if isinstance(pkg, list) else pkg))
    return " ".join(bits)

failed = False
for plat in plats:
    missing = []
    for section, i, r in records:
        va = r.get("verified_architectures")
        if va is None:
            missing.append((rid(section, i, r), "no verified_architectures"))
            continue
        if not isinstance(va, list) or not va:
            missing.append((rid(section, i, r), "verified_architectures is not a non-empty list"))
            continue
        if not all(isinstance(a, str) for a in va):
            missing.append((rid(section, i, r), "verified_architectures holds a non-string"))
            continue
        if plat not in va:
            missing.append((rid(section, i, r), "verified on %s" % ", ".join(va)))
    if missing:
        failed = True
        print("REFUSE: %s is NOT reconciled — %d of %d acceptance record(s) do not "
              "cover it:" % (plat, len(missing), len(records)))
        for name, why in missing[:15]:
            print("    %-64s (%s)" % (name, why))
        if len(missing) > 15:
            print("    ... and %d more" % (len(missing) - 15))
        print("  Reconcile that architecture first:")
        print("    scripts/reconcile-vulnerabilities.sh --arch %s ..." % plat)
        print("  then record it in verified_architectures on each record it applies to.")
    else:
        print("PUBLISH-PLATFORMS OK: %s reconciled across all %d acceptance record(s)"
              % (plat, len(records)))

sys.exit(1 if failed else 0)
PY
}

# --------------------------------------------------------------------------
_apr_self_test() {
  command -v python3 >/dev/null || { echo "SKIP - python3 absent"; return 0; }
  python3 -c 'import yaml' 2>/dev/null || { echo "SKIP - PyYAML absent"; return 0; }
  local fail=0 tmp; tmp="$(mktemp -d)"
  # shellcheck disable=SC2317  # invoked via the `t` helper below
  trap 'rm -rf "$tmp"' RETURN

  cat >"$tmp/amd64-only.yaml" <<'Y'
schema_version: 1
exceptions:
  - cve: CVE-1
    image: nginx
    package: libfoo
    verified_architectures: [linux/amd64]
not_affected:
  - cve: CVE-2
    image: caddy
    package: libbar
    verified_architectures: [linux/amd64]
Y
  cat >"$tmp/both.yaml" <<'Y'
schema_version: 1
exceptions:
  - cve: CVE-1
    image: nginx
    package: libfoo
    verified_architectures: [linux/amd64, linux/arm64]
not_affected:
  - cve: CVE-2
    image: caddy
    package: libbar
    verified_architectures: [linux/arm64, linux/amd64]
Y
  cat >"$tmp/mixed.yaml" <<'Y'
schema_version: 1
exceptions:
  - cve: CVE-1
    image: nginx
    package: libfoo
    verified_architectures: [linux/amd64, linux/arm64]
  - cve: CVE-9
    image: nginx
    package: libbaz
    verified_architectures: [linux/amd64]
Y
  cat >"$tmp/missing-field.yaml" <<'Y'
schema_version: 1
exceptions:
  - cve: CVE-1
    image: nginx
    package: libfoo
Y
  cat >"$tmp/empty-list.yaml" <<'Y'
schema_version: 1
exceptions:
  - cve: CVE-1
    image: nginx
    package: libfoo
    verified_architectures: []
Y
  cat >"$tmp/non-string.yaml" <<'Y'
schema_version: 1
exceptions:
  - cve: CVE-1
    image: nginx
    package: libfoo
    verified_architectures: [linux/amd64, 42]
Y
  cat >"$tmp/zero.yaml" <<'Y'
schema_version: 1
exceptions: []
not_affected: []
Y
  cat >"$tmp/not-a-list.yaml" <<'Y'
schema_version: 1
exceptions:
  cve: CVE-1
Y
  printf 'exceptions: [\n' >"$tmp/broken.yaml"

  # t <expect-rc> <name> <platforms> <ledger>
  t() {
    local want="$1" name="$2" plats="$3" led="$4" rc=0
    # Subshell: die() exits, and an exit here would kill the whole self-test
    # rather than register a single case.
    ( assert_platforms_reconciled "$plats" "$led" ) >/dev/null 2>&1 || rc=$?
    if [ "$rc" -eq "$want" ]; then echo "  ok   $name"; else
      echo "  FAIL $name (rc=$rc want=$want)"; fail=$((fail + 1)); fi
  }

  t 0 "amd64 passes on an amd64-only ledger"          "linux/amd64"              "$tmp/amd64-only.yaml"
  t 1 "arm64 REFUSED on an amd64-only ledger"         "linux/arm64"              "$tmp/amd64-only.yaml"
  t 1 "multi-arch REFUSED when arm64 unverified"      "linux/amd64,linux/arm64"  "$tmp/amd64-only.yaml"
  t 0 "multi-arch passes when both verified"          "linux/amd64,linux/arm64"  "$tmp/both.yaml"
  t 0 "order in verified_architectures is irrelevant" "linux/arm64"              "$tmp/both.yaml"
  t 1 "ONE unverified record blocks the platform"     "linux/arm64"              "$tmp/mixed.yaml"
  t 0 "that same ledger still publishes amd64"        "linux/amd64"              "$tmp/mixed.yaml"
  t 1 "a record with no verified_architectures blocks" "linux/amd64"             "$tmp/missing-field.yaml"
  t 1 "an empty verified_architectures blocks"        "linux/amd64"              "$tmp/empty-list.yaml"
  t 1 "a non-string architecture blocks"              "linux/arm64"              "$tmp/non-string.yaml"
  t 0 "a zero-exception ledger publishes anywhere"    "linux/amd64,linux/arm64"  "$tmp/zero.yaml"
  t 1 "a malformed ledger REFUSES (never passes)"     "linux/amd64"              "$tmp/broken.yaml"
  t 1 "a non-list section REFUSES"                    "linux/amd64"              "$tmp/not-a-list.yaml"
  t 1 "an empty platform list REFUSES"                ""                         "$tmp/both.yaml"
  t 1 "a bare arch (no os/) REFUSES"                  "arm64"                    "$tmp/both.yaml"
  t 1 "a trailing comma REFUSES"                      "linux/amd64,"             "$tmp/both.yaml"
  t 1 "a duplicate platform REFUSES"                  "linux/amd64,linux/amd64"  "$tmp/both.yaml"
  t 1 "an over-deep platform REFUSES"                 "linux/arm64/v8"           "$tmp/both.yaml"
  t 1 "a missing ledger REFUSES"                      "linux/amd64"              "$tmp/nope.yaml"
  t 1 "the real ledger does not authorize arm64"      "linux/arm64"              "$_d/../policies/vulnerability-exceptions.yaml"
  t 0 "the real ledger does authorize amd64"          "linux/amd64"              "$_d/../policies/vulnerability-exceptions.yaml"

  echo "self-test: $((21 - fail)) ok, $fail failed"
  [ "$fail" -eq 0 ]
}

case "${1-}" in
  --self-test) _apr_self_test && echo "assert-publish-platforms-reconciled.sh: SELF-TEST OK" ;;
  "") echo "usage: assert-publish-platforms-reconciled.sh <platforms-csv> | --self-test" >&2; exit 2 ;;
  *) assert_platforms_reconciled "$1" "${2:-$LEDGER}" ;;
esac
