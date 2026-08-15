#!/usr/bin/env bash
# =============================================================================
# scripts/compare-architecture-evidence.sh <amd64-evidence-dir> <arm64-evidence-dir>
# -----------------------------------------------------------------------------
# Turn two architectures' child evidence into the ONLY defensible input for
# widening the exception ledger (#139).
#
# THE RULE THIS ENFORCES. An amd64 exception may gain linux/arm64 when, and only
# when, the same finding was actually observed and evaluated on arm64, against
# the same package at the same installed version. Everything else is a separate
# decision:
#
#   TRANSFERABLE   same CVE, same package, same installed version on both.
#                  The amd64 reasoning applies unchanged.
#   VERSION-DIFFERS same CVE and package, DIFFERENT installed version. The amd64
#                  record pins a version that is not what arm64 ships, so it
#                  cannot be widened — a new decision is required.
#   ARM64-ONLY     present on arm64, absent on amd64. Never covered by an
#                  existing record; needs its own decision.
#   NOT-PRESENT    an amd64 finding that does not occur on arm64. There is
#                  NOTHING TO APPROVE. Granting arm64 here would be inventing an
#                  approval for a finding that does not exist, which is the
#                  specific mistake this script exists to prevent.
#
# It emits a report and a machine-readable JSON. It does NOT edit the ledger:
# widening an exception is a risk decision, and this only supplies the evidence
# a human decides on.
#
# Usage:
#   compare-architecture-evidence.sh <amd64-dir> <arm64-dir> [--json out.json]
#   compare-architecture-evidence.sh --self-test
# =============================================================================
set -uo pipefail

compare() {
  local a="${1:?amd64 evidence dir}" b="${2:?arm64 evidence dir}" out="${3:-}"
  [ -d "$a" ] || { echo "REFUSE: no amd64 evidence at '$a'" >&2; return 1; }
  [ -d "$b" ] || { echo "REFUSE: no arm64 evidence at '$b'" >&2; return 1; }

  AMD="$a" ARM="$b" OUT="$out" python3 - <<'PY'
import glob, json, os, sys, collections

amd_dir, arm_dir, out = os.environ["AMD"], os.environ["ARM"], os.environ["OUT"]

def load(d):
    """image_label -> {(cve,pkg): version}, plus the package inventory."""
    findings, packages, meta = {}, {}, {}
    for f in sorted(glob.glob(os.path.join(d, "*-evidence", "trivy.json"))):
        slug = os.path.basename(os.path.dirname(f)).replace("-evidence", "")
        try:
            doc = json.load(open(f))
        except Exception as e:
            print("REFUSE: unreadable %s (%s)" % (f, e), file=sys.stderr)
            sys.exit(1)
        fs, pk = {}, {}
        for r in doc.get("Results") or []:
            for v in r.get("Vulnerabilities") or []:
                fs[(v["VulnerabilityID"], v.get("PkgName"))] = v.get("InstalledVersion")
            for p in r.get("Packages") or []:
                pk[p.get("Name")] = p.get("Version")
        findings[slug], packages[slug] = fs, pk
        rec = os.path.join(d, slug + ".json")
        if os.path.exists(rec):
            meta[slug] = json.load(open(rec))
    return findings, packages, meta

A, APK, AMETA = load(amd_dir)
B, BPK, BMETA = load(arm_dir)

if not A: print("REFUSE: no amd64 child evidence found", file=sys.stderr); sys.exit(1)
if not B: print("REFUSE: no arm64 child evidence found", file=sys.stderr); sys.exit(1)

# A child present on one side only cannot be compared. Say so rather than
# quietly comparing the intersection.
only_a, only_b = sorted(set(A) - set(B)), sorted(set(B) - set(A))
shared = sorted(set(A) & set(B))

report = {"transferable": [], "version_differs": [], "arm64_only": [],
          "not_present_on_arm64": [], "images_only_amd64": only_a,
          "images_only_arm64": only_b, "execution_modes": {}}

for slug in sorted(set(list(BMETA) + list(AMETA))):
    m = BMETA.get(slug) or AMETA.get(slug) or {}
    if m.get("execution_mode"):
        report["execution_modes"][slug] = {
            "platform": m.get("platform"), "execution_mode": m.get("execution_mode"),
            "host_architecture": m.get("host_architecture"),
            "packages_inventoried": m.get("packages_inventoried")}

for slug in shared:
    fa, fb = A[slug], B[slug]
    for key, ver_a in sorted(fa.items()):
        cve, pkg = key
        if key in fb:
            ver_b = fb[key]
            row = {"image": slug, "cve": cve, "package": pkg,
                   "amd64_version": ver_a, "arm64_version": ver_b}
            (report["transferable"] if ver_a == ver_b
             else report["version_differs"]).append(row)
        else:
            report["not_present_on_arm64"].append(
                {"image": slug, "cve": cve, "package": pkg,
                 "amd64_version": ver_a,
                 "arm64_package_version": BPK.get(slug, {}).get(pkg),
                 "note": "no arm64 finding — nothing to approve"})
    for key, ver_b in sorted(fb.items()):
        if key not in fa:
            report["arm64_only"].append(
                {"image": slug, "cve": key[0], "package": key[1],
                 "arm64_version": ver_b, "note": "needs its own decision"})

def show(title, rows, fmt):
    print("== %s (%d) ==" % (title, len(rows)))
    for r in rows:
        print("   " + fmt(r))
    if not rows:
        print("   (none)")
    print()

print()
show("TRANSFERABLE — same CVE, package and version on both", report["transferable"],
     lambda r: "%-22s %-18s %-24s %s" % (r["image"], r["cve"], r["package"], r["amd64_version"]))
show("VERSION DIFFERS — needs a separate decision", report["version_differs"],
     lambda r: "%-22s %-18s %-24s amd64=%s arm64=%s"
               % (r["image"], r["cve"], r["package"], r["amd64_version"], r["arm64_version"]))
show("ARM64-ONLY — needs its own decision", report["arm64_only"],
     lambda r: "%-22s %-18s %-24s %s" % (r["image"], r["cve"], r["package"], r["arm64_version"]))
show("NOT PRESENT ON ARM64 — do NOT grant arm64", report["not_present_on_arm64"],
     lambda r: "%-22s %-18s %-24s amd64=%s" % (r["image"], r["cve"], r["package"], r["amd64_version"]))

if only_a or only_b:
    print("== INCOMPLETE COMPARISON ==")
    for s in only_a: print("   amd64 only, no arm64 counterpart: %s" % s)
    for s in only_b: print("   arm64 only, no amd64 counterpart: %s" % s)
    print()

modes = {v["execution_mode"] for v in report["execution_modes"].values()}
print("execution modes observed: %s" % (", ".join(sorted(modes)) or "unknown"))
if "qemu" in modes:
    print("NOTE: qemu execution is emulation. It yields genuine image, package and")
    print("      reconciliation evidence, but it is NOT native-arm64 runtime")
    print("      evidence and does not satisfy #111.")
print()
print("summary: %d transferable, %d version-differs, %d arm64-only, %d not-present"
      % (len(report["transferable"]), len(report["version_differs"]),
         len(report["arm64_only"]), len(report["not_present_on_arm64"])))

if out:
    json.dump(report, open(out, "w"), indent=2, sort_keys=True)
    print("written: %s" % out)

# Exit non-zero when anything needs a human decision, so this cannot be wired
# into a pipeline that treats "differences exist" as success.
sys.exit(1 if (report["version_differs"] or report["arm64_only"]
               or only_a or only_b) else 0)
PY
}

self_test() {
  local pass=0 fail=0 tmp
  ck() { if eval "$2"; then pass=$((pass+1)); echo "ok   - $1"; else fail=$((fail+1)); echo "FAIL - $1"; fi; }
  tmp="$(mktemp -d)"

  mk() { # mk <dir> <slug> <json-vulns> <json-pkgs> [exec_mode]
    mkdir -p "$1/$2-evidence"
    cat > "$1/$2-evidence/trivy.json" <<EOF
{"Results":[{"Target":"t","Vulnerabilities":$3,"Packages":$4}]}
EOF
    cat > "$1/$2.json" <<EOF
{"image_label":"$2","platform":"linux/x","execution_mode":"${5:-native}","host_architecture":"amd64","packages_inventoried":1}
EOF
  }

  # same finding, same version -> transferable
  mk "$tmp/a" nginx-prod '[{"VulnerabilityID":"CVE-1","PkgName":"zlib","InstalledVersion":"1.0"}]' '[{"Name":"zlib","Version":"1.0"}]'
  mk "$tmp/b" nginx-prod '[{"VulnerabilityID":"CVE-1","PkgName":"zlib","InstalledVersion":"1.0"}]' '[{"Name":"zlib","Version":"1.0"}]' qemu
  # Assertions match the ASCII summary line, not the section headings: those
  # contain an em-dash, and a pattern spanning it is a locale question rather
  # than a statement about the classification.
  #
  # Output is CAPTURED before matching. `compare | grep` under `set -o pipefail`
  # reports compare's non-zero status, and compare exits non-zero exactly when
  # differences exist — so a matching grep would still read as a failed
  # assertion. Every assertion about a deliberately-failing command needs this.
  say()  { compare "$1" "$2" 2>/dev/null || true; }
  sums() { say "$1" "$2" | grep '^summary:' || true; }

  ck "identical findings compare clean (exit 0)" "compare '$tmp/a' '$tmp/b' >/dev/null 2>&1"
  ck "and are reported as transferable" \
     "sums '$tmp/a' '$tmp/b' | grep -q '1 transferable, 0 version-differs, 0 arm64-only, 0 not-present'"
  ck "qemu execution is called out as not native evidence" \
     "say '$tmp/a' '$tmp/b' | grep -q 'NOT native-arm64'"

  # differing version -> must NOT be transferable
  rm -rf "$tmp/c"; mk "$tmp/c" nginx-prod '[{"VulnerabilityID":"CVE-1","PkgName":"zlib","InstalledVersion":"2.0"}]' '[{"Name":"zlib","Version":"2.0"}]'
  ck "a differing installed version is NOT transferable" \
     "sums '$tmp/a' '$tmp/c' | grep -q '0 transferable, 1 version-differs'"
  ck "a differing version exits non-zero" "! compare '$tmp/a' '$tmp/c' >/dev/null 2>&1"

  # finding absent on arm64 -> nothing to approve
  rm -rf "$tmp/d"; mk "$tmp/d" nginx-prod '[]' '[{"Name":"zlib","Version":"1.0"}]'
  ck "an amd64 finding absent on arm64 is 'nothing to approve'" \
     "sums '$tmp/a' '$tmp/d' | grep -q '0 transferable, 0 version-differs, 0 arm64-only, 1 not-present'"

  # arm64-only finding
  rm -rf "$tmp/e"; mk "$tmp/e" nginx-prod '[{"VulnerabilityID":"CVE-1","PkgName":"zlib","InstalledVersion":"1.0"},{"VulnerabilityID":"CVE-9","PkgName":"musl","InstalledVersion":"3.0"}]' '[{"Name":"zlib","Version":"1.0"}]'
  ck "an arm64-only finding needs its own decision" \
     "sums '$tmp/a' '$tmp/e' | grep -q '1 transferable, 0 version-differs, 1 arm64-only'"

  # missing counterpart image
  rm -rf "$tmp/f"; mk "$tmp/f" caddy-prod '[]' '[]'
  ck "a child present on only one side is an INCOMPLETE comparison" \
     "say '$tmp/a' '$tmp/f' | grep -q 'INCOMPLETE COMPARISON'"
  ck "an incomplete comparison exits non-zero" "! compare '$tmp/a' '$tmp/f' >/dev/null 2>&1"
  ck "an empty evidence directory is REFUSED, not treated as no differences" \
     "mkdir -p '$tmp/empty' && ! compare '$tmp/a' '$tmp/empty' >/dev/null 2>&1"

  rm -rf "$tmp"
  echo "----"
  printf 'self-test: %d ok, %d failed\n' "$pass" "$fail"
  [ "$fail" -eq 0 ]
}

case "${1:-}" in
  --self-test) self_test ;;
  "")          echo "usage: $(basename "$0") <amd64-dir> <arm64-dir> [out.json] | --self-test" >&2; exit 64 ;;
  *)           compare "$1" "${2:?arm64 evidence dir required}" "${3:-}" ;;
esac
