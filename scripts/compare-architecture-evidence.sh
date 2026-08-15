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

# --- vulnerability-database comparability ----------------------------------
# The two sides are normally collected by different runs, so they can be judged
# against different database snapshots. When they are, a finding present on one
# side and absent on the other may be a difference in TIME rather than in
# ARCHITECTURE, and labelling it "arm64-only" asserts a causality the evidence
# does not support.
#
# Both labels stay fail-safe either way — one asks for a decision, the other
# refuses to grant arm64 — but the WORDING has to stay honest, so it changes
# when the snapshots differ.
def db_ids(meta):
    return sorted({m.get("trivy_db_identity") for m in meta.values()
                   if m.get("trivy_db_identity")})

adb, bdb = db_ids(AMETA), db_ids(BMETA)

# A side judged against more than one snapshot cannot be reasoned about at all:
# its own children disagree about what was known when.
for side, ids in (("amd64", adb), ("arm64", bdb)):
    if len(ids) > 1:
        print("REFUSE: %s evidence spans %d database snapshots; one comparison "
              "basis is required" % (side, len(ids)), file=sys.stderr)
        for i in ids:
            print("  - %s" % i, file=sys.stderr)
        sys.exit(1)

same_db = bool(adb) and bool(bdb) and adb == bdb
if adb and bdb and not same_db:
    ARM_ONLY_LABEL = "UNMATCHED-IN-AMD64-BASELINE"
    NOT_PRESENT_LABEL = "NOT-OBSERVED-IN-ARM64-SNAPSHOT"
    CAUSALITY = ("database snapshots DIFFER — the two classes below are not "
                 "evidence of an architectural difference")
else:
    ARM_ONLY_LABEL = "ARM64-ONLY"
    NOT_PRESENT_LABEL = "NOT PRESENT ON ARM64"
    CAUSALITY = None

# --- usable evidence --------------------------------------------------------
# A child whose package inventory failed to derive cannot support a transfer
# decision: comparing against an empty package map makes every amd64 finding
# look absent on arm64, which reads as "nothing to approve" for the wrong
# reason. Refuse those children explicitly rather than quietly comparing them.
unusable = sorted({slug for slug, m in list(AMETA.items()) + list(BMETA.items())
                   if m.get("packages_inventoried") == 0})

# A child present on one side only cannot be compared. Say so rather than
# quietly comparing the intersection.
only_a, only_b = sorted(set(A) - set(B)), sorted(set(B) - set(A))
shared = sorted(set(A) & set(B))

report = {"transferable": [], "version_differs": [], "arm64_only": [],
          "not_present_on_arm64": [], "images_only_amd64": only_a,
          "images_only_arm64": only_b, "execution_modes": {},
          "amd64_db_identity": adb[0] if adb else None,
          "arm64_db_identity": bdb[0] if bdb else None,
          "same_database_snapshot": same_db,
          "unusable_children_zero_inventory": unusable,
          "labels": {"arm64_only": ARM_ONLY_LABEL,
                     "not_present": NOT_PRESENT_LABEL}}

# Children with no inventory are excluded from comparison entirely, not
# compared and then footnoted.
shared = [s for s in shared if s not in unusable]

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
print("== COMPARISON BASIS ==")
print("   amd64 database: %s" % (adb[0] if adb else "UNKNOWN"))
print("   arm64 database: %s" % (bdb[0] if bdb else "UNKNOWN"))
if CAUSALITY:
    print("   %s." % CAUSALITY)
    print("   A finding on one side and not the other may be a difference in")
    print("   TIME, not in ARCHITECTURE. The two classes are still safe to act")
    print("   on — one asks for a decision, the other withholds arm64 — but")
    print("   neither may be cited as proof of an architectural difference.")
elif same_db:
    print("   identical — differences below are attributable to architecture.")
else:
    print("   at least one side records no database identity; treat the two")
    print("   asymmetric classes below as unattributed.")
print()

if unusable:
    print("== EXCLUDED: no package inventory (%d) ==" % len(unusable))
    for s in unusable:
        print("   %-22s packages_inventoried=0 — cannot support a transfer decision" % s)
    print("   These children were NOT compared. An empty package map would make")
    print("   every amd64 finding look absent on arm64, which reads as 'nothing")
    print("   to approve' for entirely the wrong reason.")
    print()

show("TRANSFERABLE — same CVE, package and version on both", report["transferable"],
     lambda r: "%-22s %-18s %-24s %s" % (r["image"], r["cve"], r["package"], r["amd64_version"]))
show("VERSION DIFFERS — needs a separate decision", report["version_differs"],
     lambda r: "%-22s %-18s %-24s amd64=%s arm64=%s"
               % (r["image"], r["cve"], r["package"], r["amd64_version"], r["arm64_version"]))
show("%s — needs its own decision" % ARM_ONLY_LABEL, report["arm64_only"],
     lambda r: "%-22s %-18s %-24s %s" % (r["image"], r["cve"], r["package"], r["arm64_version"]))
show("%s — do NOT grant arm64" % NOT_PRESENT_LABEL, report["not_present_on_arm64"],
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
print("summary: %d transferable, %d version-differs, %d arm64-only, %d not-present, "
      "%d excluded, same-db=%s"
      % (len(report["transferable"]), len(report["version_differs"]),
         len(report["arm64_only"]), len(report["not_present_on_arm64"]),
         len(unusable), "yes" if same_db else "no"))

if out:
    json.dump(report, open(out, "w"), indent=2, sort_keys=True)
    print("written: %s" % out)

# Exit non-zero when anything needs a human decision OR when the comparison is
# not fully attributable, so this cannot be wired into a pipeline that treats
# "differences exist" — or "we could not tell" — as success.
sys.exit(1 if (report["version_differs"] or report["arm64_only"]
               or only_a or only_b or unusable or not same_db) else 0)
PY
}

self_test() {
  local pass=0 fail=0 tmp
  ck() { if eval "$2"; then pass=$((pass+1)); echo "ok   - $1"; else fail=$((fail+1)); echo "FAIL - $1"; fi; }
  tmp="$(mktemp -d)"

  mk() { # mk <dir> <slug> <json-vulns> <json-pkgs> [exec_mode] [db] [pkgcount]
    mkdir -p "$1/$2-evidence"
    cat > "$1/$2-evidence/trivy.json" <<EOF
{"Results":[{"Target":"t","Vulnerabilities":$3,"Packages":$4}]}
EOF
    cat > "$1/$2.json" <<EOF
{"image_label":"$2","platform":"linux/x","execution_mode":"${5:-native}","host_architecture":"amd64","trivy_db_identity":"${6:-db-A}","packages_inventoried":${7:-1}}
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
  # REFUSE messages go to stderr, and `say` discards it. This captures both
  # streams — and, like `say`, swallows the exit status, because `compare | grep`
  # under pipefail reports compare's status and compare fails ON PURPOSE here.
  both() { compare "$1" "$2" 2>&1 || true; }

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

  # --- database comparability ----------------------------------------------
  # Two sides judged against different snapshots cannot attribute an asymmetric
  # finding to architecture, and must say so in the labels.
  rm -rf "$tmp/g"; mk "$tmp/g" nginx-prod '[{"VulnerabilityID":"CVE-1","PkgName":"zlib","InstalledVersion":"1.0"},{"VulnerabilityID":"CVE-9","PkgName":"musl","InstalledVersion":"3.0"}]' '[{"Name":"zlib","Version":"1.0"}]' qemu db-B
  ck "differing databases are reported in the comparison basis" \
     "say '$tmp/a' '$tmp/g' | grep -q 'amd64 database: db-A' &&
      say '$tmp/a' '$tmp/g' | grep -q 'arm64 database: db-B'"
  ck "differing databases relabel arm64-only as UNMATCHED-IN-AMD64-BASELINE" \
     "say '$tmp/a' '$tmp/g' | grep -q 'UNMATCHED-IN-AMD64-BASELINE'"
  ck "...and it no longer claims an architectural difference" \
     "say '$tmp/a' '$tmp/g' | grep -q 'not evidence of an architectural difference'"
  ck "matching databases keep the ARM64-ONLY wording" \
     "say '$tmp/a' '$tmp/e' | grep -q 'ARM64-ONLY' &&
      ! say '$tmp/a' '$tmp/e' | grep -q 'UNMATCHED-IN-AMD64-BASELINE'"
  rm -rf "$tmp/h"; mk "$tmp/h" nginx-prod '[]' '[{"Name":"zlib","Version":"1.0"}]' native db-B
  ck "differing databases relabel not-present as NOT-OBSERVED-IN-ARM64-SNAPSHOT" \
     "say '$tmp/a' '$tmp/h' | grep -q 'NOT-OBSERVED-IN-ARM64-SNAPSHOT'"
  ck "a differing database alone exits non-zero" \
     "! compare '$tmp/a' '$tmp/h' >/dev/null 2>&1"

  # One side judged against two snapshots cannot be reasoned about at all.
  rm -rf "$tmp/i"
  mk "$tmp/i" nginx-prod '[]' '[]' native db-A
  mk "$tmp/i" caddy-prod '[]' '[]' native db-B
  ck "evidence spanning two databases on one side is REFUSED" \
     "! compare '$tmp/i' '$tmp/b' >/dev/null 2>&1 &&
      both '$tmp/i' '$tmp/b' | grep -q 'spans 2 database snapshots'"

  # --- zero inventory must be excluded, not compared ------------------------
  rm -rf "$tmp/j"; mk "$tmp/j" nginx-prod '[]' '[]' qemu db-A 0
  ck "a child with no package inventory is EXCLUDED from comparison" \
     "say '$tmp/a' '$tmp/j' | grep -q 'EXCLUDED: no package inventory'"
  ck "...and is NOT counted as 'nothing to approve'" \
     "sums '$tmp/a' '$tmp/j' | grep -q '0 not-present, 1 excluded'"
  ck "an excluded child exits non-zero" \
     "! compare '$tmp/a' '$tmp/j' >/dev/null 2>&1"

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
