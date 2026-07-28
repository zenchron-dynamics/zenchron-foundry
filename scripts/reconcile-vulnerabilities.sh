#!/usr/bin/env bash
# =============================================================================
# scripts/reconcile-vulnerabilities.sh
# -----------------------------------------------------------------------------
# Reconcile EVERY CRITICAL/HIGH finding for ONE image against the machine-
# readable exception ledger, scoped to that image (#102, #103).
#
# What this replaces, and why:
#
#   The enforcing gate used to be
#       trivy ... --ignore-unfixed --ignorefile policies/.trivyignore
#   which has two holes:
#
#   #103  `--ignore-unfixed` drops every not-yet-fixed finding BEFORE the ledger
#         is consulted. A brand-new unfixed CRITICAL therefore ships with no
#         owner, no reachability decision, no expiry and no compensating
#         control — the opposite of what the exception policy claims.
#
#   #102  `.trivyignore` is GLOBAL. Trivy takes one ignore file per scan, so a
#         CVE accepted as unreachable on caddy was suppressed on all 10 images,
#         including one where the same CVE is reachable. The ledger's `image`
#         field was audit metadata that enforced nothing.
#
# The fix is to stop suppressing anything at scan time. Trivy reports the FULL
# CRITICAL/HIGH set, and this script decides — per image — whether each finding
# is governed. A finding with no in-scope, unexpired ledger entry FAILS the
# build, whether or not a fix exists upstream.
#
# Scope matching (a finding is governed only if ALL hold):
#   * advisory id equal (CVE-… or GHSA-…);
#   * ledger `image` scope covers this image — exact family, the `php-all`
#     family group, or `all`;
#   * if the entry pins `package`, it equals the finding's package;
#   * if the entry pins `installed_version`, it equals the finding's version;
#   * if the entry pins `arch`, it equals the scanned architecture;
#   * `expires_at` is strictly in the future.
#
# `fix_available` is REQUIRED on every entry and must match what the scanner
# says. That closes the drift where an exception written for "no fix exists"
# keeps suppressing the finding for months after upstream ships one: the moment
# a fix appears the entry stops matching reality and the build fails, forcing
# re-review. Fixable findings are NOT auto-blocked — this repository knowingly
# governs some (a pinned base lagging an upstream fix) — but they must be
# declared as such by a human.
#
# Usage:
#   reconcile-vulnerabilities.sh <trivy-json> <image-family> [<image-version>]
#         [--policy FILE] [--arch ARCH] [--json OUT] [--today YYYY-MM-DD]
#   reconcile-vulnerabilities.sh --self-test
#
# Exit: 0 = every finding governed (or none), 1 = ungoverned/expired/drift, or
# any failure to read the inputs. An unreadable scan is a FAILURE, never an
# empty finding set reported as clean.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

reconcile() {
  SCAN="$1" FAMILY="$2" VERSION="${3:-}" POLICY="${POLICY:-$ROOT/policies/vulnerability-exceptions.yaml}" \
  ARCH="${ARCH:-}" OUT_JSON="${OUT_JSON:-}" TODAY="${TODAY:-$(date -u +%F)}" \
  python3 - <<'PY'
import json, os, sys, datetime

scan   = os.environ["SCAN"]
family = os.environ["FAMILY"]
version= os.environ.get("VERSION") or ""
policy = os.environ["POLICY"]
arch   = os.environ.get("ARCH") or ""
out    = os.environ.get("OUT_JSON") or ""
today  = os.environ["TODAY"]

def die(msg):
    print("RECONCILE FAIL: %s" % msg, file=sys.stderr)
    sys.exit(1)

try:
    import yaml
except ImportError:
    die("PyYAML is required to read the exception ledger")

# --- inputs. Unreadable input is a failure, never an empty clean result. -----
try:
    with open(scan) as fh:
        doc = json.load(fh)
except Exception as exc:
    die("cannot read scanner JSON '%s': %s" % (scan, exc))
try:
    with open(policy) as fh:
        led = yaml.safe_load(fh) or {}
except Exception as exc:
    die("cannot read exception ledger '%s': %s" % (policy, exc))

if led.get("schema_version") != 1:
    die("ledger schema_version must be 1")
entries = led.get("exceptions")
if not isinstance(entries, list):
    die("ledger has no 'exceptions' list — an absent ledger is not an empty one")

# PyYAML turns an unquoted 2099-01-01 into datetime.date. Normalise every value
# to a string so date handling, comparison and JSON emission all agree.
for _e in entries:
    for _k, _v in list(_e.items()):
        if isinstance(_v, (datetime.date, datetime.datetime)):
            _e[_k] = _v.isoformat()

# --- findings ---------------------------------------------------------------
SEVERITIES = {"CRITICAL", "HIGH"}
findings = []
results = doc.get("Results")
if results is None:
    die("scanner JSON has no 'Results' key — wrong format or a truncated file")
for r in results:
    for v in (r.get("Vulnerabilities") or []):
        if (v.get("Severity") or "").upper() not in SEVERITIES:
            continue
        findings.append({
            "id": v.get("VulnerabilityID"),
            "package": v.get("PkgName"),
            "installed_version": v.get("InstalledVersion"),
            "fixed_version": v.get("FixedVersion") or "",
            "severity": v.get("Severity"),
            "fix_available": bool(v.get("FixedVersion")),
        })

# --- scope ------------------------------------------------------------------
PHP_FAMILIES = {"php-cli", "php-fpm", "php-worker", "php-frankenphp"}

def in_scope(entry_image, fam):
    if entry_image == "all":
        return True
    if entry_image == "php-all":
        return fam in PHP_FAMILIES
    return entry_image == fam

def _upstream(v):
    """Upstream version from a Debian version: 5.36.0-7+deb12u3 -> (5,36,0).

    Non-numeric components are dropped so an epoch or a packaging suffix cannot
    make the comparison silently wrong.
    """
    core = str(v or "").split(":")[-1].split("-")[0]
    out = []
    for part in core.split("."):
        digits = "".join(c for c in part if c.isdigit())
        if not digits:
            break
        out.append(int(digits))
    return tuple(out)


def version_binding_holds(e, f):
    """Version scope, kept OUT of covers() on purpose.

    covers() answers "does this record address this finding at all" (advisory,
    image, package, arch). This answers "is it still valid for the version in
    front of us". Keeping them separate is what lets a not_affected record whose
    binding has lapsed be reported as RE-EVALUATE instead of vanishing into the
    generic "no exception" case.

    `not_affected_below` pins the upstream version below which the finding does
    not apply; `installed_version` pins an exact package build."""
    want = e.get("installed_version")
    if want and want != f["installed_version"]:
        return False
    below = e.get("not_affected_below")
    if below:
        if not _upstream(f["installed_version"]) or not _upstream(below):
            return False                      # cannot compare -> fail closed
        if _upstream(f["installed_version"]) >= _upstream(below):
            return False                      # moved into the vulnerable range
    return True


def covers(e, f):
    if e.get("cve") != f["id"]:
        return False
    if not in_scope(e.get("image", ""), family):
        return False
    # `package` may be a single binary package or the SET of binary packages
    # built from one source package (util-linux -> libblkid1, libmount1, …).
    # A source-package advisory legitimately lands on several of them.
    pkg = e.get("package")
    if pkg:
        allowed = pkg if isinstance(pkg, list) else [pkg]
        if f["package"] not in allowed:
            return False
    if e.get("arch") and arch and e["arch"] != arch:
        return False
    # An exception authorises ONLY the architectures it was reconciled on.
    # `arch_note: unverified` is not enough: if the record does not list the
    # architecture being scanned it simply does not apply, the finding is
    # ungoverned, and publication for that architecture fails. That is what
    # stops amd64 evidence silently authorising an arm64 release.
    verified = e.get("verified_architectures")
    if verified and arch and arch not in verified:
        return False
    return True

# Findings determined NOT TO APPLY. Distinct from an exception: nothing is being
# accepted, so these carry evidence rather than an owner/expiry, and they do not
# expire. Recording a proven-not-affected finding as an "exception" would
# misstate it as accepted risk.
not_affected = led.get("not_affected") or []
if not isinstance(not_affected, list):
    die("ledger 'not_affected' must be a list when present")

violations, governed, cleared, used = [], [], [], set()
for f in findings:
    na = [e for e in not_affected if covers(e, f) and version_binding_holds(e, f)]
    if na:
        e = na[0]
        cleared.append({**f, "not_affected": {k: e.get(k) for k in
                        ("cve", "image", "package", "classification", "evidence")}})
        continue
    stale_na = [e for e in not_affected if covers(e, f)]
    if stale_na:
        e = stale_na[0]
        violations.append({**f, "why":
            "not_affected record for %s no longer holds: installed %s is outside its "
            "version binding (%s) — RE-EVALUATE, the finding may now apply"
            % (e.get("cve"), f["installed_version"],
               e.get("not_affected_below") or e.get("installed_version"))})
        continue
    matches = [e for e in entries if covers(e, f) and version_binding_holds(e, f)]
    if not matches:
        # The #103 case: unfixed findings used to vanish here before anyone
        # looked at them. Now they are as blocking as fixable ones.
        violations.append({**f, "why": "no in-scope exception in the ledger"})
        continue
    e = matches[0]
    used.add((e.get("cve"), e.get("image")))
    exp = str(e.get("expires_at", ""))
    if exp <= today:
        violations.append({**f, "why": "exception expired (%s <= %s)" % (exp, today)})
        continue
    if "fix_available" not in e:
        violations.append({**f, "why": "exception does not declare fix_available"})
        continue
    if bool(e["fix_available"]) != f["fix_available"]:
        violations.append({**f, "why":
            "ledger says fix_available=%s, scanner says %s (fix %r) — re-review required"
            % (e["fix_available"], f["fix_available"], f["fixed_version"] or None)})
        continue
    governed.append({**f, "exception": {k: e.get(k) for k in
                     ("cve", "image", "owner", "approver", "expires_at",
                      "release_blocking", "fix_available")}})

image_label = family + (("/" + version) if version else "")
report = {
    "image": image_label,
    "arch": arch or "unspecified",
    "checked_at": today,
    "findings_total": len(findings),
    "not_affected": cleared,
    "governed": governed,
    "violations": violations,
    "verdict": "PASS" if not violations else "FAIL",
    # Entries that matched here — the aggregate stale check across the whole
    # matrix consumes this; a per-image view cannot tell "unused" from
    # "belongs to another image".
    "matched_exceptions": sorted("%s@%s" % (c, i) for c, i in used),
}
if out:
    with open(out, "w") as fh:
        json.dump(report, fh, indent=2, default=str)
        fh.write("\n")
    print("reconciliation written: %s" % out)

if violations:
    print("REFUSE: %d ungoverned CRITICAL/HIGH finding(s) in %s:" % (len(violations), image_label),
          file=sys.stderr)
    for v in violations:
        print("  %-24s %-28s %-18s %s" % (v["id"], v["package"], v["installed_version"], v["why"]),
              file=sys.stderr)
    print("  -> fix the finding, or add a scoped entry to policies/vulnerability-exceptions.yaml",
          file=sys.stderr)
    sys.exit(1)

print("RECONCILE PASS: %s — %d CRITICAL/HIGH finding(s): %d accepted via %d exception(s), "
      "%d determined not-affected"
      % (image_label, len(findings), len(governed),
         len(set(f["id"] for f in governed)), len(cleared)))
PY
}

# --- self-test (offline, fixture-driven) ------------------------------------
self_test() {
  local tmp ok=0 bad=0
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '${tmp}'" RETURN
  # Every case reads the FIXTURE ledger, never the real one — otherwise the
  # suite silently grades itself against production data.
  export POLICY="$tmp/led.yaml"
  t() { if eval "$2"; then ok=$((ok+1)); echo "  ok   $1"; else bad=$((bad+1)); echo "  FAIL $1"; fi; }

  _scan() { # _scan <file> <id> <pkg> <version> <fixed|-> <severity>
    python3 - "$@" <<'PY'
import json, sys
f, vid, pkg, ver, fixed, sev = sys.argv[1:7]
json.dump({"Results": [{"Vulnerabilities": [{
    "VulnerabilityID": vid, "PkgName": pkg, "InstalledVersion": ver,
    "FixedVersion": "" if fixed == "-" else fixed, "Severity": sev}]}]}, open(f, "w"))
PY
  }
  _led() { # _led <file> <yaml-body-of-one-entry>
    { echo "schema_version: 1"; echo "exceptions:"; printf '  - %s\n' "$1"; } > "$tmp/led.yaml"
  }

  local BASE='{cve: CVE-2099-1, image: caddy, owner: o, approver: a, reason: r, created_at: 2026-01-01, expires_at: 2099-01-01, release_blocking: false, compensating_controls: [c], fix_available: false}'
  _scan "$tmp/unfixed.json" CVE-2099-1 curl 1.0 - HIGH
  _scan "$tmp/fixed.json"   CVE-2099-1 curl 1.0 2.0 HIGH
  _scan "$tmp/other.json"   CVE-2099-9 curl 1.0 -   HIGH
  _scan "$tmp/low.json"     CVE-2099-1 curl 1.0 -   MEDIUM
  _scan "$tmp/pkg.json"     CVE-2099-1 openssl 1.0 - HIGH
  printf '{"Results": []}' > "$tmp/clean.json"
  printf 'not json'        > "$tmp/broken.json"
  printf '{"NoResults": 1}' > "$tmp/noresults.json"

  _led "$BASE"
  t "governed unfixed finding passes"          "reconcile '$tmp/unfixed.json' caddy >/dev/null"
  t "clean scan passes"                        "reconcile '$tmp/clean.json' caddy >/dev/null"
  t "a MEDIUM is out of gate scope"            "reconcile '$tmp/low.json' caddy >/dev/null"

  # #103: the finding the old gate dropped silently.
  t "UNGOVERNED unfixed finding is rejected"   "! reconcile '$tmp/other.json' caddy >/dev/null 2>&1"
  # `set -o pipefail` would report reconcile's intended non-zero exit, not
  # grep's verdict — capture first, then match.
  t "…and names the advisory" \
    "out=\"\$(reconcile '$tmp/other.json' caddy 2>&1 || true)\"; grep -q CVE-2099-9 <<<\"\$out\""

  # fix_available drift: upstream shipped a fix, the entry still says none.
  t "fix appearing upstream forces re-review"  "! reconcile '$tmp/fixed.json' caddy >/dev/null 2>&1"

  # #102: the same entry must NOT cover another image.
  t "caddy exception does not cover nginx"     "! reconcile '$tmp/unfixed.json' nginx >/dev/null 2>&1"
  _led "${BASE/image: caddy/image: php-all}"
  t "php-all covers php-fpm"                   "reconcile '$tmp/unfixed.json' php-fpm >/dev/null"
  t "php-all does NOT cover caddy"             "! reconcile '$tmp/unfixed.json' caddy >/dev/null 2>&1"
  _led "${BASE/image: caddy/image: all}"
  t "explicit 'all' scope covers any image"    "reconcile '$tmp/unfixed.json' nginx >/dev/null"

  # package / version binding
  _led "${BASE%\}}, package: curl}"
  t "package binding matches"                  "reconcile '$tmp/unfixed.json' caddy >/dev/null"
  t "package binding rejects another package"  "! reconcile '$tmp/pkg.json' caddy >/dev/null 2>&1"
  _led "${BASE%\}}, installed_version: 9.9}"
  t "version binding rejects another version"  "! reconcile '$tmp/unfixed.json' caddy >/dev/null 2>&1"

  # --- architecture evidence -------------------------------------------------
  # An exception authorises only the architectures it was reconciled on; an
  # arch_note saying "unverified" is not enough if the record still applies.
  cat > "$tmp/led.yaml" <<'YAML'
schema_version: 1
exceptions:
  - cve: CVE-2099-1
    image: caddy
    package: curl
    fix_available: false
    verified_architectures: [linux/amd64]
    owner: o
    approver: a
    reason: r
    created_at: 2026-01-01
    expires_at: 2099-01-01
    release_blocking: false
    compensating_controls: [c]
YAML
  _scan "$tmp/arch.json" CVE-2099-1 curl 1.0 - HIGH
  t "exception applies on the verified architecture" \
    "ARCH=linux/amd64 reconcile '$tmp/arch.json' caddy >/dev/null 2>&1"
  t "exception does NOT apply on an unverified architecture" \
    "! ARCH=linux/arm64 reconcile '$tmp/arch.json' caddy >/dev/null 2>&1"

  # --- version binding on not_affected records (round-2 requirement) --------
  # A not_affected decision must self-invalidate when the package moves into the
  # vulnerable range, instead of silently suppressing a finding that now applies.
  cat > "$tmp/led.yaml" <<'YAML'
schema_version: 1
exceptions: []
not_affected:
  - cve: CVE-2099-1
    image: caddy
    package: perl-base
    installed_version: 5.36.0-7+deb12u3
    not_affected_below: 5.37.10
    classification: false-positive-disputed-range
    evidence: fixture
YAML
  _scan "$tmp/v-old.json" CVE-2099-1 perl-base 5.36.0-7+deb12u3 - HIGH
  t "not_affected holds below the introduction version" \
    "reconcile '$tmp/v-old.json' caddy >/dev/null 2>&1"
  _scan "$tmp/v-new.json" CVE-2099-1 perl-base 5.38.0-1 - HIGH
  t "not_affected STOPS applying inside the vulnerable range" \
    "! reconcile '$tmp/v-new.json' caddy >/dev/null 2>&1"
  t "…and says RE-EVALUATE rather than 'no exception'" \
    "out=\"\$(reconcile '$tmp/v-new.json' caddy 2>&1 || true)\"; grep -q 'RE-EVALUATE' <<<\"\$out\""

  # expiry + schema hygiene
  _led "${BASE/expires_at: 2099-01-01/expires_at: 2026-01-02}"
  t "expired exception is rejected"            "! TODAY=2026-07-28 reconcile '$tmp/unfixed.json' caddy >/dev/null 2>&1"
  _led "${BASE/, fix_available: false/}"
  t "entry without fix_available is rejected"  "! reconcile '$tmp/unfixed.json' caddy >/dev/null 2>&1"

  # fail-closed inputs
  _led "$BASE"
  t "unreadable scan JSON fails closed"        "! reconcile '$tmp/broken.json' caddy >/dev/null 2>&1"
  t "scan without Results fails closed"        "! reconcile '$tmp/noresults.json' caddy >/dev/null 2>&1"
  t "missing scan file fails closed"           "! reconcile '$tmp/nope.json' caddy >/dev/null 2>&1"
  printf 'exceptions: []\n' > "$tmp/led.yaml"
  t "ledger without schema_version fails closed" "! reconcile '$tmp/unfixed.json' caddy >/dev/null 2>&1"

  # evidence
  _led "$BASE"
  t "writes machine-readable evidence" \
    "OUT_JSON='$tmp/ev.json' reconcile '$tmp/unfixed.json' caddy >/dev/null && python3 -c \"
import json;d=json.load(open('$tmp/ev.json'))
assert d['verdict']=='PASS' and d['findings_total']==1
assert d['matched_exceptions']==['CVE-2099-1@caddy'], d['matched_exceptions']\""
  t "evidence records violations too" \
    "! OUT_JSON='$tmp/bad.json' reconcile '$tmp/other.json' caddy >/dev/null 2>&1; python3 -c \"
import json;d=json.load(open('$tmp/bad.json'))
assert d['verdict']=='FAIL' and len(d['violations'])==1\""

  echo "self-test: $ok ok, $bad failed"
  [ "$bad" -eq 0 ]
}

main() {
  [ "${1:-}" = "--self-test" ] && { self_test; return $?; }
  local scan="${1:?usage: reconcile-vulnerabilities.sh <trivy-json> <family> [version] [--json OUT]}"
  local family="${2:?family required}"
  shift 2
  # The version is optional and may legitimately be the EMPTY string (nginx and
  # caddy are versionless "prod" edge images, and callers pass "" positionally).
  # Consume it whenever the next argument is not a flag — including when empty —
  # otherwise "" falls through to the flag parser as an unknown argument.
  local version=""
  if [ "$#" -gt 0 ]; then
    case "$1" in --*) : ;; *) version="$1"; shift ;; esac
  fi
  while [ $# -gt 0 ]; do
    case "$1" in
      --policy) POLICY="$2"; shift 2 ;;
      --arch)   ARCH="$2"; shift 2 ;;
      --json)   OUT_JSON="$2"; shift 2 ;;
      --today)  TODAY="$2"; shift 2 ;;
      *) echo "unknown argument: $1" >&2; return 1 ;;
    esac
  done
  export POLICY ARCH OUT_JSON TODAY
  reconcile "$scan" "$family" "$version"
}

main "$@"
