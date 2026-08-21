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
#   * ledger `image` scope covers this image — exact family, a version-bounded
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
# shellcheck source=lib/common.sh
[ -n "${_COMMON_SOURCED:-}" ] || . "$ROOT/scripts/lib/common.sh"
_COMMON_SOURCED=1

reconcile() {
  # The canonical label comes from scripts/lib/common.sh, so this and the
  # matrix-wide aggregate cannot disagree about what an image is called.
  SCAN="$1" FAMILY="$2" VERSION="${3:-}" POLICY="${POLICY:-$ROOT/policies/vulnerability-exceptions.yaml}" \
  ARCH="${ARCH:-}" OUT_JSON="${OUT_JSON:-}" TODAY="${TODAY:-$(date -u +%F)}" \
  IMAGE_LABEL="$(image_label "$2" "${3:-}")" REPO_ROOT="$ROOT" \
  python3 - <<'PY'
import json, os, sys, datetime

# THE shared record identity — see scripts/lib/exception_id.py. Three tools pair
# records by this string and must not compute it differently.
sys.path.insert(0, os.path.join(os.environ["REPO_ROOT"], "scripts", "lib"))
from exception_id import exc_id, duplicate_scopes
import strict_yaml

scan   = os.environ["SCAN"]
family = os.environ["FAMILY"]
version= os.environ.get("VERSION") or ""
policy = os.environ["POLICY"]
arch   = os.environ.get("ARCH") or ""
require_arch = (os.environ.get("REQUIRE_ARCH") or "1") != "0"
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
    # STRICT: yaml.safe_load keeps the LAST of a duplicated key, so a record
    # could show release_blocking twice — or two verified_architectures lists —
    # and enforce the value a reviewer did not read.
    led = strict_yaml.load(policy) or {}
except strict_yaml.DuplicateKeyError as exc:
    die("exception ledger '%s' has a %s" % (policy, exc))
except Exception as exc:
    die("cannot read exception ledger '%s': %s" % (policy, exc))

# Architecture is mandatory when enforcing. Without it the verified_architectures
# restriction was bypassable simply by omitting --arch, so amd64-only evidence
# could authorise any architecture. REQUIRE_ARCH=0 exists only for the offline
# self-test of arch-independent behaviour.
if require_arch and not arch:
    die("--arch is required: an exception authorises only the architectures it "
        "was reconciled on, so reconciliation without an architecture proves nothing")

if led.get("schema_version") != 1:
    die("ledger schema_version must be 1")
entries = led.get("exceptions")
if not isinstance(entries, list):
    die("ledger has no 'exceptions' list — an absent ledger is not an empty one")

# Architecture evidence is REQUIRED on every record: a record with no
# verified_architectures would otherwise apply everywhere, which is the very
# claim ("evidence-backed for arm64") this must refuse to make.
if require_arch:
    for _e in entries:
        if not _e.get("verified_architectures"):
            die("exception %s (%s) has no verified_architectures — every record must "
                "state the architectures it was reconciled on"
                % (_e.get("cve"), _e.get("image")))


# Two records with identical scope are indistinguishable: whichever is listed
# first governs every finding and the other can never match, so it would be
# reported stale forever and could never be cleared by any scan.
for _first, _dup, _id in duplicate_scopes(entries):
    die("duplicate exception scope at entries[%d] and entries[%d]: %s — two "
        "records with the same cve/image/package/installed_version cannot be "
        "told apart" % (_first, _dup, _id))

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

# --- VERSION-BOUNDED SELECTORS ----------------------------------------------
# `php-all` used to mean "every PHP family, any version". That is a MOVING
# selector: the moment a new PHP version entered MATRIX_IMAGES, every historical
# php-all risk decision would silently start governing it — decisions made from
# evidence that never included that version.
#
# Selectors touching a PHP family must now name the version cohort they were
# evidenced on. `php-8.3-8.4` is immutable by construction: adding PHP 8.5 to the
# matrix cannot widen it, so 8.5 begins UNGOVERNED and must earn its own entries
# from its own evidence.
#
# Bare PHP family selectors (`php-frankenphp`) have the same defect and are
# refused with a diagnostic naming the cohort form to use.
PHP_COHORTS = {
    "php-8.3-8.4": {"8.3", "8.4"},
    "php-frankenphp-8.3-8.4": {"8.3", "8.4"},
    "php-cli-8.3-8.4": {"8.3", "8.4"},
    "php-fpm-8.3-8.4": {"8.3", "8.4"},
    "php-worker-8.3-8.4": {"8.3", "8.4"},
}


def _cohort_family(sel):
    """php-frankenphp-8.3-8.4 -> php-frankenphp ; php-8.3-8.4 -> any PHP family."""
    base = sel.rsplit("-8.3-8.4", 1)[0]
    return None if base == "php" else base


def in_scope(entry_image, fam, ver):
    if entry_image == "all":
        # `all` must not silently absorb a newly added PHP version either.
        if fam in PHP_FAMILIES:
            return ver in {"8.3", "8.4"}
        return True
    if entry_image == "php-all":
        die("exception selector 'php-all' is no longer accepted: it is a MOVING "
            "selector that would silently govern any newly added PHP version. "
            "Use the version-bounded cohort 'php-8.3-8.4', or an explicit "
            "affected_images list.")
    if entry_image in PHP_COHORTS:
        want = PHP_COHORTS[entry_image]
        cf = _cohort_family(entry_image)
        if cf is not None and fam != cf:
            return False
        if cf is None and fam not in PHP_FAMILIES:
            return False
        return ver in want
    if entry_image == fam:
        if fam in PHP_FAMILIES:
            die("exception selector %r is a bare PHP family selector and is not "
                "version-bounded: it would silently govern a newly added PHP "
                "version. Use %r instead." % (entry_image, entry_image + "-8.3-8.4"))
        return True
    return False

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
    # `installed_version` is an EXACT build string, or an explicit finite list of
    # exact build strings. A list exists for one real case: an advisory against a
    # source package whose binaries carry different Debian epochs — CVE-2026-53615
    # covers util-linux, where bsdutils is 1:2.38.1-5+deb12u3 and the other seven
    # binaries are 2.38.1-5+deb12u3. Splitting that into two entries would break
    # the source-package grouping the ledger deliberately uses.
    #
    # A list is membership, never a range: no wildcards, no prefixes, no
    # comparison. Anything not literally observed does not match, so a package
    # moving to a NEW vulnerable version leaves the finding ungoverned and the
    # build refuses. That is the whole point of binding the version.
    #
    # `package_versions` is the STRICTER, per-package form: {package: [versions]}.
    # The flat list above is membership across the WHOLE entry, so for the
    # util-linux epoch case it also accepts bsdutils at the non-epoch string and
    # libmount1 at the epoch string — tuples that do not exist in Debian. That is
    # harmless today but it governs combinations nobody evidenced. When an entry
    # supplies `package_versions`, each package is bound to its OWN observed
    # versions and a cross-matched tuple refuses. Fail-closed: a package absent
    # from the mapping matches nothing.
    pv = e.get("package_versions")
    if pv:
        allowed_for_pkg = pv.get(f["package"])
        if not allowed_for_pkg:
            return False
        if f["installed_version"] not in allowed_for_pkg:
            return False
        return True

    want = e.get("installed_version")
    if want:
        allowed = want if isinstance(want, list) else [want]
        if f["installed_version"] not in allowed:
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
    if not in_scope(e.get("image", ""), family, version):
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

# A not_affected record suppresses a finding permanently — it does not expire —
# so it must be bounded on every axis. An unvalidated record with `image: all`,
# no package and no version binding could silently suppress an advisory across
# unrelated packages, images, versions and architectures for ever.
_NA_REQUIRED = ("cve", "image", "package", "classification", "evidence",
                "references", "verified_architectures")
for _e in not_affected:
    _who = "%s (%s)" % (_e.get("cve"), _e.get("image"))
    for _k in _NA_REQUIRED:
        if not _e.get(_k):
            die("not_affected %s is missing required field '%s'" % (_who, _k))
    if _e.get("image") == "all":
        die("not_affected %s uses image: all — a not-affected determination must "
            "name the image families it was established on" % _who)
    if not (_e.get("installed_version") or _e.get("not_affected_below")):
        die("not_affected %s has no version binding (installed_version and/or "
            "not_affected_below) — it would keep applying after the package moves "
            "into the vulnerable range" % _who)
    if require_arch and not _e.get("verified_architectures"):
        die("not_affected %s has no verified_architectures" % _who)

violations, governed, cleared, used, shadowed = [], [], [], set(), set()
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
    used.add(exc_id(e))
    # Records that also cover this finding but did not govern it. They are not
    # stale — the finding they describe is real and present — they are merely
    # shadowed. Reporting them as "matched no finding" would send someone to
    # delete a correct record.
    for _other in matches[1:]:
        shadowed.add(exc_id(_other))
    exp = str(e.get("expires_at", ""))
    if exp <= today:
        violations.append({**f, "why": "exception expired (%s <= %s)" % (exp, today)})
        continue
    if "fix_available" not in e:
        violations.append({**f, "why": "exception does not declare fix_available"})
        continue
    # release_blocking: true means exactly that. Previously the value was read
    # and emitted but never used, so a record explicitly marked release-blocking
    # still produced PASS — a class-4 finding could greenlight a release.
    if e.get("release_blocking") is True:
        violations.append({**f, "why":
            "exception %s is marked release_blocking: true — the release is BLOCKED "
            "until it is remediated or the record is downgraded with evidence"
            % e.get("cve")})
        continue
    if bool(e["fix_available"]) != f["fix_available"]:
        violations.append({**f, "why":
            "ledger says fix_available=%s, scanner says %s (fix %r) — re-review required"
            % (e["fix_available"], f["fix_available"], f["fixed_version"] or None)})
        continue
    governed.append({**f, "exception": {k: e.get(k) for k in
                     ("cve", "image", "owner", "approver", "expires_at",
                      "release_blocking", "fix_available")}})

# Canonical label, computed by image_label() in scripts/lib/common.sh.
image_label = os.environ["IMAGE_LABEL"]
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
    # matrix consumes these; a per-image view cannot tell "unused" from
    # "belongs to another image". Keyed by exc_id(), which is unique per
    # acceptance scope; the former "cve@image" key merged distinct records.
    "matched_exception_ids": sorted(used),
    # Covered the finding but did not govern it (an earlier record did). Not
    # stale, just redundant — reported separately so nobody deletes a record
    # that correctly describes a live finding.
    "shadowed_exception_ids": sorted(shadowed - used),
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
  # --arch is mandatory in enforcing mode, so every case supplies one; the cases
  # that test the architecture rule override or clear it explicitly.
  export ARCH="linux/amd64"
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

  local BASE='{cve: CVE-2099-1, image: caddy, owner: o, approver: a, reason: r, created_at: 2026-01-01, expires_at: 2099-01-01, release_blocking: false, compensating_controls: [c], fix_available: false, verified_architectures: [linux/amd64]}'
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
  _led "${BASE/image: caddy/image: php-8.3-8.4}"
  t "php-8.3-8.4 covers php-fpm 8.4"           "reconcile '$tmp/unfixed.json' php-fpm 8.4 >/dev/null"
  t "php-8.3-8.4 does NOT cover caddy"         "! reconcile '$tmp/unfixed.json' caddy prod >/dev/null 2>&1"
  # The whole point of the cohort: a NEW PHP version is not silently absorbed.
  t "php-8.3-8.4 does NOT cover php-fpm 8.5"   "! reconcile '$tmp/unfixed.json' php-fpm 8.5 >/dev/null 2>&1"
  _led "${BASE/image: caddy/image: php-all}"
  t "the retired php-all selector is REFUSED"  "! reconcile '$tmp/unfixed.json' php-fpm 8.4 >/dev/null 2>&1"
  _led "${BASE/image: caddy/image: all}"
  t "explicit 'all' scope covers any image"    "reconcile '$tmp/unfixed.json' nginx >/dev/null"

  # package / version binding
  _led "${BASE%\}}, package: curl}"
  t "package binding matches"                  "reconcile '$tmp/unfixed.json' caddy >/dev/null"
  t "package binding rejects another package"  "! reconcile '$tmp/pkg.json' caddy >/dev/null 2>&1"
  _led "${BASE%\}}, installed_version: 9.9}"
  t "version binding rejects another version"  "! reconcile '$tmp/unfixed.json' caddy >/dev/null 2>&1"

  # --- review findings: fail-open paths that must now block -----------------
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
    release_blocking: true
    compensating_controls: [c]
YAML
  _scan "$tmp/blocking.json" CVE-2099-1 curl 1.0 - CRITICAL
  t "release_blocking: true BLOCKS the release" \
    "! ARCH=linux/amd64 reconcile '$tmp/blocking.json' caddy >/dev/null 2>&1"
  t "…and says why" \
    "out=\"\$(ARCH=linux/amd64 reconcile '$tmp/blocking.json' caddy 2>&1 || true)\"; grep -q 'release_blocking' <<<\"\$out\""

  # Omitting --arch used to bypass the architecture restriction entirely.
  t "enforcing mode REFUSES a missing --arch" \
    "! ARCH= reconcile '$tmp/blocking.json' caddy >/dev/null 2>&1"

  # Every record must carry architecture evidence.
  cat > "$tmp/led.yaml" <<'YAML'
schema_version: 1
exceptions:
  - cve: CVE-2099-1
    image: caddy
    package: curl
    fix_available: false
    owner: o
    approver: a
    reason: r
    created_at: 2026-01-01
    expires_at: 2099-01-01
    release_blocking: false
    compensating_controls: [c]
YAML
  _scan "$tmp/noarch.json" CVE-2099-1 curl 1.0 - HIGH
  t "an exception without verified_architectures is refused" \
    "! ARCH=linux/amd64 reconcile '$tmp/noarch.json' caddy >/dev/null 2>&1"

  # not_affected records must be bounded on every axis.
  _na() { cat > "$tmp/led.yaml"; }
  _na <<'YAML'
schema_version: 1
exceptions: []
not_affected:
  - cve: CVE-2099-1
    image: all
    package: curl
    classification: c
    evidence: e
    references: [r]
    verified_architectures: [linux/amd64]
    installed_version: "1.0"
YAML
  t "not_affected with image: all is refused" \
    "! ARCH=linux/amd64 reconcile '$tmp/noarch.json' caddy >/dev/null 2>&1"
  _na <<'YAML'
schema_version: 1
exceptions: []
not_affected:
  - cve: CVE-2099-1
    image: caddy
    classification: c
    evidence: e
    references: [r]
    verified_architectures: [linux/amd64]
    installed_version: "1.0"
YAML
  t "not_affected without a package is refused" \
    "! ARCH=linux/amd64 reconcile '$tmp/noarch.json' caddy >/dev/null 2>&1"
  _na <<'YAML'
schema_version: 1
exceptions: []
not_affected:
  - cve: CVE-2099-1
    image: caddy
    package: curl
    classification: c
    evidence: e
    references: [r]
    verified_architectures: [linux/amd64]
YAML
  t "not_affected without a version binding is refused" \
    "! ARCH=linux/amd64 reconcile '$tmp/noarch.json' caddy >/dev/null 2>&1"
  _na <<'YAML'
schema_version: 1
exceptions: []
not_affected:
  - cve: CVE-2099-1
    image: caddy
    package: curl
    classification: c
    references: [r]
    verified_architectures: [linux/amd64]
    installed_version: "1.0"
YAML
  t "not_affected without evidence is refused" \
    "! ARCH=linux/amd64 reconcile '$tmp/noarch.json' caddy >/dev/null 2>&1"

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
    references: [fixture]
    verified_architectures: [linux/amd64]
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
assert d['matched_exception_ids']==['CVE-2099-1|caddy|*|*'], d['matched_exception_ids']
assert d['shadowed_exception_ids']==[], d['shadowed_exception_ids']\""

  # --- stable record IDs (the aggregate stale check pairs on these) ----------
  # Two records differing ONLY by package. Under the previous 'cve@image' key
  # they collapsed to one ID, so matching either marked both live and neither
  # could ever be reported stale.
  { echo "schema_version: 1"; echo "exceptions:";
    echo "  - {cve: CVE-2099-1, image: caddy, package: curl, owner: o, approver: a, reason: r, created_at: 2026-01-01, expires_at: 2099-01-01, release_blocking: false, compensating_controls: [c], fix_available: false, verified_architectures: [linux/amd64]}";
    echo "  - {cve: CVE-2099-1, image: caddy, package: openssl, owner: o, approver: a, reason: r, created_at: 2026-01-01, expires_at: 2099-01-01, release_blocking: false, compensating_controls: [c], fix_available: false, verified_architectures: [linux/amd64]}";
  } > "$tmp/led.yaml"
  t "same cve+image, different package -> distinct IDs" \
    "OUT_JSON='$tmp/two.json' reconcile '$tmp/unfixed.json' caddy >/dev/null && python3 -c \"
import json;d=json.load(open('$tmp/two.json'))
assert d['matched_exception_ids']==['CVE-2099-1|caddy|curl|*'], d['matched_exception_ids']\""

  # A record whose scope is identical to another can never match, so it would be
  # reported stale forever and could never be cleared by any scan.
  { echo "schema_version: 1"; echo "exceptions:";
    printf '  - %s\n' "$BASE"; printf '  - %s\n' "$BASE"; } > "$tmp/led.yaml"
  t "duplicate exception scope fails closed" \
    "! reconcile '$tmp/unfixed.json' caddy >/dev/null 2>&1"
  t "...and the duplicate is named with both indices" \
    "out=\"\$(reconcile '$tmp/unfixed.json' caddy 2>&1 || true)\"; grep -q 'duplicate exception scope at entries\\[0\\] and entries\\[1\\]' <<<\"\$out\""

  # Two DIFFERENT records that both cover the same finding: the first governs,
  # the second is shadowed. Shadowed is not stale — the finding is real.
  { echo "schema_version: 1"; echo "exceptions:";
    echo "  - {cve: CVE-2099-1, image: caddy, owner: o, approver: a, reason: r, created_at: 2026-01-01, expires_at: 2099-01-01, release_blocking: false, compensating_controls: [c], fix_available: false, verified_architectures: [linux/amd64]}";
    echo "  - {cve: CVE-2099-1, image: all, owner: o, approver: a, reason: r, created_at: 2026-01-01, expires_at: 2099-01-01, release_blocking: false, compensating_controls: [c], fix_available: false, verified_architectures: [linux/amd64]}";
  } > "$tmp/led.yaml"
  t "an overlapping record is recorded as shadowed, not dropped" \
    "OUT_JSON='$tmp/shadow.json' reconcile '$tmp/unfixed.json' caddy >/dev/null && python3 -c \"
import json;d=json.load(open('$tmp/shadow.json'))
assert d['matched_exception_ids']==['CVE-2099-1|caddy|*|*'], d['matched_exception_ids']
assert d['shadowed_exception_ids']==['CVE-2099-1|all|*|*'], d['shadowed_exception_ids']\""
  _led "$BASE"
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
