#!/usr/bin/env python3
"""Classify every exception-ledger entry against a buildless cohort rescan.

WHY THIS IS NOT scripts/reconcile-vulnerabilities.sh. That gate answers one
question per IMAGE — "is every finding here governed by some record". This
answers the inverse question per RECORD — "what happened to the thing this
record was written for" — which is what an expiry decision actually needs and
which the pass/fail gate cannot express. The two share the scope-matching and
version-binding rules by importing nothing and re-deriving nothing: the rules
below are a deliberate, commented mirror of the gate's, and the gate's own
`matched_exception_ids` output is cross-checked against this classification so
a divergence is reported rather than hidden.

Every record lands in EXACTLY ONE bucket:

  still-present            the finding is there, on a bound package, at a bound
                           version, and the upstream artifact has not moved
  absent                   the advisory is not reported on any in-scope child
  installed-version-changed the advisory is there but the package moved off the
                           version the record pins, so the binding no longer holds
  fix-now-available        a fixed version is offered where the record says none
                           exists, or a patched official base is now published
  upstream-moved-unpatched the pinned upstream base tag has moved to a new
                           digest, and the new head STILL carries the bound
                           package at the same unpatched version — so a rebuild
                           is available and would not remediate this
  evidence-unavailable     no measurement covers this record's scope
  selector-no-longer-resolves the record's image or package selector matches no
                           measured child, or no finding on a bound package
  ownership-boundary-changed the remediation owner recorded for the finding is
                           not the owner the ownership model derives today

Usage:  classify-expiry-refresh.py --refresh-dir DIR [--out FILE]
        classify-expiry-refresh.py --self-test
"""
import argparse
import glob
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts", "lib"))

PHP_FAMILIES = {"php-cli", "php-fpm", "php-worker", "php-frankenphp"}
PHP_COHORTS = {
    "php-8.3-8.4": {"8.3", "8.4"},
    "php-frankenphp-8.3-8.4": {"8.3", "8.4"},
    "php-cli-8.3-8.4": {"8.3", "8.4"},
    "php-fpm-8.3-8.4": {"8.3", "8.4"},
    "php-worker-8.3-8.4": {"8.3", "8.4"},
}


def cohort_family(sel):
    base = sel.rsplit("-8.3-8.4", 1)[0]
    return None if base == "php" else base


def in_scope(entry_image, fam, ver):
    """Mirror of reconcile-vulnerabilities.sh in_scope(). Version-bounded
    cohorts only: a bare or moving selector is a defect, not a wildcard."""
    if entry_image == "all":
        return ver in {"8.3", "8.4"} if fam in PHP_FAMILIES else True
    if entry_image in PHP_COHORTS:
        cf = cohort_family(entry_image)
        if cf is not None and fam != cf:
            return False
        if cf is None and fam not in PHP_FAMILIES:
            return False
        return ver in PHP_COHORTS[entry_image]
    return entry_image == fam and fam not in PHP_FAMILIES


def version_binding_holds(e, pkg, installed):
    """Mirror of the gate's version_binding_holds(). `package_versions` is the
    stricter per-package form and fails closed for a package it does not list;
    the flat `installed_version` list is membership across the whole record."""
    pv = e.get("package_versions")
    if pv:
        allowed = pv.get(pkg)
        return bool(allowed) and installed in allowed
    want = e.get("installed_version")
    if want:
        allowed = want if isinstance(want, list) else [want]
        if installed not in allowed:
            return False
    return True


def packages_of(e):
    p = e.get("package")
    if not p:
        return None
    return list(p) if isinstance(p, list) else [p]


def owner_of(image_label, pkg, installed, fixed, newer_base):
    """Delegate to the repository's own ownership model rather than restating
    it here — a second copy is a second thing that can drift."""
    out = subprocess.run(
        ["bash", os.path.join(ROOT, "scripts", "classify-remediation-owner.sh"),
         "--image", image_label, "--package", pkg,
         "--installed", installed or "", "--fixed", fixed or "",
         "--newer-base-available", newer_base],
        capture_output=True, text=True, check=False)
    kv = {}
    for line in out.stdout.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            kv[k] = v
    return kv


def load_children(refresh_dir):
    """Child key -> {family, version, platform, findings}. The child key comes
    from the acceptance evidence, so family/version/platform are the ACCEPTED
    identity of the artifact and are never re-derived from a filename guess."""
    children = {}
    for f in sorted(glob.glob(os.path.join(refresh_dir, "findings", "*.findings.json"))):
        slug = os.path.basename(f).replace(".findings.json", "")
        parts = slug.split("_")          # php-cli_8.3_linux_amd64
        fam, ver, plat = parts[0], parts[1], "%s/%s" % (parts[2], parts[3])
        children[slug] = {
            "child_key": "%s/%s/%s" % (fam, ver, plat),
            "family": fam, "version": ver, "platform": plat,
            "image_label": "%s/%s" % (fam, ver),
            "findings": json.load(open(f))["findings"],
        }
    return children


def load_base_heads(refresh_dir):
    """Upstream-base head evidence: the advisory set AND the package inventory.

    EVIDENCE CLASS upstream-base. These may establish upstream ownership and
    patched-base availability ONLY. They are NEVER read as the child's package
    inventory — the child Dockerfile purges build tooling AND installs packages
    of its own, so the two inventories differ in both directions.

    THE INVENTORY IS LOAD-BEARING, not decoration. Without it, "the advisory is
    absent from the new base head" reads as "upstream patched it", when the real
    explanation may be that the package was never in the base at all and the
    finding belongs to a Foundry layer. That is not a hypothetical: libaom3 is
    absent from every FrankenPHP base head and present in the FrankenPHP child.
    """
    heads = {}
    for f in sorted(glob.glob(os.path.join(refresh_dir, "upstream-base-heads", "*.head.trivy.json"))):
        name = os.path.basename(f).replace(".head.trivy.json", "")
        doc = json.load(open(f))
        pkgs = {}
        for r in (doc.get("Results") or []):
            for v in (r.get("Vulnerabilities") or []):
                pkgs.setdefault((v.get("VulnerabilityID"), v.get("PkgName")), set()).add(
                    (v.get("InstalledVersion"), v.get("FixedVersion") or ""))
        inv = {}
        invf = os.path.join(refresh_dir, "upstream-base-heads", name + ".head.dpkg.txt")
        if os.path.exists(invf):
            for line in open(invf):
                parts = line.split()
                if len(parts) == 2:
                    inv[parts[0]] = parts[1]
        heads[name] = {"advisories": pkgs, "inventory": inv}
    return heads


# family/version -> the base-head scan that covers it, and whether that base
# tag's digest moved since the pin the cohort was built from.
BASE_FOR = {
    ("php-cli", "8.3"): "php_8.3-cli", ("php-worker", "8.3"): "php_8.3-cli",
    ("php-cli", "8.4"): "php_8.4-cli", ("php-worker", "8.4"): "php_8.4-cli",
    ("php-fpm", "8.3"): "php_8.3-fpm", ("php-fpm", "8.4"): "php_8.4-fpm",
    ("php-frankenphp", "8.3"): "frankenphp_8.3",
    ("php-frankenphp", "8.4"): "frankenphp_8.4",
    ("caddy", "prod"): "caddy", ("nginx", "prod"): "nginx",
}


def is_vendored_go(pkg):
    """A Go module compiled INTO an upstream binary. It never appears in dpkg,
    so a dpkg inventory can neither confirm nor deny it — asking the inventory
    about `stdlib` would report every Go finding as Foundry-owned, which is the
    exact opposite of the truth."""
    if pkg == "stdlib":
        return True
    return pkg.startswith(("golang.org/", "google.golang.org/", "github.com/",
                           "gopkg.in/", "go.uber.org/"))


def classify(entry, children, heads, moved_bases):
    cve = entry.get("cve")
    pkgs = packages_of(entry)
    verified = entry.get("verified_architectures") or []
    scope = [c for c in children.values()
             if in_scope(entry.get("image", ""), c["family"], c["version"])
             and (not verified or c["platform"] in verified)
             and (not entry.get("arch") or entry["arch"] == c["platform"])]
    ev = {"in_scope_children": sorted(c["child_key"] for c in scope)}
    if not scope:
        return "selector-no-longer-resolves", ev, \
            "no measured child satisfies this record's image selector and verified architectures"
    id_hits, pkg_hits, bound_hits, unbound = [], [], [], []
    for c in scope:
        for f in c["findings"]:
            if f["id"] != cve:
                continue
            id_hits.append((c, f))
            if pkgs is not None and f["pkg"] not in pkgs:
                continue
            pkg_hits.append((c, f))
            if version_binding_holds(entry, f["pkg"], f["installed"]):
                bound_hits.append((c, f))
            else:
                unbound.append((c, f))
    ev["advisory_hits"] = len(id_hits)
    ev["bound_hits"] = len(bound_hits)
    ev["observed"] = sorted({"%s@%s%s" % (f["pkg"], f["installed"],
                                          (" fix:" + f["fixed"]) if f["fixed"] else "")
                             for _, f in (bound_hits or pkg_hits or id_hits)})
    ev["architectures_evidenced"] = sorted({c["platform"] for c, _ in (bound_hits or pkg_hits or id_hits)})
    if not id_hits:
        return "absent", ev, "the advisory is not reported on any in-scope child"
    if not pkg_hits:
        return "selector-no-longer-resolves", ev, \
            "the advisory is present but never on a package this record binds"
    if not bound_hits:
        return "installed-version-changed", ev, \
            "the advisory is present on a bound package, at a version outside this record's binding"
    scanner_fix = sorted({f["fixed"] for _, f in bound_hits if f["fixed"]})
    ev["scanner_fixed_versions"] = scanner_fix
    if scanner_fix and entry.get("fix_available") is False:
        return "fix-now-available", ev, \
            "the scanner now offers a fixed version where the record declares none exists"
    # Is a PATCHED official base already published? Only an upstream-base head
    # scan can establish that, and only for the packages it owns.
    base_state = set()
    for c, f in bound_hits:
        key = BASE_FOR.get((c["family"], c["version"]))
        if not key:
            base_state.add("no-base-head-evidence")
            continue
        moved = moved_bases.get(key, False)
        if key not in heads:
            # No head scan because the tag never moved: the accepted child was
            # built from the digest the tag still points at.
            base_state.add("base-tag-unmoved" if not moved else "no-base-head-evidence")
            continue
        if is_vendored_go(f["pkg"]):
            hv = heads[key]["advisories"].get((cve, f["pkg"]))
            if hv is None:
                base_state.add("vendored-module-advisory-absent-from-head")
            elif any(iv != f["installed"] for iv, _ in hv):
                base_state.add("base-head-package-version-changed")
            else:
                base_state.add("head-moved-same-version" if moved else "head-unchanged")
            continue
        inv = heads[key]["inventory"]
        if inv and f["pkg"] not in inv:
            # The package is not in the base AT ALL. Nothing about the base can
            # remediate it and nothing about the base explains it: it entered
            # through a Foundry layer, so the remediation owner is Foundry.
            base_state.add("package-absent-from-base")
            continue
        head_versions = heads[key]["advisories"].get((cve, f["pkg"]))
        head_installed = inv.get(f["pkg"])
        if head_installed and head_installed != f["installed"]:
            base_state.add("base-head-package-version-changed")
        elif head_versions is None:
            base_state.add("advisory-absent-from-head-same-version")
        else:
            base_state.add("head-moved-same-version" if moved else "head-unchanged")
    ev["upstream_base_head_state"] = sorted(base_state)
    if "package-absent-from-base" in base_state:
        return "ownership-boundary-changed", ev, \
            "the bound package is not installed in the upstream base at all, so the finding is owned by a Foundry layer and not by the base the record names"
    if base_state and base_state <= {"vendored-module-advisory-absent-from-head"}:
        return "fix-now-available", ev, \
            "the moved upstream base head no longer vendors a vulnerable build of this module"
    if "base-head-package-version-changed" in base_state:
        return "fix-now-available", ev, \
            "the moved upstream base head carries the bound package at a different version — a newer official base is published"
    if "head-moved-same-version" in base_state:
        return "upstream-moved-unpatched", ev, \
            "the pinned base tag moved to a new digest and the new head still carries the bound package at the same unpatched version"
    return "still-present", ev, \
        "present on a bound package at a bound version; the upstream artifact has not moved"


BUCKETS = ("still-present", "absent", "installed-version-changed", "fix-now-available",
           "upstream-moved-unpatched", "evidence-unavailable",
           "selector-no-longer-resolves", "ownership-boundary-changed")


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--refresh-dir", required=True)
    ap.add_argument("--ledger", default=os.path.join(ROOT, "policies", "vulnerability-exceptions.yaml"))
    ap.add_argument("--moved-bases", default="")
    ap.add_argument("--out", default="")
    args = ap.parse_args(argv)

    import yaml
    from exception_id import exc_id
    led = yaml.safe_load(open(args.ledger))
    entries = led["exceptions"]
    children = load_children(args.refresh_dir)
    heads = load_base_heads(args.refresh_dir)
    moved = {}
    if args.moved_bases:
        moved = json.load(open(args.moved_bases))

    # The gate's own view, so a classification that disagrees with the enforcing
    # gate is surfaced instead of quietly overriding it.
    gate_matched = set()
    for f in glob.glob(os.path.join(args.refresh_dir, "reconciliations", "*.reconcile.json")):
        gate_matched |= set(json.load(open(f))["matched_exception_ids"])

    rows = []
    for i, e in enumerate(entries, 1):
        bucket, ev, why = classify(e, children, heads, moved)
        eid = exc_id(e)
        pkgs = packages_of(e) or []
        # Feed the ownership model what was ACTUALLY OBSERVED, not the record's
        # own claims and not a placeholder image. The model keys on installed
        # and fixed versions; passing an empty `--fixed` for a finding that has
        # one reports a vendored Go module as an unfixable distro package.
        obs = (ev.get("observed") or [""])[0]
        obs_pkg = obs.split("@")[0] if obs else (pkgs[0] if pkgs else "unknown")
        obs_ver = obs.split("@")[1].split(" fix:")[0] if "@" in obs else ""
        obs_fix = obs.split(" fix:")[1] if " fix:" in obs else ""
        first_child = (ev.get("in_scope_children") or ["unknown/unknown"])[0]
        label = "/".join(first_child.split("/")[:2])
        own = owner_of(label, obs_pkg, obs_ver, obs_fix,
                       "yes" if ev.get("upstream_base_head_state") == ["head-moved-same-version"] else "no")
        rows.append({
            "n": i, "exception_id": eid, "cve": e.get("cve"), "image_selector": e.get("image"),
            "packages": pkgs, "bound_version": e.get("installed_version"),
            "ledger_fix_available": e.get("fix_available"), "expires_at": str(e.get("expires_at")),
            "reachability": e.get("reachability"), "classification": bucket, "why": why,
            "evidence": ev, "matched_by_gate": eid in gate_matched,
            "remediation_owner": own.get("owner"),
            "rebuild_can_remediate": own.get("rebuild_can_remediate"),
            "root_cause_key": own.get("root_cause_key"),
        })
    report = {"schema_version": 1, "record_type": "expiry-refresh-classification",
              "entries_total": len(rows), "buckets": {}, "entries": rows}
    for r in rows:
        report["buckets"][r["classification"]] = report["buckets"].get(r["classification"], 0) + 1
    text = json.dumps(report, indent=2, default=str) + "\n"
    if args.out:
        open(args.out, "w").write(text)
        print("classification written: %s" % args.out)
    for k, v in sorted(report["buckets"].items()):
        print("%-32s %d" % (k, v))
    print("%-32s %d" % ("TOTAL", len(rows)))
    return 0


def _self_test():
    rc = 0

    def ck(name, cond):
        nonlocal rc
        print(("ok   " if cond else "FAIL ") + name)
        if not cond:
            rc = 1
    ck("a version-bounded cohort covers its own family", in_scope("php-frankenphp-8.3-8.4", "php-frankenphp", "8.3"))
    ck("a cohort does not cover another family", not in_scope("php-frankenphp-8.3-8.4", "php-fpm", "8.3"))
    ck("a cohort does not cover an unlisted version", not in_scope("php-8.3-8.4", "php-cli", "8.5"))
    ck("a non-PHP selector matches its family", in_scope("caddy", "caddy", "prod"))
    ck("a non-PHP selector does not match another", not in_scope("caddy", "nginx", "prod"))
    ck("'all' refuses an unevidenced PHP version", not in_scope("all", "php-cli", "8.5"))
    ck("an exact installed_version binds", version_binding_holds({"installed_version": "1.0"}, "p", "1.0"))
    ck("a moved version breaks the binding", not version_binding_holds({"installed_version": "1.0"}, "p", "1.1"))
    ck("a list binding is membership, not a range",
       version_binding_holds({"installed_version": ["1:2.0", "2.0"]}, "p", "2.0")
       and not version_binding_holds({"installed_version": ["1:2.0", "2.0"]}, "p", "2.1"))
    ck("package_versions fails closed for an unlisted package",
       not version_binding_holds({"package_versions": {"a": ["1"]}}, "b", "1"))
    ck("package_versions refuses a cross-matched tuple",
       not version_binding_holds({"package_versions": {"a": ["1:2"], "b": ["2"]}}, "b", "1:2"))
    ck("a record with no version binding still holds", version_binding_holds({}, "p", "9"))
    ck("packages_of normalises a scalar", packages_of({"package": "x"}) == ["x"])
    ck("packages_of keeps a set", packages_of({"package": ["a", "b"]}) == ["a", "b"])
    ck("a Go module path is vendored", is_vendored_go("github.com/getkin/kin-openapi")
       and is_vendored_go("google.golang.org/grpc") and is_vendored_go("golang.org/x/net"))
    ck("the Go toolchain pseudo-package is vendored", is_vendored_go("stdlib"))
    ck("a distro package is NOT vendored Go",
       not is_vendored_go("libaom3") and not is_vendored_go("libssl3")
       and not is_vendored_go("perl-base"))
    ck("every child family maps to a base", all(
        k in BASE_FOR for k in [("php-cli", "8.3"), ("php-fpm", "8.4"),
                                ("php-worker", "8.3"), ("php-frankenphp", "8.4"),
                                ("caddy", "prod"), ("nginx", "prod")]))
    ck("the bucket set is exactly the eight declared", len(BUCKETS) == 8 and len(set(BUCKETS)) == 8)
    print("classify-expiry-refresh.py: SELF-TEST %s (19 assertions)" % ("OK" if rc == 0 else "FAILED"))
    return rc


if __name__ == "__main__":
    sys.exit(_self_test() if "--self-test" in sys.argv else main())
