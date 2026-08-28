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
#   scripts/license/license-inventory.sh --bundle <evidence-bundle> [--out FILE]
#   scripts/license/license-inventory.sh --self-test
#
# --bundle is the RELEASE-PATH form. The gate could always consume the release
# path and nothing made it: it read a bare directory, so an inventory could be
# built over any SPDX files at all and still satisfy the policy, with nothing
# tying a licence verdict to a shipped artifact, an evidence class or a source
# revision. --bundle reads the SBOMs the evidence bundle SEALED — each already
# bound to its child's manifest digest and covered by the bundle's checksums —
# refuses a bundle whose bill of materials is incomplete, and stamps
# release_binding into the inventory so the verdict names what it is about.
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

usage() {
  sed -n '19,22p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 64
}

# -----------------------------------------------------------------------------
# build <sbom_dir> <out_or_dash>
# -----------------------------------------------------------------------------
build() {
  SBOM_DIR="$1" OUT="$2" BUNDLE="${3:-}" python3 <<'PY'
import json, os, sys, glob, hashlib

sbom_dir = os.environ["SBOM_DIR"]
out      = os.environ["OUT"]
bundle   = os.environ.get("BUNDLE") or ""

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


def norm_path(p):
    """One spelling for a file path across the two formats.

    SPDX writes `bin/busybox`; CycloneDX writes `/bin/busybox`. Two spellings of
    one path is how a cross-format lookup silently finds nothing and then reports
    the file as unattributable.
    """
    s = str(p or "").strip().replace("\\", "/")
    while s.startswith("./"):
        s = s[2:]
    return s.lstrip("/")


def subject_digests(doc):
    """The sha256 subjects a document names, used ONLY as a grouping key.

    This is deliberately NOT a binding check. assert-image-sbom-licences.sh owns
    the binding decision (does this document describe THIS child's manifest
    digest); here the digests only answer "are these two documents about the same
    image", so that ownership facts recorded in one format may be read for the
    other. An empty result costs a document nothing except cross-format
    attribution, which is the fail-closed direction: a file whose owner cannot be
    shown stays visible as unresolved.
    """
    subs = set()
    for v in doc.get("documentDescribes") or []:
        if isinstance(v, str) and v.strip():
            subs.add(v.strip().lower())
    pkgs = {p.get("SPDXID"): p for p in (doc.get("packages") or [])
            if isinstance(p, dict)}
    for rel in doc.get("relationships") or []:
        if not isinstance(rel, dict):
            continue
        if (rel.get("relationshipType") or "").upper() != "DESCRIBES":
            continue
        if (rel.get("spdxElementId") or "") != "SPDXRef-DOCUMENT":
            continue
        root = pkgs.get(rel.get("relatedSpdxElement"))
        if not isinstance(root, dict):
            continue
        cand = root.get("versionInfo")
        if isinstance(cand, str) and cand.strip().lower().startswith("sha256:"):
            subs.add(cand.strip().lower())
        for ck in root.get("checksums") or []:
            if isinstance(ck, dict) and (ck.get("algorithm") or "").upper() == "SHA256":
                v = str(ck.get("checksumValue") or "").strip().lower()
                if v:
                    subs.add(v if v.startswith("sha256:") else "sha256:" + v)
        for r in root.get("externalRefs") or []:
            loc = str((r or {}).get("referenceLocator") or "")
            loc = loc.replace("%3A", ":").replace("%3a", ":")
            if "sha256:" in loc:
                tail = loc.rsplit("sha256:", 1)[1].strip().lower()
                tail = tail.split("?", 1)[0].split("#", 1)[0]
                if tail:
                    subs.add("sha256:" + tail)
    comp = ((doc.get("metadata") or {}).get("component") or {})
    if isinstance(comp, dict):
        for h in comp.get("hashes") or []:
            if isinstance(h, dict) and h.get("content"):
                alg = (h.get("alg") or "SHA-256").lower().replace("-", "")
                subs.add("%s:%s" % ("sha256" if alg == "sha256" else alg,
                                    str(h["content"]).strip().lower()))
        for ref in (comp.get("purl"), comp.get("bom-ref"), comp.get("version")):
            if isinstance(ref, str):
                r2 = ref.replace("%3A", ":").replace("%3a", ":")
                if "sha256:" in r2:
                    tail = r2.rsplit("sha256:", 1)[1].strip().lower()
                    tail = tail.split("?", 1)[0].split("#", 1)[0]
                    if tail:
                        subs.add("sha256:" + tail)
    return {s for s in subs if s.startswith("sha256:")}


# =============================================================================
# THE FILE-COMPONENT EVIDENCE MODEL
# -----------------------------------------------------------------------------
# Three distinct things live in this pipeline and conflating any two of them is
# the defect this code exists to prevent:
#
#   1. package / library / application components  -> package licence policy
#   2. policies/repository-material.yaml           -> copied material IN THE TREE
#   3. independently licensed files inside images  -> need an EXPLICIT disposition
#
# (2) does NOT cover (3). Material introduced only inside a container image is
# never in the tree, so the repository-material inventory cannot see it and must
# never be cited as covering it.
#
# EVERY CycloneDX `type: "file"` component, and EVERY SPDX `files[]` entry (which
# this parser previously did not look at AT ALL — a file-level blind spot on the
# other half of the same evidence), receives exactly ONE of four classifications,
# each with a mechanically recorded reason. No component may disappear without a
# recorded classification and reason.
#
#   scanner-observation     the scanner recorded a path and a hash and NOTHING
#                           else. Excludable from package-policy findings ONLY
#                           when ALL of the following hold and are recorded:
#                             - no independent licence assertion
#                             - no external provenance suggesting separately
#                               distributed material (no purl, cpe, supplier,
#                               publisher, author, copyright, externalReferences)
#                             - no evidence of local modification (no `modified`,
#                               no `pedigree`, no patch/variant/commit record, no
#                               attribution or notice text, no fileContributors)
#                             - no conflicting licence metadata
#                             - an edge to the file is shown, so the document
#                               positions it as image content rather than leaving
#                               it unaccounted
#   package-attributed      an OWNING PACKAGE is proven, and the file's licence
#                           obligation is INHERITED from it. Deduplicating the
#                           file against its owner does NOT remove an obligation:
#                           the obligation still exists and is now counted once,
#                           on the package, instead of N times, on N paths.
#                           Ownership must be proven through a STABLE SBOM
#                           RELATIONSHIP or package-manager evidence:
#                             - SPDX `Package CONTAINS File`
#                             - syft's `evident-by` OTHER relationship
#                             - a CycloneDX `dependencies` edge
#                           Filename similarity, installation path and a shared
#                           version are NOT sufficient and are never used. Where
#                           the relationship is read from the SPDX companion of
#                           the same image subject, the join is the exact path
#                           WITHIN ONE SCAN OF ONE SUBJECT and, when both
#                           documents carry a digest for the file, the digests
#                           must agree — a differing digest revokes the
#                           attribution rather than tolerating it.
#                           Recorded per file: owning package identity, package
#                           version, relationship evidence, inherited licence
#                           expression, and whether the file carries exceptional
#                           or conflicting licence metadata.
#                           A package-owned file that carries an INDEPENDENT or
#                           CONFLICTING licence declaration is NOT attributed —
#                           it stays visible.
#   independently-licensed  the document asserts a licence for the file, or gives
#                           it its own purl / cpe / supplier / publisher / author
#                           / copyright / externalReference, or records local
#                           modification, or its licence metadata conflicts.
#   unresolved              anything else. No edge was shown, so no owner was
#                           shown, so nothing has been established. ABSENCE OF
#                           METADATA IS NOT EVIDENCE OF ABSENCE OF LICENCE:
#                           deleting a file's licence metadata moves it here, to
#                           a visible class, never to scanner-observation.
#
# ONLY `scanner-observation` and `package-attributed` are withheld from package
# licence policy, and BOTH require an edge to have been SHOWN. Assumption is
# never sufficient: "syft is configured owned-by-package so these must be owned"
# is a claim about a config file, not about the document in hand, and this parser
# will not make it.
#
# `independently-licensed` and `unresolved` files are ADDED TO `components[]` and
# therefore reach the policy gate exactly like a package would. That is what
# makes the following evasion impossible: relabelling an independently licensed
# component as `type: "file"` does not remove it from package policy, because the
# licence identity is tested BEFORE any type-based exclusion.
#
# ACCOUNTING INVARIANT, asserted rather than reported:
#
#     input file components == scanner-observation + package-attributed
#                              + independently-licensed + unresolved
#
# An unaccounted component is a REFUSAL, not a rounding difference.
# =============================================================================

CLASS_SCANNER = "scanner-observation"
CLASS_ATTRIBUTED = "package-attributed"
CLASS_INDEPENDENT = "independently-licensed"
CLASS_UNRESOLVED = "unresolved"
FILE_CLASSES = (CLASS_SCANNER, CLASS_ATTRIBUTED, CLASS_INDEPENDENT,
                CLASS_UNRESOLVED)
FILE_CLASS_EXCLUDED = (CLASS_SCANNER, CLASS_ATTRIBUTED)
FILE_CLASS_VISIBLE = (CLASS_INDEPENDENT, CLASS_UNRESOLVED)

PROVENANCE_FIELDS = ("purl", "cpe", "supplier", "publisher", "author",
                     "copyright", "external_refs")


def classify_file(e):
    """e -> (class, reason). Every branch records WHY, mechanically."""
    lics = e["licences"]

    # --- conflicting licence metadata: visible, always ----------------------
    # Two different identifiers asserted for one file is a disagreement about an
    # obligation. It is never a scanner artifact and it is never inheritable.
    if len(lics) > 1:
        return (CLASS_INDEPENDENT,
                "the document asserts %d different licence identifiers for this "
                "file (%s); a disagreement about an obligation is not "
                "inheritable from an owning package"
                % (len(lics), ", ".join(lics)))

    # --- an independent licence identity: visible, always -------------------
    if lics:
        owned = ("; its owning package %s asserts %s, which %s"
                 % (", ".join(sorted(e["owner_purls"])[:3]),
                    ", ".join(sorted(e["owner_licences"])) or "nothing",
                    "differs" if (e["owner_licences"] and
                                  set(e["owner_licences"]) != set(lics))
                    else "does not resolve the file's own declaration")
                 ) if e["owner_purls"] else ""
        return (CLASS_INDEPENDENT,
                "the document asserts licence %s for this file%s"
                % (lics[0], owned))
    for k in PROVENANCE_FIELDS:
        if e.get(k):
            return (CLASS_INDEPENDENT,
                    "the file carries external provenance of its own (%s=%s), "
                    "which suggests separately distributed material"
                    % (k, str(e[k])[:120]))
    if e.get("modified"):
        return (CLASS_INDEPENDENT,
                "the document records local modification (%s); a modified file "
                "carries obligations its unmodified upstream does not"
                % str(e["modified"])[:160])

    # --- an owner PROVEN by a stable relationship ---------------------------
    if e["owner_purls"]:
        return (CLASS_ATTRIBUTED,
                "owned by %s (version %s) via %s; licence obligation INHERITED "
                "as %s and counted once on the package rather than once per "
                "path — the obligation is not removed, it is de-duplicated"
                % (", ".join(sorted(e["owner_purls"])[:4]),
                   ", ".join(sorted(e["owner_versions"])[:4]) or "unstated",
                   ", ".join(sorted(e["owner_relationships"])) or "unstated",
                   ", ".join(sorted(e["owner_licences"])) or "NOASSERTION"))

    # --- a bare observation, with an edge but no package identity -----------
    if e["owners_any"]:
        return (CLASS_SCANNER,
                "an edge to this file is shown from %s, which carries no package "
                "identity; the document asserts no licence, no purl, no cpe, no "
                "supplier, publisher, author, copyright or external reference "
                "for it, records no local modification, and its licence metadata "
                "does not conflict"
                % ", ".join(sorted(e["owners_any"])[:4]))

    return (CLASS_UNRESOLVED,
            "no edge to this file is shown anywhere in the document set, so no "
            "owning package has been established; the absence of licence "
            "metadata is not evidence that no licence applies, so this file is "
            "reported rather than excluded")


records = {}   # (name, version) -> record
file_entries = []


def add(name, version, ident, source_file, fmt, field, raw, ctype="package",
        fclass=None, fjust=None):
    key = (name or "", version or "")
    r = records.setdefault(key, {
        "name": key[0], "version": key[1],
        "licenses": [], "sources": [], "purls": [],
        "component_type": ctype,
    })
    if ctype == "file":
        r["component_type"] = "file"
        if fclass:
            r["file_class"] = fclass
        if fjust:
            r["file_justification"] = fjust
    r["sources"].append({
        "file": os.path.basename(source_file), "format": fmt,
        "field": field, "value": raw if raw is not None else "",
        "normalised": ident,
    })
    for i in ident:
        if i not in r["licenses"]:
            r["licenses"].append(i)


files = sorted(glob.glob(os.path.join(sbom_dir, "*.json")))
if bundle:
    # Read exactly the documents the bundle SEALED as SBOMs. content/sbom/ also
    # holds INDEX.json, which is the bundle's own index and is not a bill of
    # materials — globbing it in made the inventory refuse the release path it
    # was added to consume.
    _man_p = os.path.join(bundle, "manifest.json")
    if not os.path.exists(_man_p):
        sys.stderr.write("REFUSE: %r is not an evidence bundle (no manifest.json). "
                         "A licence verdict bound to nothing is not a release "
                         "control\n" % bundle)
        raise SystemExit(1)
    _sealed = set()
    for _c in json.load(open(_man_p)).get("children") or []:
        if _c.get("sbom"):
            _sealed.add(os.path.basename(_c["sbom"]["file"]))
            for _cp in _c["sbom"].get("companions") or []:
                _sealed.add(os.path.basename(_cp["file"]))
    files = [f for f in files if os.path.basename(f) in _sealed]
    if not files:
        sys.stderr.write("REFUSE: the bundle at %r seals no SBOM. A licence "
                         "verdict over an empty bill of materials is a clean "
                         "verdict about nothing\n" % bundle)
        raise SystemExit(1)

# --- pass 1: load and identify every document -------------------------------
loaded = []
for f in files:
    try:
        with open(f) as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as e:
        sys.stderr.write("REFUSE: %s is not readable JSON: %s\n" % (f, e))
        raise SystemExit(1)
    if "spdxVersion" in doc or "SPDXID" in doc:
        loaded.append((f, "spdx", doc))
    elif doc.get("bomFormat") == "CycloneDX" or "components" in doc:
        loaded.append((f, "cyclonedx", doc))
    else:
        sys.stderr.write("REFUSE: %s is neither SPDX nor CycloneDX\n" % f)
        raise SystemExit(1)

# --- pass 2: file ownership, per image subject ------------------------------
# SPDX states file ownership explicitly (`Package CONTAINS File`, and syft's
# `evident-by` OTHER relationship for a binary a package was detected from).
# CycloneDX has no containment concept, so syft's CycloneDX file components can
# arrive with no in-document owner at all. Reading the SPDX companion of the SAME
# image subject is what makes the CycloneDX exclusion mechanically justified
# instead of assumed. Two guards keep that from degenerating into a filename
# join: the two documents must name the SAME sha256 subject, and where both
# carry a digest for the file the digests must AGREE.
spdx_owner_index = {}   # subject -> {path: [owner dicts]}
spdx_edge_index = {}    # subject -> {path: set(labels of any edge)}
spdx_hash_index = {}    # subject -> {path: {alg: value}}


def _pkg_purl(pkg):
    for r in pkg.get("externalRefs") or []:
        if isinstance(r, dict) and r.get("referenceType") == "purl":
            return str(r.get("referenceLocator") or "")
    return ""


def _pkg_licences(pkg):
    out = set()
    for fld in ("licenseConcluded", "licenseDeclared"):
        out.update(norm(pkg.get(fld)))
    return sorted(out)


def _checksums(obj, key):
    out = {}
    for ck in obj.get(key) or []:
        if isinstance(ck, dict):
            alg = str(ck.get("algorithm") or ck.get("alg") or "").upper().replace("-", "")
            val = str(ck.get("checksumValue") or ck.get("content") or "").strip().lower()
            if alg and val:
                out[alg] = val
    return out


for f, kind, doc in loaded:
    if kind != "spdx":
        continue
    subs = subject_digests(doc)
    if not subs:
        continue
    pkgs = {p.get("SPDXID"): p for p in (doc.get("packages") or [])
            if isinstance(p, dict)}
    fmap = {fl.get("SPDXID"): fl for fl in (doc.get("files") or [])
            if isinstance(fl, dict)}
    owners, edges, hashes = {}, {}, {}
    for fl in fmap.values():
        pth = norm_path(fl.get("fileName"))
        if pth:
            h = _checksums(fl, "checksums")
            if h:
                hashes[pth] = h
    for rel in doc.get("relationships") or []:
        if not isinstance(rel, dict):
            continue
        rt = (rel.get("relationshipType") or "").upper()
        if rt not in ("CONTAINS", "OTHER"):
            continue
        evidence = "SPDX:CONTAINS"
        if rt == "OTHER":
            if "evident-by" not in str(rel.get("comment") or ""):
                continue
            evidence = "SPDX:OTHER(evident-by)"
        owner = pkgs.get(rel.get("spdxElementId"))
        target = fmap.get(rel.get("relatedSpdxElement"))
        if not isinstance(owner, dict) or not isinstance(target, dict):
            continue
        path = norm_path(target.get("fileName"))
        if not path:
            continue
        purl = _pkg_purl(owner)
        edges.setdefault(path, set()).add(purl or str(owner.get("name") or "?"))
        if purl.startswith("pkg:"):
            owners.setdefault(path, []).append({
                "purl": purl,
                "name": str(owner.get("name") or ""),
                "version": str(owner.get("versionInfo") or ""),
                "licences": _pkg_licences(owner),
                "relationship": evidence,
            })
    for sub in subs:
        d = spdx_owner_index.setdefault(sub, {})
        for k, v in owners.items():
            d.setdefault(k, []).extend(v)
        d2 = spdx_edge_index.setdefault(sub, {})
        for k, v in edges.items():
            d2.setdefault(k, set()).update(v)
        d3 = spdx_hash_index.setdefault(sub, {})
        for k, v in hashes.items():
            d3.setdefault(k, {}).update(v)


def owner_facts(owner_list):
    """Flatten proven owners into the fields a disposition must record."""
    return {
        "owner_purls": {o["purl"] for o in owner_list},
        "owner_versions": {o["version"] for o in owner_list if o["version"]},
        "owner_licences": {lic for o in owner_list for lic in o["licences"]},
        "owner_relationships": {o["relationship"] for o in owner_list},
    }


# --- pass 3: components ------------------------------------------------------
parsed = []
for f, kind, doc in loaded:
    subs = subject_digests(doc)
    x_owner, x_edge, x_hash = {}, {}, {}
    for s in subs:
        for k, v in (spdx_owner_index.get(s) or {}).items():
            x_owner.setdefault(k, []).extend(v)
        for k, v in (spdx_edge_index.get(s) or {}).items():
            x_edge.setdefault(k, set()).update(v)
        for k, v in (spdx_hash_index.get(s) or {}).items():
            x_hash.setdefault(k, {}).update(v)

    if kind == "spdx":
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
        # SPDX files[] were previously read by NOTHING. A parser that fixes the
        # CycloneDX file blind spot while leaving the SPDX one open has moved the
        # blind spot, not closed it.
        for fl in doc.get("files") or []:
            if not isinstance(fl, dict):
                continue
            path = norm_path(fl.get("fileName"))
            lics = set()
            for v in [fl.get("licenseConcluded")] + list(fl.get("licenseInfoInFiles") or []):
                lics.update(norm(v))
            modified = ""
            for k in ("noticeText", "attributionTexts", "fileContributors",
                      "licenseComments"):
                if fl.get(k):
                    modified = "%s present" % k
                    break
            cp = str(fl.get("copyrightText") or "").strip()
            e = {
                "path": path, "licences": sorted(lics), "purl": "",
                "cpe": "", "supplier": "", "publisher": "", "author": "",
                "copyright": cp if cp and cp.lower() not in UNKNOWN_TOKENS else "",
                "external_refs": False, "modified": modified,
                "owners_any": set(x_edge.get(path) or ()),
            }
            e.update(owner_facts(x_owner.get(path) or []))
            cls, why = classify_file(e)
            file_entries.append({
                "path": path, "format": "spdx", "document": os.path.basename(f),
                "class": cls, "reason": why, "licenses": sorted(lics),
                "owner_purls": sorted(e["owner_purls"])[:8],
                "owner_versions": sorted(e["owner_versions"])[:8],
                "owner_relationships": sorted(e["owner_relationships"]),
                "inherited_licence_expression": sorted(e["owner_licences"]),
                "conflicting_or_exceptional_licence_metadata": (
                    len(lics) > 1
                    or bool(lics and e["owner_licences"]
                            and set(lics) != set(e["owner_licences"]))),
            })
            if cls in FILE_CLASS_VISIBLE:
                # ONE canonical spelling for a file component, so that the SPDX
                # entry and the CycloneDX entry for the same file collapse onto
                # one record instead of being counted twice under `bin/busybox`
                # and `/bin/busybox`.
                for v in sorted(lics) or [None]:
                    add("/" + path, "", norm(v), f, "spdx",
                        "licenseInfoInFiles", v,
                        ctype="file", fclass=cls, fjust=why)

    else:
        parsed.append((f, "cyclonedx"))
        comps = [c for c in (doc.get("components") or []) if isinstance(c, dict)]
        byref = {}
        for c in comps:
            ref = c.get("bom-ref")
            if isinstance(ref, str):
                byref[ref] = c
        # CycloneDX's own dependency graph, read in both directions. `dependsOn`
        # is a dependency edge, not a containment edge, so it is only ever
        # EVIDENCE THAT AN EDGE EXISTS; package ownership additionally requires
        # the other endpoint to carry a pkg: purl.
        edges = {}
        for d in doc.get("dependencies") or []:
            if not isinstance(d, dict):
                continue
            a = d.get("ref")
            for b in d.get("dependsOn") or []:
                if not isinstance(a, str) or not isinstance(b, str):
                    continue
                edges.setdefault(a, set()).add(b)
                edges.setdefault(b, set()).add(a)

        for c in comps:
            ctype = str(c.get("type") or "").strip().lower()
            nm, ver = c.get("name"), c.get("version")
            lic = c.get("licenses") or []

            if ctype == "file":
                path = norm_path(nm)
                lics = set()
                for entry in lic:
                    if not isinstance(entry, dict):
                        continue
                    if "expression" in entry:
                        lics.update(norm(entry["expression"]))
                    else:
                        lo = entry.get("license") or {}
                        lics.update(norm(lo.get("id") or lo.get("name")))

                # Cross-document attribution is a join on ONE subject and ONE
                # path, and it is REVOKED when the two documents disagree about
                # the file's digest. A shared filename with a different content
                # hash is a different file, and inheriting an owner across that
                # is exactly the "filename similarity" reasoning this must not do.
                own_list = list(x_owner.get(path) or [])
                owners_any = set(x_edge.get(path) or ())
                digest_conflict = ""
                cdx_h = _checksums(c, "hashes")
                spdx_h = x_hash.get(path) or {}
                for alg in set(cdx_h) & set(spdx_h):
                    if cdx_h[alg] != spdx_h[alg]:
                        digest_conflict = ("the SPDX companion records %s %s for "
                                           "this path and the CycloneDX document "
                                           "records %s" % (alg, spdx_h[alg], cdx_h[alg]))
                        break
                if digest_conflict:
                    own_list, owners_any = [], set()

                ref = c.get("bom-ref")
                for other in (edges.get(ref, ()) if isinstance(ref, str) else ()):
                    oc = byref.get(other) or {}
                    label = str(oc.get("purl") or oc.get("name") or other)
                    owners_any.add(label)
                    if str(oc.get("type") or "").lower() != "file" \
                       and str(oc.get("purl") or "").startswith("pkg:"):
                        olic = set()
                        for entry in oc.get("licenses") or []:
                            if not isinstance(entry, dict):
                                continue
                            if "expression" in entry:
                                olic.update(norm(entry["expression"]))
                            else:
                                lo = entry.get("license") or {}
                                olic.update(norm(lo.get("id") or lo.get("name")))
                        own_list.append({
                            "purl": oc["purl"], "name": str(oc.get("name") or ""),
                            "version": str(oc.get("version") or ""),
                            "licences": sorted(olic),
                            "relationship": "CycloneDX:dependencies",
                        })
                sup = c.get("supplier") or {}
                ped = c.get("pedigree") or {}
                modified = ""
                if c.get("modified"):
                    modified = "component.modified is true"
                elif isinstance(ped, dict) and any(
                        ped.get(k) for k in ("patches", "variants", "commits",
                                             "ancestors", "descendants")):
                    modified = "component.pedigree records %s" % ", ".join(
                        sorted(k for k in ("patches", "variants", "commits",
                                           "ancestors", "descendants") if ped.get(k)))
                elif digest_conflict:
                    modified = digest_conflict
                e = {
                    "path": path, "licences": sorted(lics),
                    "purl": str(c.get("purl") or ""),
                    "cpe": str(c.get("cpe") or ""),
                    "supplier": (sup.get("name") if isinstance(sup, dict) else "") or "",
                    "publisher": str(c.get("publisher") or ""),
                    "author": str(c.get("author") or ""),
                    "copyright": str(c.get("copyright") or ""),
                    "external_refs": bool(c.get("externalReferences")),
                    "modified": modified,
                    "owners_any": owners_any,
                }
                e.update(owner_facts(own_list))
                cls, why = classify_file(e)
                file_entries.append({
                    "path": path, "format": "cyclonedx",
                    "document": os.path.basename(f),
                    "class": cls, "reason": why, "licenses": sorted(lics),
                    "owner_purls": sorted(e["owner_purls"])[:8],
                    "owner_versions": sorted(e["owner_versions"])[:8],
                    "owner_relationships": sorted(e["owner_relationships"]),
                    "inherited_licence_expression": sorted(e["owner_licences"]),
                    "conflicting_or_exceptional_licence_metadata": (
                        len(lics) > 1
                        or bool(lics and e["owner_licences"]
                                and set(lics) != set(e["owner_licences"]))),
                })
                if cls in FILE_CLASS_VISIBLE:
                    canon_name = "/" + path
                    if not lics:
                        add(canon_name, "", [], f, "cyclonedx", "licenses", None,
                            ctype="file", fclass=cls, fjust=why)
                    for v in sorted(lics):
                        add(canon_name, "", norm(v), f, "cyclonedx", "license", v,
                            ctype="file", fclass=cls, fjust=why)
                    if c.get("purl"):
                        key = (canon_name, "")
                        if c["purl"] not in records[key]["purls"]:
                            records[key]["purls"].append(c["purl"])
                continue

            # --- an ordinary software component ------------------------------
            if not lic:
                add(nm, ver, [], f, "cyclonedx", "licenses", None)
            for entry in lic:
                if not isinstance(entry, dict):
                    continue
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

# --- the file-component disposition, and the accounting invariant ------------
# Reported ALWAYS, including the excluded classes, because a findings total that
# went down without naming what moved is not a measurement. The invariant is
# ASSERTED, not printed: an unaccounted component is a refusal.
fc_counts = {k: 0 for k in FILE_CLASSES}
uniq = {}
for e in file_entries:
    if e["class"] not in fc_counts:
        sys.stderr.write("REFUSE: file component %r received class %r, which is "
                         "not one of the four declared dispositions\n"
                         % (e["path"], e["class"]))
        raise SystemExit(1)
    if not e.get("reason"):
        sys.stderr.write("REFUSE: file component %r was classified %r with no "
                         "recorded reason. A component may not disappear without "
                         "one\n" % (e["path"], e["class"]))
        raise SystemExit(1)
    fc_counts[e["class"]] += 1
    uniq.setdefault((e["class"], e["path"]), e)

_accounted = sum(fc_counts.values())
if _accounted != len(file_entries):
    sys.stderr.write(
        "REFUSE: %d file component(s) went in and %d were accounted for across "
        "%s. An unaccounted component is a component nobody decided anything "
        "about\n" % (len(file_entries), _accounted, list(FILE_CLASSES)))
    raise SystemExit(1)

_kept = sum(1 for c in components if c.get("component_type") == "file")
_kept_expected = len({e["path"] for e in file_entries
                      if e["class"] in FILE_CLASS_VISIBLE})
if _kept != _kept_expected:
    sys.stderr.write(
        "REFUSE: %d file component(s) are classified visible "
        "(independently-licensed or unresolved) but %d reached components[]. A "
        "visible class that does not reach the policy gate is a blind spot with "
        "a label on it\n" % (_kept_expected, _kept))
    raise SystemExit(1)

uniq_counts = {k: 0 for k in FILE_CLASSES}
for (cls, _p) in uniq:
    uniq_counts[cls] += 1


def _disposition(e):
    d = {"path": e["path"], "document": e["document"], "class": e["class"],
         "reason": e["reason"], "licenses": e["licenses"]}
    if e["owner_purls"]:
        d["owning_package"] = e["owner_purls"]
        d["owning_package_version"] = e["owner_versions"]
        d["relationship_evidence"] = e["owner_relationships"]
        d["inherited_licence_expression"] = e["inherited_licence_expression"]
    d["conflicting_or_exceptional_licence_metadata"] = \
        e["conflicting_or_exceptional_licence_metadata"]
    return d


image_files = {
    "model": "foundry.image-file-disposition/v2",
    "input_file_components": len(file_entries),
    "by_class_observations": fc_counts,
    "by_class_distinct_paths": uniq_counts,
    "accounting_invariant": (
        "input file components == %d == scanner-observation %d + "
        "package-attributed %d + independently-licensed %d + unresolved %d"
        % (len(file_entries), fc_counts[CLASS_SCANNER],
           fc_counts[CLASS_ATTRIBUTED], fc_counts[CLASS_INDEPENDENT],
           fc_counts[CLASS_UNRESOLVED])),
    "accounting_invariant_holds": True,
    "excluded_from_package_policy": list(FILE_CLASS_EXCLUDED),
    "kept_in_package_policy": list(FILE_CLASS_VISIBLE),
    "raw_file_components": len(file_entries),
    "normalised_policy_findings_from_files": _kept,
    "deduplication_note": (
        "package-attributed files are DE-DUPLICATED against their owning "
        "package, not exempted. The obligation inherited from the owner still "
        "exists; it is counted once, on the package, instead of once per path. "
        "Nothing here removes an obligation."),
    "independently_licensed": sorted(
        [_disposition(e) for (c, _p), e in uniq.items()
         if c == CLASS_INDEPENDENT], key=lambda x: x["path"])[:2000],
    "unresolved": sorted(
        [_disposition(e) for (c, _p), e in uniq.items()
         if c == CLASS_UNRESOLVED], key=lambda x: x["path"])[:2000],
    "package_attributed_sample": sorted(
        [_disposition(e) for (c, _p), e in uniq.items()
         if c == CLASS_ATTRIBUTED], key=lambda x: x["path"])[:50],
    "scanner_observation_sample": sorted(
        [_disposition(e) for (c, _p), e in uniq.items()
         if c == CLASS_SCANNER], key=lambda x: x["path"])[:50],
    "note": ("policies/repository-material.yaml covers copied material IN THE "
             "REPOSITORY and does NOT cover files introduced only inside a "
             "container image; those files are never in the tree. This block is "
             "their disposition. independently-licensed and unresolved entries "
             "are ALSO present in components[] and reach the licence policy gate."),
}

# --- the release binding -----------------------------------------------------
# WHAT WAS WRONG. The gate CAN consume the release path and nothing made it: it
# read a bare directory of SPDX files, so an inventory could be built over any
# SBOMs at all and still satisfy the gate. Nothing tied a licence verdict to a
# shipped artifact, an evidence class or a source revision — the two halves
# never met on one artifact.
#
# --bundle binds them. The SBOMs are the ones the evidence bundle SEALED
# (content/sbom/, each already bound to its child's manifest digest and covered
# by the bundle's checksums), and the inventory records which bundle, which
# evidence_class and which source_revision it is a licence verdict FOR.
release_binding = None
if bundle:
    man_p = os.path.join(bundle, "manifest.json")
    if not os.path.exists(man_p):
        sys.stderr.write("REFUSE: %r is not an evidence bundle (no manifest.json). "
                         "A licence verdict bound to nothing is not a release "
                         "control\n" % bundle)
        raise SystemExit(1)
    man = json.load(open(man_p))
    sb = man.get("sbom") or {}
    if not sb.get("complete"):
        sys.stderr.write(
            "REFUSE: the bundle's bill of materials is not complete "
            "(present=%r, %s of %s children). A licence inventory over a partial "
            "SBOM set reports a clean verdict for the components it happened to "
            "see\n" % (sb.get("present"), sb.get("children_with_sbom"),
                       sb.get("children_total")))
        raise SystemExit(1)
    sealed = set()
    for c in man["children"]:
        if c.get("sbom"):
            sealed.add(os.path.basename(c["sbom"]["file"]))
            for cp in c["sbom"].get("companions") or []:
                sealed.add(os.path.basename(cp["file"]))
    seen = {os.path.basename(f) for f, _ in parsed}
    if seen != sealed:
        sys.stderr.write(
            "REFUSE: the inventory read %d SBOM file(s); the bundle seals %d, and "
            "the sets differ by %s. An inventory over documents the bundle did "
            "not seal is not a verdict about what shipped\n"
            % (len(seen), len(sealed), ", ".join(sorted(seen ^ sealed))[:200]))
        raise SystemExit(1)
    release_binding = {
        "bundle_id": man["bundle_id"],
        "evidence_class": man["evidence_class"],
        "source_revision": man["source_revision"],
        "bundle_content_checksum": man["checksums"]["content_checksum"],
        "children_total": sb["children_total"],
        "sbom_complete": True,
    }

doc = {
    "schema": "foundry.license-inventory/v1",
    "release_binding": release_binding,
    "sbom_files": [os.path.basename(f) for f, _ in parsed],
    "sbom_formats": sorted({fmt for _, fmt in parsed}),
    "component_count": len(components),
    "unknown_count": sum(1 for c in components if c["unknown"]),
    "conflict_count": sum(1 for c in components if c["conflict"]),
    "package_component_count": sum(1 for c in components
                                   if c.get("component_type") != "file"),
    "file_component_count": sum(1 for c in components
                                if c.get("component_type") == "file"),
    "image_files": image_files,
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
print("components: %d (packages %d, files kept %d), unknown: %d, conflicting: %d"
      % (doc["component_count"], doc["package_component_count"],
         doc["file_component_count"], doc["unknown_count"], doc["conflict_count"]))
print("image file components (raw): %d = scanner-observation %d + "
      "package-attributed %d + independently-licensed %d + unresolved %d"
      % (image_files["input_file_components"],
         image_files["by_class_observations"][CLASS_SCANNER],
         image_files["by_class_observations"][CLASS_ATTRIBUTED],
         image_files["by_class_observations"][CLASS_INDEPENDENT],
         image_files["by_class_observations"][CLASS_UNRESOLVED]))
print("normalised policy findings from files: %d (the excluded classes are "
      "de-duplicated against an owning package or recorded as bare scanner "
      "observations; no obligation is removed)"
      % image_files["normalised_policy_findings_from_files"])
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
  local dir="" out="-" bundle=""
  case "${1:-}" in
    --self-test) self_test; exit $? ;;
    "") usage ;;
  esac
  while [ $# -gt 0 ]; do
    case "$1" in
      --sbom-dir) dir="${2:-}"; shift 2 ;;
      --bundle)   bundle="${2:-}"; shift 2 ;;
      --out)      out="${2:-}"; shift 2 ;;
      *) usage ;;
    esac
  done
  # --bundle is the release-path form: the SBOMs are the ones the evidence
  # bundle sealed, and the inventory records the evidence_class and revision it
  # is a verdict FOR.
  if [ -n "$bundle" ] && [ -z "$dir" ]; then dir="$bundle/content/sbom"; fi
  [ -n "$dir" ] || usage
  cd "$ROOT" || exit 1
  build "$dir" "$out" "$bundle"
}

main "$@"
