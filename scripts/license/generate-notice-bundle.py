#!/usr/bin/env python3
# =============================================================================
# scripts/license/generate-notice-bundle.py
#   THE canonical distribution-notice and source-obligation producer. Issue #120.
# -----------------------------------------------------------------------------
# WHAT WAS MISSING, EXACTLY.
#
# #120's remaining criterion reads, literally:
#
#     "Produce third-party notices and preserve corresponding license
#      texts/source-offer obligations."
#
# scripts/license/generate-notice.sh renders an attribution list out of a
# normalised inventory. That is one of the four things the criterion asks for.
# It is bound to no candidate, it carries no licence text, it knows nothing
# about a source obligation, and nothing consumes its output — so a release
# could be authorized with no notice material at all and no check would move.
#
# This producer is the other three. It is deterministic, it is fail-closed, and
# its verdict is an INPUT to the canonical authorization rather than a report
# filed beside it (scripts/release/validate-authorization-record.sh
# --require-notice-bundle).
#
# WHAT IT REFUSES TO DO.
#
#   * It never decides a legal question. Reciprocal obligations, source-offer
#     sufficiency, "OR" elections and outbound terms are #98's and counsel's.
#   * It never marks an obligation satisfied. There is no field an engineer can
#     set to make a source obligation go away; `satisfied` comes only from an
#     approval record this repository does not yet have.
#   * It never emits a bundle that LOOKS complete. A refusal writes its draft —
#     a refusal that produces nothing is a refusal nobody can read afterwards —
#     and the draft is stamped `draft: true`, `satisfies_authorization: false`.
#
# THE BUNDLE IS SCOPED TO A CANDIDATE, NOT TO THE PROJECT.
#
# It is written under a release-evidence directory and never as a root NOTICE.
# A root NOTICE beside a LICENSE that declares itself a placeholder would read
# as Zenchron Foundry's own outbound terms, which are undetermined (#98). The
# bundle says what the CANDIDATE IMAGES carry; it says nothing about what
# Foundry grants.
#
# DETERMINISM. The same ordered inputs produce byte-identical outputs. There are
# NO non-reproducible fields — no generation timestamp, no hostname, no run id.
# Every collection is sorted. `--out-dir` is the only thing that varies and it
# does not reach the content. Asserted in tests/license/test_notice_bundle.sh by
# producing twice into different directories and comparing bytes.
#
# EVERY REFUSAL CARRIES ITS OWN CODE. "It failed" is not a diagnostic.
#
#   NB-INPUT-ABSENT            a declared input is missing or empty
#   NB-INPUT-MALFORMED         an input is not the document type it must be
#   NB-BINDING-ABSENT          the inventory is not bound to any candidate
#   NB-BINDING-INCOMPLETE      it binds fewer children than it expected
#   NB-REVISION-MISMATCH       evidence from a different source revision
#   NB-DIGEST-MISMATCH         evidence for a different image digest
#   NB-PLATFORM-MISMATCH       evidence for a different platform
#   NB-MATRIX-MISMATCH         the candidate matrix disagrees with the record
#   NB-DISPOSITION-MISSING     a distributed component with no licence
#                              disposition from any of the four sources
#   NB-CONFLICT-UNRESOLVED     component and file evidence still disagree
#   NB-ATTRIBUTION-UNSUPPORTED a package-attributed file with no relationship
#   NB-FILE-INDEPENDENT-UNTREATED  an independently licensed image file with
#                              no recorded treatment
#   NB-FILE-UNRESOLVED         an unresolved image file remains
#   NB-LICENCE-TEXT-MISSING    a required licence text is not carried
#   NB-LICENCE-TEXT-HASH       a carried text is not the bytes recorded
#   NB-NOTICE-MISSING          a required upstream NOTICE is absent
#   NB-NOTICE-HASH             a carried NOTICE is not the bytes recorded
#   NB-SOURCE-OBLIGATION-UNRESOLVED  a source or source-offer obligation is open
#   NB-ATTESTATION-CONFLICT    scanner and attestation name different licences
#   NB-ATTESTATION-SCOPE       an attestation reached a component, image family,
#                              version or platform it does not cover
#   NB-ATTESTATION-TEXT-MISSING  an attestation whose asserted text is not carried
#   NB-LEGAL-REVIEW-REQUIRED   an identifier the policy sends to counsel
#   NB-IMAGE-MATERIAL-INPUT    the in-image accounting is absent or malformed
#   NB-IMAGE-MATERIAL-UNBOUND  it describes another revision or cohort
#   NB-IMAGE-MATERIAL-CHILD    it names a child this candidate does not stage
#   NB-IMAGE-MATERIAL-ABSENT   a component ships no copyright material
#   NB-IMAGE-MATERIAL-AMBIGUOUS  material present but not self-sufficient
#   NB-IMAGE-MATERIAL-MAPPING  the recorded symlink chain does not actually
#                              lead from that package to that file
#   NB-IMAGE-MATERIAL-DRIFT    a carried file is absent or not its bytes
#   NB-IMAGE-MATERIAL-LEGAL-REVIEW  what is owed cannot be decided mechanically
#   NB-ATTESTATION-NOT-IN-IMAGE  an attestation was offered as a substitute
#                              for material the image does not carry
#   NB-PUBLICATION-AUTHORITY-MISSING  nobody has authorized distribution (#98)
#
# Usage:
#   generate-notice-bundle.py --inventory F --authorization F --material F
#                             --policy F --licence-texts F --attestations F
#                             --source-obligations F --image-materials F
#                             --out-dir D
# =============================================================================
import argparse
import collections
import hashlib
import json
import os
import sys

SCHEMA = "foundry.notice-bundle/v1"
PRODUCER = "scripts/license/generate-notice-bundle.py"

# The four evidence sources, in the order a disposition is looked for. They are
# never interchangeable and the bundle records WHICH one decided each component.
SRC_SCANNER = "scanner-observed"
SRC_ATTESTED = "upstream-attested"
SRC_POLICY = "policy-asserted"
SRC_LEGAL = "legally-approved"

STATUS_COMPLETE = "complete"
STATUS_INCOMPLETE = "incomplete"
STATUS_LEGAL = "legal-review-required"
STATUS_NOPUB = "publication-authority-missing"


class Findings(object):
    """Every refusal, with its code, in one place. Order is insertion order and
    insertion order is deterministic because every loop below is over a sorted
    collection."""

    def __init__(self):
        self.items = []

    def add(self, code, detail):
        self.items.append({"code": code, "detail": detail})

    def codes(self):
        return sorted({f["code"] for f in self.items})

    def __len__(self):
        return len(self.items)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def hard(code, msg):
    sys.stderr.write("REFUSE [%s]: %s\n" % (code, msg))
    raise SystemExit(2)


def load_json(path, what):
    if not path or not os.path.isfile(path) or os.path.getsize(path) == 0:
        hard("NB-INPUT-ABSENT",
             "%s (%s) is absent or empty. An absent input is a refusal, never a "
             "skip: a notice bundle built over evidence that did not arrive "
             "reports coverage it does not have" % (what, path or "<unset>"))
    try:
        with open(path) as fh:
            return json.load(fh)
    except ValueError as e:
        hard("NB-INPUT-MALFORMED", "%s (%s) is not readable JSON: %s" % (what, path, e))


def load_yaml(path, what):
    if not path or not os.path.isfile(path) or os.path.getsize(path) == 0:
        hard("NB-INPUT-ABSENT",
             "%s (%s) is absent or empty. An absent input is a refusal, never a "
             "skip" % (what, path or "<unset>"))
    try:
        import yaml
    except ImportError:
        hard("NB-INPUT-ABSENT",
             "PyYAML is required to read %s. A missing library must not turn "
             "into a skipped control" % what)
    try:
        with open(path) as fh:
            return yaml.safe_load(fh) or {}
    except Exception as e:                                    # noqa: BLE001
        hard("NB-INPUT-MALFORMED", "%s (%s) is unreadable: %s" % (what, path, e))


# -----------------------------------------------------------------------------
# the candidate binding — what this bundle is a bundle FOR
# -----------------------------------------------------------------------------
def bind_candidate(inv, auth, f):
    b = inv.get("image_binding") or {}
    if not b:
        f.add("NB-BINDING-ABSENT",
              "the licence inventory carries no image_binding. A notice bundle "
              "over an unbound inventory is a document about no particular "
              "images. Rebuild it with scripts/license/assert-image-sbom-licences.sh "
              "--authorization <record> --sbom-dir <dir> --out <inventory>")
        return {}

    exp, got = b.get("children_expected"), b.get("children_bound")
    if not exp or exp != got:
        f.add("NB-BINDING-INCOMPLETE",
              "the inventory binds %s of %s expected children. A notice bundle "
              "over a partial matrix reports clean for the images it happened to "
              "see" % (got, exp))

    if b.get("source_revision") != auth.get("source_revision"):
        f.add("NB-REVISION-MISMATCH",
              "the licence evidence is for source revision %s and the "
              "authorization record was written for %s. Notice material from "
              "another tree describes another set of components"
              % (b.get("source_revision"), auth.get("source_revision")))

    ac = {}
    for c in auth.get("children") or []:
        ac[str(c.get("child_key") or "")] = c
    if exp and len(ac) != exp:
        f.add("NB-MATRIX-MISMATCH",
              "the authorization record carries %d child(ren) and the licence "
              "evidence expected %s" % (len(ac), exp))

    bound = []
    for ch in sorted(b.get("children") or [], key=lambda c: str(c.get("child_key"))):
        key = str(ch.get("child_key") or "")
        rec = ac.get(key)
        if rec is None:
            f.add("NB-MATRIX-MISMATCH",
                  "the licence evidence binds child %r, which the authorization "
                  "record does not declare" % key)
            continue
        if ch.get("manifest_digest") != rec.get("manifest_digest"):
            f.add("NB-DIGEST-MISMATCH",
                  "child %s: the licence evidence names digest %s and the "
                  "authorization record names %s. Notice material for another "
                  "image is not notice material for this one"
                  % (key, str(ch.get("manifest_digest"))[:23],
                     str(rec.get("manifest_digest"))[:23]))
        if ch.get("platform") != rec.get("platform"):
            f.add("NB-PLATFORM-MISMATCH",
                  "child %s: the licence evidence names platform %r and the "
                  "authorization record names %r. An amd64 bill of materials is "
                  "not evidence about the arm64 child"
                  % (key, ch.get("platform"), rec.get("platform")))
        bound.append({
            "child_key": key,
            "image_label": rec.get("image_label"),
            "platform": ch.get("platform"),
            "manifest_digest": ch.get("manifest_digest"),
        })
    missing = sorted(set(ac) - {c["child_key"] for c in bound})
    for k in missing:
        f.add("NB-MATRIX-MISMATCH",
              "the authorization record declares child %r and the licence "
              "evidence binds no notice material for it" % k)
    return {
        "source_revision": b.get("source_revision"),
        "children_expected": exp,
        "children_bound": got,
        "platforms": sorted(b.get("platforms") or []),
        "execution_modes": sorted(b.get("execution_modes") or []),
        "children": bound,
    }


# -----------------------------------------------------------------------------
# the carried licence-text store
# -----------------------------------------------------------------------------
def load_store(prov_path, prov, root, f):
    if prov.get("record_type") != "carried-licence-texts":
        hard("NB-INPUT-MALFORMED",
             "%s is not a carried-licence-texts record (record_type=%r)"
             % (prov_path, prov.get("record_type")))
    store = {}
    for e in sorted(prov.get("files") or [], key=lambda x: str(x.get("spdx_id"))):
        sid, rel = e.get("spdx_id"), e.get("path")
        full = os.path.join(root, rel or "")
        if not rel or not os.path.isfile(full) or os.path.getsize(full) == 0:
            f.add("NB-LICENCE-TEXT-MISSING",
                  "%s records a text for %s at %s and it is absent or empty"
                  % (prov_path, sid, rel or "<unset>"))
            continue
        got = sha256_file(full)
        if got != (e.get("sha256") or ""):
            f.add("NB-LICENCE-TEXT-HASH",
                  "%s: the text carried for %s hashes to %s and the provenance "
                  "record names %s. A recipient checking the hash would be the "
                  "first to find out"
                  % (prov_path, sid, got[:16], str(e.get("sha256"))[:16]))
            continue
        store[sid] = {"path": rel, "sha256": got, "bytes": os.path.getsize(full),
                      "upstream_path": e.get("upstream_path"),
                      "source_url": e.get("source_url")}
    return store


# -----------------------------------------------------------------------------
# the upstream attestations — scoped, never widening
# -----------------------------------------------------------------------------
def index_attestations(att, store, families, versions, platforms, f):
    """Return {(name, version): attestation-view}. An attestation reaches a
    component ONLY on an exact (name, version) match AND only where its declared
    families / versions / platforms cover the candidate cohort. Anything else is
    NB-ATTESTATION-SCOPE — an attestation that widens is an attestation about
    software nobody read."""
    idx = {}
    for a in sorted(att.get("attestations") or [], key=lambda x: str(x.get("id"))):
        aid = str(a.get("id"))
        asserts = a.get("asserts") or {}
        sid, text = asserts.get("spdx_id"), asserts.get("licence_text")
        scope = a.get("applies_to") or {}
        af = set(scope.get("image_families") or [])
        av = set(str(x) for x in (scope.get("image_versions") or []))
        ap = set(scope.get("platforms") or [])
        if not af or not av or not ap:
            f.add("NB-ATTESTATION-SCOPE",
                  "attestation %s declares no image families, versions or "
                  "platforms. An attestation with no scope is an attestation "
                  "that would reach anything" % aid)
            continue
        if not ap.issuperset(platforms):
            f.add("NB-ATTESTATION-SCOPE",
                  "attestation %s covers platforms %s and the candidate cohort "
                  "ships %s" % (aid, sorted(ap), sorted(platforms)))
            continue
        # The declared image scope must actually REACH this cohort. Without
        # this, an attestation written for the 8.5 experimental family would be
        # applied to an 8.3/8.4 production cohort on the strength of its
        # component list alone: the exact (name, version) match is necessary and
        # it is not sufficient, because a component name says nothing about
        # which images ship it.
        if not (af & set(families)):
            f.add("NB-ATTESTATION-SCOPE",
                  "attestation %s declares image families %s and this candidate "
                  "cohort ships %s. An attestation must not reach a family it "
                  "does not cover" % (aid, sorted(af), sorted(families)))
            continue
        if not (av & set(versions)):
            f.add("NB-ATTESTATION-SCOPE",
                  "attestation %s declares image versions %s and this candidate "
                  "cohort ships %s. An attestation for one version must not "
                  "widen to another" % (aid, sorted(av), sorted(versions)))
            continue
        if sid not in store:
            f.add("NB-ATTESTATION-TEXT-MISSING",
                  "attestation %s asserts %s and names the text %s, which is not "
                  "in the carried store. An attestation without its text "
                  "discharges nothing" % (aid, sid, text))
            continue
        for c in sorted(a.get("components") or [],
                        key=lambda x: (str(x.get("name")), str(x.get("version")))):
            key = (str(c.get("name")), str(c.get("version")))
            if key in idx and idx[key]["spdx_id"] != sid:
                f.add("NB-ATTESTATION-CONFLICT",
                      "two attestations assert different licences for %s@%s: %s "
                      "and %s" % (key[0], key[1], idx[key]["spdx_id"], sid))
                continue
            idx[key] = {"attestation_id": aid, "spdx_id": sid,
                        "licence_text": store[sid]["path"],
                        "licence_text_sha256": store[sid]["sha256"],
                        "upstream_revision": (a.get("upstream") or {}).get("revision_tag"),
                        "upstream_commit": (a.get("upstream") or {}).get("revision_commit"),
                        "upstream_content_sha256": (a.get("upstream") or {}).get("content_sha256"),
                        "evidence_class": a.get("evidence_class"),
                        "image_families": sorted(af),
                        "image_versions": sorted(av),
                        "platforms": sorted(ap)}
    return idx


# -----------------------------------------------------------------------------
# component dispositions — one source each, recorded
# -----------------------------------------------------------------------------
def dispose(inv, attest_idx, store, policy_state, policy_default, f):
    """One disposition per component, naming WHICH of the four sources decided it.

    Image FILE components that carry no licence identity are deliberately not
    given a NB-DISPOSITION-MISSING finding here: the four-way file accounting in
    check_files() already refuses them once, as a class, with their count and
    examples. Reporting the same 7,972 facts twice under two codes would inflate
    the bundle and tell a reader nothing new. A file component that DOES carry a
    licence identity is disposed exactly like a package, because it needs a
    notice exactly like one."""
    out = []
    deferred_files = 0
    for c in sorted(inv.get("components") or [],
                    key=lambda x: (str(x.get("name")), str(x.get("version")))):
        name = str(c.get("name") or "")
        ver = str(c.get("version") or "")
        lics = sorted(c.get("licenses") or [])
        is_file = c.get("component_type") == "file"
        att = attest_idx.get((name, ver))
        if is_file and not lics and not att and not c.get("conflict"):
            deferred_files += 1
            continue

        if c.get("conflict"):
            f.add("NB-CONFLICT-UNRESOLVED",
                  "%s@%s: sources disagree about the licence (%s). A notice "
                  "rendered over a disagreement publishes an attribution nobody "
                  "verified" % (name, ver, ", ".join(lics)))
            out.append({"name": name, "version": ver, "component_type":
                        "file" if is_file else "package", "source": None,
                        "licences": lics, "state": "conflict"})
            continue

        if lics and att:
            if att["spdx_id"] not in lics:
                f.add("NB-ATTESTATION-CONFLICT",
                      "%s@%s: the scanner observed %s and attestation %s asserts "
                      "%s. An attestation may FILL a silence; it may never "
                      "OVERRIDE an observation, and a disagreement is a review "
                      "item, not a precedence rule"
                      % (name, ver, ", ".join(lics), att["attestation_id"],
                         att["spdx_id"]))
                out.append({"name": name, "version": ver, "component_type":
                            "file" if is_file else "package", "source": None,
                            "licences": lics, "state": "attestation-conflict"})
                continue

        if lics:
            src, ids, ev = SRC_SCANNER, lics, None
        elif att:
            src, ids, ev = SRC_ATTESTED, [att["spdx_id"]], att
        else:
            f.add("NB-DISPOSITION-MISSING",
                  "%s@%s: no licence disposition from any source — the scanner "
                  "asserted nothing, no upstream attestation covers it, and a "
                  "policy row cannot classify an identifier that does not exist. "
                  "A distributed component with no disposition cannot be given a "
                  "notice" % (name, ver))
            out.append({"name": name, "version": ver, "component_type":
                        "file" if is_file else "package", "source": None,
                        "licences": [], "state": "no-disposition"})
            continue

        states = sorted({policy_state.get(i, policy_default) for i in ids})
        texts = []
        for i in ids:
            if i in store:
                texts.append({"spdx_id": i, "path": store[i]["path"],
                              "sha256": store[i]["sha256"]})
            else:
                f.add("NB-LICENCE-TEXT-MISSING",
                      "%s@%s is licensed %s and no canonical text for %s is "
                      "carried. A redistributor owes the recipient the text of "
                      "the licence it ships under" % (name, ver, i, i))
        if "denied" in states:
            f.add("NB-LEGAL-REVIEW-REQUIRED",
                  "%s@%s: %s is DENIED by policy" % (name, ver, ", ".join(ids)))
        if "legal-review-required" in states:
            f.add("NB-LEGAL-REVIEW-REQUIRED",
                  "%s@%s: %s needs legal review and has not had it. "
                  "legal-review-required is not a soft state — a component "
                  "sitting there is exactly as unshippable as a denied one"
                  % (name, ver, ", ".join(ids)))
        d = {"name": name, "version": ver,
             "component_type": "file" if is_file else "package",
             "source": src, "licences": ids, "policy_states": states,
             "state": "disposed", "licence_texts": texts}
        if ev:
            d["attestation"] = {k: ev[k] for k in sorted(ev)}
        if is_file:
            d["file_class"] = c.get("file_class")
        out.append(d)
    return out, deferred_files


# -----------------------------------------------------------------------------
# the image-file disposition, carried through rather than re-derived
# -----------------------------------------------------------------------------
def check_files(inv, f):
    im = inv.get("image_files") or {}
    if not im:
        f.add("NB-INPUT-MALFORMED",
              "the licence inventory carries no image_files block. The four-way "
              "file-component accounting is what stops a component being hidden "
              "by relabelling it type=file")
        return {}
    obs = im.get("by_class_observations") or {}
    total = im.get("input_file_components")
    got = sum(int(v or 0) for v in obs.values())
    if total is None or got != total:
        f.add("NB-INPUT-MALFORMED",
              "the file-component accounting does not close: %s components in, "
              "%d accounted across %s" % (total, got, sorted(obs)))
    # ONE finding per file CLASS, with its count and examples — not one per
    # path. 7,972 identical lines is the shape the backlog grouping exists to
    # remove; the refusal is the same and the report is readable. The full lists
    # stay in the inventory, which is an input this bundle names.
    ind = sorted(im.get("independently_licensed") or [], key=lambda x: str(x.get("path")))
    if ind:
        f.add("NB-FILE-INDEPENDENT-UNTREATED",
              "%d image file(s) are independently licensed and have no recorded "
              "treatment in this bundle, e.g. %s. An independently licensed file "
              "inside an image is covered by NO repository control by "
              "construction: policies/repository-material.yaml sees the tree, not "
              "the image" % (len(ind), ", ".join(str(e.get("path")) for e in ind[:8])))
    unres = sorted(im.get("unresolved") or [], key=lambda x: str(x.get("path")))
    if unres:
        f.add("NB-FILE-UNRESOLVED",
              "%d image file(s) are unresolved, e.g. %s. The absence of licence "
              "metadata is not evidence that no licence applies, so an unresolved "
              "file stays visible and refuses rather than being counted as a bare "
              "scanner observation"
              % (len(unres), ", ".join(str(e.get("path")) for e in unres[:8])))
    bad = [e for e in sorted(im.get("package_attributed_sample") or [],
                             key=lambda x: str(x.get("path")))
           if not e.get("relationship_evidence") or not e.get("owning_package")]
    if bad:
        f.add("NB-ATTRIBUTION-UNSUPPORTED",
              "%d package-attributed image file(s) carry no owning package or no "
              "relationship proving it, e.g. %s. Filename, path and version "
              "similarity are never sufficient"
              % (len(bad), ", ".join(str(e.get("path")) for e in bad[:8])))
    return {
        "input_file_components": total,
        "by_class": {k: obs[k] for k in sorted(obs)},
        "accounting_invariant": im.get("accounting_invariant"),
        "independently_licensed": len(im.get("independently_licensed") or []),
        "unresolved": len(im.get("unresolved") or []),
        "deduplication_note": im.get("deduplication_note"),
    }


# -----------------------------------------------------------------------------
# the material that is INSIDE the images (#120 action N1)
# -----------------------------------------------------------------------------
def expand_per_child(pc, index=None):
    """The accounting stores identical per-child outcomes once against the list
    of children that share them. A reader that assumed {child: outcome} would
    see nothing at all, so the indirection is followed in one place."""
    if not pc:
        return {}
    def name(c):
        if isinstance(c, int):
            return index[c] if index and 0 <= c < len(index) else "<child %d>" % c
        return c
    if "outcome" in pc:
        return {name(c): pc["outcome"] for c in pc.get("children") or []}
    out = {}
    for g in pc.get("outcomes") or []:
        for c in g.get("children") or []:
            out[name(c)] = g["outcome"]
    return out


def check_image_materials(accdoc, root, binding, auth, attest_idx, allow_sub, f):
    """The canonical SPDX text of GPL-2.0 is not busybox's copyright statement,
    and `retain-copyright-notice` is an obligation about the second. This
    consumes the in-image accounting and refuses on anything it could not
    establish.

    AN UPSTREAM ATTESTATION IS NOT AN IN-IMAGE FILE. Where the image ships no
    copyright material, an attestation may be RECORDED beside the gap and may
    never close it — unless the attestation policy explicitly says that evidence
    class may substitute, which the shipped policy does not. Letting it close the
    gap silently would be one evidence class masquerading as another, which is
    the distinction the four-source model exists to keep."""
    if accdoc.get("schema") != "foundry.image-licence-accounting/v1":
        f.add("NB-IMAGE-MATERIAL-INPUT",
              "the in-image accounting is not a "
              "foundry.image-licence-accounting/v1 record (schema=%r)"
              % accdoc.get("schema"))
        return {}
    if accdoc.get("source_revision") != binding.get("source_revision"):
        f.add("NB-IMAGE-MATERIAL-UNBOUND",
              "the in-image accounting was taken at source revision %s and this "
              "candidate is %s. Material read out of another tree's images "
              "describes another set of components"
              % (accdoc.get("source_revision"), binding.get("source_revision")))
    want_children = {str(c.get("child_key")) for c in auth.get("children") or []}
    if accdoc.get("children_accounted") != len(want_children):
        f.add("NB-IMAGE-MATERIAL-UNBOUND",
              "the in-image accounting covers %s child(ren) and this candidate "
              "stages %d. An accounting over a partial cohort reports complete "
              "coverage of images it never opened"
              % (accdoc.get("children_accounted"), len(want_children)))

    counts = collections.Counter()
    referenced = {}
    # Reason texts are interned in the accounting record; a reader that took
    # `reason` literally would report an empty diagnostic for 342 components.
    texts = accdoc.get("reason_texts") or {}
    cindex = accdoc.get("children_index") or []

    def why_of(r):
        return r.get("reason") or texts.get(r.get("reason_key"), "")
    for r in sorted(accdoc.get("components") or [],
                    key=lambda x: str(x.get("component"))):
        cls = r.get("classification")
        counts[cls] += 1
        name = str(r.get("name") or "")
        per = expand_per_child(r.get("per_child"), cindex)
        for ck in sorted(per):
            if ck not in want_children:
                f.add("NB-IMAGE-MATERIAL-CHILD",
                      "%s: the accounting carries material from child %r, which "
                      "this candidate does not stage. Another image's file is "
                      "not this image's evidence" % (r.get("component"), ck))
        if cls == "extracted":
            for ck in sorted(per):
                d = per[ck]
                chain = d.get("chain") or []
                resolved = d.get("resolved_path")
                # THE MAPPING ITSELF IS CHECKED. A chain that does not start at
                # this package's own doc path, or whose hops do not link up, or
                # whose last hop is not the file being claimed, is a package
                # mapped to somebody else's copyright file.
                if d.get("sha256") and not chain and d.get("indirect") is False:
                    # The direct case: no indirection, so the file must be the
                    # package's own convention path and nothing else.
                    if resolved not in ("usr/share/doc/%s/copyright" % name,
                                        "usr/share/doc/%s/copyright.gz" % name):
                        f.add("NB-IMAGE-MATERIAL-MAPPING",
                              "%s: the record claims no indirection and resolves "
                              "to %r, which is not this package's own "
                              "documentation path" % (r.get("component"), resolved))
                if d.get("sha256") and chain:
                    start = chain[0].get("path")
                    if start not in ("usr/share/doc/%s" % name,
                                     "usr/share/doc/%s/copyright" % name,
                                     "usr/share/doc/%s/copyright.gz" % name):
                        f.add("NB-IMAGE-MATERIAL-MAPPING",
                              "%s: the recorded chain starts at %r, which is not "
                              "this package's own documentation path"
                              % (r.get("component"), start))
                    for i in range(len(chain) - 1):
                        tgt = chain[i].get("link_target_resolved")
                        nxt = chain[i + 1].get("path")
                        if tgt and nxt and not nxt.startswith(tgt):
                            f.add("NB-IMAGE-MATERIAL-MAPPING",
                                  "%s: hop %d points at %r and the next hop is "
                                  "%r. A redirected symlink is a package mapped "
                                  "to another package's file"
                                  % (r.get("component"), i, tgt, nxt))
                    if resolved and chain[-1].get("path") != resolved:
                        f.add("NB-IMAGE-MATERIAL-MAPPING",
                              "%s: the chain ends at %r and the record claims %r"
                              % (r.get("component"), chain[-1].get("path"), resolved))
                if d.get("sha256"):
                    referenced.setdefault(d["sha256"], []).append(r.get("component"))
        elif cls in ("absent", "path-expected-unavailable"):
            att = attest_idx.get((name, str(r.get("version") or "")))
            if att and not allow_sub:
                f.add("NB-ATTESTATION-NOT-IN-IMAGE",
                      "%s ships no copyright material and attestation %s asserts "
                      "%s for it. An upstream attestation is a DIFFERENT evidence "
                      "class from a file the image carries; it is recorded beside "
                      "the gap and does not close it, because "
                      "defaults.may_substitute_for_in_image_material is false"
                      % (r.get("component"), att["attestation_id"], att["spdx_id"]))
            elif att and allow_sub:
                continue
            f.add("NB-IMAGE-MATERIAL-ABSENT",
                  "%s: %s" % (r.get("component"), why_of(r) or cls))
        elif cls == "ambiguous":
            why = why_of(r)
            if not why:
                outs = per.get("outcomes") or ([{"outcome": per.get("outcome")}]
                                               if per.get("outcome") else [])
                amb = [g["outcome"] for g in outs
                       if (g.get("outcome") or {}).get("state") == "ambiguous"]
                why = (amb or [{}])[0].get("reason", "")
            f.add("NB-IMAGE-MATERIAL-AMBIGUOUS",
                  "%s: %s" % (r.get("component"), why))
        elif cls == "legal-review-required":
            f.add("NB-IMAGE-MATERIAL-LEGAL-REVIEW",
                  "%s: %s" % (r.get("component"), why_of(r)))

    # --- the carried bytes must BE there and BE what was recorded ------------
    carried = (accdoc.get("carried_texts") or {}).get("files") or []
    by_hash = {c["sha256"]: c for c in carried}
    for h in sorted(referenced):
        c = by_hash.get(h)
        if c is None:
            f.add("NB-IMAGE-MATERIAL-DRIFT",
                  "the accounting binds %s to material sha256 %s and the carried "
                  "store does not hold it"
                  % (", ".join(referenced[h][:3]), h[:16]))
            continue
        p = os.path.join(root, c["path"])
        if not os.path.isfile(p) or os.path.getsize(p) == 0:
            f.add("NB-IMAGE-MATERIAL-DRIFT",
                  "%s is recorded as carried and is absent or empty" % c["path"])
            continue
        got = sha256_file(p)
        if got != h:
            f.add("NB-IMAGE-MATERIAL-DRIFT",
                  "%s hashes to %s and the accounting binds %s. A copyright "
                  "notice that is not the bytes that shipped is not the notice"
                  % (c["path"], got[:16], h[:16]))
    return {
        "accounting": accdoc.get("record_type"),
        "extraction_tool": accdoc.get("extraction_tool"),
        "extraction_tool_sha256": accdoc.get("extraction_tool_sha256"),
        "children_accounted": accdoc.get("children_accounted"),
        "implicated_components": accdoc.get("implicated_components"),
        "by_class": {k: counts[k] for k in sorted(counts)},
        "carried_files": len(carried),
        "distinct_material_hashes_bound": len(referenced),
        "attestation_may_substitute_for_in_image_material": allow_sub,
    }


# -----------------------------------------------------------------------------
# repository material — its texts and its upstream NOTICE files
# -----------------------------------------------------------------------------
def check_material(mat, root, f):
    rows = []
    for m in sorted(mat.get("materials") or [], key=lambda x: str(x.get("id"))):
        ob = m.get("obligations") or {}
        lic = (m.get("licence") or {}).get("declared_spdx")
        row = {"id": m.get("id"), "path": m.get("path"), "spdx_id": lic,
               "artifacts": []}
        for key in ("required_license_text", "required_notice", "local_notice"):
            rel = ob.get(key)
            if not rel:
                continue
            full = os.path.join(root, rel)
            if not os.path.isfile(full) or os.path.getsize(full) == 0:
                code = "NB-NOTICE-MISSING" if key != "required_license_text" \
                    else "NB-LICENCE-TEXT-MISSING"
                f.add(code, "%s (%s): %s names %s and it is absent or empty"
                      % (m.get("id"), m.get("path"), key, rel))
                continue
            row["artifacts"].append({"kind": key, "path": rel,
                                     "sha256": sha256_file(full)})
        rows.append(row)
    return rows


def check_material_notice_hashes(root, f):
    """Every third-party PROVENANCE.yaml in the tree records the bytes of the
    LICENSE and NOTICE it carries. Those records are what make "the NOTICE is
    present" checkable rather than asserted, so a drifted NOTICE refuses here the
    same way a drifted licence text does."""
    import yaml
    rows = []
    base = os.path.join(root, "third-party")
    if not os.path.isdir(base):
        return rows
    for d in sorted(os.listdir(base)):
        p = os.path.join(base, d, "PROVENANCE.yaml")
        if not os.path.isfile(p):
            continue
        try:
            with open(p) as fh:
                doc = yaml.safe_load(fh) or {}
        except Exception as e:                                # noqa: BLE001
            f.add("NB-INPUT-MALFORMED", "%s is unreadable: %s" % (p, e))
            continue
        if doc.get("record_type") == "carried-licence-texts":
            continue                       # the SPDX store, checked separately
        for e in sorted(doc.get("files") or [], key=lambda x: str(x.get("path"))):
            rel = e.get("path")
            full = os.path.join(root, rel or "")
            if not rel or not os.path.isfile(full) or os.path.getsize(full) == 0:
                f.add("NB-NOTICE-MISSING",
                      "%s records %s and it is absent or empty"
                      % (p, rel or "<unset>"))
                continue
            got = sha256_file(full)
            if e.get("sha256") and got != e["sha256"]:
                f.add("NB-NOTICE-HASH",
                      "%s: %s hashes to %s and the record names %s. An upstream "
                      "NOTICE that is not the bytes it claims to be is not the "
                      "upstream NOTICE" % (p, rel, got[:16], e["sha256"][:16]))
                continue
            rows.append({"record": os.path.relpath(p, root), "path": rel,
                         "sha256": got,
                         "upstream_path": e.get("upstream_path"),
                         "project": (doc.get("upstream") or {}).get("project"),
                         "revision": (doc.get("upstream") or {}).get("revision_tag")})
    return rows


# -----------------------------------------------------------------------------
# source obligations — facts in, no conclusion out
# -----------------------------------------------------------------------------
def check_source_obligations(so, f):
    rows = []
    for c in sorted(so.get("components") or [],
                    key=lambda x: (str(x.get("binary")), str(x.get("binary_version")))):
        state = c.get("source_obligation")
        row = {
            "binary": c.get("binary"), "binary_version": c.get("binary_version"),
            "ecosystem": c.get("eco"),
            "source_package": c.get("source"),
            "source_version": c.get("source_version"),
            "reciprocal_identifiers": sorted(c.get("reciprocal") or []),
            "licence_texts_carried": bool(c.get("texts_carried")),
            "status": state,
        }
        if state != "satisfied":
            f.add("NB-SOURCE-OBLIGATION-UNRESOLVED",
                  "%s@%s (source %s %s) carries %s and its source obligation is "
                  "%r. No engineering act sets this to satisfied: it needs an "
                  "approved delivery mechanism and a duration commitment only a "
                  "rights holder can make (#98)"
                  % (c.get("binary"), c.get("binary_version"), c.get("source"),
                     c.get("source_version"),
                     ", ".join(sorted(c.get("reciprocal") or [])), state))
        rows.append(row)
    return rows


# -----------------------------------------------------------------------------
# the human-readable notices
# -----------------------------------------------------------------------------
def render_notices(binding, dispositions, material, notices, verdict, status,
                   publication):
    by_lic = {}
    for d in dispositions:
        if d.get("state") != "disposed":
            continue
        for lic in d["licences"]:
            by_lic.setdefault(lic, []).append("%s %s" % (d["name"], d["version"]))
    L = []
    if verdict == "PASS" and status == STATUS_COMPLETE:
        L.append("THIRD-PARTY NOTICES — release candidate")
    else:
        L.append("THIRD-PARTY NOTICE BUNDLE — DRAFT, INCOMPLETE, "
                 "NOT APPROVED FOR DISTRIBUTION")
        L.append("")
        L.append("This bundle was produced from measured evidence and it is NOT a")
        L.append("legal artifact. It does not state Zenchron Foundry's own licence,")
        L.append("which is undetermined and tracked in issue %s. It must not be"
                 % publication.get("tracked_issue"))
        L.append("shipped, published or presented as an approved notice set.")
    L.append("")
    L.append("Scope        : the candidate images below, and nothing else.")
    L.append("Source rev   : %s" % binding.get("source_revision"))
    L.append("Children     : %s of %s bound"
             % (binding.get("children_bound"), binding.get("children_expected")))
    L.append("Platforms    : %s" % ", ".join(binding.get("platforms") or []))
    L.append("Execution    : %s" % ", ".join(binding.get("execution_modes") or []))
    L.append("Verdict      : %s (%s)" % (verdict, status))
    L.append("")
    L.append("Candidate images")
    L.append("-" * 78)
    for c in binding.get("children") or []:
        L.append("  %-28s %-14s %s" % (c.get("image_label"), c.get("platform"),
                                       c.get("manifest_digest")))
    L.append("")
    L.append("Third-party components, by licence")
    L.append("=" * 78)
    for lic in sorted(by_lic):
        L.append("")
        L.append(lic)
        L.append("-" * len(lic))
        for item in sorted(set(by_lic[lic])):
            L.append("  %s" % item)
    L.append("")
    L.append("Repository material carried in this distribution")
    L.append("=" * 78)
    for m in material:
        L.append("")
        L.append("%s  (%s)" % (m.get("path"), m.get("spdx_id")))
        for a in m.get("artifacts") or []:
            L.append("    %-22s %s  sha256:%s"
                     % (a["kind"], a["path"], a["sha256"][:16]))
    if notices:
        L.append("")
        L.append("Upstream NOTICE files retained")
        L.append("=" * 78)
        for n in notices:
            L.append("  %-52s %s @ %s" % (n["path"], n.get("project"),
                                          n.get("revision")))
    L.append("")
    return "\n".join(L) + "\n"


# -----------------------------------------------------------------------------
def produce(args):
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    f = Findings()

    inv = load_json(args.inventory, "the licence inventory")
    if inv.get("schema") != "foundry.license-inventory/v1":
        hard("NB-INPUT-MALFORMED",
             "%s is not a foundry.license-inventory/v1 document (schema=%r)"
             % (args.inventory, inv.get("schema")))
    auth = load_json(args.authorization, "the authorization record")
    if auth.get("schema_version") != 1 or not isinstance(auth.get("children"), list):
        hard("NB-INPUT-MALFORMED",
             "%s is not a schemas/post-build-authorization-v1 record"
             % args.authorization)
    mat = load_yaml(args.material, "the repository-material inventory")
    if mat.get("schema") != "foundry.repository-material/v1":
        hard("NB-INPUT-MALFORMED",
             "%s is not a foundry.repository-material/v1 inventory" % args.material)
    pol = load_yaml(args.policy, "the licence policy")
    att = load_yaml(args.attestations, "the upstream licence attestations")
    if att.get("schema") != "foundry.upstream-licence-attestation/v1":
        hard("NB-INPUT-MALFORMED",
             "%s is not a foundry.upstream-licence-attestation/v1 document"
             % args.attestations)
    imgmat = load_json(args.image_materials, "the in-image licence accounting")
    so = load_yaml(args.source_obligations, "the source-obligation facts")
    if so.get("schema") != "foundry.source-obligations/v1":
        hard("NB-INPUT-MALFORMED",
             "%s is not a foundry.source-obligations/v1 document"
             % args.source_obligations)
    prov = load_yaml(args.licence_texts, "the carried licence-text provenance")

    policy_state = {}
    for e in pol.get("licenses") or []:
        if e.get("id"):
            policy_state[e["id"]] = e.get("state")
    for d in pol.get("denied") or []:
        if isinstance(d, str):
            policy_state[d] = "denied"
    policy_default = pol.get("default_state", "legal-review-required")
    publication = pol.get("publication") or {}

    binding = bind_candidate(inv, auth, f)
    store = load_store(args.licence_texts, prov, root, f)

    families = sorted({str(c.get("image_label") or "").split("/")[0]
                       for c in auth.get("children") or []})
    versions = sorted({str(c.get("image_label") or "").partition("/")[2]
                       for c in auth.get("children") or []})
    platforms = sorted({str(c.get("platform") or "")
                        for c in auth.get("children") or []})
    attest_idx = index_attestations(att, store, families, versions, platforms, f)

    dispositions, deferred_files = dispose(inv, attest_idx, store, policy_state,
                                           policy_default, f)
    files = check_files(inv, f)
    allow_sub = bool((att.get("defaults") or {})
                     .get("may_substitute_for_in_image_material"))
    image_materials = check_image_materials(imgmat, root, binding, auth,
                                            attest_idx, allow_sub, f)
    material = check_material(mat, root, f)
    notices = check_material_notice_hashes(root, f)
    source_rows = check_source_obligations(so, f)

    # --- publication authority: independent, and false today -----------------
    pub_present = (publication.get("decision") not in (None, "undetermined")
                   and bool(publication.get("notices_approved_for_distribution")))
    if not pub_present:
        f.add("NB-PUBLICATION-AUTHORITY-MISSING",
              "publication.decision is %r and "
              "publication.notices_approved_for_distribution is %r in %s. Nobody "
              "has authorized distribution, so no notice bundle can be a "
              "DISTRIBUTION notice bundle. This refusal is INDEPENDENT of every "
              "other one above: a complete licence and notice set does not "
              "create the authority to ship it (%s)"
              % (publication.get("decision"),
                 publication.get("notices_approved_for_distribution"),
                 os.path.basename(args.policy),
                 publication.get("tracked_issue")))

    # THREE INDEPENDENT AXES, and collapsing them is the failure this block
    # avoids. `verdict` is about the NOTICE AND SOURCE MATERIAL only — is it
    # complete and legally clear? Publication authority is a SEPARATE input,
    # because a bundle can be perfect and there still be nobody who has said the
    # images may be distributed. Folding authority into the verdict would make
    # AR-PUBLICATION-AUTHORITY-MISSING unreachable: every bundle would already be
    # a draft for another reason and the independent refusal would never fire.
    codes = f.codes()
    engineering_codes = [c for c in codes
                         if c not in ("NB-LEGAL-REVIEW-REQUIRED",
                                      "NB-PUBLICATION-AUTHORITY-MISSING")]
    legal_outstanding = "NB-LEGAL-REVIEW-REQUIRED" in codes
    verdict = "PASS" if not engineering_codes and not legal_outstanding else "REFUSE"
    if engineering_codes:
        status = STATUS_INCOMPLETE
    elif legal_outstanding:
        status = STATUS_LEGAL
    elif not pub_present:
        status = STATUS_NOPUB
    else:
        status = STATUS_COMPLETE

    out = os.path.abspath(args.out_dir)
    os.makedirs(out, exist_ok=True)

    unresolved = {
        "schema": "foundry.notice-unresolved-obligations/v1",
        "producer": PRODUCER,
        "source_revision": binding.get("source_revision"),
        "finding_count": len(f),
        "codes": codes,
        "findings": f.items,
    }
    source_manifest = {
        "schema": "foundry.source-obligation-manifest/v1",
        "producer": PRODUCER,
        "source_revision": binding.get("source_revision"),
        "authority": so.get("source_authorities"),
        "delivery_mechanisms_considered": so.get("delivery_mechanisms_considered"),
        "unresolved_legal_questions": so.get("unresolved_legal_questions"),
        "component_count": len(source_rows),
        "satisfied_count": sum(1 for r in source_rows if r["status"] == "satisfied"),
        "unresolved_count": sum(1 for r in source_rows if r["status"] != "satisfied"),
        "components": source_rows,
        "note": ("No engineering act sets a component to satisfied. Doing so "
                 "requires an approved delivery mechanism and a duration or "
                 "availability commitment, and both are #98's."),
    }
    texts_manifest = {
        "schema": "foundry.notice-licence-texts/v1",
        "producer": PRODUCER,
        "provenance_record": os.path.relpath(os.path.abspath(args.licence_texts), root),
        "form": ("immutable references to the texts carried in the tree, not "
                 "copies: a second copy is a second thing that can drift"),
        "count": len(store),
        "texts": [dict(spdx_id=k, **store[k]) for k in sorted(store)],
    }

    for nm, doc in (("unresolved-obligations.json", unresolved),
                    ("source-obligation-manifest.json", source_manifest),
                    ("licence-text-references.json", texts_manifest)):
        with open(os.path.join(out, nm), "w") as fh:
            fh.write(json.dumps(doc, indent=2, sort_keys=True) + "\n")

    notices_txt = render_notices(binding, dispositions, material, notices,
                                 verdict, status, publication)
    with open(os.path.join(out, "THIRD-PARTY-NOTICES.txt"), "w") as fh:
        fh.write(notices_txt)

    artifacts = {}
    for nm in sorted(("unresolved-obligations.json",
                      "source-obligation-manifest.json",
                      "licence-text-references.json",
                      "THIRD-PARTY-NOTICES.txt")):
        artifacts[nm] = sha256_file(os.path.join(out, nm))

    manifest = {
        "schema": SCHEMA,
        "record_type": "notice-bundle",
        "schema_version": 1,
        "producer": PRODUCER,
        "verdict": verdict,
        "status": status,
        # DRAFT means "cannot authorize", not merely "the notice material is
        # incomplete". A bundle whose notice and source material is perfect but
        # which nobody has authority to distribute is still a draft, because the
        # thing a non-draft claims is that it may be used — and it may not.
        "draft": status != STATUS_COMPLETE,
        "satisfies_authorization": status == STATUS_COMPLETE,
        "publication_authority_present": pub_present,
        "engineering_complete": not engineering_codes,
        "legal_review_outstanding": legal_outstanding,
        "source_revision": binding.get("source_revision"),
        # BOUND to the record this bundle is a bundle FOR, by that record's own
        # bytes. A bundle filed beside a record it does not name is a document
        # anyone could move next to a different one.
        "authorization_record": os.path.basename(args.authorization),
        "authorization_record_sha256": sha256_file(args.authorization),
        "candidate": binding,
        "component_count": len(dispositions),
        "components_disposed": sum(1 for d in dispositions if d["state"] == "disposed"),
        "image_file_components_deferred_to_file_accounting": deferred_files,
        "components_by_source": {
            SRC_SCANNER: sum(1 for d in dispositions if d.get("source") == SRC_SCANNER),
            SRC_ATTESTED: sum(1 for d in dispositions if d.get("source") == SRC_ATTESTED),
            SRC_POLICY: 0,
            SRC_LEGAL: 0,
        },
        "image_files": files,
        "in_image_materials": image_materials,
        "repository_material": material,
        "upstream_notices_retained": notices,
        "licence_texts": {"count": len(store),
                          "manifest": "licence-text-references.json"},
        "source_obligations": {
            "component_count": source_manifest["component_count"],
            "unresolved_count": source_manifest["unresolved_count"],
            "manifest": "source-obligation-manifest.json",
        },
        "finding_count": len(f),
        "finding_codes": codes,
        "artifacts": artifacts,
        "inputs": {
            "inventory": os.path.basename(args.inventory),
            "authorization": os.path.basename(args.authorization),
            "material": os.path.relpath(os.path.abspath(args.material), root),
            "policy": os.path.relpath(os.path.abspath(args.policy), root),
            "licence_texts": os.path.relpath(os.path.abspath(args.licence_texts), root),
            "attestations": os.path.relpath(os.path.abspath(args.attestations), root),
            "source_obligations": os.path.relpath(os.path.abspath(args.source_obligations), root),
            "image_materials": os.path.relpath(os.path.abspath(args.image_materials), root),
        },
        "dispositions": dispositions,
        "note": ("This bundle is scoped to the candidate images named above. It "
                 "is NOT Zenchron Foundry's outbound licence, it does not "
                 "authorize publication, and a PASS makes a candidate eligible "
                 "for the next independent release control and nothing more."),
    }
    blob = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    manifest["bundle_sha256"] = sha256_bytes(blob.encode())
    blob = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    with open(os.path.join(out, "notice-manifest.json"), "w") as fh:
        fh.write(blob)

    sums = []
    for nm in sorted(os.listdir(out)):
        if nm == "SHA256SUMS":
            continue
        sums.append("%s  %s" % (sha256_file(os.path.join(out, nm)), nm))
    with open(os.path.join(out, "SHA256SUMS"), "w") as fh:
        fh.write("\n".join(sums) + "\n")

    sys.stderr.write("notice bundle: %s (%s), %d finding(s)%s\n"
                     % (verdict, status, len(f),
                        (" — codes: " + ", ".join(codes)) if codes else ""))
    for item in f.items[:40]:
        sys.stderr.write("  [%s] %s\n" % (item["code"], item["detail"]))
    if len(f) > 40:
        sys.stderr.write("  ... and %d more (see unresolved-obligations.json)\n"
                         % (len(f) - 40))
    return 0 if verdict == "PASS" else 1


def main():
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--inventory")
    ap.add_argument("--authorization")
    ap.add_argument("--material")
    ap.add_argument("--policy")
    ap.add_argument("--licence-texts", dest="licence_texts")
    ap.add_argument("--attestations")
    ap.add_argument("--source-obligations", dest="source_obligations")
    ap.add_argument("--image-materials", dest="image_materials")
    ap.add_argument("--out-dir", dest="out_dir")
    args = ap.parse_args()
    # There is deliberately NO --self-test. A flag whose only possible outcome
    # is exit 0 is an affordance somebody wires into CI as "the gate ran", which
    # is the precise shape this repository keeps removing. The behavioural suite
    # is tests/license/test_notice_bundle.sh, the required `repo structure` job
    # runs it directly, and it can fail.
    missing = [k for k in ("inventory", "authorization", "material", "policy",
                           "licence_texts", "attestations", "source_obligations",
                           "image_materials", "out_dir") if not getattr(args, k)]
    if missing:
        hard("NB-INPUT-ABSENT",
             "every input is required and these were not given: %s. A producer "
             "that defaults a missing input is a producer that can be run "
             "against nothing" % ", ".join("--" + m.replace("_", "-") for m in missing))
    return produce(args)


if __name__ == "__main__":
    sys.exit(main())
