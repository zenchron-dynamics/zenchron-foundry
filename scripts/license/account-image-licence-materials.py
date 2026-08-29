#!/usr/bin/env python3
# =============================================================================
# scripts/license/account-image-licence-materials.py — #120 action N1, part 2.
# -----------------------------------------------------------------------------
# Every component implicated by the substantive licence backlog gets exactly ONE
# material classification, and the classes reconcile to the implicated total or
# this tool refuses.
#
# WHY THE PACKAGE DATABASE AND NOT A VERSION-STRING HEURISTIC. The backlog
# grouper classifies ecosystems from version syntax, which is the right tool for
# grouping a refusal and the wrong one here: it reads 78 real Debian packages as
# `unclassified` because their versions carry no `+debNuM` marker. N1 is an
# accounting over what is INSIDE the image, so the package identity comes from
# the image's own installed-package database — `var/lib/dpkg/status` and
# `lib/apk/db/installed`, extracted from the accepted digests — and a component
# is Debian-governed if and only if that image says it is.
#
# `/usr/share/doc/<pkg>/copyright` IS NOT UNIVERSAL COVERAGE, and pretending it
# is would be the whole failure of this action. It is one ecosystem's
# convention:
#
#   Debian     ships it per binary package, sometimes as a symlink to a sibling
#              package's file, sometimes gzip-compressed, and it frequently
#              defers to /usr/share/common-licenses/<NAME>.
#   Alpine     ships NOTHING of the sort. apk strips documentation; the package
#              database carries an `L:` field, which is a licence IDENTIFIER and
#              not a copyright notice or a licence text.
#   Go         modules are compiled into a binary. There is no vendored licence
#              tree in a runtime image, so no path was ever expected.
#   PHP        the interpreter and the extensions compiled by
#              docker-php-ext-install are not dpkg-managed and leave no licence
#              file behind; PEAR components under /usr/local/lib/php/doc do.
#
# So the classes distinguish "the image ships nothing because this ecosystem
# never does" from "the convention applies here and the file is missing". They
# are different findings with different owners and collapsing them would hide
# the second inside the first.
#
# THE SIX CLASSES, exactly one per component:
#
#   extracted                  material present and captured, directly or
#                              through a symlink resolved INSIDE that same image
#   ambiguous                  material present but not self-sufficient — e.g. a
#                              copyright file whose only licence reference
#                              points at a /usr/share/common-licenses path that
#                              is not in that image
#   absent                     package-manager-governed, and the ecosystem ships
#                              no such material at all; no path was expected
#   path-expected-unavailable  the convention DOES apply and the expected file
#                              is not in the image. Fail-closed.
#   non-package-managed        no package manager in the image governs it
#   legal-review-required      whether anything is owed cannot be decided
#                              mechanically
#
# The invariant the brief states is asserted with `absent` as the union of the
# two absence classes, AND the six-way sum is asserted separately, so the
# sub-split can never be used to lose a component:
#
#   implicated = extracted + ambiguous + absent + non-package-managed
#                + legal-review-required
#
# Usage:
#   account-image-licence-materials.py --materials FILE --diagnostic FILE
#       --acceptance FILE --out FILE [--objects DIR]
# =============================================================================
import argparse
import collections
import gzip
import hashlib
import json
import os
import posixpath
import re
import sys

SCHEMA = "foundry.image-licence-accounting/v1"
TOOL = "scripts/license/account-image-licence-materials.py"

CLASSES = ("extracted", "ambiguous", "absent", "path-expected-unavailable",
           "non-package-managed", "legal-review-required")
ABSENT_UNION = ("absent", "path-expected-unavailable")

# Common-licence names legitimately contain dots (LGPL-2.1), so a greedy match
# cannot simply strip them — and an ungreedy one truncates the name. The match is
# therefore RESOLVED against the names the image actually ships, trimming
# trailing punctuation only until it hits one. Getting this wrong reported 24
# packages as deferring to a file that was sitting in the image all along.
COMMON_LICENCE_REF = re.compile(rb"/usr/share/common-licenses/([A-Za-z0-9._+-]+)")


def resolve_common_ref(raw_name, present):
    cand = raw_name
    while cand:
        if cand in present:
            return cand, True
        if cand[-1] in ".,;:":
            cand = cand[:-1]
            continue
        return raw_name.rstrip(".,;:") or raw_name, False
    return raw_name, False


def hard(code, msg):
    sys.stderr.write("REFUSE [%s]: %s\n" % (code, msg))
    raise SystemExit(2)


def is_image_path(label):
    if label.startswith("/"):
        return True
    return label.startswith("../") and "@" not in label


def split_nv(label):
    n, _, v = label.rpartition("@")
    return (n, v) if n else (label, "")


def implicated_from_diagnostic(text):
    """The 535 substantive findings, taken from the gate's OWN refusal output.
    The committed backlog JSON truncates one group's component list at 80, so it
    cannot be the source: an accounting built on a truncated list would report
    complete coverage of a set it never saw."""
    sections, cur, declared = collections.OrderedDict(), None, {}
    for ln in text.splitlines():
        m = re.match(r"^  (.+) \((\d+)\):$", ln)
        if m:
            cur = m.group(1)
            sections[cur] = []
            declared[cur] = int(m.group(2))
            continue
        if ln.startswith("    - ") and cur is not None:
            sections[cur].append(ln[6:])
    for k, items in sections.items():
        if len(items) != declared[k]:
            hard("NA-DIAGNOSTIC-TRUNCATED",
                 "section %r declares %d finding(s) and carries %d"
                 % (k, declared[k], len(items)))
    out = []
    for head, items in sections.items():
        if head.startswith("no licence could be established"):
            for x in items:
                if not is_image_path(x):
                    out.append((x, "no-assertion"))
        elif head.startswith("sources disagree"):
            out += [(x.split(" (")[0], "conflict") for x in items]
        elif head.startswith("licence needs legal review"):
            out += [(x.split(" [")[0], "legal-review") for x in items]
    return out


def parse_dpkg_status(raw):
    """{(package, version): {arch, source}} for packages whose Status says the
    package is actually installed. `deinstall`/`config-files` entries are NOT
    installed material and must not be counted as present."""
    out = {}
    for block in raw.decode("utf-8", "replace").split("\n\n"):
        f = {}
        key = None
        for line in block.splitlines():
            if line.startswith((" ", "\t")) and key:
                f[key] += "\n" + line.strip()
            elif ":" in line:
                key, _, val = line.partition(":")
                f[key] = val.strip()
        if not f.get("Package") or not f.get("Version"):
            continue
        if " installed" not in (f.get("Status") or ""):
            continue
        src = (f.get("Source") or f["Package"]).split(" ")[0]
        out[(f["Package"], f["Version"])] = {
            "architecture": f.get("Architecture"), "source_package": src}
    return out


def parse_apk_db(raw):
    """{(P, V): {origin, licence}} from the apk installed database."""
    out, cur = {}, {}
    for block in raw.decode("utf-8", "replace").split("\n\n"):
        cur = {}
        for line in block.splitlines():
            k, _, v = line.partition(":")
            if _:
                cur[k] = v
        if cur.get("P") and cur.get("V"):
            out[(cur["P"], cur["V"])] = {
                "origin": cur.get("o") or cur["P"],
                "apk_declared_licence": cur.get("L")}
    return out


TEXT_KINDS = ("deb-copyright", "deb-doc-licence", "deb-common-licence",
              "apk-licence", "generic-licence")


def publish(mats, objects, outdir):
    """Carry the licence/copyright TEXTS into the repository, content-addressed.

    One file per distinct sha256, whatever number of packages, children or paths
    refer to it — 118 Debian copyright files across 18 children collapse to 118
    objects, not 2,124 copies. Every consumer is bound to the hash, so a shared
    file cannot drift for one consumer and not another.

    Package databases and distro-identity files are deliberately NOT carried.
    They are evidence for the MAPPING, not material an obligation requires
    preserving, and they are two thirds of the bytes."""
    objdir = os.path.join(outdir, "objects")
    os.makedirs(objdir, exist_ok=True)
    refs = {}
    for c in mats["children"]:
        for m in child_materials(mats, c):
            h = m.get("sha256")
            if not h or m["kind"] not in TEXT_KINDS:
                continue
            r = refs.setdefault(h, {"sha256": h, "kind": m["kind"],
                                    "paths": set(), "children": set()})
            r["paths"].add(m["path"])
            r["children"].add(c["child_key"])
    files = []
    for h in sorted(refs):
        src = os.path.join(objects, h[:2], h)
        raw = open(src, "rb").read()
        if hashlib.sha256(raw).hexdigest() != h:
            hard("NA-OBJECT-DRIFT", "stored object %s does not hash to its name" % h)
        d = os.path.join(objdir, h[:2])
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, h), "wb") as fh:
            fh.write(raw)
        r = refs[h]
        files.append({"path": "%s/objects/%s/%s" % (outdir.rstrip("/"), h[:2], h),
                      "sha256": h, "bytes": len(raw), "kind": r["kind"],
                      "verbatim": True, "local_modifications": "none",
                      "in_image_paths": sorted(r["paths"]),
                      "children": sorted(r["children"])})
    return {"count": len(files), "bytes": sum(f["bytes"] for f in files),
            "directory": outdir, "files": files}


def child_materials(mats, c):
    """The extraction manifest stores identical material sets once and has each
    child reference the set it has. A reader that assumed a per-child list would
    silently see nothing, so this is the ONE place the indirection is followed."""
    if "materials" in c:
        return c["materials"]
    sets = mats.get("material_sets")
    idx = c.get("material_set")
    if sets is None or idx is None or idx >= len(sets):
        hard("NA-INPUT-MALFORMED",
             "child %s references material set %r and the manifest holds %s set(s)"
             % (c.get("child_key"), idx, "no" if sets is None else len(sets)))
    return sets[idx]


def collapse(per, index=None):
    """Eighteen children usually reach the SAME copyright file by the same chain.
    Storing that outcome eighteen times makes a 2 MB record out of a 200 KB one,
    so identical outcomes are stored once against the list of children that share
    them. Nothing is lost — every child still appears exactly once — and a child
    whose outcome DIFFERS keeps its own entry, which is the case that matters."""
    groups = collections.OrderedDict()
    for ck in sorted(per):
        key = json.dumps(per[ck], sort_keys=True)
        groups.setdefault(key, []).append(index[ck] if index else ck)
    if len(groups) == 1:
        only = list(groups)[0]
        return {"children": groups[only], "outcome": json.loads(only)}
    return {"outcomes": [{"children": v, "outcome": json.loads(k)}
                         for k, v in groups.items()]}


def per_child_outcomes(pc):
    """Read a collapsed per_child block back as {child: outcome}."""
    if not pc:
        return {}
    if "outcome" in pc:
        return {c: pc["outcome"] for c in pc["children"]}
    out = {}
    for g in pc.get("outcomes") or []:
        for c in g["children"]:
            out[c] = g["outcome"]
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--materials", required=True)
    ap.add_argument("--diagnostic", required=True)
    ap.add_argument("--acceptance", required=True)
    ap.add_argument("--objects", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--publish-dir",
                    help="carry the licence/copyright TEXTS into the repository, "
                         "content-addressed, with a carried-licence-texts "
                         "provenance record. Package databases and distro "
                         "identity files are NOT carried: they are evidence for "
                         "the mapping, not material an obligation requires "
                         "preserving, and they are the bulk of the bytes.")
    a = ap.parse_args()

    mats = json.load(open(a.materials))
    if mats.get("schema") != "foundry.image-licence-materials/v1":
        hard("NA-INPUT-MALFORMED",
             "%s is not a foundry.image-licence-materials/v1 record" % a.materials)
    acc = json.load(open(a.acceptance))
    expected = len(acc.get("children") or [])
    if len(mats.get("children") or []) != expected:
        hard("NA-COHORT-INCOMPLETE",
             "the extraction covers %d child(ren) and the accepted run staged "
             "%d. An accounting over a partial cohort reports complete coverage "
             "of images it never opened"
             % (len(mats.get("children") or []), expected))

    implicated = implicated_from_diagnostic(open(a.diagnostic).read())

    # --- per-child indexes, from the images' OWN databases -------------------
    def obj(sha):
        p = os.path.join(a.objects, sha[:2], sha)
        return open(p, "rb").read() if os.path.isfile(p) else None

    children = {}
    for c in mats["children"]:
        by_path = {m["path"]: m for m in child_materials(mats, c)}
        deb, apk = {}, {}
        for path, kind, parse, target in (
                ("var/lib/dpkg/status", "dpkg-status", parse_dpkg_status, "deb"),
                ("lib/apk/db/installed", "apk-db", parse_apk_db, "apk")):
            rec = by_path.get(path)
            if rec and rec.get("sha256"):
                raw = obj(rec["sha256"])
                if raw is None:
                    hard("NA-OBJECT-MISSING",
                         "%s: %s is recorded as sha256 %s and no such object is "
                         "stored" % (c["child_key"], path, rec["sha256"]))
                (deb if target == "deb" else apk).update(parse(raw))
        children[c["child_key"]] = {
            "child": c, "by_path": by_path, "deb": deb, "apk": apk,
            "common_licenses": {
                posixpath.basename(p) for p in by_path
                if p.startswith("usr/share/common-licenses/")},
        }

    # --- resolve one Debian package's copyright material in one child --------
    def deb_material(ci, pkg):
        """Return (state, record). Symlinks are followed INSIDE the image and the
        target's own hash is carried, because "libfoo1 is covered by libfoo's
        copyright" is a claim about a relationship that has to be shown."""
        base = "usr/share/doc/%s/copyright" % pkg
        hops = []
        # Resolve the DOC DIRECTORY chain first. Debian links a whole doc
        # directory at a sibling package's, and it CHAINS:
        # binutils-x86-64-linux-gnu -> libbinutils -> binutils-common. Following
        # one hop reported four installed packages as missing a copyright file
        # the image ships two indirections away.
        dirpath = "usr/share/doc/%s" % pkg
        rec = None
        for _ in range(8):
            rec = (ci["by_path"].get(dirpath + "/copyright")
                   or ci["by_path"].get(dirpath + "/copyright.gz"))
            if rec is not None:
                break
            dl = ci["by_path"].get(dirpath)
            if dl is not None and dl.get("type") in ("symlink", "hardlink"):
                hops.append({"path": dl["path"], "type": "symlink-directory",
                             "link_target_raw": dl["link_target_raw"],
                             "link_target_resolved": dl["link_target_resolved"]})
                dirpath = dl["link_target_resolved"]
                continue
            break
        path = dirpath + "/copyright"
        for _ in range(8):
            if rec is None:
                rec = ci["by_path"].get(path) or ci["by_path"].get(path + ".gz")
            if rec is None:
                return "path-expected-unavailable", {
                    "expected_path": base, "chain": hops,
                    "reason": ("the package is installed according to this "
                               "image's own dpkg database and neither "
                               "/usr/share/doc/<pkg>/copyright nor any doc "
                               "directory or file symlink chain from it "
                               "reaches a copyright file in this image")}
            hops.append({"path": rec["path"], "type": rec["type"]})
            if rec["type"] in ("symlink", "hardlink"):
                path = rec["link_target_resolved"]
                hops[-1]["link_target_raw"] = rec["link_target_raw"]
                hops[-1]["link_target_resolved"] = path
                rec = None
                continue
            # `captured: true` is implied by a stored sha256; only an explicit
            # false (the size cap fired) means the bytes were not taken.
            if rec.get("captured") is False or not rec.get("sha256"):
                return "ambiguous", {
                    "expected_path": base, "chain": hops,
                    "reason": rec.get("capture_skipped_reason", "not captured")}
            raw = obj(rec["sha256"])
            if raw is None:
                return "path-expected-unavailable", {
                    "expected_path": base, "chain": hops,
                    "reason": "recorded object %s is not stored" % rec["sha256"]}
            body = raw
            transformed = None
            if rec["path"].endswith(".gz"):
                try:
                    body = gzip.decompress(raw)
                    transformed = {
                        "form": "gzip-decompressed",
                        "derived_sha256": hashlib.sha256(body).hexdigest(),
                        "note": ("a DERIVED artifact with its own checksum; the "
                                 "stored bytes remain the compressed ones that "
                                 "shipped")}
                except OSError:
                    return "ambiguous", {"expected_path": base, "chain": hops,
                                         "reason": "recorded .gz is not gzip"}
            raw_refs = sorted({r.decode() for r in COMMON_LICENCE_REF.findall(body)})
            resolved = [resolve_common_ref(r, ci["common_licenses"]) for r in raw_refs]
            refs = sorted({n for n, _ in resolved})
            missing = sorted({n for n, ok in resolved if not ok})
            # The chain is kept whenever it carries information — that is,
            # whenever there WAS an indirection. For the common case, a package
            # whose own copyright file is right where the convention says, the
            # single hop repeats `resolved_path` and is dropped. `indirect`
            # says which case this is, so its absence is never ambiguous.
            trivial = (len(hops) == 1 and hops[0].get("path") == rec["path"]
                       and hops[0].get("type") == "file")
            out = {"expected_path": base, "indirect": not trivial,
                   "resolved_path": rec["path"], "sha256": rec["sha256"],
                   "bytes": rec.get("bytes"),
                   "verbatim": transformed is None,
                   "common_licence_refs": refs}
            if not trivial:
                out["chain"] = hops
            if transformed:
                out["derived"] = transformed
            if missing:
                out["reason"] = (
                    "the copyright file defers to %s and %s not in this image, "
                    "so the file alone does not state the terms"
                    % (", ".join("/usr/share/common-licenses/" + r for r in missing),
                       "it is" if len(missing) == 1 else "they are"))
                out["common_licence_refs_missing"] = missing
                return "ambiguous", out
            return "extracted", out
        return "ambiguous", {"expected_path": base, "chain": hops,
                             "reason": "symlink chain did not terminate"}

    # CHILD KEYS ARE INTERNED. Nearly every component's outcome covers all
    # eighteen Debian children, and writing out eighteen 30-character keys per
    # component is 100 KB of repetition in a record the repository caps at
    # 512 KB. `children_index` is the one place the names live; a per_child
    # entry carries positions into it.
    cindex = {k: i for i, k in enumerate(sorted(children))}
    cnames = sorted(children)

    rows = []
    for label, finding in implicated:
        name, version = split_nv(label)
        in_deb = sorted(k for k, ci in children.items() if (name, version) in ci["deb"])
        in_apk = sorted(k for k, ci in children.items() if (name, version) in ci["apk"])
        row = {"component": label, "name": name, "version": version,
               "finding": finding,
               "children_installed": len(in_deb) + len(in_apk)}

        if in_deb:
            row["package_manager"] = "dpkg"
            row["source_package"] = children[in_deb[0]]["deb"][(name, version)]["source_package"]
            per = {}
            worst = "extracted"
            order = {"extracted": 0, "ambiguous": 1, "path-expected-unavailable": 2}
            for k in in_deb:
                st, det = deb_material(children[k], name)
                per[k] = dict(det, state=st)
                if order[st] > order[worst]:
                    worst = st
            row["per_child"] = collapse(per, cindex)
            row["classification"] = worst
            hashes = sorted({d.get("sha256") for d in per.values() if d.get("sha256")})
            row["material_sha256"] = hashes
        elif in_apk:
            row["package_manager"] = "apk"
            meta = children[in_apk[0]]["apk"][(name, version)]
            row["apk_origin"] = meta["origin"]
            row["apk_declared_licence"] = meta["apk_declared_licence"]
            row["classification"] = "absent"
            row["reason"] = (
                "Alpine ships no per-package copyright or licence file: apk "
                "strips documentation. The database records L:%r, which is a "
                "licence IDENTIFIER, not a copyright notice and not a licence "
                "text. No path was expected, and none is missing."
                % meta["apk_declared_licence"])
        elif label == "../@UNKNOWN":
            row["classification"] = "legal-review-required"
            row["reason"] = (
                "a nameless binary-cataloguer artifact. Whether it denotes a "
                "distributed component at all cannot be decided from the image, "
                "so neither can what it owes.")
        else:
            row["classification"] = "non-package-managed"
            row["package_manager"] = None
            if name.startswith("ghcr.io/"):
                row["reason"] = ("the image root: the SBOM's own subject, not a "
                                 "third-party dependency inside it")
            elif label in ("debian@12", "alpine@3.23.5"):
                row["reason"] = ("a distro identity marker read from "
                                 "/etc/os-release, not an installed package")
            elif re.match(r"^v?\d", version) and "/" in name or name == "caddy":
                row["reason"] = ("a Go module compiled into a binary. A runtime "
                                 "image carries no vendored licence tree, so no "
                                 "in-image path was ever expected")
            else:
                row["reason"] = ("built into the image outside any package "
                                 "manager (docker-php-ext-install, pecl, or a "
                                 "copied binary), so the image's package "
                                 "database does not govern it and no ecosystem "
                                 "convention applies")
            # PEAR components DO leave a licence file behind; find it.
            hits = []
            for k, ci in children.items():
                for p, rec in ci["by_path"].items():
                    if p.startswith("usr/local/lib/php/doc/%s/" % name) and rec.get("sha256"):
                        hits.append({"child": k, "path": p, "sha256": rec["sha256"]})
            if hits:
                row["classification"] = "extracted"
                row["package_manager"] = "pear"
                row["material_sha256"] = sorted({h["sha256"] for h in hits})
                row["per_child"] = collapse(
                    {h["child"]: {"state": "extracted",
                                  "resolved_path": h["path"],
                                  "sha256": h["sha256"]} for h in hits}, cindex)
                row["reason"] = ("PEAR ships its licence under "
                                 "/usr/local/lib/php/doc/<component>/")
        rows.append(row)

    # REASON TEXTS ARE INTERNED. Three hundred and twenty components share one
    # sentence about Go modules; writing it out three hundred and twenty times
    # is 48 KB of the same string and pushes the record past the repository's
    # 512 KB per-file limit, which exists precisely to stop this. Each row keeps
    # a `reason_key`; the text is in `reason_texts`, once.
    reason_texts, keys = {}, {}
    for r in rows:
        why = r.pop("reason", None)
        if not why:
            continue
        if why not in keys:
            keys[why] = "R%02d" % (len(keys) + 1)
            reason_texts[keys[why]] = why
        r["reason_key"] = keys[why]

    counts = collections.Counter(r["classification"] for r in rows)
    for c in CLASSES:
        counts.setdefault(c, 0)
    six = sum(counts[c] for c in CLASSES)
    if six != len(rows):
        hard("NA-ACCOUNTING-UNBALANCED",
             "%d implicated component(s) and %d classified across %s"
             % (len(rows), six, list(CLASSES)))
    absent_union = sum(counts[c] for c in ABSENT_UNION)
    five = (counts["extracted"] + counts["ambiguous"] + absent_union
            + counts["non-package-managed"] + counts["legal-review-required"])
    if five != len(rows):
        hard("NA-ACCOUNTING-UNBALANCED",
             "the stated invariant does not hold: %d != %d" % (five, len(rows)))

    published = None
    if a.publish_dir:
        published = publish(mats, a.objects, a.publish_dir)

    doc = {
        "schema": SCHEMA,
        "record_type": "image-licence-accounting",
        "producer": TOOL,
        "extraction_tool": mats.get("extraction_tool"),
        "extraction_tool_sha256": mats.get("extraction_tool_sha256"),
        "source_revision": mats.get("source_revision"),
        "children_accounted": len(mats["children"]),
        "children_index": cnames,
        "implicated_components": len(rows),
        "classes": list(CLASSES),
        "by_class": {c: counts[c] for c in CLASSES},
        "absent_union": absent_union,
        "invariant": ("implicated = extracted + ambiguous + absent + "
                      "non-package-managed + legal-review-required, with absent "
                      "as the union of absent and path-expected-unavailable"),
        "invariant_holds": True,
        "reason_texts": reason_texts,
        "carried_texts": published,
        "components": rows,
    }
    with open(a.out, "w") as fh:
        # indent=1, not 2: this record is 535 components deep and the repository
        # blocks files over 512 KB. One space per level keeps it readable and
        # keeps it under, which is the trade the limit is asking for.
        fh.write(json.dumps(doc, indent=1, sort_keys=True) + "\n")
    sys.stderr.write("accounting: %d implicated component(s)\n" % len(rows))
    for c in CLASSES:
        sys.stderr.write("  %-28s %4d\n" % (c, counts[c]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
