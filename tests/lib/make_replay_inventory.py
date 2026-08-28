#!/usr/bin/env python3
"""Rebuild the licence inventory of the accepted 20-child run FROM COMMITTED
EVIDENCE, so the notice producer can be exercised against real measurements
without regenerating an 86 MB set of SBOMs.

WHY THIS LIVES UNDER tests/ AND NOT UNDER scripts/.

A tool in scripts/ that manufactured a canonical-looking licence inventory out
of a log file would be a bypass of the gate, not a replay of it. This is the
same reasoning tests/lib/make_authorization_fixture.py already carries, and it
is why neither tool is on a release path.

WHAT IS REAL HERE, AND WHAT IS NOT — stated precisely, because a reconstruction
filed beside real records is a reconstruction somebody will later read as one.

  REAL, verbatim from committed evidence:
    * the image_binding block — 20 children, their immutable manifest digests,
      platforms, per-document sha256, source revision, execution modes. Taken
      byte-for-byte from
      docs/audits/.../licence/rerun-image-binding.json, which the binding gate
      itself stamped during the buildless re-run.
    * every package component and its measured licence state — parsed out of
      docs/audits/.../licence/image-licence-policy-diagnostic.log, the gate's
      own refusal output: 8,507 findings over 8,527 components.

  NOT REAL, and deliberately fail-closed:
    * the FOUR-WAY file-component disposition. Splitting the 7,972 file entries
      into scanner-observation / package-attributed / independently-licensed /
      unresolved is a function of the `dependencies` graphs and CONTAINS /
      evident-by relationships in the 20 CycloneDX documents and their SPDX
      companions. Those documents are 86 MB and are NOT committed, so the split
      is not derivable from the committed record — see
      docs/licensing/image-licence-backlog-2026-08-28.md section 5.
      Every file entry is therefore emitted as `unresolved`, which is the
      fail-closed class: nothing has been established about it. Emitting them as
      `scanner-observation` would be inventing the very evidence that is absent,
      and it would make the replay quieter than the real run.

The output is NOT committed and is NOT an audit record. It is built into a
scratch directory by tests/license/test_notice_bundle.sh and thrown away.
"""
import argparse
import hashlib
import json
import re
import sys

UNK_HEAD = "no licence could be established"
CON_HEAD = "sources disagree about the licence"
REV_HEAD = "licence needs legal review and has not had it"


def sections(text):
    out, cur, declared = {}, None, {}
    for ln in text.splitlines():
        m = re.match(r"^  (.+) \((\d+)\):$", ln)
        if m:
            cur = m.group(1)
            out[cur] = []
            declared[cur] = int(m.group(2))
            continue
        if ln.startswith("    - ") and cur is not None:
            out[cur].append(ln[6:])
    for k, v in out.items():
        if len(v) != declared[k]:
            sys.stderr.write("REFUSE: section %r declares %d and carries %d\n"
                             % (k, declared[k], len(v)))
            raise SystemExit(1)
    return out


def pick(sec, head):
    for k in sec:
        if k.startswith(head):
            return sec[k]
    return []


def is_path(label):
    if label.startswith("/"):
        return True
    return label.startswith("../") and "@" not in label


def split_nv(label):
    n, _, v = label.rpartition("@")
    return (n, v) if n else (label, "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binding", required=True)
    ap.add_argument("--diagnostic", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    bind = json.load(open(a.binding))
    ib = bind.get("image_binding") or {}
    if ib.get("record_type") != "image-sbom-licence-binding":
        sys.stderr.write("REFUSE: %s carries no image_binding stamped by the "
                         "binding gate\n" % a.binding)
        raise SystemExit(1)

    sec = sections(open(a.diagnostic).read())
    unknown = pick(sec, UNK_HEAD)
    conflicts = pick(sec, CON_HEAD)
    review = pick(sec, REV_HEAD)

    components, file_entries = [], []
    for label in sorted(unknown):
        if is_path(label):
            file_entries.append({
                "path": label, "document": "not-committed", "class": "unresolved",
                "reason": ("the four-way disposition is a function of the "
                           "CycloneDX dependency graph and the SPDX CONTAINS / "
                           "evident-by relationships, and those 40 documents are "
                           "not committed. Nothing has been established about "
                           "this file, so it stays in the fail-closed class"),
                "licenses": [],
                "conflicting_or_exceptional_licence_metadata": False,
            })
            continue
        n, v = split_nv(label)
        components.append({"name": n, "version": v, "licenses": [], "purls": [],
                           "sources": [], "component_type": "library",
                           "unknown": True, "conflict": False})
    for line in sorted(conflicts):
        head, _, expr = line.partition(" (")
        n, v = split_nv(head)
        vals = sorted({x.strip() for x in expr.rstrip(")").split(" vs ") if x.strip()})
        components.append({"name": n, "version": v, "licenses": vals, "purls": [],
                           "sources": [], "component_type": "library",
                           "unknown": False, "conflict": True})
    for line in sorted(review):
        head, _, lic = line.partition(" [")
        n, v = split_nv(head)
        components.append({"name": n, "version": v, "licenses": [lic.rstrip("]")],
                           "purls": [], "sources": [], "component_type": "library",
                           "unknown": False, "conflict": False})

    # The clean components the diagnostic does not list, because a gate prints
    # findings and not passes. component_count minus the findings is how many
    # there were; they cannot be named from the committed record, so they are
    # not invented — the replay carries the components the evidence names and
    # records the shortfall in the open.
    named = len(components) + len(file_entries)
    total = bind.get("component_count")

    counts = {"scanner-observation": 0, "package-attributed": 0,
              "independently-licensed": 0, "unresolved": len(file_entries)}
    for e in file_entries:
        components.append({"name": e["path"], "version": "", "licenses": [],
                           "purls": [], "sources": [], "component_type": "file",
                           "file_class": "unresolved", "unknown": True,
                           "conflict": False})

    doc = {
        "schema": "foundry.license-inventory/v1",
        "replay_of": ("docs/audits/real-image-inventories-2026-08-28 — rebuilt "
                      "from committed evidence, NOT regenerated from SBOMs"),
        "replay_named_components": named,
        "replay_inventory_component_count": total,
        "replay_unnamed_clean_components": (total - named) if total else None,
        "release_binding": None,
        "image_binding": ib,
        "sbom_files": sorted(c.get("sbom_file") for c in ib.get("children") or []),
        "sbom_formats": sorted(ib.get("sbom_schemas") or []),
        "component_count": len(components),
        "unknown_count": sum(1 for c in components if c["unknown"]),
        "conflict_count": sum(1 for c in components if c["conflict"]),
        "package_component_count": sum(1 for c in components
                                       if c.get("component_type") != "file"),
        "file_component_count": sum(1 for c in components
                                    if c.get("component_type") == "file"),
        "image_files": {
            "model": "foundry.image-file-disposition/v2",
            "input_file_components": len(file_entries),
            "by_class_observations": counts,
            "by_class_distinct_paths": counts,
            "accounting_invariant": (
                "input file components == %d == scanner-observation 0 + "
                "package-attributed 0 + independently-licensed 0 + unresolved %d"
                % (len(file_entries), len(file_entries))),
            "accounting_invariant_holds": True,
            "excluded_from_package_policy": ["scanner-observation",
                                             "package-attributed"],
            "kept_in_package_policy": ["independently-licensed", "unresolved"],
            "raw_file_components": len(file_entries),
            "normalised_policy_findings_from_files": len(file_entries),
            "deduplication_note": (
                "package-attributed files are DE-DUPLICATED against their owning "
                "package, not exempted. This replay attributes none, because the "
                "documents that prove ownership are not committed."),
            "independently_licensed": [],
            "unresolved": file_entries[:2000],
            "package_attributed_sample": [],
            "scanner_observation_sample": [],
            "note": ("REPLAY. The four-way split is not derivable from the "
                     "committed record; every file entry is in the fail-closed "
                     "class."),
        },
        "components": components,
    }
    blob = json.dumps(doc, indent=2, sort_keys=True) + "\n"
    doc["inventory_sha256"] = hashlib.sha256(blob.encode()).hexdigest()
    with open(a.out, "w") as fh:
        fh.write(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    sys.stderr.write(
        "replay inventory: %d components (%d package, %d file), %d unknown, "
        "%d conflicting; %s of %s inventory components are named by the "
        "diagnostic (a gate prints findings, not passes)\n"
        % (doc["component_count"], doc["package_component_count"],
           doc["file_component_count"], doc["unknown_count"],
           doc["conflict_count"], named, total))
    return 0


if __name__ == "__main__":
    sys.exit(main())
