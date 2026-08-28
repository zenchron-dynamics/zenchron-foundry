#!/usr/bin/env python3
"""Build a SATISFIABLE input set for scripts/license/generate-notice-bundle.py.

WHY A SATISFIABLE SET IS NEEDED AT ALL.

Against the real cohort the producer REFUSES, and it should: 699 findings, none
of them invented. A suite that only ever saw a refusal would prove the producer
can say no and nothing about whether it can ever say yes — which is the shape of
a check that is green because it is vacuous, inverted. So the truth table needs
one cell where every axis is genuinely satisfied, and that cell needs inputs
that genuinely satisfy it.

WHAT IS REAL AND WHAT IS FIXTURE, stated plainly so nothing here is mistaken
for a measurement:

  REAL   the candidate identity — 20 children, their image labels, platforms and
         immutable manifest digests, and the source revision, all taken from the
         authorization record handed in.
  REAL   the carried licence texts, the upstream attestations and the
         repository-material inventory: the shipped files are used unmodified.
  FIXTURE the component list. Two packages under licences the shipped policy
         classifies `allowed`, so the notice renders over a resolved inventory.
  FIXTURE the licence policy's `publication` block. The shipped one records
         `decision: undetermined` (#98) and MUST NOT be edited; this writes a
         SEPARATE file into a scratch directory that records a decision, purely
         so the publication axis can be exercised in both states.
  FIXTURE the source-obligation states. The shipped facts record every component
         `unresolved`, because no rights holder has approved a delivery
         mechanism. This writes a scratch file recording `satisfied` so the
         satisfied path is exercised. Nothing it writes reaches the repository.

Nothing here is committed and nothing here is an audit record.
"""
import argparse
import json
import os
import shutil
import sys

import yaml


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--authorization", required=True)
    ap.add_argument("--root", required=True,
                    help="repository root to read the shipped policies from")
    ap.add_argument("--out", required=True, help="scratch directory to fill")
    ap.add_argument("--publication", choices=("present", "missing"),
                    default="present")
    ap.add_argument("--source-obligations", dest="so",
                    choices=("satisfied", "unresolved"), default="satisfied")
    a = ap.parse_args()

    os.makedirs(a.out, exist_ok=True)
    rec = json.load(open(a.authorization))
    children = rec.get("children") or []
    if not children:
        sys.stderr.write("REFUSE: the authorization record stages no children\n")
        return 1

    # --- the inventory, bound to the REAL candidate identities ---------------
    inv_children = []
    for c in sorted(children, key=lambda x: str(x.get("child_key"))):
        label = str(c.get("image_label") or "")
        fam, _, ver = label.partition("/")
        inv_children.append({
            "child_key": c["child_key"], "image_family": fam,
            "image_label": label, "image_version": ver,
            "platform": c["platform"], "manifest_digest": c["manifest_digest"],
            "source_revision": rec["source_revision"],
            "producer": "scripts/generate-sbom.sh",
        })
    zero = {"scanner-observation": 0, "package-attributed": 0,
            "independently-licensed": 0, "unresolved": 0}
    inventory = {
        "schema": "foundry.license-inventory/v1",
        "fixture": "tests/lib/make_notice_inputs.py — NOT a measurement",
        "release_binding": None,
        "image_binding": {
            "record_type": "image-sbom-licence-binding",
            "children_expected": len(children),
            "children_bound": len(children),
            "all_children_bound": True,
            "source_revision": rec["source_revision"],
            "platforms": sorted({c["platform"] for c in children}),
            "execution_modes": sorted({str(c.get("execution_mode") or "native")
                                       for c in children}),
            "sbom_schemas": ["SPDX-2.3"],
            "producers": ["scripts/generate-sbom.sh"],
            "children": inv_children,
        },
        "sbom_files": [], "sbom_formats": ["SPDX-2.3"],
        "component_count": 2, "unknown_count": 0, "conflict_count": 0,
        "package_component_count": 2, "file_component_count": 0,
        "image_files": {
            "model": "foundry.image-file-disposition/v2",
            "input_file_components": 0,
            "by_class_observations": dict(zero),
            "by_class_distinct_paths": dict(zero),
            "accounting_invariant": "input file components == 0",
            "accounting_invariant_holds": True,
            "excluded_from_package_policy": ["scanner-observation",
                                             "package-attributed"],
            "kept_in_package_policy": ["independently-licensed", "unresolved"],
            "raw_file_components": 0,
            "normalised_policy_findings_from_files": 0,
            "deduplication_note": "no file components in this fixture",
            "independently_licensed": [], "unresolved": [],
            "package_attributed_sample": [], "scanner_observation_sample": [],
            "note": "fixture",
        },
        "components": [
            {"name": "zlib1g", "version": "1:1.2.13.dfsg-1", "licenses": ["Zlib"],
             "purls": [], "sources": [], "component_type": "library",
             "unknown": False, "conflict": False},
            {"name": "libssl3", "version": "3.0.15-1~deb12u1",
             "licenses": ["Apache-2.0"], "purls": [], "sources": [],
             "component_type": "library", "unknown": False, "conflict": False},
        ],
    }
    with open(os.path.join(a.out, "inventory.json"), "w") as fh:
        json.dump(inventory, fh, indent=2, sort_keys=True)

    # --- the policy: the shipped one, with ONLY the publication block moved --
    pol = yaml.safe_load(open(os.path.join(a.root, "policies/license-policy.yaml")))
    if a.publication == "present":
        pol["publication"]["decision"] = "B"
        pol["publication"]["notices_approved_for_distribution"] = True
        pol["publication"]["decided_by"] = "fixture-owner (tests only)"
    with open(os.path.join(a.out, "license-policy.yaml"), "w") as fh:
        yaml.safe_dump(pol, fh, sort_keys=True)

    # --- the source-obligation facts, with ONLY the state moved -------------
    so = yaml.safe_load(open(os.path.join(a.root, "policies/source-obligations.yaml")))
    if a.so == "satisfied":
        for c in so.get("components") or []:
            c["source_obligation"] = "satisfied"
    with open(os.path.join(a.out, "source-obligations.yaml"), "w") as fh:
        yaml.safe_dump(so, fh, sort_keys=True)

    # --- shipped, unmodified -------------------------------------------------
    for rel, name in (("policies/repository-material.yaml", "repository-material.yaml"),
                      ("policies/upstream-licence-attestations.yaml", "attestations.yaml"),
                      ("third-party/licence-texts/PROVENANCE.yaml", "licence-texts.yaml")):
        shutil.copyfile(os.path.join(a.root, rel), os.path.join(a.out, name))

    sys.stderr.write("notice inputs: %d children, publication=%s, "
                     "source-obligations=%s -> %s\n"
                     % (len(children), a.publication, a.so, a.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
