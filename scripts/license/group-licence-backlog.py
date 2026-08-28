#!/usr/bin/env python3
# =============================================================================
# scripts/license/group-licence-backlog.py — normalise a licence refusal into a
# backlog grouped by ROOT CAUSE and LICENCE EXPRESSION.
# -----------------------------------------------------------------------------
# assert-license-policy.sh prints one line per finding. Over a 20-child image
# cohort that is thousands of lines in which the same three or four causes recur,
# and a backlog with one row per finding is a backlog nobody can act on: it hides
# that 163 of 196 "conflicts" are ONE normalisation defect and that 248 of 320
# "no assertion" findings are ONE cataloguer's output.
#
# This tool DECIDES NOTHING. It does not resolve, suppress, waive or reclassify a
# finding; every input line appears in exactly one output group and the group
# totals reconcile to the input totals or the tool refuses. It is a lens, not a
# gate.
#
# Root causes are derived, never assumed:
#   RC1  an SPDX licence EXPRESSION and the CycloneDX enumeration of its own
#        members, i.e. the same fact at two granularities. Detected by showing
#        every asserted set is a subset of the union and one of them IS the union.
#   RC2  one identifier spelled two ways (LicenseRef-X / free text "X Y" / a `+`
#        rendered as `-`). Detected by canonicalising and finding one set.
#   RC3  no source states the whole expression — the members are enumerated but
#        the expression that joins them was truncated.
#   RC4  a licence TEXT HASH used as an identifier: the scanner resolved nothing
#        and emitted sha256:<64 hex>.
#   RC5  a substantive divergence: two sources naming genuinely different
#        licences. This is the only conflict class that is a LEGAL question.
#
# Usage:
#   group-licence-backlog.py --diagnostic <assert-license-policy stderr capture>
#                            [--out FILE] [--markdown FILE]
# =============================================================================
import argparse
import collections
import json
import re
import sys

UNK_HEAD = "no licence could be established"
CON_HEAD = "sources disagree about the licence"
REV_HEAD = "licence needs legal review and has not had it"
DEN_HEAD = "licence is DENIED by policy"
EXP_HEAD = "the exception that permitted this has EXPIRED"
HEADS = [UNK_HEAD, CON_HEAD, REV_HEAD, DEN_HEAD, EXP_HEAD]


def parse_diagnostic(text):
    """Split a gate refusal into its declared sections, and REFUSE if a section
    holds a different number of lines than its own header claims."""
    sections, cur = collections.OrderedDict(), None
    declared = {}
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
            sys.stderr.write(
                "REFUSE: section %r declares %d finding(s) and carries %d. A "
                "backlog built from a truncated diagnostic under-reports the "
                "thing it exists to report\n" % (k, declared[k], len(items)))
            raise SystemExit(1)
    return sections


# --- file components ---------------------------------------------------------
# A CycloneDX `type: "file"` component is named by its PATH. Nothing else in an
# image inventory begins with `/` or `../`. Go module names contain slashes too,
# which is why the test is on the FIRST character and not on "contains a slash":
# classifying `cel.dev/expr@v0.25.1` as a file path would delete 248 real
# package findings from the backlog.
def is_image_path(label):
    # A file component in this inventory has an EMPTY version, so the gate prints
    # its bare path with no `@`. `../@UNKNOWN` is therefore NOT a file: it carries
    # an explicit version, which only a package component can have — it is a
    # binary-cataloguer entry with a degenerate name. Counting it as a file turns
    # the committed 7,972 / 535 split into 7,973 / 534, which is exactly the kind
    # of one-row drift that makes two records of the same run disagree.
    if label.startswith("/"):
        return True
    return label.startswith("../") and "@" not in label


def split_name(label):
    name, _, ver = label.rpartition("@")
    return (name, ver) if name else (label, "")


ECOSYSTEM_RULES = [
    ("pkg:oci  image root", lambda n, v: v.startswith("sha256:")),
    ("pkg:apk  Alpine", lambda n, v: bool(re.search(r"-r\d+$", v))),
    ("pkg:deb  Debian", lambda n, v: bool(re.search(r"(deb\d+u?\d*|\+b\d+|\+nmu\d*|~deb|^\d+:)", v))),
    # A Go module path starts with a REAL host (`cel.dev/expr`,
    # `github.com/...`). Testing merely for "a dot in the first segment" would
    # swallow `../@UNKNOWN`, which is a degenerate binary-cataloguer entry and not
    # a Go module at all.
    ("pkg:golang  Go module", lambda n, v: bool(
        re.match(r"^[a-z0-9][a-z0-9-]*(\.[a-z0-9-]+)+/", n))
        or bool(re.match(r"^v\d+\.\d+\.\d+", v))),
    ("pkg:generic  PHP binary/extension", lambda n, v: bool(re.fullmatch(r"8\.\d+\.\d+", v))),
    ("pkg:generic  distro identity", lambda n, v: n in ("alpine", "debian")),
    ("pkg:pear  PEAR/PECL", lambda n, v: bool(n) and n[0].isupper() and bool(re.fullmatch(r"\d+\.\d+\.\d+", v))),
]


def ecosystem(label):
    n, v = split_name(label)
    for name, test in ECOSYSTEM_RULES:
        try:
            if test(n, v):
                return name
        except Exception:
            continue
    return "pkg:generic  unclassified"


# Family attribution is derived from the PACKAGE MANAGER the version string
# belongs to, cross-checked against the cohort's own per-child package counts in
# sbom-document-index.json. It is NOT a per-child package list: the 40 documents
# are 86 MB and are not committed, so a per-child attribution is not derivable
# from the committed record and is reported as such rather than guessed.
FAMILY_BY_ECOSYSTEM = {
    "pkg:apk  Alpine": "Alpine-based family (caddy/prod)",
    "pkg:deb  Debian": "Debian bookworm families (nginx/prod, php-cli, php-fpm, php-worker, php-frankenphp)",
    "pkg:golang  Go module": "caddy/prod (Go modules linked into the caddy binary)",
    "pkg:generic  PHP binary/extension": "php-cli, php-fpm (and via them php-worker)",
    "pkg:pear  PEAR/PECL": "php-cli, php-fpm, php-worker, php-frankenphp",
    "pkg:oci  image root": "all 10 image families",
    "pkg:generic  distro identity": "all families (base-image identity component)",
    "pkg:generic  unclassified": "not derivable from the committed record",
}


def canon(v):
    v = v.strip()
    if v.startswith("LicenseRef-"):
        v = v[len("LicenseRef-"):]
    v = v.strip("()")
    v = v.replace("+", "-").replace("_or_", " OR ")
    v = re.sub(r"[\s/_]+", "-", v)
    return re.sub(r"-+", "-", v.lower()).strip("-")


def members(expr):
    return frozenset(canon(p) for p in re.split(r"\s+AND\s+", expr.strip("()")) if p.strip())


def conflict_root_cause(values):
    real = [v for v in values if v != "NOASSERTION"]
    if any(re.fullmatch(r"(LicenseRef-)?(sha256:)?[0-9a-f]{64}", v) for v in real):
        return "RC4 licence text hash used as an identifier"
    sets = [members(v) for v in real]
    if not sets:
        return "RC5 substantive divergence"
    union = frozenset().union(*sets)
    if not all(s <= union for s in sets):
        return "RC5 substantive divergence"
    if len(set(sets)) == 1:
        return "RC2 one identifier, two spellings"
    if any(s == union for s in sets):
        return "RC1 SPDX expression vs CycloneDX enumeration of its members"
    return "RC3 no source states the whole expression"


CONFLICT_LINE = re.compile(r"^(.+?)@(.+?) \((.*)\)$")
REVIEW_LINE = re.compile(r"^(.+?)@(.+?) \[(.+)\]$")


def pick(sections, head):
    """Sections are keyed by the gate's own heading, and one of those headings
    carries a parenthesised aside. Matching on the prefix rather than on equality
    is what stops a renamed aside from silently emptying a whole class."""
    out = []
    for k, v in sections.items():
        if k.startswith(head):
            out.extend(v)
    return out


def build(sections):
    groups = []
    counted = 0

    # --- no licence could be established ------------------------------------
    unknown = pick(sections, UNK_HEAD)
    files = [x for x in unknown if is_image_path(x)]
    pkgs = [x for x in unknown if not is_image_path(x)]
    counted += len(unknown)
    if files:
        groups.append({
            "group_id": "G-FILE-NOASSERTION",
            "finding_type": "no licence assertion",
            "root_cause": "CycloneDX `type: \"file\"` components counted as software components",
            "licence_expression": "NOASSERTION (a file path has no licence of its own)",
            "component": "image file paths",
            "version": "n/a",
            "count": len(files),
            "distinct_components": len(set(files)),
            "families": "all 10 image families",
            "platforms": "linux/amd64 + linux/arm64",
            "kind": "technical",
            "policy_owner": "maintainer (scripts/license/license-inventory.sh)",
            "legal_owner": "none — this is not a legal question",
            "evidence_needed": ("per-file disposition: an owner edge shown in the "
                                "document set, or the file stays visible as "
                                "independently licensed / unresolved"),
            "examples": sorted(files)[:8],
        })
    by_eco = collections.defaultdict(list)
    for x in pkgs:
        by_eco[ecosystem(x)].append(x)
    for eco, items in sorted(by_eco.items(), key=lambda kv: -len(kv[1])):
        groups.append({
            "group_id": "G-NOASSERT-" + re.sub(r"[^A-Z0-9]+", "-", eco.upper()).strip("-"),
            "finding_type": "no licence assertion",
            "root_cause": "the cataloguer that produced these components emits no "
                          "licence field for them",
            "licence_expression": "NOASSERTION",
            "component": eco,
            "version": "various — see components",
            "count": len(items),
            "distinct_components": len({split_name(i)[0] for i in items}),
            "families": FAMILY_BY_ECOSYSTEM.get(eco, "not derivable"),
            "platforms": "linux/amd64 + linux/arm64",
            "kind": "technical",
            "policy_owner": "maintainer (policies/syft.yaml cataloguer selection)",
            "legal_owner": "external counsel (#98) once an identifier is established",
            "evidence_needed": "an upstream licence identifier per component, from "
                               "the project's own metadata rather than the scanner",
            "components": sorted(items),
        })

    # --- sources disagree ----------------------------------------------------
    conflicts = pick(sections, CON_HEAD)
    counted += len(conflicts)
    parsed = []
    for line in conflicts:
        m = CONFLICT_LINE.match(line)
        if not m:
            sys.stderr.write("REFUSE: unparseable conflict line %r\n" % line)
            raise SystemExit(1)
        vals = [v.strip() for v in m.group(3).split(" vs ")]
        parsed.append((m.group(1), m.group(2), vals, conflict_root_cause(vals)))
    by_rc = collections.defaultdict(list)
    for n, v, vals, rc in parsed:
        by_rc[rc].append((n, v, vals))
    for rc, items in sorted(by_rc.items(), key=lambda kv: -len(kv[1])):
        union = sorted({" AND ".join(sorted(frozenset().union(
            *[members(x) for x in vals if x != "NOASSERTION"])))
            for _n, _v, vals in items})
        legal = rc.startswith("RC5")
        groups.append({
            "group_id": "G-CONFLICT-" + rc.split()[0],
            "finding_type": "sources disagree",
            "root_cause": rc,
            "licence_expression_canonicalised": union[:6],
            "licence_expression": "see licence_expression_canonicalised (lowercased, LicenseRef- stripped, + rendered as -)",
            "distinct_licence_expressions": len(union),
            "component": "package components",
            "version": "various — see components",
            "count": len(items),
            "distinct_components": len({n for n, _v, _x in items}),
            "families": "Debian bookworm families, and Alpine for the apk entries",
            "platforms": "linux/amd64 + linux/arm64",
            "kind": "legal" if legal else "technical",
            "policy_owner": "maintainer (license-inventory.sh conflict rule)",
            "legal_owner": ("external counsel (#98)" if legal
                            else "none — no source names a different licence"),
            "evidence_needed": ("a licence-expression normaliser that treats an "
                                "expression and the enumeration of its members as "
                                "one assertion, applied in the inventory and "
                                "REVIEWED — not a suppression"),
            "components": ["%s@%s" % (n, v) for n, v, _x in sorted(items)][:80],
        })

    # --- legal review required ----------------------------------------------
    review = pick(sections, REV_HEAD)
    counted += len(review)
    by_lic = collections.defaultdict(list)
    for line in review:
        m = REVIEW_LINE.match(line)
        if not m:
            sys.stderr.write("REFUSE: unparseable review line %r\n" % line)
            raise SystemExit(1)
        by_lic[m.group(3)].append((m.group(1), m.group(2)))
    for lic, items in sorted(by_lic.items(), key=lambda kv: -len(kv[1])):
        ecos = sorted({ecosystem("%s@%s" % (n, v)) for n, v in items})
        groups.append({
            "group_id": "G-REVIEW-" + re.sub(r"[^A-Za-z0-9]+", "-", lic),
            "finding_type": "legal review required",
            "root_cause": "the policy classifies this identifier as "
                          "legal-review-required and no review is recorded",
            "licence_expression": lic,
            "component": ", ".join(sorted("%s@%s" % (n, v) for n, v in items)),
            "version": sorted({v for _n, v in items}),
            "count": len(items),
            "distinct_components": len({n for n, _v in items}),
            "families": "; ".join(FAMILY_BY_ECOSYSTEM.get(e, e) for e in ecos),
            "platforms": "linux/amd64 + linux/arm64",
            "kind": "legal",
            "policy_owner": "maintainer (policies/license-policy.yaml)",
            "legal_owner": "external counsel — NOT APPOINTED; that gap is #98",
            "evidence_needed": ("a recorded legal decision for this identifier "
                                "under the shipped distribution model, or a "
                                "time-boxed exception with granted_by/expires/"
                                "tracked_issue"),
        })

    for head in (DEN_HEAD, EXP_HEAD):
        items = pick(sections, head)
        counted += len(items)
        if items:
            groups.append({
                "group_id": "G-" + re.sub(r"[^A-Z]+", "-", head.upper()).strip("-"),
                "finding_type": head,
                "root_cause": head,
                "licence_expression": "various",
                "component": "various",
                "version": "various",
                "count": len(items),
                "distinct_components": len(set(items)),
                "families": "not derivable from the committed record",
                "platforms": "linux/amd64 + linux/arm64",
                "kind": "policy",
                "policy_owner": "maintainer (policies/license-policy.yaml)",
                "legal_owner": "external counsel (#98)",
                "evidence_needed": "a recorded decision",
                "components": sorted(items),
            })

    total_in = sum(len(v) for v in sections.values())
    total_out = sum(g["count"] for g in groups)
    if total_in != total_out or total_in != counted:
        sys.stderr.write(
            "REFUSE: %d finding(s) went in and %d came out. A grouping that "
            "loses a finding is a suppression with a nicer name\n"
            % (total_in, total_out))
        raise SystemExit(1)
    return {
        "record_type": "licence-backlog-grouping",
        "schema_version": 1,
        "totals": {k: len(v) for k, v in sections.items()},
        "total_findings": total_in,
        "image_file_findings": len(files),
        "substantive_findings": total_in - len(files),
        "group_count": len(groups),
        "groups": groups,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--diagnostic", required=True)
    ap.add_argument("--out", default="-")
    args = ap.parse_args()
    with open(args.diagnostic) as fh:
        doc = build(parse_diagnostic(fh.read()))
    blob = json.dumps(doc, indent=2, sort_keys=True) + "\n"
    if args.out == "-":
        sys.stdout.write(blob)
    else:
        with open(args.out, "w") as fh:
            fh.write(blob)
    sys.stderr.write("groups: %d over %d finding(s) (%d image-file, %d substantive)\n"
                     % (doc["group_count"], doc["total_findings"],
                        doc["image_file_findings"], doc["substantive_findings"]))


if __name__ == "__main__":
    main()
