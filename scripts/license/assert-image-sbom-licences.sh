#!/usr/bin/env bash
# =============================================================================
# scripts/license/assert-image-sbom-licences.sh — the IMAGE half of the licence
# gate, bound to the candidate images a real run actually staged.
# -----------------------------------------------------------------------------
# WHAT WAS MISSING, EXACTLY.
#
# scripts/license/assert-license-policy.sh is a fail-closed licence gate over a
# normalised inventory, and scripts/license/license-inventory.sh builds that
# inventory out of SBOMs. Both shipped and both worked. What did not exist was a
# workflow that RAN them over the SBOMs of the images a release candidate is
# made of: .github/workflows/ci.yml carried exactly one licence-gate line,
#
#     bash scripts/license/assert-license-policy.sh --self-test
#
# which is the gate testing ITSELF. It gates no image, it reads no candidate,
# and an assertion that merely grepped the workflow directory for
# `scripts/license/` matched that one line and reported the gate as wired — a
# check that was literally true and substantively false. See
# tests/integration/test_evidence_path_e2e.sh stage 9.
#
# The repository half of that blind spot is closed by
# scripts/license/assert-repository-material.sh, which the required `repo
# structure` job runs over the real tree. This script is the image half.
#
# WHAT IT BINDS, AND WHY EACH FIELD IS LOAD-BEARING.
#
# An SBOM on its own is a document. It becomes evidence only once it is tied to
# the exact artifact it claims to describe, so every child is bound on FIVE
# facts and any one of them disagreeing is a refusal:
#
#   image name + version   the child's identity within the shipping matrix
#   platform               an amd64 SBOM is not evidence about the arm64 child;
#                          the two collided outright before child_slug() existed
#   immutable digest       the SBOM's own subject must be THIS manifest digest,
#                          not merely a file filed under the right name
#   source revision        the tree the image was built from
#   content hash           the bytes the producing run hashed, so an SBOM
#                          swapped after the fact is not the SBOM that was made
#
# The first three come from ONE identity function. Filenames are derived by
# calling scripts/generate-sbom.sh --print-names — the PRODUCER's own hook —
# never by re-deriving a name here. A second derivation of one identity is the
# defect that made a complete SBOM directory read as sbom.present=false, and it
# is not being reintroduced in the consumer.
#
# INPUTS ARE THE RUN'S OWN ARTIFACTS, NOT FIXTURES.
#
#   --authorization  the canonical schemas/post-build-authorization-v1 record
#                    that scripts/release/authorize-staged-candidates.sh wrote
#                    for the run. It declares expected_matrix BEFORE evaluation,
#                    so a silently missing child cannot produce a smaller
#                    passing record, and it carries each child's registry
#                    resolved manifest digest.
#   --sbom-dir       the SBOMs scripts/generate-sbom.sh produced against the
#                    staged DIGEST references.
#   --binding-dir    one binding record per child, written by the same step that
#                    produced the SBOM, naming the digest it ran against and the
#                    sha256 of each document it wrote. A hand-written SBOM has no
#                    binding whose hash it satisfies, which is what makes
#                    "fixtures instead of candidate artifacts" refusable rather
#                    than merely discouraged.
#
# EVERY REFUSAL CARRIES ITS OWN CODE. "It failed" is not a diagnostic.
#
#   IL-AUTHORIZATION-UNREADABLE   the record is absent or not parseable
#   IL-AUTHORIZATION-INVALID      it is not a post-build-authorization-v1 record
#   IL-MATRIX-IDENTITY            expected_matrix disagrees with MATRIX_COUNT
#   IL-CHILDREN-SHORT             fewer children than expected_matrix declared
#   IL-CHILD-DUPLICATE            two records for one (image, platform)
#   IL-CHILD-UNEXPECTED           a child outside the declared matrix
#   IL-SBOM-MISSING               an expected child has no SBOM document
#   IL-SBOM-UNEXPECTED            a document bound to no child in the record
#   IL-BINDING-MISSING            an SBOM with no binding record for its child
#   IL-BINDING-MALFORMED          a binding record missing a bound field
#   IL-DIGEST-MISMATCH            binding or subject names another digest
#   IL-PLATFORM-MISMATCH          the binding names another platform
#   IL-REVISION-MISMATCH          the binding names another source revision
#   IL-SBOM-CONTENT-DRIFT         the document is not the bytes the run hashed
#   IL-SBOM-SUBJECT-ABSENT        the document says nothing about what it is for
#   IL-EVIDENCE-STALE             the binding is older than the accepted window
#   IL-EVIDENCE-FUTURE            the binding is dated after the decision date
#   IL-INVENTORY-FAILED           license-inventory.sh refused the document set
#
# The cohort is derived from MATRIX_IMAGES and MATRIX_COUNT in
# scripts/lib/common.sh and CROSS-CHECKED against the authorization record's own
# expected_matrix. Taking the expected count from the record would make the check
# self-confirming: a matrix change would not move the expectation. A disagreement
# between the two IS a refusal, and it is the one worth having.
#
# It emits a foundry.license-inventory/v1 document carrying an `image_binding`
# block, so the verdict that follows names what it is a verdict FOR. The VERDICT
# itself is not made here: scripts/license/assert-license-policy.sh decides it
# from policies/license-policy.yaml, and duplicating that judgement here would
# be a second decision to drift.
#
# Usage:
#   assert-image-sbom-licences.sh --authorization FILE --sbom-dir DIR --out FILE
#        [--binding-dir DIR] [--today YYYY-MM-DD] [--max-age-days N]
#   assert-image-sbom-licences.sh --self-test
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../lib/common.sh
. "$ROOT/scripts/lib/common.sh"
set +e

usage() {
  sed -n '/^# Usage:/,/^# ===/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//' >&2
  exit 64
}

# -----------------------------------------------------------------------------
# expected_names <authorization.json> -> TSV on stdout
#
#   child_key <TAB> family <TAB> version <TAB> platform <TAB> spdx <TAB> cdx
#
# The filenames come from scripts/generate-sbom.sh --print-names. That is the
# PRODUCER's hook, and using it is the whole point: the consumer must not own a
# second spelling of the identity the producer writes.
# -----------------------------------------------------------------------------
expected_names() {
  local auth="$1"
  python3 - "$auth" <<'PY' || return 1
import json, sys
rec = json.load(open(sys.argv[1]))
for c in rec.get("children") or []:
    label = str(c.get("image_label") or "")
    fam, _, ver = label.partition("/")
    print("\t".join([str(c.get("child_key") or ""), fam, ver, str(c.get("platform") or "")]))
PY
  return 0
}

# -----------------------------------------------------------------------------
# name_table <authorization.json> <out.tsv>
# -----------------------------------------------------------------------------
name_table() {
  local auth="$1" out="$2" key fam ver plat names spdx cdx
  : >"$out"
  while IFS="$(printf '\t')" read -r key fam ver plat; do
    [ -n "$fam" ] || continue
    names="$(bash "$ROOT/scripts/generate-sbom.sh" --print-names "$fam" "$ver" "$plat" 2>/dev/null)" || {
      echo "REFUSE [IL-MATRIX-IDENTITY]: the SBOM producer refuses the identity ($fam, $ver, $plat) taken from the authorization record; a child whose identity cannot be spelled has no bill of materials to look up" >&2
      return 1
    }
    spdx="$(printf '%s\n' "$names" | awk -F'\t' '$1=="spdx-json"{print $2}')"
    cdx="$(printf '%s\n' "$names" | awk -F'\t' '$1=="cdx-json"{print $2}')"
    [ -n "$spdx" ] || { echo "REFUSE [IL-MATRIX-IDENTITY]: no spdx-json name for $key" >&2; return 1; }
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$key" "$fam" "$ver" "$plat" "$spdx" "$cdx" >>"$out"
  done < <(expected_names "$auth")
  [ -s "$out" ]
}

# -----------------------------------------------------------------------------
# bind — the whole check, in one python pass over inputs it is HANDED.
# Nothing is discovered here that the authorization record did not declare.
# -----------------------------------------------------------------------------
bind() {
  IL_AUTH="$1" IL_SBOM_DIR="$2" IL_BIND_DIR="$3" IL_NAMES="$4" IL_OUT="$5" \
  IL_TODAY="$6" IL_MAX_AGE="$7" IL_MATRIX_COUNT="$MATRIX_COUNT" \
  IL_MATRIX_IMAGES="$(matrix_images | tr '\n' ' ')" python3 <<'PY'
import datetime
import hashlib
import json
import os
import sys

auth_p   = os.environ["IL_AUTH"]
sbom_d   = os.environ["IL_SBOM_DIR"]
bind_d   = os.environ["IL_BIND_DIR"]
names_p  = os.environ["IL_NAMES"]
out_p    = os.environ["IL_OUT"]
today_s  = os.environ["IL_TODAY"]
max_age  = int(os.environ["IL_MAX_AGE"])
matrix_n = int(os.environ["IL_MATRIX_COUNT"])
# The SHIPPING MATRIX ITSELF, not merely its size. A count check accepts a
# substituted image as long as the total stays right, which is how an
# experimental family slips into a cohort that still reads 10/10. The labels
# come from MATRIX_IMAGES in scripts/lib/common.sh, the one declaration every
# other tool derives from; deriving the cohort from the evidence's own count
# would make the check self-confirming.
matrix_labels = set()
for tok in os.environ["IL_MATRIX_IMAGES"].split():
    fam, _, sel = tok.partition(":")
    matrix_labels.add("%s/%s" % (fam, sel))

findings = []


def refuse(code, msg):
    findings.append((code, msg))


def hard(code, msg):
    sys.stderr.write("REFUSE [%s]: %s\n" % (code, msg))
    raise SystemExit(1)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


try:
    rec = json.load(open(auth_p))
except (OSError, ValueError) as e:
    hard("IL-AUTHORIZATION-UNREADABLE",
         "the authorization record %s is unreadable (%s). A licence verdict "
         "with no record of what was staged is a verdict about nothing" % (auth_p, e))

if rec.get("schema_version") != 1 or not isinstance(rec.get("children"), list):
    hard("IL-AUTHORIZATION-INVALID",
         "%s is not a schemas/post-build-authorization-v1 record (schema_version=%r). "
         "The child set, the digests and the source revision this gate binds to all "
         "come from that record; anything else is a lookalike"
         % (auth_p, rec.get("schema_version")))

exp = rec.get("expected_matrix") or {}
for f in ("images", "platforms", "expected_children"):
    if not exp.get(f):
        hard("IL-AUTHORIZATION-INVALID",
             "%s declares no expected_matrix.%s. Completeness has to be judged "
             "against a set declared BEFORE evaluation, or a silently missing "
             "child produces a smaller passing record" % (auth_p, f))

# MATRIX_COUNT in scripts/lib/common.sh is the ONE declaration of the shipping
# matrix size. It is DERIVED here, never restated: a literal 10 or 20 would
# re-baseline itself the day the matrix changes.
if int(exp["images"]) != matrix_n:
    hard("IL-MATRIX-IDENTITY",
         "the record claims %d images; MATRIX_COUNT in scripts/lib/common.sh "
         "declares %d. Two declarations of the shipping matrix mean the licence "
         "verdict may be complete for a matrix nobody ships"
         % (int(exp["images"]), matrix_n))

platforms = list(exp["platforms"])
want_children = matrix_n * len(platforms)
if int(exp["expected_children"]) != want_children:
    hard("IL-MATRIX-IDENTITY",
         "expected_children=%d but MATRIX_COUNT(%d) x %d platform(s) is %d"
         % (int(exp["expected_children"]), matrix_n, len(platforms), want_children))

revision = str(rec.get("source_revision") or "")
if not revision:
    hard("IL-AUTHORIZATION-INVALID",
         "%s carries no source_revision; an SBOM cannot be bound to the tree it "
         "was built from" % auth_p)

# --- the declared child set -------------------------------------------------
children = {}
for c in rec["children"]:
    key = str(c.get("child_key") or "")
    label = str(c.get("image_label") or "")
    plat = str(c.get("platform") or "")
    if not key:
        key = "%s/%s" % (label, plat)
    if key in children:
        refuse("IL-CHILD-DUPLICATE",
               "two records for child %s. A duplicated child lets one image's "
               "clean bill of materials stand in for another's" % key)
        continue
    if plat not in platforms:
        refuse("IL-CHILD-UNEXPECTED",
               "child %s is on platform %r, which expected_matrix does not "
               "declare (%s)" % (key, plat, ", ".join(platforms)))
    if label not in matrix_labels:
        refuse("IL-CHILD-UNEXPECTED",
               "child %s names image %r, which is not in MATRIX_IMAGES. The "
               "shipping matrix is declared in scripts/lib/common.sh and a "
               "child outside it is an image nobody ships being licensed as "
               "though they did — an experimental family is exactly this shape"
               % (key, label))
    children[key] = c

# COVERAGE BY IDENTITY, not by count. 19 of 20 and 20 of 20 with one image
# duplicated and another absent are different failures and must read that way.
seen_pairs = {(str(c.get("image_label") or ""), str(c.get("platform") or ""))
              for c in children.values()}
for label in sorted(matrix_labels):
    for plat in platforms:
        if (label, plat) not in seen_pairs:
            refuse("IL-CHILDREN-SHORT",
                   "the shipping matrix declares %s on %s and the authorization "
                   "record covers no such child. A licence verdict that omits a "
                   "shipped image is clean about images it never saw"
                   % (label, plat))

if len(children) < want_children:
    refuse("IL-CHILDREN-SHORT",
           "the record covers %d of the %d children expected_matrix declares "
           "(%d images x %d platforms). A licence verdict over a partial matrix "
           "reports clean for the images it happened to see"
           % (len(children), want_children, matrix_n, len(platforms)))
elif len(children) > want_children:
    refuse("IL-CHILD-UNEXPECTED",
           "the record covers %d children; expected_matrix declares %d"
           % (len(children), want_children))

# --- the identity table the PRODUCER spells ---------------------------------
names = {}
with open(names_p) as fh:
    for line in fh:
        line = line.rstrip("\n")
        if not line:
            continue
        key, fam, ver, plat, spdx, cdx = line.split("\t")
        names[key] = {"family": fam, "version": ver, "platform": plat,
                      "spdx": spdx, "cdx": cdx}

# --- what is actually on disk -----------------------------------------------
if not os.path.isdir(sbom_d):
    hard("IL-SBOM-MISSING",
         "the SBOM directory %r does not exist. An absent directory is not an "
         "empty result to shrug at; it is every child missing at once" % sbom_d)
if not os.path.isdir(bind_d):
    hard("IL-BINDING-MISSING",
         "the binding directory %r does not exist. Without the records the "
         "producing run wrote, nothing ties any document to a staged digest and "
         "a hand-written SBOM is indistinguishable from a candidate one" % bind_d)

on_disk = set(n for n in os.listdir(sbom_d)
              if n.endswith(".json") and os.path.isfile(os.path.join(sbom_d, n)))
claimed = set()
today = datetime.date.fromisoformat(today_s)
bound = []

for key in sorted(children):
    c = children[key]
    ident = names.get(key)
    if ident is None:
        refuse("IL-CHILD-UNEXPECTED",
               "child %s has no identity in the producer's name table" % key)
        continue
    digest = str(c.get("manifest_digest") or "").lower()
    plat = str(c.get("platform") or "")
    spdx_name, cdx_name = ident["spdx"], ident["cdx"]
    claimed.add(spdx_name)
    claimed.add(cdx_name)

    spdx_p = os.path.join(sbom_d, spdx_name)
    if not os.path.isfile(spdx_p):
        refuse("IL-SBOM-MISSING",
               "child %s has no bill of materials: %s is absent from %s. This is "
               "fatal, never a quiet sbom.present=false"
               % (key, spdx_name, sbom_d))
        continue

    bind_p = os.path.join(bind_d, "%s.binding.json" % os.path.splitext(
        os.path.splitext(spdx_name)[0])[0])
    if not os.path.isfile(bind_p):
        refuse("IL-BINDING-MISSING",
               "child %s: %s is present but no binding record %s names the digest "
               "it was produced against. A document nobody's run vouches for is a "
               "fixture, and a fixture cannot license a release"
               % (key, spdx_name, os.path.basename(bind_p)))
        continue
    try:
        b = json.load(open(bind_p))
    except (OSError, ValueError) as e:
        refuse("IL-BINDING-MALFORMED", "child %s: %s is unreadable (%s)"
               % (key, os.path.basename(bind_p), e))
        continue

    missing = [f for f in ("image_family", "image_version", "platform",
                           "manifest_digest", "source_revision", "generated_at",
                           "producer", "documents")
               if not b.get(f)]
    if missing:
        refuse("IL-BINDING-MALFORMED",
               "child %s: binding record omits %s" % (key, ", ".join(missing)))
        continue

    if str(b["manifest_digest"]).lower() != digest:
        refuse("IL-DIGEST-MISMATCH",
               "child %s: the binding names digest %s; the authorization record "
               "resolved %s from the registry. An SBOM produced against another "
               "digest is another image's bill of materials"
               % (key, b["manifest_digest"], digest))
    if str(b["platform"]) != plat:
        refuse("IL-PLATFORM-MISMATCH",
               "child %s: the binding names platform %r, the record %r. An amd64 "
               "bill of materials is not evidence about the arm64 child"
               % (key, b["platform"], plat))
    if str(b["image_family"]) != ident["family"] or str(b["image_version"]) != ident["version"]:
        refuse("IL-PLATFORM-MISMATCH",
               "child %s: the binding names image %s/%s, the record %s/%s"
               % (key, b["image_family"], b["image_version"],
                  ident["family"], ident["version"]))
    if str(b["source_revision"]) != revision:
        refuse("IL-REVISION-MISMATCH",
               "child %s: the binding names source revision %s; the authorization "
               "record was written for %s. An SBOM of a different tree cannot "
               "license this one" % (key, b["source_revision"], revision))

    # --- staleness ----------------------------------------------------------
    try:
        gen = datetime.date.fromisoformat(str(b["generated_at"])[:10])
    except ValueError:
        refuse("IL-BINDING-MALFORMED",
               "child %s: generated_at %r is not an ISO date" % (key, b["generated_at"]))
        gen = None
    if gen is not None:
        if gen > today:
            refuse("IL-EVIDENCE-FUTURE",
                   "child %s: the SBOM binding is dated %s, after the decision "
                   "date %s. Evidence from the future is evidence nobody produced"
                   % (key, gen.isoformat(), today.isoformat()))
        elif (today - gen).days > max_age:
            refuse("IL-EVIDENCE-STALE",
                   "child %s: the SBOM binding is %d days old (limit %d). A "
                   "licence verdict over stale evidence describes an image that "
                   "is no longer the candidate"
                   % (key, (today - gen).days, max_age))

    # --- the bytes the run hashed ------------------------------------------
    docs = b["documents"]
    if not isinstance(docs, dict) or spdx_name not in docs:
        refuse("IL-BINDING-MALFORMED",
               "child %s: the binding lists no sha256 for %s" % (key, spdx_name))
    else:
        actual = sha256_file(spdx_p)
        if actual != str(docs[spdx_name]).lower():
            refuse("IL-SBOM-CONTENT-DRIFT",
                   "child %s: %s hashes to %s; the producing run recorded %s. "
                   "These are not the bytes that were generated against the "
                   "staged digest — a document swapped after the fact is a "
                   "fixture wearing a candidate's filename"
                   % (key, spdx_name, actual[:16], str(docs[spdx_name])[:16]))
    for extra, want in sorted(docs.items()):
        if extra == spdx_name:
            continue
        p = os.path.join(sbom_d, extra)
        if not os.path.isfile(p):
            refuse("IL-SBOM-MISSING",
                   "child %s: the binding names companion document %s, which is "
                   "absent" % (key, extra))
        elif sha256_file(p) != str(want).lower():
            refuse("IL-SBOM-CONTENT-DRIFT",
                   "child %s: companion %s is not the document the run hashed"
                   % (key, extra))

    # --- the document's OWN subject ----------------------------------------
    try:
        doc = json.load(open(spdx_p))
    except (OSError, ValueError) as e:
        refuse("IL-SBOM-SUBJECT-ABSENT",
               "child %s: %s is not readable JSON (%s). An SBOM the licence path "
               "cannot parse is an SBOM whose subject nobody checked"
               % (key, spdx_name, e))
        continue
    subjects = set()
    for v in doc.get("documentDescribes") or []:
        if isinstance(v, str):
            subjects.add(v.strip().lower())
    comp = ((doc.get("metadata") or {}).get("component") or {})
    for h in comp.get("hashes") or []:
        if isinstance(h, dict) and h.get("content"):
            alg = (h.get("alg") or "SHA-256").lower().replace("-", "")
            subjects.add("%s:%s" % ("sha256" if alg == "sha256" else alg,
                                    str(h["content"]).lower()))
    for ref in (comp.get("purl"), comp.get("bom-ref")):
        if isinstance(ref, str) and "sha256:" in ref:
            subjects.add("sha256:" + ref.rsplit("sha256:", 1)[1].strip().lower())
    if not subjects:
        refuse("IL-SBOM-SUBJECT-ABSENT",
               "child %s: %s names no subject at all. An SBOM that does not say "
               "what it describes cannot be bound to a child, and an unbindable "
               "SBOM is how a foreign bill of materials passes for this one"
               % (key, spdx_name))
    elif digest not in subjects:
        refuse("IL-DIGEST-MISMATCH",
               "child %s: %s describes %s, not this child's manifest digest %s. "
               "The filename matched and the file hashed cleanly — the SUBJECT "
               "did not" % (key, spdx_name, ", ".join(sorted(subjects)[:3]), digest))

    # The SBOM's declared schema. A document in a format this repository does
    # not declare cannot be read as a bill of materials, and recording which one
    # it is keeps a CycloneDX file from silently standing in for SPDX.
    sbom_schema = doc.get("spdxVersion") or doc.get("bomFormat")
    if not sbom_schema:
        refuse("IL-SBOM-SUBJECT-ABSENT",
               "child %s: %s declares neither spdxVersion nor bomFormat; it is "
               "not an SBOM in a format this repository declares"
               % (key, spdx_name))
    bound.append({
        "child_key": key,
        "image_label": str(c.get("image_label") or ""),
        "image_family": ident["family"],
        "image_version": ident["version"],
        "platform": plat,
        "manifest_digest": digest,
        "digest_reference": str(c.get("digest_reference") or ""),
        "source_revision": revision,
        "sbom_file": spdx_name,
        "sbom_sha256": docs.get(spdx_name) if isinstance(docs, dict) else None,
        "sbom_schema": sbom_schema,
        "producer": str(b.get("producer") or ""),
        "evidence_generated_at": str(b.get("generated_at") or ""),
        # Carried, never flattened: an emulated child is a different quality of
        # evidence from a natively built one, and the #111 native-arch gate
        # decides what that is worth. Recording it here means a licence verdict
        # cannot erase the disclosure on its way past.
        "execution_mode": str(c.get("execution_mode") or "undisclosed"),
        "host_architecture": str(c.get("host_architecture") or "undisclosed"),
    })

# --- documents bound to no child --------------------------------------------
for extra in sorted(on_disk - claimed):
    refuse("IL-SBOM-UNEXPECTED",
           "%s is in the SBOM set but names no child of this authorization "
           "record. A document nobody staged has no place in the bill of "
           "materials a release is licensed on — this is also how an "
           "experimental image is kept out" % extra)

if findings:
    seen = set()
    for code, msg in findings:
        sys.stderr.write("REFUSE [%s]: %s\n" % (code, msg))
        seen.add(code)
    sys.stderr.write("\nimage-SBOM licence binding REFUSED: %d finding(s), codes: %s\n"
                     % (len(findings), ", ".join(sorted(seen))))
    raise SystemExit(1)

meta = {
    "record_type": "image-sbom-licence-binding",
    "authorization_record": os.path.basename(auth_p),
    "workflow_run_id": rec.get("workflow_run_id"),
    "workflow_run_attempt": rec.get("workflow_run_attempt"),
    "repository": rec.get("repository"),
    "staging_package": rec.get("staging_package"),
    "source_revision": revision,
    "matrix_images": matrix_n,
    "platforms": platforms,
    "children_expected": want_children,
    "children_bound": len(bound),
    "all_children_bound": len(bound) == want_children,
    "execution_modes": sorted({c["execution_mode"] for c in bound}),
    "sbom_schemas": sorted({str(c["sbom_schema"]) for c in bound}),
    "producers": sorted({c["producer"] for c in bound}),
    "decision_date": today.isoformat(),
    "max_evidence_age_days": max_age,
    "children": bound,
}
with open(out_p, "w") as fh:
    json.dump(meta, fh, indent=2, sort_keys=True)
print("image-SBOM binding OK: %d/%d children bound to staged digests at %s"
      % (len(bound), want_children, revision))
PY
}

# -----------------------------------------------------------------------------
# stamp <inventory.json> <binding.json>
# Attaches the binding to the inventory the licence gate will read, so the
# verdict names what it is a verdict FOR.
# -----------------------------------------------------------------------------
stamp() {
  IL_INV="$1" IL_BIND="$2" python3 <<'PY'
import hashlib, json, os, sys
inv_p, bind_p = os.environ["IL_INV"], os.environ["IL_BIND"]
inv = json.load(open(inv_p))
if inv.get("schema") != "foundry.license-inventory/v1":
    sys.stderr.write("REFUSE [IL-INVENTORY-FAILED]: %s is not a "
                     "foundry.license-inventory/v1 document\n" % inv_p)
    raise SystemExit(1)
inv.pop("inventory_sha256", None)
inv["image_binding"] = json.load(open(bind_p))
blob = json.dumps(inv, indent=2, sort_keys=True) + "\n"
inv["inventory_sha256"] = hashlib.sha256(blob.encode()).hexdigest()
open(inv_p, "w").write(json.dumps(inv, indent=2, sort_keys=True) + "\n")
print("image inventory bound: %s" % inv_p)
PY
}

main() {
  local auth="" sbom="" bindd="" out="" today="" max_age=14
  case "${1:-}" in --self-test) exec bash "$ROOT/tests/license/test_image_sbom_licence_gate.sh" ;; esac
  while [ $# -gt 0 ]; do
    case "$1" in
      --authorization) auth="${2:-}"; shift 2 ;;
      --sbom-dir)      sbom="${2:-}"; shift 2 ;;
      --binding-dir)   bindd="${2:-}"; shift 2 ;;
      --out)           out="${2:-}"; shift 2 ;;
      --today)         today="${2:-}"; shift 2 ;;
      --max-age-days)  max_age="${2:-}"; shift 2 ;;
      *) usage ;;
    esac
  done
  [ -n "$auth" ] && [ -n "$sbom" ] && [ -n "$out" ] || usage
  [ -n "$bindd" ] || bindd="${sbom%/}-bindings"
  [ -n "$today" ] || today="$(date -u +%Y-%m-%d)"

  local tmp; tmp="$(mktemp -d)" || return 1
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" EXIT

  name_table "$auth" "$tmp/names.tsv" || return 1
  bind "$auth" "$sbom" "$bindd" "$tmp/names.tsv" "$tmp/binding.json" \
       "$today" "$max_age" || return 1

  # The inventory itself is built by the SHIPPED normaliser. This script does
  # not parse licences: license-inventory.sh owns that, and a second parser
  # would be a second answer to drift.
  bash "$ROOT/scripts/license/license-inventory.sh" --sbom-dir "$sbom" --out "$out" || {
    echo "REFUSE [IL-INVENTORY-FAILED]: license-inventory.sh refused the candidate SBOM set" >&2
    return 1
  }
  stamp "$out" "$tmp/binding.json" || return 1
}

main "$@"
