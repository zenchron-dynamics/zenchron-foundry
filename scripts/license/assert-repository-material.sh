#!/usr/bin/env bash
# =============================================================================
# scripts/license/assert-repository-material.sh — the repository-material half
# of the licence gate (#120).
# -----------------------------------------------------------------------------
# THE BLIND SPOT THIS CLOSES.
#
# scripts/license/assert-license-policy.sh reads IMAGE SBOMs. An SBOM of a built
# image enumerates what is in that image. Material that lives in the repository
# but in no image is therefore invisible to that gate BY CONSTRUCTION — copied
# configuration, seccomp profiles, scripts, workflow fragments, documentation
# excerpts, fixtures, vendored schemas, patches, generated third-party files.
# security/seccomp/zenchron-default.json proved it: 832 lines copied verbatim
# from Moby v27.3.1, unattributed, under a first-party filename, and no control
# in this repository could see it.
#
# WHAT THIS GATE COMPOSES. Four sources, and the composition is the point —
# each source alone reports clean about the thing it cannot see:
#
#   SOURCE 1  image SBOM licence evidence        --image-inventory (optional)
#   SOURCE 2  the repository-material inventory  policies/repository-material.yaml
#   SOURCE 3  required licence texts and notices files named by source 2
#   SOURCE 4  project-level outbound licence     LICENSE + policies/license-policy.yaml
#
# Source 4 is not decoration. Every per-file obligation checked here is DERIVED
# from that policy's `obligations` list for the declared SPDX id — this script
# contains no licence judgement of its own and cannot approve anything the
# policy does not classify as allowed.
#
# HOW DISCOVERY WORKS, AND WHAT IT CANNOT PROVE.
#
# Deciding that an arbitrary file was copied from somewhere is undecidable in
# general. There is no scan that establishes a file is first-party. So:
#
#   * heuristic_scan() below is HEURISTIC. It fires on three high-precision
#     signals (see HEURISTIC_SIGNALS). Every hit must be inventoried or
#     disposed. A hit is evidence; SILENCE IS NOT EVIDENCE OF ANYTHING.
#   * two of the five entries in the shipped inventory trip NO signal at all.
#     They were found by a human reading a directory. That is recorded in the
#     inventory and it is the honest measure of this scanner's recall.
#   * the non-heuristic half is the REVIEWED BASELINE: an explicit list of the
#     tracked paths a human reviewed. Material outside it is refused
#     (RM-BASELINE-STALE) rather than assumed clean.
#
# advisory_scan() reports low-precision prose provenance phrases. It REFUSES
# NOTHING and is labelled ADVISORY in the output, because "derived from" is
# ordinary English and treating it as a control would be a check that is
# literally true and substantively false.
#
# EVERY REFUSAL CARRIES ITS OWN CODE. "It failed" is not a diagnostic.
#
#   RM-INVENTORY-UNREADABLE      the inventory is missing or not parseable
#   RM-INVENTORY-MALFORMED       it is not a foundry.repository-material/v1 doc
#   RM-MATERIAL-PATH-MISSING     an inventoried path is not in the tree
#   RM-HASH-DRIFT                content changed since review, unreviewed
#   RM-ENTRY-UNREVIEWED          an entry nobody has recorded a review for
#   RM-LICENCE-UNRECOGNISED      no SPDX id, or one the policy does not allow
#   RM-LICENCE-TEXT-MISSING      obligation retain-license-text is unmet
#   RM-NOTICE-MISSING            obligation retain-notice-file is unmet
#   RM-COPYRIGHT-MISSING         obligation retain-copyright-notice is unmet
#   RM-CHANGES-NOT-STATED        obligation state-changes is unmet
#   RM-UNINVENTORIED-MATERIAL    a signal fired on a file in neither array
#   RM-BASELINE-UNVERIFIABLE     the reviewed baseline cannot be checked
#   RM-BASELINE-STALE            tracked paths outside the reviewed baseline
#   RM-OUTBOUND-TERMS-PLACEHOLDER  placeholder terms presented as final
#   RM-REPOSITORY-EVIDENCE-ABSENT  image evidence with no repository evidence
#   RM-IMAGE-EVIDENCE-ABSENT     repository evidence with no image evidence
#   RM-TREE-UNREADABLE           the tracked file set cannot be established
#
# Usage:
#   assert-repository-material.sh [--root DIR] [--inventory FILE] [--policy FILE]
#        [--license-file FILE] [--image-inventory FILE]
#        [--require-reviewed-baseline] [--require-final-outbound-terms]
#        [--require-image-evidence]
#   assert-repository-material.sh --self-test
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

usage() {
  sed -n '70,76p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 64
}

# -----------------------------------------------------------------------------
# gate — every argument arrives through the environment so that no shell
# quoting decision can change what python sees.
# -----------------------------------------------------------------------------
gate() {
  python3 <<'PY'
import hashlib
import os
import re
import subprocess
import sys

root       = os.environ["RM_ROOT"]
inv_path   = os.environ["RM_INVENTORY"]
pol_path   = os.environ["RM_POLICY"]
lic_path   = os.environ["RM_LICENSE_FILE"]
img_path   = os.environ.get("RM_IMAGE_INVENTORY") or ""
req_base   = os.environ.get("RM_REQUIRE_BASELINE") == "1"
req_final  = os.environ.get("RM_REQUIRE_FINAL_TERMS") == "1"
req_image  = os.environ.get("RM_REQUIRE_IMAGE_EVIDENCE") == "1"

try:
    import yaml
except ImportError:
    sys.stderr.write("REFUSE [RM-INVENTORY-UNREADABLE]: PyYAML is required\n")
    raise SystemExit(2)

findings = []          # (code, message)
notes = []


def refuse(code, msg):
    findings.append((code, msg))


def hard(code, msg):
    """A refusal that makes every later check meaningless. Report and stop."""
    sys.stderr.write("REFUSE [%s]: %s\n" % (code, msg))
    raise SystemExit(1)


def abspath(rel):
    return os.path.join(root, rel)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# =============================================================================
# SOURCE 2 — the repository-material inventory
# =============================================================================
if not os.path.isfile(inv_path):
    hard("RM-INVENTORY-UNREADABLE",
         "%s does not exist. The repository-material half of the licence gate "
         "has no input, and an absent inventory is not an empty one." % inv_path)
try:
    with open(inv_path) as fh:
        inv = yaml.safe_load(fh)
except (OSError, ValueError, yaml.YAMLError) as e:
    hard("RM-INVENTORY-UNREADABLE", "%s is unreadable: %s" % (inv_path, e))

if not isinstance(inv, dict) or inv.get("schema") != "foundry.repository-material/v1":
    hard("RM-INVENTORY-MALFORMED",
         "%s is not a foundry.repository-material/v1 document" % inv_path)

materials = inv.get("materials")
dispositions = inv.get("dispositions")
if not isinstance(materials, list) or not isinstance(dispositions, list):
    hard("RM-INVENTORY-MALFORMED",
         "%s must carry both `materials` and `dispositions` arrays. A document "
         "with only one of them cannot express 'this file was looked at and is "
         "not third-party material'." % inv_path)

# Optional but strongly preferred: validate against the shipped JSON Schema.
schema_file = os.path.join(root, "schemas", "repository-material-v1.schema.json")
if os.path.isfile(schema_file):
    try:
        import json as _json
        import jsonschema
        with open(schema_file) as fh:
            _schema = _json.load(fh)
        try:
            jsonschema.validate(
                instance=_json.loads(_json.dumps(inv, default=str)), schema=_schema)
        except jsonschema.ValidationError as e:
            hard("RM-INVENTORY-MALFORMED",
                 "%s fails schemas/repository-material-v1.schema.json at %s: %s"
                 % (inv_path, "/".join(str(p) for p in e.absolute_path) or "<root>",
                    e.message))
    except ImportError:
        notes.append("jsonschema is not installed; structural validation was "
                     "SKIPPED. Field-level checks below still ran.")

# =============================================================================
# SOURCE 4 — project-level outbound licence state
# =============================================================================
try:
    with open(pol_path) as fh:
        pol = yaml.safe_load(fh) or {}
except (OSError, ValueError, yaml.YAMLError) as e:
    hard("RM-INVENTORY-UNREADABLE", "licence policy %s is unreadable: %s" % (pol_path, e))

policy_state = {}
policy_obligations = {}
for entry in pol.get("licenses") or []:
    lid = entry.get("id")
    if lid:
        policy_state[lid] = entry.get("state")
        policy_obligations[lid] = list(entry.get("obligations") or [])
for d in pol.get("denied") or []:
    if isinstance(d, str):
        policy_state[d] = "denied"
policy_default = pol.get("default_state", "legal-review-required")

publication = pol.get("publication") or {}
pub_decision = publication.get("decision")
pub_approved = bool(publication.get("notices_approved_for_distribution"))

license_text = ""
if os.path.isfile(lic_path):
    with open(lic_path, encoding="utf-8", errors="replace") as fh:
        license_text = fh.read()
# The LICENSE file says of itself, in its last paragraph, that it is a
# placeholder to be replaced before publication. That self-declaration is the
# fact this gate reads; it does not interpret the grant.
placeholder_self_declared = bool(
    re.search(r"replace this file\s+before publication", license_text, re.I)
    or re.search(r"[Dd]o not assume any OSI licen[sc]e applies", license_text))

outbound_final = not placeholder_self_declared and pub_decision not in (None, "undetermined") and pub_approved

if req_final and not outbound_final:
    why = []
    if placeholder_self_declared:
        why.append("LICENSE declares itself a placeholder to be replaced before publication")
    if pub_decision in (None, "undetermined"):
        why.append("policies/license-policy.yaml publication.decision is %r" % (pub_decision,))
    if not pub_approved:
        why.append("publication.notices_approved_for_distribution is false")
    refuse("RM-OUTBOUND-TERMS-PLACEHOLDER",
           "final outbound terms were asserted, but the project has none: %s. "
           "Choosing the outbound licence is issue %s and is the owner's and "
           "counsel's act, not this gate's — the refusal is the whole point, "
           "and it is not cleared by editing this script."
           % ("; ".join(why), publication.get("tracked_issue")))

# =============================================================================
# the tracked file set
# =============================================================================
try:
    out = subprocess.run(["git", "-C", root, "ls-files", "-z"],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    tracked = sorted(p for p in out.stdout.decode("utf-8", "replace").split("\0") if p)
except (OSError, subprocess.CalledProcessError) as e:
    hard("RM-TREE-UNREADABLE",
         "`git ls-files` failed in %s (%s). The set of files to scan cannot be "
         "established, and scanning a guessed set would report clean about "
         "whatever it happened to miss." % (root, e))
if not tracked:
    hard("RM-TREE-UNREADABLE", "`git ls-files` in %s returned nothing" % root)
tracked_set = set(tracked)

# =============================================================================
# per-entry obligation checks — DERIVED from source 4, not hardcoded
# =============================================================================
material_paths = []
obligation_artifacts = set()
reviewed_count = 0

for m in materials:
    mid = m.get("id") or "<unnamed>"
    mpath = m.get("path") or ""
    material_paths.append(mpath)
    ob = m.get("obligations") or {}
    for key in ("required_license_text", "required_notice", "local_notice"):
        v = ob.get(key)
        if v:
            obligation_artifacts.add(v)

    rev = m.get("review") or {}
    if rev.get("status") != "reviewed":
        refuse("RM-ENTRY-UNREVIEWED",
               "%s (%s): review.status is %r. Unreviewed material is refused, "
               "not carried — that is the difference between 'we looked and it "
               "is fine' and 'we did not look'."
               % (mid, mpath, rev.get("status")))
        continue
    reviewed_count += 1

    full = abspath(mpath)
    if not os.path.isfile(full):
        refuse("RM-MATERIAL-PATH-MISSING",
               "%s: inventoried path %s is not in the tree. Either the material "
               "was removed and the entry must be retired, or the path is wrong "
               "and nothing is being checked." % (mid, mpath))
        continue
    if mpath not in tracked_set:
        refuse("RM-MATERIAL-PATH-MISSING",
               "%s: %s exists on disk but is not tracked by git, so it is not "
               "the file a reviewer or a release would see." % (mid, mpath))
        continue

    declared_hash = (m.get("hashes") or {}).get("repository_content_sha256") or ""
    actual = sha256_file(full)
    if actual != declared_hash:
        refuse("RM-HASH-DRIFT",
               "%s: %s now hashes %s but was reviewed at %s. The content changed "
               "after review, so every licence fact recorded for it describes a "
               "file that no longer exists. Re-review, then update "
               "hashes.repository_content_sha256 and review.reviewed_on."
               % (mid, mpath, actual, declared_hash or "<none declared>"))
        continue

    spdx = (m.get("licence") or {}).get("declared_spdx")
    if not spdx:
        refuse("RM-LICENCE-UNRECOGNISED",
               "%s (%s): no declared_spdx. 'we did not establish a licence' and "
               "'the licence is fine' must never be the same answer." % (mid, mpath))
        continue
    state = policy_state.get(spdx, policy_default)
    if state != "allowed":
        refuse("RM-LICENCE-UNRECOGNISED",
               "%s (%s): licence %s resolves to %r in %s. Only `allowed` may "
               "carry repository material; anything else is a decision nobody "
               "has recorded." % (mid, mpath, spdx, state, os.path.basename(pol_path)))
        continue

    obligations = policy_obligations.get(spdx, [])
    ob_get = lambda k: (ob.get(k) or "")

    if "retain-license-text" in obligations:
        lt = ob_get("required_license_text")
        lt_full = abspath(lt) if lt else ""
        if not lt:
            refuse("RM-LICENCE-TEXT-MISSING",
                   "%s (%s): %s carries obligation retain-license-text and the "
                   "entry names no required_license_text."
                   % (mid, mpath, spdx))
        elif not os.path.isfile(lt_full) or os.path.getsize(lt_full) == 0:
            refuse("RM-LICENCE-TEXT-MISSING",
                   "%s (%s): %s obligation retain-license-text is unmet — "
                   "%s is absent or empty. The obligation attaches TODAY, to "
                   "material already in this tree; it does not wait on any "
                   "outbound licence decision."
                   % (mid, mpath, spdx, lt))

    if "retain-notice-file" in obligations:
        nt = ob_get("required_notice")
        nt_full = abspath(nt) if nt else ""
        if not nt:
            refuse("RM-NOTICE-MISSING",
                   "%s (%s): %s carries obligation retain-notice-file and the "
                   "entry names no required_notice." % (mid, mpath, spdx))
        elif not os.path.isfile(nt_full) or os.path.getsize(nt_full) == 0:
            refuse("RM-NOTICE-MISSING",
                   "%s (%s): %s obligation retain-notice-file is unmet — the "
                   "upstream NOTICE %s is absent or empty. A local attribution "
                   "note is not a substitute for the upstream NOTICE file."
                   % (mid, mpath, spdx, nt))

    if "retain-copyright-notice" in obligations and not ob_get("copyright_attribution"):
        refuse("RM-COPYRIGHT-MISSING",
               "%s (%s): %s requires the copyright notice to be retained and "
               "the entry records none." % (mid, mpath, spdx))

    if "state-changes" in obligations:
        lm = m.get("local_modifications") or {}
        method = (m.get("acquisition") or {}).get("method")
        changed = bool(lm.get("modified"))
        changes = [c for c in (lm.get("changes") or []) if c]
        if method == "verbatim-copy" and changed:
            refuse("RM-CHANGES-NOT-STATED",
                   "%s (%s): acquisition.method is verbatim-copy but "
                   "local_modifications.modified is true. One of the two is "
                   "wrong and a reader cannot tell which." % (mid, mpath))
        elif method != "verbatim-copy" and not changes:
            refuse("RM-CHANGES-NOT-STATED",
                   "%s (%s): %s requires a redistributor to state the changes "
                   "made, acquisition.method is %r, and local_modifications."
                   "changes is empty. A copy silently diverging from the "
                   "upstream it credits is worse than an uncredited copy."
                   % (mid, mpath, spdx, method))

disposition_paths = [d.get("path") or "" for d in dispositions]
covered = set(material_paths) | set(disposition_paths) | obligation_artifacts

# =============================================================================
# DISCOVERY — heuristic. Read the module header before trusting it.
# =============================================================================
# TIER 1 — REFUSING signals, chosen for precision. A hit means "a human must
# account for this file". No hit means NOTHING AT ALL.
HEURISTIC_SIGNALS = (
    ("path-third-party",
     "the path is under a directory conventionally used for foreign material"),
    ("embedded-licence-grant",
     "the file body contains the operative words of a licence grant"),
    ("foreign-copyright-header",
     "the file's first 40 lines carry a copyright line that is not Zenchron's"),
)

RE_PATH_SIGNAL = re.compile(
    r"^(third[-_]party|vendor|external|contrib|patches|upstream)/")
RE_GRANT_SIGNAL = re.compile(
    r"Permission is hereby granted"
    r"|Licensed under the Apache Licen[sc]e"
    r"|Redistribution and use in source and binary forms"
    r"|GNU GENERAL PUBLIC LICEN[SC]E"
    r"|Mozilla Public Licen[sc]e Version"
    r"|SPDX-Licen[sc]e-Identifier:")
# A copyright STATEMENT, not the word. `retain-copyright-notice` in a policy
# obligation list is not an attribution and must not be read as one.
RE_COPYRIGHT = re.compile(r"copyright[^\n]{0,40}?(?:\(c\)|\u00a9|\d{4})", re.I)

# TIER 2 — ADVISORY ONLY. Ordinary English. Reported, never refused.
RE_ADVISORY = re.compile(
    r"copied verbatim|verbatim copy|pinned copy of|vendored from"
    r"|upstream copy|derived from the (moby|docker|upstream)"
    r"|third-party attribution", re.I)


def read_head_and_body(path, head_lines=40, cap=1024 * 1024):
    try:
        with open(path, "rb") as fh:
            raw = fh.read(cap)
    except OSError:
        return None, None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None, None
    return "\n".join(text.splitlines()[:head_lines]), text


unscannable = []
signal_hits = []      # (path, signal-id, evidence)
advisory_hits = []

for rel in tracked:
    if RE_PATH_SIGNAL.match(rel):
        signal_hits.append((rel, "path-third-party", rel.split("/")[0] + "/"))
    head, body = read_head_and_body(abspath(rel))
    if body is None:
        unscannable.append(rel)
        continue
    mgrant = RE_GRANT_SIGNAL.search(body)
    if mgrant:
        signal_hits.append((rel, "embedded-licence-grant", mgrant.group(0)))
    for line in (head or "").splitlines():
        if RE_COPYRIGHT.search(line) and "zenchron" not in line.lower():
            signal_hits.append((rel, "foreign-copyright-header", line.strip()[:100]))
            break
    if RE_ADVISORY.search(body):
        advisory_hits.append(rel)

uninventoried = {}
for rel, sig, ev in signal_hits:
    if rel in covered:
        continue
    uninventoried.setdefault(rel, []).append((sig, ev))

for rel in sorted(uninventoried):
    detail = "; ".join("%s: %r" % (s, e) for s, e in uninventoried[rel])
    refuse("RM-UNINVENTORIED-MATERIAL",
           "%s trips a copied-material signal and appears in neither "
           "`materials` nor `dispositions` of %s [%s]. Add it to the inventory "
           "with its provenance, or dispose of it with a reason and a reviewer. "
           "Do not silence the signal."
           % (rel, os.path.basename(inv_path), detail))

# =============================================================================
# the reviewed baseline — the NON-heuristic half
# =============================================================================
base = inv.get("baseline") or {}
base_rel = base.get("path_list") or ""
base_full = abspath(base_rel) if base_rel else ""
baseline_paths = None

if not base_rel or not os.path.isfile(base_full):
    refuse("RM-BASELINE-UNVERIFIABLE",
           "the reviewed baseline path list (%s) is missing. Without it, "
           "'no signal fired' is the only thing this gate could say about the "
           "other %d tracked files, and that is not a finding."
           % (base_rel or "<unset>", len(tracked)))
else:
    actual_base_hash = sha256_file(base_full)
    declared_base_hash = base.get("path_list_sha256") or ""
    if actual_base_hash != declared_base_hash:
        refuse("RM-BASELINE-UNVERIFIABLE",
               "%s hashes %s but %s declares %s. The baseline was edited without "
               "recording a review, so it no longer records what anybody looked at."
               % (base_rel, actual_base_hash, os.path.basename(inv_path),
                  declared_base_hash or "<none>"))
    else:
        with open(base_full, encoding="utf-8") as fh:
            baseline_paths = set(
                ln.strip() for ln in fh if ln.strip() and not ln.startswith("#"))
        if base.get("path_count") != len(baseline_paths):
            refuse("RM-BASELINE-UNVERIFIABLE",
                   "%s declares path_count %r but %s holds %d paths"
                   % (os.path.basename(inv_path), base.get("path_count"),
                      base_rel, len(baseline_paths)))

if baseline_paths is not None:
    outside = sorted(p for p in tracked_set - baseline_paths if p not in covered)
    if outside:
        msg = ("%d tracked file(s) are outside the reviewed baseline and in "
               "neither inventory array: %s%s. Nothing has established what "
               "they are. Review them, then regenerate the baseline with "
               "`git ls-files | LC_ALL=C sort > %s` and update "
               "baseline.path_list_sha256, path_count and reviewed_at_revision."
               % (len(outside), ", ".join(outside[:10]),
                  "" if len(outside) <= 10 else ", ...", base_rel))
        if req_base:
            refuse("RM-BASELINE-STALE", msg)
        else:
            notes.append("BASELINE DRIFT (not refused at this scope; "
                         "--require-reviewed-baseline refuses it): " + msg)

# =============================================================================
# SOURCE 1 — image SBOM licence evidence, and the composition rule
# =============================================================================
image_components = None
# THE OTHER DIRECTION OF THE COMPOSITION RULE.
#
# The block below already refuses image evidence presented beside an empty
# repository verdict. The reverse was silently permitted: with no
# --image-inventory this gate printed "not supplied (this run decides nothing
# about image components)" and exited 0, so a repository-only PASS read exactly
# like a licence clearance. It is not one. An SBOM sees what is IN the image and
# this gate sees what is in the TREE; neither is a superset of the other, and a
# clean result from one can never compensate for the absence of the other.
#
# --require-image-evidence is what a release-authorization caller passes. The
# flag is off by default so the required `repo structure` job — which is
# buildless and has no candidate image to build an SBOM from — keeps gating the
# repository half exactly as it does today.
if req_image and not img_path:
    refuse("RM-IMAGE-EVIDENCE-ABSENT",
           "image SBOM licence evidence was REQUIRED and none was supplied. The "
           "repository-material inventory cannot see what is inside a candidate "
           "image, so a clean repository verdict on its own licenses nothing. "
           "Build the image half with "
           "scripts/license/assert-image-sbom-licences.sh --authorization "
           "<post-build-authorization.json> --sbom-dir <candidate SBOMs> and "
           "pass the result as --image-inventory")
if img_path:
    try:
        import json as _json2
        with open(img_path) as fh:
            img = _json2.load(fh)
    except (OSError, ValueError) as e:
        hard("RM-INVENTORY-UNREADABLE", "image inventory %s is unreadable: %s" % (img_path, e))
    if img.get("schema") != "foundry.license-inventory/v1":
        hard("RM-INVENTORY-MALFORMED",
             "%s is not a foundry.license-inventory/v1 document" % img_path)
    image_components = len(img.get("components") or [])
    if reviewed_count == 0:
        refuse("RM-REPOSITORY-EVIDENCE-ABSENT",
               "image SBOM licence evidence was presented (%s, %d components) "
               "while the repository-material inventory asserts NO reviewed "
               "material. An image SBOM cannot see repository material, so a "
               "clean image verdict beside an empty repository verdict is the "
               "exact blind spot #120 exists to close — not two clean results."
               % (os.path.basename(img_path), image_components))

# =============================================================================
# report
# =============================================================================
print("repository-material gate — four-source composition")
print("  SOURCE 1  image SBOM licence evidence  : %s"
      % ("%s (%d components)" % (img_path, image_components) if img_path
         else ("REQUIRED AND ABSENT" if req_image
               else "not supplied (this run decides nothing about image components)")))
print("  SOURCE 2  repository-material inventory: %s (%d materials, %d dispositions, %d reviewed)"
      % (inv_path, len(materials), len(dispositions), reviewed_count))
print("  SOURCE 3  licence texts and notices    : %d artifact(s) named by source 2"
      % len(obligation_artifacts))
print("  SOURCE 4  project outbound licence     : %s + %s -> %s"
      % (os.path.basename(lic_path), os.path.basename(pol_path),
         "FINAL" if outbound_final else "NOT FINAL (placeholder / undetermined)"))
print("  discovery: HEURISTIC over %d tracked files; %d signal hit(s), "
      "%d unscannable (non-UTF-8), %d advisory prose hit(s)"
      % (len(tracked), len(signal_hits), len(unscannable), len(advisory_hits)))
for sid, desc in HEURISTIC_SIGNALS:
    print("            signal %-26s %s" % (sid, desc))
print("  discovery CANNOT prove a file is first-party. Absence of a signal is "
      "not evidence; the reviewed baseline is what covers the silence.")
if advisory_hits:
    print("  ADVISORY (refuses nothing, low precision, ordinary English): "
          "%d file(s) contain prose provenance phrases, e.g. %s"
          % (len(advisory_hits), ", ".join(sorted(advisory_hits)[:5])))
if unscannable:
    print("  LIMIT: %d tracked file(s) could not be decoded as UTF-8 and were "
          "NOT content-scanned: %s" % (len(unscannable), ", ".join(unscannable[:5])))
for n in notes:
    print("  NOTE: %s" % n)

if findings:
    out = ["", "REFUSE: repository material is not accounted for — %d finding(s):" % len(findings)]
    for code in sorted({c for c, _ in findings}):
        msgs = [m for c, m in findings if c == code]
        out.append("")
        out.append("  [%s] (%d)" % (code, len(msgs)))
        for m in msgs:
            out.append("    - %s" % m)
    out.append("")
    out.append("  Resolve each by recording the fact in %s — not by editing this gate."
               % os.path.basename(inv_path))
    sys.stderr.write("\n".join(out) + "\n")
    raise SystemExit(1)

print("repository-material OK: %d reviewed material(s), 0 findings" % reviewed_count)
if not outbound_final:
    print("NOTE: the project's OUTBOUND licence is not settled (issue %s). "
          "This gate accounted for INBOUND obligations that attach today; it "
          "established no right to distribute anything."
          % publication.get("tracked_issue"))
PY
}

# -----------------------------------------------------------------------------
# self-test — fixture trees only, under a scratch dir. The real inventory is
# READ, never written.
# -----------------------------------------------------------------------------
self_test() {
  local fail=0 tmp
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" EXIT

  ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1
           [ -n "${RM_SELFTEST_VERBOSE:-}" ] && { echo "--- captured output ---"; cat "$tmp/out"; echo "--- end ---"; }
         fi; }

  # `gate | grep` inherits gate's status under pipefail, so a MATCHING grep on a
  # refusal reads as a failure — backwards. Capture, then assert on the capture.
  # shellcheck disable=SC2034  # every RM_* below is read by gate()'s python
  # heredoc through os.environ; `set -a` is what puts them there.
  run() { ( set -a; RM_ROOT="$1" RM_INVENTORY="$2" RM_POLICY="$3" \
            RM_LICENSE_FILE="$4" RM_IMAGE_INVENTORY="${5:-}" \
            RM_REQUIRE_BASELINE="${6:-0}" RM_REQUIRE_FINAL_TERMS="${7:-0}" \
            RM_REQUIRE_IMAGE_EVIDENCE="${8:-0}"; \
            set +a; gate ) >"$tmp/out" 2>&1; }
  says() { grep -q "$1" "$tmp/out"; }

  # --- a minimal, self-consistent fixture tree -------------------------------
  local F="$tmp/fix"
  mkfix() {
    rm -rf "$F"; mkdir -p "$F/security/seccomp" "$F/third-party/up-v1" "$F/policies"
    printf '{"defaultAction":"SCMP_ACT_ERRNO"}\n' >"$F/security/seccomp/prof.json"
    # A licence-grant string, so the fixture proves the signal can fire.
    printf 'Apache Licence text stand-in.\nLicensed under the Apache License, Version 2.0\n' \
      >"$F/third-party/up-v1/LICENSE"
    printf 'Upstream NOTICE stand-in.\nCopyright 2012-2017 Upstream, Inc.\n' \
      >"$F/third-party/up-v1/NOTICE"
    cat >"$F/policies/license-policy.yaml" <<'YAML'
version: 1
default_state: legal-review-required
states: [allowed, denied, legal-review-required]
publication:
  decision: undetermined
  tracked_issue: 98
  notices_approved_for_distribution: false
licenses:
  - id: Apache-2.0
    state: allowed
    obligations: [retain-copyright-notice, retain-license-text, state-changes, retain-notice-file]
  - id: GPL-3.0-only
    state: legal-review-required
denied: []
exceptions: []
YAML
    cat >"$F/LICENSE" <<'TXT'
Copyright (c) 2026 Zenchron Dynamics. All rights reserved.
If you require an open-source license for a public fork, replace this file
before publication. Do not assume any OSI license applies by default.
TXT
    ( cd "$F" && git init -q . && git config user.email f@f && git config user.name f \
      && git add -A && git commit -qm f ) >/dev/null 2>&1
  }

  # Rebuild the inventory from the fixture's real hashes so the happy path is
  # genuinely self-consistent rather than asserted.
  mkinv() { # mkinv <extra-yaml-or-empty>
    local ph bh
    ph="$(shasum -a 256 "$F/security/seccomp/prof.json" | cut -d' ' -f1)"
    ( cd "$F" && git ls-files | LC_ALL=C sort ) >"$F/policies/baseline.txt"
    bh="$(shasum -a 256 "$F/policies/baseline.txt" | cut -d' ' -f1)"
    cat >"$F/policies/repository-material.yaml" <<YAML
schema: foundry.repository-material/v1
version: 1
tracked_issue: 120
baseline:
  path_list: policies/baseline.txt
  path_list_sha256: $bh
  path_count: $(wc -l <"$F/policies/baseline.txt" | tr -d ' ')
  reviewed_at_revision: $(printf '0%.0s' $(seq 40))
  reviewed_by: fixture-owner
  reviewed_on: '2026-08-27'
materials:
  - id: fixture-profile
    path: security/seccomp/prof.json
    material_identity: Fixture upstream profile stand-in for the gate self-test.
    upstream:
      project: up/up
      source_url: https://example.invalid/up
      revision: v1
      path: profiles/prof.json
    acquisition:
      method: verbatim-copy
      acquired_on: '2026-08-27'
      recorded_by: fixture-owner
    local_modifications:
      modified: false
      changes: []
    licence:
      declared_spdx: ${FIX_SPDX:-Apache-2.0}
      determination: Fixture determination recorded for the self-test only.
    obligations:
      required_license_text: ${FIX_LT-third-party/up-v1/LICENSE}
      required_notice: ${FIX_NT-third-party/up-v1/NOTICE}
      local_notice: null
      copyright_attribution: ${FIX_CR-Copyright 2012-2017 Upstream, Inc.}
      source_offer: not-applicable
      reciprocity: none
    hashes:
      repository_content_sha256: ${FIX_HASH:-$ph}
      upstream_content_sha256: null
    review:
      status: ${FIX_REVIEW:-reviewed}
      reviewed_by: fixture-owner
      reviewed_on: '2026-08-27'
      tracked_issue: 120
dispositions:
  - path: policies/repository-material.yaml
    classification: scanner-self-reference
    reason: >-
      The fixture inventory records a copyright attribution line, so it trips
      the foreign-copyright-header signal on itself, exactly as the shipped
      inventory does.
    reviewed_by: fixture-owner
    reviewed_on: '2026-08-27'
YAML
    ( cd "$F" && git add -A && git commit -qm inv ) >/dev/null 2>&1
    # The baseline must include the files the last commit added.
    ( cd "$F" && git ls-files | LC_ALL=C sort ) >"$F/policies/baseline.txt"
    bh="$(shasum -a 256 "$F/policies/baseline.txt" | cut -d' ' -f1)"
    local n; n="$(wc -l <"$F/policies/baseline.txt" | tr -d ' ')"
    sed -i.bak -e "s|^  path_list_sha256: .*|  path_list_sha256: $bh|" \
               -e "s|^  path_count: .*|  path_count: $n|" \
               "$F/policies/repository-material.yaml"
    rm -f "$F/policies/repository-material.yaml.bak"
    ( cd "$F" && git add -A && git commit -qm inv2 ) >/dev/null 2>&1
    ( cd "$F" && git ls-files | LC_ALL=C sort ) >"$F/policies/baseline.txt"
  }

  local I="$F/policies/repository-material.yaml"
  local P="$F/policies/license-policy.yaml"
  local L="$F/LICENSE"

  mkfix; mkinv
  ck "a self-consistent fixture tree PASSES" "run '$F' '$I' '$P' '$L'"
  ck "...and names all four sources it composed" \
     "says 'SOURCE 1' && says 'SOURCE 2' && says 'SOURCE 3' && says 'SOURCE 4'"
  ck "...and says out loud that discovery is HEURISTIC" \
     "says 'discovery: HEURISTIC' && says 'CANNOT prove a file is first-party'"
  ck "...and reports the outbound licence as NOT FINAL" "says 'NOT FINAL'"

  # --- 1. an inventoried copied file missing its licence text ---------------
  mkfix; mkinv; rm -f "$F/third-party/up-v1/LICENSE"
  ck "REFUSE: an inventoried copy whose licence text is absent" \
     "! run '$F' '$I' '$P' '$L'"
  ck "...with diagnostic RM-LICENCE-TEXT-MISSING" "says 'RM-LICENCE-TEXT-MISSING'"

  # --- 2. a required NOTICE missing -----------------------------------------
  mkfix; mkinv; rm -f "$F/third-party/up-v1/NOTICE"
  ck "REFUSE: the upstream NOTICE an Apache-2.0 entry must carry is absent" \
     "! run '$F' '$I' '$P' '$L'"
  ck "...with diagnostic RM-NOTICE-MISSING" "says 'RM-NOTICE-MISSING'"

  # --- 3. hash drift without inventory review -------------------------------
  mkfix; mkinv; printf '{"defaultAction":"SCMP_ACT_ALLOW"}\n' >"$F/security/seccomp/prof.json"
  ck "REFUSE: the material changed after it was reviewed" \
     "! run '$F' '$I' '$P' '$L'"
  ck "...with diagnostic RM-HASH-DRIFT naming both hashes" \
     "says 'RM-HASH-DRIFT' && says 'was reviewed at'"

  # --- 4. an unrecognized or missing licence --------------------------------
  mkfix; FIX_SPDX=GPL-3.0-only mkinv
  ck "REFUSE: a licence the policy does not classify as allowed" \
     "! run '$F' '$I' '$P' '$L'"
  ck "...with diagnostic RM-LICENCE-UNRECOGNISED" "says 'RM-LICENCE-UNRECOGNISED'"
  mkfix; FIX_SPDX=NEVER-HEARD-OF-1.0 mkinv
  ck "REFUSE: an SPDX id nobody has classified falls to the policy default" \
     "! run '$F' '$I' '$P' '$L'"
  ck "...and is reported as unrecognised, not silently allowed" \
     "says 'RM-LICENCE-UNRECOGNISED' && says 'legal-review-required'"

  # --- 5. a copied repository file absent from the inventory ----------------
  mkfix; mkinv
  mkdir -p "$F/vendor/thing"
  printf 'Copyright (c) 2020 Somebody Else\nPermission is hereby granted, free of charge\n' \
    >"$F/vendor/thing/copied.txt"
  ( cd "$F" && git add -A && git commit -qm sabotage ) >/dev/null 2>&1
  ck "SABOTAGE: a copied file in neither inventory array is REFUSED" \
     "! run '$F' '$I' '$P' '$L'"
  ck "...with diagnostic RM-UNINVENTORIED-MATERIAL naming the file" \
     "says 'RM-UNINVENTORIED-MATERIAL' && says 'vendor/thing/copied.txt'"
  ck "...naming WHICH signals fired, not merely that one did" \
     "says 'path-third-party' && says 'embedded-licence-grant' && says 'foreign-copyright-header'"
  ck "NON-VACUOUS: disposing of that same file with a reason clears it" \
     "printf '  - path: vendor/thing/copied.txt\n    classification: first-party\n    reason: fixture disposition text long enough to satisfy the schema minimum length\n    reviewed_by: fixture-owner\n    reviewed_on: \"2026-08-27\"\n' >>'$I'
      ( cd '$F' && git add -A && git commit -qm disp ) >/dev/null 2>&1
      ( cd '$F' && git ls-files | LC_ALL=C sort ) > '$F/policies/baseline.txt'
      b=\$(shasum -a 256 '$F/policies/baseline.txt' | cut -d' ' -f1)
      n=\$(wc -l <'$F/policies/baseline.txt' | tr -d ' ')
      sed -i.bak -e \"s|^  path_list_sha256: .*|  path_list_sha256: \$b|\" -e \"s|^  path_count: .*|  path_count: \$n|\" '$I' && rm -f '$I.bak'
      ( cd '$F' && git add -A && git commit -qm disp2 ) >/dev/null 2>&1
      ( cd '$F' && git ls-files | LC_ALL=C sort ) > '$F/policies/baseline.txt'
      run '$F' '$I' '$P' '$L'"

  # --- 6. a placeholder presented as final terms ----------------------------
  mkfix; mkinv
  ck "REFUSE: placeholder outbound terms asserted as final" \
     "! run '$F' '$I' '$P' '$L' '' 0 1"
  ck "...with diagnostic RM-OUTBOUND-TERMS-PLACEHOLDER naming both facts" \
     "says 'RM-OUTBOUND-TERMS-PLACEHOLDER' && says 'declares itself a placeholder' \
      && says 'publication.decision'"
  ck "NON-VACUOUS: the identical tree passes when finality is NOT asserted" \
     "run '$F' '$I' '$P' '$L'"

  # --- 7. image evidence present, repository evidence absent ----------------
  mkfix; FIX_REVIEW=unreviewed mkinv
  printf '{"schema":"foundry.license-inventory/v1","components":[{"name":"libfoo","version":"1","licenses":["MIT"]}]}\n' \
    >"$tmp/img.json"
  ck "REFUSE: a clean image verdict beside an empty repository verdict" \
     "! run '$F' '$I' '$P' '$L' '$tmp/img.json'"
  ck "...with diagnostic RM-REPOSITORY-EVIDENCE-ABSENT" \
     "says 'RM-REPOSITORY-EVIDENCE-ABSENT'"
  ck "...and the entry is separately reported as unreviewed" "says 'RM-ENTRY-UNREVIEWED'"
  mkfix; mkinv
  ck "NON-VACUOUS: the same image evidence passes beside REVIEWED repo evidence" \
     "run '$F' '$I' '$P' '$L' '$tmp/img.json'"

  # --- 7b. repository evidence present, image evidence absent ---------------
  # The mirror of case 7, and the direction that used to pass in silence: with
  # no --image-inventory the gate printed "not supplied" and exited 0, so a
  # repository-only PASS read like a licence clearance for a release.
  mkfix; mkinv
  ck "a repository-only run still passes when image evidence is NOT required" \
     "run '$F' '$I' '$P' '$L'"
  ck "REFUSE: the identical clean tree once image evidence is REQUIRED" \
     "! run '$F' '$I' '$P' '$L' '' 0 0 1"
  ck "...with diagnostic RM-IMAGE-EVIDENCE-ABSENT" "says 'RM-IMAGE-EVIDENCE-ABSENT'"
  ck "...naming the script that produces the missing half" \
     "says 'assert-image-sbom-licences.sh'"
  ck "...and SOURCE 1 is reported as REQUIRED AND ABSENT, not as 'not supplied'" \
     "says 'REQUIRED AND ABSENT'"
  ck "NON-VACUOUS: the same required run passes once image evidence IS supplied" \
     "run '$F' '$I' '$P' '$L' '$tmp/img.json' 0 0 1"

  # --- the reviewed baseline ------------------------------------------------
  mkfix; mkinv
  printf 'nothing interesting at all\n' >"$F/quiet.txt"
  ( cd "$F" && git add -A && git commit -qm quiet ) >/dev/null 2>&1
  ck "a file tripping NO signal still passes at PR scope" "run '$F' '$I' '$P' '$L'"
  ck "...but is reported as baseline drift rather than passed in silence" \
     "says 'BASELINE DRIFT' && says 'quiet.txt'"
  ck "REFUSE: the same file at release scope, because nobody reviewed it" \
     "! run '$F' '$I' '$P' '$L' '' 1 0"
  ck "...with diagnostic RM-BASELINE-STALE" "says 'RM-BASELINE-STALE'"
  mkfix; mkinv; printf 'tampered\n' >>"$F/policies/baseline.txt"
  ck "REFUSE: an edited baseline whose hash no longer matches the inventory" \
     "! run '$F' '$I' '$P' '$L'"
  ck "...with diagnostic RM-BASELINE-UNVERIFIABLE" "says 'RM-BASELINE-UNVERIFIABLE'"

  # --- malformed / absent inputs -------------------------------------------
  mkfix; mkinv
  ck "REFUSE: an absent inventory is not an empty one" \
     "! run '$F' '$F/nope.yaml' '$P' '$L'"
  ck "...with diagnostic RM-INVENTORY-UNREADABLE" "says 'RM-INVENTORY-UNREADABLE'"
  printf 'schema: something-else\n' >"$tmp/wrong.yaml"
  ck "REFUSE: a document that is not a repository-material inventory" \
     "! run '$F' '$tmp/wrong.yaml' '$P' '$L'"
  ck "...with diagnostic RM-INVENTORY-MALFORMED" "says 'RM-INVENTORY-MALFORMED'"
  printf '{"schema":"not-a-license-inventory"}\n' >"$tmp/badimg.json"
  ck "REFUSE: an image inventory that is not a foundry.license-inventory/v1" \
     "! run '$F' '$I' '$P' '$L' '$tmp/badimg.json'"

  # --- the SHIPPED inventory must itself be structurally valid --------------
  # Structure only. Whether the shipped tree SATISFIES every obligation is what
  # the real invocation decides, and this must not pre-judge it.
  mkfix; mkinv
  ck "the shipped policies/repository-material.yaml parses and is v1" \
     "python3 -c 'import yaml,sys;d=yaml.safe_load(open(sys.argv[1]));
sys.exit(0 if d.get(\"schema\")==\"foundry.repository-material/v1\"
             and isinstance(d.get(\"materials\"),list) and d[\"materials\"]
             and isinstance(d.get(\"dispositions\"),list) else 1)' \
      '$ROOT/policies/repository-material.yaml'"

  echo "----"
  if [ "$fail" -eq 0 ]; then echo "assert-repository-material: SELF-TEST OK"
  else echo "assert-repository-material: SELF-TEST FAILED"; fi
  return "$fail"
}

main() {
  local inv="" pol="" lic="" img="" req_base=0 req_final=0 req_image=0 root="$ROOT"
  case "${1:-}" in --self-test) self_test; exit $? ;; esac
  while [ $# -gt 0 ]; do
    case "$1" in
      --root)             root="${2:-}"; shift 2 ;;
      --inventory)        inv="${2:-}";  shift 2 ;;
      --policy)           pol="${2:-}";  shift 2 ;;
      --license-file)     lic="${2:-}";  shift 2 ;;
      --image-inventory)  img="${2:-}";  shift 2 ;;
      --require-reviewed-baseline)   req_base=1;  shift ;;
      --require-final-outbound-terms) req_final=1; shift ;;
      --require-image-evidence)      req_image=1; shift ;;
      *) usage ;;
    esac
  done
  RM_ROOT="$root" \
  RM_INVENTORY="${inv:-$root/policies/repository-material.yaml}" \
  RM_POLICY="${pol:-$root/policies/license-policy.yaml}" \
  RM_LICENSE_FILE="${lic:-$root/LICENSE}" \
  RM_IMAGE_INVENTORY="$img" \
  RM_REQUIRE_BASELINE="$req_base" \
  RM_REQUIRE_FINAL_TERMS="$req_final" \
  RM_REQUIRE_IMAGE_EVIDENCE="$req_image" \
    gate
}

main "$@"
