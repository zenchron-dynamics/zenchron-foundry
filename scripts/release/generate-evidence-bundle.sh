#!/usr/bin/env bash
# =============================================================================
# scripts/release/generate-evidence-bundle.sh — the durable release evidence
# bundle, and its offline verifier.
# -----------------------------------------------------------------------------
# THE DEFECT THIS EXISTS FOR (#128).
#
# scan-images.yml uploads its scan and consolidated-result artifacts with 30-day
# retention. The release decision they justify has to stand up for years: a
# conformity assessment, a customer audit, an incident reconstruction, a
# vulnerability re-triage. On day 31 the digests are still in the registry and
# the reason they were accepted is gone — which scanner, which frozen database,
# which exception records, which smoke and metadata results, which authorization.
#
# The fix is not longer retention. Artifact retention caps at 90 days on this
# plan, and a workflow artifact is not immutable storage: a run can be deleted, a
# repository can be transferred. The fix is a bundle that verifies with NO
# NETWORK, no GitHub API, no registry, and no surviving workflow run — and a
# checksum discipline in which nothing sits outside coverage.
#
# THE CHECKSUM ORDER IS THE CONTROL. Everything the generator produces —
# including the VEX document it invokes generate-vex.sh to produce — is written
# into content/ FIRST. Only then is the aggregate computed, and only then are the
# per-file sums written. A file added afterwards is a file no digest covers, and
# `verify` refuses on exactly that: a file on disk that SHA256SUMS does not name.
#
#   <bundle>/
#     manifest.json          the record; schemas/release-evidence-bundle-v1
#     content/               everything the manifest indexes
#       acceptance/          the source acceptance record, verbatim
#       children/<slug>.json per-child evidence extract
#       vex/openvex.json     machine-readable dispositions (#115)
#       policy/              digests of every policy that decided the verdict
#       provenance/          run + revision binding
#       authorization/       the authorization record
#       retention/           class, expiry, storage requirement
#       sbom/                SBOM bytes + index, when supplied
#     SHA256SUMS             manifest.json + every file under content/
#     BUNDLE.sha256          sha256(SHA256SUMS) — one value to quote in an audit
#
# DETERMINISM. The generator never reads the wall clock. Timestamps come from the
# acceptance record, so regenerating a bundle from the same inputs produces the
# same bytes — which is what makes "the bundle was not tampered with" checkable
# rather than assertable.
#
# Identity is child_key()/child_slug() from scripts/lib/common.sh, checked
# against the key the record carries. Per-child evidence checksums are the ones
# the acceptance pipeline already produced; the aggregate uses
# scripts/release/evidence-checksum.sh, the same path-independent function, so a
# relocated bundle still verifies.
#
# Usage:
#   generate-evidence-bundle.sh generate --evidence <acceptance.json>
#        --out <dir> --evidence-class <class>
#        [--release vYYYY.MM.DD --candidate rcN] [--sbom-dir DIR]
#        [--provenance FILE] [--ledger FILE] [--today YYYY-MM-DD]
#   generate-evidence-bundle.sh verify <dir>
#   generate-evidence-bundle.sh --self-test
# =============================================================================
set -euo pipefail
_GEB_D="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GEB_ROOT="${GEB_ROOT:-$(cd "$_GEB_D/../.." && pwd)}"
# shellcheck source=../lib/common.sh
. "$_GEB_D/../lib/common.sh"
# shellcheck source=evidence-checksum.sh
. "$_GEB_D/evidence-checksum.sh"

GEB_SCHEMA="$GEB_ROOT/schemas/release-evidence-bundle-v1.schema.json"
GEB_RETENTION="$GEB_ROOT/policies/retention.yaml"
GEB_CLASS_POLICY="$GEB_ROOT/policies/evidence-classes.yaml"

# The policy files whose CONTENT decided the verdict. Their digests go into the
# bundle so "reconstruct the decision" means reading these exact bytes, not
# whatever the repository says today.
GEB_POLICY_FILES="policies/vulnerability-exceptions.yaml
policies/lifecycle.yaml
policies/release-governance.yaml
policies/cosign-identities.yaml
policies/native-arch-requirements.yaml
policies/required-release-checks.yaml
policies/retention.yaml
policies/evidence-classes.yaml"

_geb_need_py() {
  python3 -c 'import yaml' 2>/dev/null \
    || die "python3 with PyYAML is required"
}

# The ONE identity derivation, same as every other consumer.
#
# The table carries the SBOM filenames too, derived by sbom_filename() — the
# function scripts/generate-sbom.sh calls to WRITE them. Python never re-derives
# a name here: a second derivation of one identity is exactly how the producer's
# output set and this consumer's lookup set stopped intersecting, and the bundle
# reported `sbom.present: false` over a complete SBOM directory with exit 0.
#
# Columns: child_key, child_slug, <format>=<filename> for every declared format.
_geb_identity_table() { # <record.json>   (acceptance evidence OR a bundle manifest)
  local fam ver plat row f name
  python3 - "$1" <<'PY' |
import json, sys
rec = json.load(open(sys.argv[1]))
for c in rec.get("children") or []:
    fam = c.get("image_family")
    ver = c.get("image_version")
    if fam is None:
        fam, _, ver = (c.get("image_label") or "").partition("/")
    print("%s	%s	%s" % (fam or "", ver or "", c.get("platform") or ""))
PY
  while IFS="$(printf '	')" read -r fam ver plat; do
    row="$(child_key "$fam" "$ver" "$plat")	$(child_slug "$fam" "$ver" "$plat")"
    for f in $SBOM_FORMATS; do
      name="$(sbom_filename "$fam" "$ver" "$plat" "$f")" || return 1
      row="$row	$f=$name"
    done
    printf '%s\n' "$row"
  done
}

# The SBOM document format of record. SPDX is what the licence inventory, the
# release seal and every downstream consumer read; a CycloneDX companion is
# accepted alongside it but does not substitute for it.
GEB_SBOM_REQUIRED_FORMAT=spdx-json

# =============================================================================
# generate
# =============================================================================
geb_generate() {
  local ev="" out="" cls="" rel="" cand="" sbom="" prov="" ledger="" today=""
  local auth="" auth_absent=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --evidence)       ev="${2:?}"; shift 2 ;;
      --out)            out="${2:?}"; shift 2 ;;
      --evidence-class) cls="${2:?}"; shift 2 ;;
      --release)        rel="${2:?}"; shift 2 ;;
      --candidate)      cand="${2:?}"; shift 2 ;;
      --sbom-dir)       sbom="${2:?}"; shift 2 ;;
      --authorization)  auth="${2:?}"; shift 2 ;;
      --authorization-absent) auth_absent="${2:?}"; shift 2 ;;
      --provenance)     prov="${2:?}"; shift 2 ;;
      --ledger)         ledger="${2:?}"; shift 2 ;;
      --today)          today="${2:?}"; shift 2 ;;
      *) die "generate: unknown argument: $1" ;;
    esac
  done
  [ -n "$ev" ]  || die "generate: --evidence is required"
  [ -n "$out" ] || die "generate: --out is required"
  [ -n "$cls" ] || die "generate: --evidence-class is required — a class is never inferred"
  [ -f "$ev" ]  || die "acceptance evidence not found: $ev"
  ledger="${ledger:-$GEB_ROOT/policies/vulnerability-exceptions.yaml}"
  today="${today:-$(date -u +%F)}"
  _geb_need_py

  # --- the authorization decision is stated, never defaulted -----------------
  # An authorization is what makes a bundle a record of a DECISION rather than
  # a record of a build. Exactly one of the two flags must be given, and the
  # absent case has to be argued in prose that travels with the bundle: a
  # default would put every bundle in whichever state nobody chose.
  if [ -n "$auth" ] && [ -n "$auth_absent" ]; then
    die "--authorization and --authorization-absent are mutually exclusive"
  fi
  if [ -z "$auth" ] && [ -z "$auth_absent" ]; then
    die "generate: no authorization decision. Pass --authorization <post-build-authorization.json>, the canonical record schemas/post-build-authorization-v1 that authorize-staged-candidates.sh produced for this run, or state its absence with --authorization-absent '<reason>'. A bundle that cannot name the authorization that let this build proceed records a build, not a decision"
  fi
  if [ -n "$auth_absent" ] && [ "${#auth_absent}" -lt 20 ]; then
    die "--authorization-absent needs a real reason (got ${#auth_absent} characters, need 20). 'n/a' is not a reason a later reader can act on"
  fi
  if [ -n "$auth" ]; then
    [ -f "$auth" ] || die "--authorization is not a file: $auth"
    # The SHIPPED runtime validator, not a reimplementation. This is the check
    # that no release script performed: the schema was enforced in the
    # producing workflow and by nothing that consumed the record afterwards.
    bash "$_GEB_D/validate-authorization-record.sh" "$auth" >/dev/null \
      || die "the authorization record does not satisfy post-build-authorization-v1: $auth. A record whose shape nobody can rely on binds nothing"
  fi
  if [ "$cls" = "published-artifact" ] && [ -z "$auth" ]; then
    die "class 'published-artifact' requires --authorization: a record of what WAS shipped that cannot name the authorization it shipped under is not that record"
  fi

  [ -e "$out" ] && die "refusing to write into an existing path: $out (a bundle is written once)"
  mkdir -p "$out/content"

  local tmp; tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" EXIT
  _geb_identity_table "$ev" > "$tmp/ident.tsv"

  # --- 1. every generated file is written BEFORE any checksum is taken -------
  mkdir -p "$out/content/acceptance" "$out/content/children" "$out/content/vex" \
           "$out/content/policy" "$out/content/provenance" \
           "$out/content/authorization" "$out/content/retention"
  cp "$ev" "$out/content/acceptance/acceptance-evidence.json"

  # The dispositions are part of the bundle, so they are generated INTO it
  # before the aggregate exists. Generating them afterwards is how a file ends
  # up outside checksum coverage.
  bash "$_GEB_D/generate-vex.sh" generate --evidence "$ev" --evidence-class "$cls" \
       --out "$out/content/vex/openvex.json" --ledger "$ledger" --today "$today" >/dev/null \
    || die "VEX generation failed; the bundle is not written with a missing disposition set"

  local sbom_dir_arg="${sbom:-}"
  if [ -n "$sbom_dir_arg" ]; then
    [ -d "$sbom_dir_arg" ] || die "--sbom-dir is not a directory: $sbom_dir_arg"
    mkdir -p "$out/content/sbom"
  fi
  if [ -n "$prov" ]; then
    [ -f "$prov" ] || die "--provenance is not a file: $prov"
    cp "$prov" "$out/content/provenance/attestation.json"
  fi

  GEB_SCHEMA="$GEB_SCHEMA" GEB_ROOT="$GEB_ROOT" GEB_RETENTION="$GEB_RETENTION" \
  GEB_CLASS_POLICY="$GEB_CLASS_POLICY" GEB_POLICY_FILES="$GEB_POLICY_FILES" \
  GEB_SBOM_REQUIRED_FORMAT="$GEB_SBOM_REQUIRED_FORMAT" \
  python3 - "$ev" "$out" "$cls" "$rel" "$cand" "$sbom_dir_arg" "$prov" "$ledger" \
                  "$tmp/ident.tsv" "$auth" "$auth_absent" <<'PY' || return 1
import json, os, re, sys, hashlib, datetime, shutil, collections
import yaml

(evidence_p, out, cls, rel, cand, sbom_dir, prov, ledger_p, ident_p,
 auth_p, auth_absent) = sys.argv[1:12]
root = os.environ["GEB_ROOT"]
schema_p = os.environ["GEB_SCHEMA"]
retention_p = os.environ["GEB_RETENTION"]
class_policy_p = os.environ["GEB_CLASS_POLICY"]
policy_files = [p for p in os.environ["GEB_POLICY_FILES"].split() if p]


def refuse(msg):
    print("REFUSE: " + msg, file=sys.stderr)
    sys.exit(1)


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def write_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        json.dump(obj, fh, indent=2, sort_keys=False)
        fh.write("\n")


ev = json.load(open(evidence_p))
if ev.get("record_type") != "post-acceptance-evidence":
    refuse("%s: record_type is %r, expected 'post-acceptance-evidence'"
           % (evidence_p, ev.get("record_type")))

acc = ev.get("acceptance") or {}
if acc.get("verdict") != "PASS":
    refuse("%s: acceptance verdict is %r — a bundle records an ACCEPTED run"
           % (evidence_p, acc.get("verdict")))

source_revision = ev.get("source_revision") or ""
if not re.match(r"^[0-9a-f]{40}$", source_revision):
    refuse("%s: source_revision %r is not 40 lowercase hex" % (evidence_p, source_revision))

# --- the evidence CLASS is consumed, never redefined -------------------------
# policies/evidence-classes.yaml is the contract. When it is present it is
# authoritative, including its legacy_records declarations — a pre-contract
# record carries no class field and the class must come from the human
# declaration pinned to its bytes, never from a guess. When it is absent, the
# schema enum (which lists exactly the four declared classes) bounds the value
# and the operator must state it.
declared = None
if os.path.exists(class_policy_p):
    pol = yaml.safe_load(open(class_policy_p)) or {}
    names = [c["name"] for c in pol.get("classes") or []]
    CLASSES_BY_NAME = {c["name"]: c for c in pol.get("classes") or []}
    if cls not in names:
        refuse("evidence class %r is not declared in %s; declared classes are %s"
               % (cls, os.path.relpath(class_policy_p, root), ", ".join(names)))
    ev_sha = sha256_file(evidence_p)
    for lr in pol.get("legacy_records") or []:
        if lr.get("sha256") == ev_sha:
            declared = lr.get("declared_class")
    if declared and declared != cls:
        # A bundle may carry the source record's declared class, or the ONE
        # class that directly succeeds it in the lifecycle the policy declares
        # (upstream-base -> foundry-child -> staged-candidate ->
        # published-artifact). That is a promotion, and the parent_class chain
        # is what defines it — this does not invent a second ordering. Anything
        # else is a class change nobody declared, which is exactly what the
        # contract exists to refuse.
        parent_of = (CLASSES_BY_NAME.get(cls) or {}).get("parent_class")
        if parent_of != declared:
            refuse("%s is declared class %r by %s (pinned to its sha256), but "
                   "--evidence-class says %r. A bundle may restate its source's "
                   "class or promote it by exactly one step along the declared "
                   "lifecycle (%r succeeds %r); %r does not succeed %r"
                   % (os.path.basename(evidence_p), declared,
                      os.path.relpath(class_policy_p, root), cls,
                      cls, parent_of, cls, declared))
else:
    enum = json.load(open(schema_p))["properties"]["evidence_class"]["enum"]
    if cls not in enum:
        refuse("evidence class %r is not one of %s" % (cls, ", ".join(enum)))

if cls == "published-artifact" and not (rel and cand):
    refuse("class 'published-artifact' requires --release and --candidate: a "
           "record of what WAS shipped that cannot name the release is not that "
           "record")
if rel and not re.match(r"^v[0-9]{4}\.[0-9]{2}\.[0-9]{2}(\.[0-9]+)?$", rel):
    refuse("--release %r is not vYYYY.MM.DD[.N]" % rel)
if cand and not re.match(r"^rc[1-9][0-9]*$", cand):
    refuse("--candidate %r must match rc[1-9][0-9]*" % cand)

# --- the SBOM subject binding ------------------------------------------------
# The bundle used to record exactly three facts about an SBOM — its format, its
# path and the sha256 OF THE FILE — and nothing about what the document is a
# bill of materials FOR. An SPDX document describing a completely different
# child, saved under the correct filename, satisfied all three and verified
# clean. The bytes the bundle inspected all lined up; the SUBJECT was never
# read.
#
# So it is read here, and again in verify(). A document that does not name this
# child's manifest digest is not this child's SBOM, however it is filed.
REQUIRED_FMT = os.environ["GEB_SBOM_REQUIRED_FORMAT"]


def sbom_subjects(doc):
    """Every digest this document claims to describe, lowercased."""
    out = set()
    for v in doc.get("documentDescribes") or []:
        if isinstance(v, str):
            out.add(v.strip().lower())
    # CycloneDX spells the subject as metadata.component
    comp = ((doc.get("metadata") or {}).get("component") or {})
    for h in comp.get("hashes") or []:
        if isinstance(h, dict) and h.get("content"):
            alg = (h.get("alg") or "SHA-256").lower().replace("-", "")
            out.add("%s:%s" % ("sha256" if alg == "sha256" else alg,
                               str(h["content"]).lower()))
    for ref in (comp.get("purl"), comp.get("bom-ref")):
        if isinstance(ref, str) and "sha256:" in ref:
            out.add("sha256:" + ref.rsplit("sha256:", 1)[1].strip().lower())
    return out


def check_sbom_subject(path, key, digest, platform, revision):
    try:
        doc = json.load(open(path))
    except (ValueError, OSError) as exc:
        refuse("child %s: %s is not readable JSON (%s). An SBOM the release path "
               "cannot parse is an SBOM whose subject nobody checked"
               % (key, os.path.basename(path), exc))
    if not (doc.get("spdxVersion") or doc.get("bomFormat") or doc.get("SPDXID")):
        refuse("child %s: %s declares neither spdxVersion nor bomFormat — it is "
               "not an SBOM in a format this repository declares"
               % (key, os.path.basename(path)))
    subjects = sbom_subjects(doc)
    if not subjects:
        refuse("child %s: %s names no subject at all (no documentDescribes, no "
               "metadata.component hash). An SBOM that does not say what it "
               "describes cannot be bound to a child, and an unbindable SBOM is "
               "how a foreign bill of materials passes for this one"
               % (key, os.path.basename(path)))
    if digest.lower() not in subjects:
        refuse("child %s: %s describes %s, not this child's manifest digest %s. "
               "The filename matched and the file hashed cleanly — the SUBJECT "
               "did not. An SBOM for another digest, platform or source cannot "
               "substitute for this one"
               % (key, os.path.basename(path), ", ".join(sorted(subjects)[:3]), digest))
    named = doc.get("name")
    if isinstance(named, str) and named and named != key:
        refuse("child %s: %s names itself %r. The document's own identity "
               "disagrees with the child it is filed under (platform %s, "
               "revision %s)" % (key, os.path.basename(path), named, platform, revision))


# --- identity ----------------------------------------------------------------
children_in = ev.get("children") or []
ident = []
for ln in open(ident_p).read().splitlines():
    if not ln.strip():
        continue
    cols = ln.split("\t")
    key, slug, fmts = cols[0], cols[1], collections.OrderedDict()
    for col in cols[2:]:
        fmt, _eq, name = col.partition("=")
        fmts[fmt] = name
    ident.append((key, slug, fmts))
if len(ident) != len(children_in):
    refuse("identity table has %d row(s) for %d child record(s)" % (len(ident), len(children_in)))

# NO TWO CHILDREN MAY COLLIDE ONTO ONE SBOM. Asserted over the table itself, so
# a future identity change that stopped being injective is caught here rather
# than by one child silently reading another's bill of materials.
_slugs = [row[1] for row in ident]
if len(set(_slugs)) != len(_slugs):
    refuse("two children derive the same child_slug — an identity that can be "
           "produced two ways is not one")
for _f in (ident[0][2] if ident else {}):
    _names = [row[2][_f] for row in ident]
    if len(set(_names)) != len(_names):
        refuse("two children derive the same %s SBOM filename" % _f)

# --- one revision, one database ---------------------------------------------
db = ev.get("frozen_vulnerability_database") or {}
if not db.get("frozen"):
    refuse("%s: the vulnerability database is not recorded as frozen. Findings "
           "compared across a moving database are not comparable" % evidence_p)
scanner = ev.get("scanner") or {}
if "@sha256:" not in (scanner.get("image") or ""):
    refuse("%s: scanner image %r is not digest-pinned" % (evidence_p, scanner.get("image")))

# --- children ----------------------------------------------------------------
sbom_index = []
bound_names = set()
children = []
for c, (key, slug, ident_fmts) in zip(children_in, ident):
    if c.get("child_key") != key:
        refuse("child identity mismatch: the record says %r, child_key() derives "
               "%r. There is exactly ONE identity derivation in this repository"
               % (c.get("child_key"), key))
    fam, _, ver = (c.get("image_label") or "").partition("/")
    dig = c.get("manifest_digest") or ""
    if not re.match(r"^sha256:[0-9a-f]{64}$", dig):
        refuse("child %s: manifest_digest %r is not an immutable sha256 digest" % (key, dig))
    for g in ("smoke_test", "metadata_contract", "scan", "reconciliation"):
        if c.get(g) != "PASS":
            refuse("child %s: gate %s is %r — a bundle records an accepted run, and "
                   "an accepted run has no failing gate" % (key, g, c.get(g)))
    esha = c.get("evidence_sha256") or ""
    if not re.match(r"^[0-9a-f]{64}$", esha):
        refuse("child %s: evidence_sha256 %r is missing or malformed" % (key, esha))

    child_sbom = None
    if sbom_dir:
        # The filename is NEVER guessed here. It comes from the identity table,
        # which sbom_filename() built — the same function the producer calls to
        # write the file. A wrong filename is therefore a MISSING SBOM, not a
        # near-miss the loop can recover from with a looser pattern.
        req_name = ident_fmts[REQUIRED_FMT]
        src = os.path.join(sbom_dir, req_name)
        if not os.path.exists(src):
            refuse("child %s: no %s SBOM at %s. A release whose bill of materials "
                   "for a shipped child is absent is not a release with a bill of "
                   "materials; this used to be recorded as sbom.present=false and "
                   "exit 0. Producer and consumer derive this name from ONE "
                   "function, scripts/lib/common.sh sbom_filename() — regenerate "
                   "with scripts/generate-sbom.sh, which writes exactly this name"
                   % (key, REQUIRED_FMT, os.path.join(sbom_dir, req_name)))
        bound_names.add(req_name)
        check_sbom_subject(src, key, dig, c.get("platform") or "", source_revision)
        dest_rel = "content/sbom/%s" % req_name
        shutil.copyfile(src, os.path.join(out, dest_rel))
        child_sbom = collections.OrderedDict([
            ("format", REQUIRED_FMT),
            ("sha256", sha256_file(src)),
            ("file", dest_rel),
            ("subject_digest", dig),
        ])
        companions = []
        for fmt, name in ident_fmts.items():
            if fmt == REQUIRED_FMT:
                continue
            cp = os.path.join(sbom_dir, name)
            if not os.path.exists(cp):
                continue
            bound_names.add(name)
            check_sbom_subject(cp, key, dig, c.get("platform") or "", source_revision)
            crel = "content/sbom/%s" % name
            shutil.copyfile(cp, os.path.join(out, crel))
            companions.append(collections.OrderedDict([
                ("format", fmt), ("sha256", sha256_file(cp)), ("file", crel)]))
        if companions:
            child_sbom["companions"] = companions
        sbom_index.append(collections.OrderedDict([
            ("child_key", key), ("child_slug", slug),
            ("platform", c.get("platform")), ("manifest_digest", dig),
            ("format", REQUIRED_FMT), ("file", dest_rel),
            ("sha256", child_sbom["sha256"]),
            ("companions", companions)]))

    rec = collections.OrderedDict([
        ("child_key", key), ("child_slug", slug),
        ("image_family", fam), ("image_version", ver), ("image_label", c.get("image_label")),
        ("platform", c.get("platform")), ("manifest_digest", dig),
        ("digest_reference", c.get("digest_reference")),
        ("config_architecture", c.get("config_architecture")),
        ("staging_tag", c.get("staging_tag")),
        ("execution_mode", c.get("execution_mode")),
        ("host_architecture", c.get("host_architecture")),
        ("runner_name", c.get("runner_name")),
        ("source_revision", source_revision),
        ("evidence_sha256", esha),
        ("package_inventory", c.get("package_inventory")),
        ("severity_counts", c.get("severity_counts") or {}),
        ("gates", collections.OrderedDict([
            ("smoke_test", c["smoke_test"]), ("metadata_contract", c["metadata_contract"]),
            ("scan", c["scan"]), ("reconciliation", c["reconciliation"])])),
        ("sbom", child_sbom),
        ("evidence_file", "content/children/%s.json" % slug),
    ])
    children.append(rec)
    # The full per-child extract, kept whole: the manifest is an index, and an
    # index that drops fields is where "we still have the evidence" stops being
    # true.
    write_json(os.path.join(out, "content/children/%s.json" % slug),
               collections.OrderedDict([("schema_version", 1),
                                        ("child_key", key), ("child_slug", slug),
                                        ("source_revision", source_revision),
                                        ("scanner", scanner),
                                        ("vulnerability_database", db),
                                        ("record", c)]))

if sbom_dir:
    # NOTHING UNBOUND. A file sitting in the SBOM directory that no child claims
    # is either an SBOM for a child this bundle does not carry, or a document
    # nobody derived an identity for. Copying it in would put an unattributable
    # bill of materials inside checksum coverage, where it reads as evidence.
    on_disk = sorted(n for n in os.listdir(sbom_dir)
                     if os.path.isfile(os.path.join(sbom_dir, n)))
    orphans = [n for n in on_disk if n not in bound_names]
    if orphans:
        refuse("%d file(s) in %s are bound to no child in this bundle: %s. Every "
               "SBOM name comes from sbom_filename() in scripts/lib/common.sh; a "
               "name outside that set is not an identity this repository issues"
               % (len(orphans), sbom_dir, ", ".join(orphans[:5])))
    # EXACTLY ONE SBOM OF RECORD PER CHILD, and no child without one.
    if len(sbom_index) != len(children):
        refuse("%d of %d children carry an SBOM. --sbom-dir was supplied, so the "
               "bundle claims a complete bill of materials; an incomplete one is "
               "refused rather than recorded as sbom.present=false"
               % (len(sbom_index), len(children)))
    idx_keys = [e["child_key"] for e in sbom_index]
    if len(set(idx_keys)) != len(idx_keys):
        refuse("two SBOM index entries claim the same child_key")
    write_json(os.path.join(out, "content/sbom/INDEX.json"),
               {"schema_version": 1,
                "identity_function": "scripts/lib/common.sh sbom_filename()",
                "required_format": REQUIRED_FMT,
                "children": sbom_index})

# --- findings roll-up --------------------------------------------------------
sev = collections.Counter()
advisories, tuples = set(), set()
for c in children_in:
    for k, v in (c.get("severity_counts") or {}).items():
        sev[k] += int(v)
    for cve, pkgs in (c.get("governed_findings") or {}).items():
        advisories.add(cve)
        for spec in pkgs:
            tuples.add((c["manifest_digest"], cve, spec))

# --- policy digests ----------------------------------------------------------
digests = collections.OrderedDict()
for rp in policy_files:
    ap = os.path.join(root, rp)
    if os.path.exists(ap):
        digests[rp] = sha256_file(ap)
if not digests:
    refuse("no policy file was found to digest — a bundle whose decision inputs "
           "are unrecorded reconstructs nothing")
write_json(os.path.join(out, "content/policy/policy-digests.json"),
           {"schema_version": 1, "algorithm": "sha256", "files": digests})

# --- retention ---------------------------------------------------------------
ret = yaml.safe_load(open(retention_p)) or {}
rc = None
for entry in ret.get("classes") or []:
    if entry.get("evidence_class") == cls:
        rc = entry
if rc is None:
    refuse("policies/retention.yaml declares no retention for evidence class %r "
           "— evidence with no stated retention is evidence nobody promised to "
           "keep" % cls)
authrec = ev.get("authorization_record") or {}
gen_at = authrec.get("generated_at") or ""
if not re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", gen_at):
    refuse("%s: authorization_record.generated_at %r is not RFC3339 UTC. The "
           "bundle's timestamps come from the RUN, never from the generator's "
           "clock — otherwise the same inputs produce different bytes"
           % (evidence_p, gen_at))
start = datetime.date.fromisoformat(gen_at[:10])
retain_until = (start + datetime.timedelta(days=int(rc["retention_days"]))).isoformat()
retention = collections.OrderedDict([
    ("policy_file", os.path.relpath(retention_p, root)),
    ("policy_sha256", sha256_file(retention_p)),
    ("evidence_class", cls),
    ("retention_days", int(rc["retention_days"])),
    ("retain_until", retain_until),
    ("immutable_storage_required", bool(rc.get("immutable_storage_required"))),
    ("minimum_independent_locations",
     int((ret.get("storage") or {}).get("minimum_independent_locations") or 1)),
])
write_json(os.path.join(out, "content/retention/retention.json"),
           {"schema_version": 1, "retention": retention,
            "rationale": rc.get("rationale"),
            "deletion": ret.get("deletion"), "verification": ret.get("verification")})

# --- provenance / authorization ---------------------------------------------
provenance = collections.OrderedDict([
    ("repository", "zenchron-dynamics/zenchron-foundry"),
    ("source_revision", source_revision),
    ("workflow_ref", acc.get("workflow_ref")),
    ("workflow_run_id", int(acc.get("workflow_run_id"))),
    ("workflow_run_attempt", int(acc.get("workflow_run_attempt") or 1)),
    ("staging_package", None),
    ("attestation_file", "content/provenance/attestation.json" if prov else None),
    ("attestation_sha256", sha256_file(prov) if prov else None),
])
write_json(os.path.join(out, "content/provenance/provenance.json"),
           {"schema_version": 1, "provenance": provenance,
            "run_url": acc.get("run_url"),
            "scope_note": ev.get("scope_note")})

# --- authorization ------------------------------------------------------------
# WHAT WAS WRONG. The bundle wrote content/authorization/authorization-record.json
# — a name that reads as the canonical post-build authorization — containing a
# four-field summary that failed post-build-authorization-v1 on all fifteen of
# its required properties and carried no source_revision at all. A bundle
# therefore could not be checked against the revision it was authorised for, so
# a wrong-SHA authorization was undetectable by construction. No release script
# called validate-authorization-record.sh; the schema was enforced in the
# workflow that PRODUCED the record and by nothing that consumed it.
#
# WHAT IT IS NOW. The canonical record — the artifact
# scripts/release/authorize-staged-candidates.sh writes and
# stage-and-authorize.yml schema-validates — is an INPUT, carried verbatim into
# checksum coverage at content/authorization/post-build-authorization.json, and
# bound field by field to the acceptance record beneath it.
#
# The four-field object is still useful as a manifest-level index, but it is no
# longer named as though it were the authorization. It is
# `evidence-bundle-authorization-summary` v1, it declares its own record_type,
# it names the canonical record it is a projection OF, and it exists only when
# that record is present.
def _plat_of(c):
    return c.get("platform") or ""


auth_binding = None
canonical_rel = None
canonical_sha = None
if auth_p:
    try:
        auth = json.load(open(auth_p))
    except (ValueError, OSError) as exc:
        refuse("%s is not readable JSON (%s)" % (auth_p, exc))

    def mismatch(what, got, want):
        refuse("the authorization record does not authorise this run: %s is %r, "
               "the accepted evidence says %r. An authorization that describes a "
               "different build is not this build's authorization, and until now "
               "nothing on this path could tell the two apart"
               % (what, got, want))

    # (1) THE REVISION. This is the binding whose absence made a wrong-SHA
    # authorization undetectable.
    if auth.get("source_revision") != source_revision:
        mismatch("source_revision", auth.get("source_revision"), source_revision)
    # (2) the run
    if str(auth.get("workflow_run_id")) != str(acc.get("workflow_run_id")):
        mismatch("workflow_run_id", auth.get("workflow_run_id"), acc.get("workflow_run_id"))
    if int(auth.get("workflow_run_attempt") or 1) != int(acc.get("workflow_run_attempt") or 1):
        mismatch("workflow_run_attempt", auth.get("workflow_run_attempt"),
                 acc.get("workflow_run_attempt"))
    # (3) the verdict. A refused authorization does not produce a bundle.
    if auth.get("verdict") != "PASS":
        refuse("the authorization record's verdict is %r. A bundle records an "
               "AUTHORISED run; a refusal is evidence of a refusal, not of a "
               "release candidate" % auth.get("verdict"))
    # (4) the frozen database — findings compared across two snapshots are not
    # comparable, so the authorization must have judged the same one.
    adb = (auth.get("trivy_db_snapshot") or {})
    if adb.get("identity") != db.get("identity"):
        mismatch("trivy_db_snapshot.identity", adb.get("identity"), db.get("identity"))
    if not adb.get("frozen"):
        refuse("the authorization record does not record the vulnerability "
               "database as frozen")
    # (5) the platform set
    a_plats = sorted((auth.get("expected_matrix") or {}).get("platforms") or [])
    e_plats = sorted({_plat_of(c) for c in children_in})
    if a_plats != e_plats:
        mismatch("expected_matrix.platforms", a_plats, e_plats)
    if int((auth.get("expected_matrix") or {}).get("expected_children") or 0) != len(children_in):
        mismatch("expected_matrix.expected_children",
                 (auth.get("expected_matrix") or {}).get("expected_children"),
                 len(children_in))
    # (6) THE CHILD SET, exactly. Not a count: the identities, the digests, the
    # platforms and the per-child evidence checksums, with no child authorised
    # that the run did not produce and none produced that was not authorised.
    a_children = auth.get("children") or []
    a_by_key = {}
    for c in a_children:
        k = c.get("child_key")
        if k in a_by_key:
            refuse("the authorization record authorises %r twice" % k)
        a_by_key[k] = c
    e_by_key = {c["child_key"]: c for c in children_in}
    missing = sorted(set(e_by_key) - set(a_by_key))
    extra = sorted(set(a_by_key) - set(e_by_key))
    if missing:
        refuse("the authorization record does not authorise %d child(ren) this "
               "run produced: %s" % (len(missing), ", ".join(missing[:5])))
    if extra:
        refuse("the authorization record authorises %d child(ren) this run never "
               "produced: %s. An authorization for an image outside the accepted "
               "run — an experimental line, say — cannot enter a bundle through "
               "the authorization it was never granted"
               % (len(extra), ", ".join(extra[:5])))
    for k, e in sorted(e_by_key.items()):
        a = a_by_key[k]
        if a.get("manifest_digest") != e.get("manifest_digest"):
            mismatch("children[%s].manifest_digest" % k,
                     a.get("manifest_digest"), e.get("manifest_digest"))
        if a.get("platform") != e.get("platform"):
            mismatch("children[%s].platform" % k, a.get("platform"), e.get("platform"))
        if a.get("source_revision") != source_revision:
            mismatch("children[%s].source_revision" % k,
                     a.get("source_revision"), source_revision)
        if a.get("evidence_sha256") != e.get("evidence_sha256"):
            mismatch("children[%s].evidence_sha256" % k,
                     a.get("evidence_sha256"), e.get("evidence_sha256"))
        if a.get("trivy_db_identity") != db.get("identity"):
            mismatch("children[%s].trivy_db_identity" % k,
                     a.get("trivy_db_identity"), db.get("identity"))
    # (7) the staging package every digest reference actually names
    sp = auth.get("staging_package") or ""
    bad_ref = [c["child_key"] for c in children_in
               if not (c.get("digest_reference") or "").startswith(sp + "@")]
    if bad_ref:
        refuse("the authorization record authorises staging package %r, but %d "
               "child reference(s) name another package: %s"
               % (sp, len(bad_ref), ", ".join(sorted(bad_ref)[:3])))
    # (8) the summary the acceptance record embeds must agree with the record it
    # summarises, or one of the two has been edited.
    if authrec.get("authorization_scope") and \
            auth.get("authorization_scope") != authrec.get("authorization_scope"):
        mismatch("authorization_scope", auth.get("authorization_scope"),
                 authrec.get("authorization_scope"))
    if bool(auth.get("public_exposure_authorized")) != bool(authrec.get("public_exposure_authorized")):
        mismatch("public_exposure_authorized", auth.get("public_exposure_authorized"),
                 authrec.get("public_exposure_authorized"))
    if auth.get("generated_at") != gen_at:
        mismatch("generated_at", auth.get("generated_at"), gen_at)

    canonical_rel = "content/authorization/post-build-authorization.json"
    shutil.copyfile(auth_p, os.path.join(out, canonical_rel))
    canonical_sha = sha256_file(auth_p)
    auth_binding = collections.OrderedDict([
        ("schema", "schemas/post-build-authorization-v1.schema.json"),
        ("validator", "scripts/release/validate-authorization-record.sh"),
        ("source_revision", auth["source_revision"]),
        ("repository", auth.get("repository")),
        ("workflow_ref", auth.get("workflow_ref")),
        ("workflow_run_id", int(auth["workflow_run_id"])),
        ("workflow_run_attempt", int(auth["workflow_run_attempt"])),
        ("authorized_children", len(a_children)),
        ("platforms", a_plats),
        ("trivy_db_identity", adb.get("identity")),
        ("staging_package", sp),
        ("verdict", auth["verdict"]),
    ])

authorization = collections.OrderedDict([
    ("record_present", bool(auth_p)),
    ("scope", authrec.get("authorization_scope") or ""),
    ("public_exposure_authorized", bool(authrec.get("public_exposure_authorized"))),
    ("verdict", acc.get("verdict")),
    ("generated_at", gen_at),
    ("build_created", authrec.get("build_created")),
    ("record_file", canonical_rel),
    ("record_sha256", canonical_sha),
    ("record_binding", auth_binding),
    ("absence_reason", auth_absent or None),
    ("summary_file", ("content/authorization/authorization-summary.json"
                      if auth_p else None)),
])
if not authorization["scope"]:
    refuse("%s: authorization_record.authorization_scope is empty — an "
           "authorization that does not state its scope authorises whatever the "
           "reader assumes" % evidence_p)
if auth_p:
    # A PROJECTION of the canonical record, and named as one. It is not a
    # post-build authorization, it does not claim to be, and it cannot exist
    # without the record it projects.
    write_json(os.path.join(out, "content/authorization/authorization-summary.json"),
               collections.OrderedDict([
                   ("schema_version", 1),
                   ("record_type", "evidence-bundle-authorization-summary"),
                   ("note", "A manifest-level index of the canonical post-build "
                            "authorization record, which travels beside it at "
                            "content/authorization/post-build-authorization.json. "
                            "This object is NOT an authorization and satisfies no "
                            "authorization schema; it exists so a reader can see "
                            "the decision's shape without parsing the full record."),
                   ("canonical_record_file", canonical_rel),
                   ("canonical_record_sha256", canonical_sha),
                   ("canonical_record_schema",
                    "schemas/post-build-authorization-v1.schema.json"),
                   ("authorization", authorization),
                   ("acceptance_summary", authrec),
                   ("issue_linkage", ev.get("issue_linkage")),
               ]))
else:
    # THE EXPLICIT REFUSAL, written into the bundle rather than left as silence.
    write_json(os.path.join(out, "content/authorization/AUTHORIZATION-ABSENT.json"),
               collections.OrderedDict([
                   ("schema_version", 1),
                   ("record_type", "evidence-bundle-authorization-absent"),
                   ("authorization_record_present", False),
                   ("reason", auth_absent),
                   ("consequence",
                    "This bundle names no post-build authorization. It cannot be "
                    "sealed as a release (scripts/release/release-seal.sh R13) "
                    "and must not be read as evidence that the run was "
                    "authorised — only as evidence of what the run produced."),
                   ("canonical_record_schema",
                    "schemas/post-build-authorization-v1.schema.json"),
                   ("acceptance_summary", authrec),
                   ("issue_linkage", ev.get("issue_linkage")),
               ]))

# --- dispositions ------------------------------------------------------------
vex_p = os.path.join(out, "content/vex/openvex.json")
vex = json.load(open(vex_p))
status_counts = collections.Counter(s["status"] for s in vex["statements"])
expiries = sorted(s["foundry"]["expires_at"] for s in vex["statements"]
                  if s["foundry"].get("expires_at"))
dispositions = collections.OrderedDict([
    ("file", "content/vex/openvex.json"),
    ("sha256", sha256_file(vex_p)),
    ("format", "openvex-0.2.0"),
    ("statement_count", len(vex["statements"])),
    ("exception_policy_sha256", vex["foundry"]["exception_policy_sha256"]),
    ("status_counts", dict(sorted(status_counts.items()))),
    ("earliest_exception_expiry", expiries[0] if expiries else None),
])

# --- execution disclosure ----------------------------------------------------
disc = ev.get("execution_disclosure") or {}
modes = collections.Counter(c.get("execution_mode") for c in children_in)
native_pl = sorted({c["platform"] for c in children_in if c.get("execution_mode") == "native"})
emul_pl = sorted({c["platform"] for c in children_in if c.get("execution_mode") == "qemu"})
if not disc.get("statement"):
    refuse("%s: execution_disclosure.statement is missing. Whether a child ran on "
           "its own architecture or under emulation is the difference between "
           "runtime evidence and a build artifact, and it is never inferred"
           % evidence_p)
execution = collections.OrderedDict([
    ("native_children", modes.get("native", 0)),
    ("qemu_children", modes.get("qemu", 0)),
    ("statement", disc["statement"]),
    ("native_platforms", native_pl),
    ("emulated_platforms", emul_pl),
])

mx = ev.get("matrix") or {}
platforms = sorted({c["platform"] for c in children_in})

manifest = collections.OrderedDict([
    ("schema_version", 1),
    ("bundle_type", "release-evidence-bundle"),
    ("bundle_id", "%s-%s-%s" % (cls, source_revision[:12], acc.get("workflow_run_id"))),
    ("evidence_class", cls),
    ("source_revision", source_revision),
    ("release", {"version": rel, "candidate": cand} if (rel and cand) else None),
    ("generated_at", gen_at),
    ("generator", {"script": "scripts/release/generate-evidence-bundle.sh",
                   "schema": os.path.relpath(schema_p, root)}),
    ("acceptance", collections.OrderedDict([
        ("verdict", acc.get("verdict")),
        ("workflow", acc.get("workflow")),
        ("workflow_run_id", int(acc.get("workflow_run_id"))),
        ("workflow_run_attempt", int(acc.get("workflow_run_attempt") or 1)),
        ("workflow_ref", acc.get("workflow_ref")),
        ("run_url", acc.get("run_url")),
        ("source_record_sha256", sha256_file(evidence_p)),
    ])),
    ("scanner", {"image": scanner["image"], "flags": list(scanner.get("flags") or []),
                 "digest_pinned": True}),
    ("vulnerability_database", {"identity": db["identity"], "frozen": True}),
    ("matrix", collections.OrderedDict([
        ("image_definitions", int(mx.get("image_definitions") or 0)),
        ("platforms", platforms),
        ("expected_children", int(mx.get("expected_children") or len(children_in))),
        ("observed_children", len(children_in)),
        ("platform_split", dict(collections.Counter(c["platform"] for c in children_in))),
    ])),
    ("children", children),
    ("execution_disclosure", execution),
    ("sbom", collections.OrderedDict([
        ("present", bool(sbom_index)),
        # `complete` is the fact a release decision needs and `present` never
        # was: present=true said only that SOME child had a document.
        ("complete", bool(sbom_index) and len(sbom_index) == len(children)),
        ("format", REQUIRED_FMT if sbom_index else None),
        ("identity_function", "scripts/lib/common.sh sbom_filename()"),
        ("children_with_sbom", len(sbom_index)),
        ("children_total", len(children)),
        ("index_file", "content/sbom/INDEX.json" if sbom_dir else None),
    ])),
    ("findings", collections.OrderedDict([
        ("severity_totals", dict(sorted(sev.items()))),
        ("distinct_advisories", len(advisories)),
        ("observed_tuples", len(tuples)),
    ])),
    ("reconciliation", collections.OrderedDict([
        ("children_reconciled", sum(1 for c in children_in if c.get("reconciliation") == "PASS")),
        ("children_total", len(children_in)),
        ("ungoverned_findings", 0),
        ("policy_file", os.path.relpath(ledger_p, root)),
        ("policy_sha256", sha256_file(ledger_p)),
    ])),
    ("dispositions", dispositions),
    ("policy_digests", digests),
    ("provenance", provenance),
    ("authorization", authorization),
    ("retention", retention),
    ("checksums", collections.OrderedDict([
        ("algorithm", "sha256"),
        ("content_checksum", "0" * 64),      # filled by the caller, after content/
        ("content_checksum_tool", "scripts/release/evidence-checksum.sh"),
        ("sums_file", "SHA256SUMS"),
        ("aggregate_file", "BUNDLE.sha256"),
    ])),
    ("files", []),                           # filled by the caller, after content/
])
write_json(os.path.join(out, "manifest.json"), manifest)
print("content written: %d child record(s), %d disposition statement(s)"
      % (len(children), dispositions["statement_count"]))
PY

  # --- 2. the aggregate, over content that is now COMPLETE -------------------
  local content_sum
  content_sum="$(evidence_checksum "$out/content")" || return 1

  # --- 3. seal the manifest with the aggregate and the file index -----------
  GEB_SCHEMA="$GEB_SCHEMA" python3 - "$out" "$content_sum" <<'PY' || return 1
import json, os, sys, hashlib, collections
out, content_sum = sys.argv[1], sys.argv[2]


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


files = []
for dirpath, _dirs, names in os.walk(os.path.join(out, "content")):
    for n in names:
        ap = os.path.join(dirpath, n)
        files.append({"path": os.path.relpath(ap, out), "sha256": sha256_file(ap)})
files.sort(key=lambda f: f["path"])

mp = os.path.join(out, "manifest.json")
m = json.load(open(mp), object_pairs_hook=collections.OrderedDict)
m["checksums"]["content_checksum"] = content_sum
m["files"] = files
with open(mp, "w") as fh:
    json.dump(m, fh, indent=2, sort_keys=False)
    fh.write("\n")

# SHA256SUMS covers manifest.json TOO: the index is worthless if the record it
# indexes can be edited without detection.
lines = ["%s  %s" % (sha256_file(mp), "manifest.json")]
lines += ["%s  %s" % (f["sha256"], f["path"]) for f in files]
sums = os.path.join(out, "SHA256SUMS")
with open(sums, "w") as fh:
    fh.write("\n".join(lines) + "\n")
with open(os.path.join(out, "BUNDLE.sha256"), "w") as fh:
    fh.write("%s  SHA256SUMS\n" % sha256_file(sums))
print("bundle sealed: %d file(s) covered, content_checksum=%s" % (len(files) + 1, content_sum))
PY
  log "bundle written: $out"
}

# =============================================================================
# verify — offline. No registry, no GitHub, no network, no surviving run.
# =============================================================================
geb_verify() { # <dir>
  local dir="${1:?usage: verify <bundle-dir>}"
  [ -d "$dir" ] || die "not a bundle directory: $dir"
  [ -f "$dir/manifest.json" ] || die "$dir: no manifest.json"
  [ -f "$dir/SHA256SUMS" ] || die "$dir: no SHA256SUMS — an unindexed bundle proves nothing"
  [ -f "$dir/BUNDLE.sha256" ] || die "$dir: no BUNDLE.sha256"
  [ -d "$dir/content" ] || die "$dir: no content/ directory"
  _geb_need_py

  local content_sum
  content_sum="$(evidence_checksum "$dir/content")" || return 1

  # The expected SBOM names are re-derived HERE, by the same sbom_filename()
  # the producer used, from the manifest's own (family, selector, platform).
  # Verify therefore checks the recorded path against a freshly derived
  # identity instead of trusting the string the generator wrote.
  # NOT a RETURN trap: under `set -T` (bash -T) a RETURN trap fires on EVERY
  # inner function's return and would delete this table before python reads it.
  # The scratch directory is removed explicitly on both paths instead.
  local vtmp rc; vtmp="$(mktemp -d)"
  if ! _geb_identity_table "$dir/manifest.json" > "$vtmp/ident.tsv"; then
    rm -rf "$vtmp"; return 1
  fi

  GEB_SCHEMA="$GEB_SCHEMA" GEB_SBOM_REQUIRED_FORMAT="$GEB_SBOM_REQUIRED_FORMAT" \
  python3 - "$dir" "$content_sum" "$vtmp/ident.tsv" <<'PY'

import json, os, sys, hashlib, collections
dir_, content_sum, ident_p = sys.argv[1], sys.argv[2], sys.argv[3]
schema_p = os.environ["GEB_SCHEMA"]
REQUIRED_FMT = os.environ["GEB_SBOM_REQUIRED_FORMAT"]


def refuse(msg):
    print("REFUSE: " + msg, file=sys.stderr)
    sys.exit(1)


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# --- 1. the index itself ------------------------------------------------------
sums_p = os.path.join(dir_, "SHA256SUMS")
agg = open(os.path.join(dir_, "BUNDLE.sha256")).read().split()[0]
if agg != sha256_file(sums_p):
    refuse("BUNDLE.sha256 does not match SHA256SUMS. The checksum index was "
           "changed after the bundle was sealed, so every per-file digest below "
           "it is a digest somebody else chose")

indexed = collections.OrderedDict()
for ln in open(sums_p).read().splitlines():
    if not ln.strip():
        continue
    dig, _sp, path = ln.partition("  ")
    indexed[path] = dig

# --- 2. NOTHING OUTSIDE COVERAGE ---------------------------------------------
on_disk = set()
for dirpath, _d, names in os.walk(dir_):
    for n in names:
        rel = os.path.relpath(os.path.join(dirpath, n), dir_)
        if rel in ("SHA256SUMS", "BUNDLE.sha256"):
            continue
        on_disk.add(rel)
extra = sorted(on_disk - set(indexed))
if extra:
    refuse("%d file(s) are present in the bundle but covered by no checksum: %s. "
           "A file outside coverage is a file anybody can add after the fact, "
           "which is the whole failure this bundle exists to prevent"
           % (len(extra), ", ".join(extra[:5])))
missing = sorted(set(indexed) - on_disk)
if missing:
    refuse("%d indexed file(s) are missing from the bundle: %s"
           % (len(missing), ", ".join(missing[:5])))

# --- 3. every digest ----------------------------------------------------------
bad = [p for p, d in indexed.items() if sha256_file(os.path.join(dir_, p)) != d]
if bad:
    refuse("%d file(s) do not match their recorded checksum: %s"
           % (len(bad), ", ".join(sorted(bad)[:5])))

# --- 4. the manifest --------------------------------------------------------
m = json.load(open(os.path.join(dir_, "manifest.json")))
try:
    from jsonschema import Draft202012Validator
    errs = sorted(Draft202012Validator(json.load(open(schema_p))).iter_errors(m),
                  key=lambda e: list(e.path))
    if errs:
        e = errs[0]
        loc = "/".join(str(x) for x in e.path) or "<root>"
        refuse("manifest.json violates release-evidence-bundle-v1 at %s: %s" % (loc, e.message))
except ImportError:
    pass

if m["checksums"]["content_checksum"] != content_sum:
    refuse("manifest content_checksum is %s, recomputing content/ with "
           "evidence-checksum.sh gives %s"
           % (m["checksums"]["content_checksum"], content_sum))

declared = {f["path"]: f["sha256"] for f in m["files"]}
content_on_disk = set(p for p in on_disk if p.startswith("content/"))
if set(declared) != content_on_disk:
    only_disk = sorted(content_on_disk - set(declared))
    only_man = sorted(set(declared) - content_on_disk)
    refuse("manifest file index disagrees with content/: %d only on disk (%s), "
           "%d only in the manifest (%s)"
           % (len(only_disk), ", ".join(only_disk[:3]),
              len(only_man), ", ".join(only_man[:3])))

# --- 5. the internal consistency the checksums cannot see --------------------
revs = set(c["source_revision"] for c in m["children"])
if len(revs) != 1 or m["source_revision"] not in revs:
    refuse("the bundle mixes source revisions: manifest says %s, children carry %s"
           % (m["source_revision"], ", ".join(sorted(revs))))
if m["matrix"]["observed_children"] != len(m["children"]):
    refuse("matrix.observed_children=%d but the manifest carries %d child record(s)"
           % (m["matrix"]["observed_children"], len(m["children"])))
digs = [c["manifest_digest"] for c in m["children"]]
if len(set(digs)) != len(digs):
    refuse("two children claim the same manifest digest")
keys = [c["child_key"] for c in m["children"]]
if len(set(keys)) != len(keys):
    refuse("two children claim the same child_key — one child cannot have two "
           "spellings, and two children cannot share one")

# The dispositions travel with the bundle and must still be the ones it recorded.
vp = os.path.join(dir_, m["dispositions"]["file"])
if sha256_file(vp) != m["dispositions"]["sha256"]:
    refuse("the disposition document does not match the digest the manifest records")
# ...and they must be the dispositions for THIS revision and THIS class. The
# digest check above proves only that the file has not changed since sealing;
# it says nothing about whether the document is about this bundle at all.
vdoc = json.load(open(vp))
vfd = vdoc.get("foundry") or {}
if vfd.get("source_revision") != m["source_revision"]:
    refuse("the disposition document binds source_revision %r; this bundle is "
           "for %r. Dispositions are only meaningful for the revision they were "
           "derived from" % (vfd.get("source_revision"), m["source_revision"]))
if vfd.get("evidence_class") != m["evidence_class"]:
    refuse("the disposition document was published for evidence class %r; this "
           "bundle is %r. 'What may ship' and 'what shipped' are different "
           "published statements and one does not stand in for the other"
           % (vfd.get("evidence_class"), m["evidence_class"]))
if vfd.get("exception_policy_sha256") != m["dispositions"]["exception_policy_sha256"]:
    refuse("the disposition document names exception policy %s, the manifest "
           "records %s" % (vfd.get("exception_policy_sha256"),
                           m["dispositions"]["exception_policy_sha256"]))

# --- 6. the authorization, re-bound from the bytes on disk --------------------
# Re-checked here so it holds for a bundle that came back off an archive as
# much as for one straight out of the generator. Both directions are refused:
# a record_present=true bundle whose record is missing or names another
# revision, and a record_present=false bundle that quietly carries one anyway.
au = m["authorization"]
if au["record_present"]:
    if not au.get("record_file"):
        refuse("the bundle reports an authorization record and names no file for it")
    ap_ = os.path.join(dir_, au["record_file"])
    if not os.path.exists(ap_):
        refuse("the authorization record %s is missing from the bundle" % au["record_file"])
    if au["record_file"] not in indexed:
        refuse("the authorization record %s is covered by no checksum" % au["record_file"])
    got = sha256_file(ap_)
    if got != au.get("record_sha256"):
        refuse("the authorization record hashes to %s, the manifest records %s"
               % (got, au.get("record_sha256")))
    arec = json.load(open(ap_))
    if arec.get("source_revision") != m["source_revision"]:
        refuse("the authorization record authorises revision %r; this bundle is "
               "for %r. An authorization for another source SHA does not become "
               "this bundle's by travelling inside it"
               % (arec.get("source_revision"), m["source_revision"]))
    if arec.get("verdict") != "PASS":
        refuse("the authorization record carried by this bundle has verdict %r"
               % arec.get("verdict"))
    b = au.get("record_binding") or {}
    if b.get("source_revision") != m["source_revision"]:
        refuse("authorization.record_binding.source_revision is %r, the bundle is "
               "for %r" % (b.get("source_revision"), m["source_revision"]))
    a_keys = {c.get("child_key") for c in arec.get("children") or []}
    b_keys = {c["child_key"] for c in m["children"]}
    if a_keys != b_keys:
        refuse("the authorization covers %d child(ren) and the bundle carries "
               "%d; the sets differ by %s"
               % (len(a_keys), len(b_keys),
                  ", ".join(sorted(a_keys ^ b_keys)[:5])))
    for c in m["children"]:
        ac = next(x for x in arec["children"] if x.get("child_key") == c["child_key"])
        if ac.get("manifest_digest") != c["manifest_digest"]:
            refuse("child %s: the authorization names digest %s, the bundle "
                   "carries %s" % (c["child_key"], ac.get("manifest_digest"),
                                   c["manifest_digest"]))
        if ac.get("evidence_sha256") != c["evidence_sha256"]:
            refuse("child %s: the authorization names evidence checksum %s, the "
                   "bundle carries %s" % (c["child_key"], ac.get("evidence_sha256"),
                                          c["evidence_sha256"]))
else:
    if not (au.get("absence_reason") or "").strip():
        refuse("the bundle reports no authorization record and states no reason. "
               "An unexplained absence is indistinguishable from a lost one")
    stray = [p for p in on_disk if p.startswith("content/authorization/")
             and os.path.basename(p) != "AUTHORIZATION-ABSENT.json"]
    if stray:
        refuse("the bundle reports no authorization record but carries %s"
               % ", ".join(sorted(stray)[:3]))

# --- 7. the bill of materials, re-bound to the children it claims to describe -
# Re-run over the bytes on disk, so this holds for a bundle that came back off
# an archive as much as for one straight out of the generator.
ident = []
for ln in open(ident_p).read().splitlines():
    if not ln.strip():
        continue
    cols = ln.split("\t")
    fmts = collections.OrderedDict()
    for col in cols[2:]:
        f, _eq, n = col.partition("=")
        fmts[f] = n
    ident.append((cols[0], cols[1], fmts))
if len(ident) != len(m["children"]):
    refuse("identity re-derivation produced %d row(s) for %d child record(s)"
           % (len(ident), len(m["children"])))

sb = m["sbom"]
with_sbom = [c for c in m["children"] if c.get("sbom")]
if sb["children_total"] != len(m["children"]):
    refuse("sbom.children_total=%d but the manifest carries %d child record(s)"
           % (sb["children_total"], len(m["children"])))
if sb["children_with_sbom"] != len(with_sbom):
    refuse("sbom.children_with_sbom=%d but %d child record(s) carry one"
           % (sb["children_with_sbom"], len(with_sbom)))
if bool(sb["present"]) != bool(with_sbom):
    refuse("sbom.present=%r while %d child record(s) carry an SBOM. A bundle "
           "that reports no bill of materials while carrying one — or the "
           "reverse — is the exact silent-false state this field exists to "
           "make impossible" % (sb["present"], len(with_sbom)))
if sb.get("complete") != (bool(with_sbom) and len(with_sbom) == len(m["children"])):
    refuse("sbom.complete=%r disagrees with %d of %d children carrying an SBOM"
           % (sb.get("complete"), len(with_sbom), len(m["children"])))
if sb["present"] and not sb.get("complete"):
    refuse("the bundle carries SBOMs for %d of %d children. A partial bill of "
           "materials is refused: it reads as a complete one to every consumer "
           "that only checks `present`"
           % (sb["children_with_sbom"], sb["children_total"]))

sbom_files_claimed = set()
for c, (key, slug, fmts) in zip(m["children"], ident):
    if c["child_key"] != key or c["child_slug"] != slug:
        refuse("child identity re-derivation disagrees with the manifest: the "
               "record says %r/%r, common.sh derives %r/%r"
               % (c["child_key"], c["child_slug"], key, slug))
    cs = c.get("sbom")
    if cs is None:
        if sb["present"]:
            refuse("child %s carries no SBOM in a bundle that reports one for "
                   "every child" % key)
        continue
    docs = [cs] + list(cs.get("companions") or [])
    for d in docs:
        want = "content/sbom/%s" % fmts[d["format"]]
        if d["file"] != want:
            refuse("child %s: the %s SBOM is recorded at %r; sbom_filename() in "
                   "scripts/lib/common.sh derives %r. Producer and consumer "
                   "derive ONE identity, and a document filed under any other "
                   "name is not this child's"
                   % (key, d["format"], d["file"], want))
        ap = os.path.join(dir_, d["file"])
        if not os.path.exists(ap):
            refuse("child %s: the recorded SBOM %s is not in the bundle" % (key, d["file"]))
        # The SBOM's digest is inside the bundle's own coverage: SHA256SUMS
        # names the file, and the manifest — itself covered — records the same
        # value. Both are re-checked so neither can drift alone.
        if d["file"] not in indexed:
            refuse("child %s: the SBOM %s is covered by no checksum" % (key, d["file"]))
        actual = sha256_file(ap)
        if actual != d["sha256"]:
            refuse("child %s: the SBOM %s hashes to %s, the manifest records %s"
                   % (key, d["file"], actual, d["sha256"]))
        if indexed[d["file"]] != actual:
            refuse("child %s: SHA256SUMS records %s for %s, the file hashes to %s"
                   % (key, indexed[d["file"]], d["file"], actual))
        sbom_files_claimed.add(d["file"])
        # THE SUBJECT, again. The filename matching and the file hashing cleanly
        # is exactly the state in which a foreign bill of materials passes.
        doc = json.load(open(ap))
        subj = set(str(x).strip().lower() for x in (doc.get("documentDescribes") or [])
                   if isinstance(x, str))
        comp = ((doc.get("metadata") or {}).get("component") or {})
        for h in comp.get("hashes") or []:
            if isinstance(h, dict) and h.get("content"):
                subj.add("sha256:" + str(h["content"]).lower())
        if c["manifest_digest"].lower() not in subj:
            refuse("child %s: %s describes %s, not this child's manifest digest "
                   "%s. An SBOM for another digest, platform or source does not "
                   "become this child's by being filed under its name"
                   % (key, d["file"], ", ".join(sorted(subj)[:3]) or "nothing",
                      c["manifest_digest"]))
    if cs.get("subject_digest") and cs["subject_digest"] != c["manifest_digest"]:
        refuse("child %s: the SBOM record binds subject %s, the child is %s"
               % (key, cs["subject_digest"], c["manifest_digest"]))

# Nothing unbound inside the bundle either: an SBOM file no child claims is an
# unattributable bill of materials sitting inside checksum coverage.
sbom_on_disk = set(p for p in on_disk
                   if p.startswith("content/sbom/") and not p.endswith("/INDEX.json"))
unbound = sorted(sbom_on_disk - sbom_files_claimed)
if unbound:
    refuse("%d SBOM file(s) in the bundle are claimed by no child: %s"
           % (len(unbound), ", ".join(unbound[:5])))
if sb["present"] and not os.path.exists(os.path.join(dir_, "content/sbom/INDEX.json")):
    refuse("the bundle reports a bill of materials but carries no SBOM index")

print("ok - %s: %d file(s) covered, %d child record(s), content_checksum=%s"
      % (dir_, len(indexed), len(m["children"]), content_sum))
print("   evidence_class=%s  source_revision=%s  retain_until=%s"
      % (m["evidence_class"], m["source_revision"], m["retention"]["retain_until"]))
print("   authorization record_present=%s%s"
      % (au["record_present"],
         ("" if not au["record_present"]
          else "  revision=%s children=%d verdict=%s"
               % (au["record_binding"]["source_revision"],
                  au["record_binding"]["authorized_children"],
                  au["record_binding"]["verdict"]))))
print("   sbom present=%s complete=%s (%d/%d children, format=%s)"
      % (sb["present"], sb.get("complete"), sb["children_with_sbom"],
         sb["children_total"], sb["format"]))
PY
  rc=$?
  rm -rf "$vtmp"
  return "$rc"
}

# =============================================================================
# _mk_sboms <acceptance.json> <dir> good|foreign|trname
# Buildless SPDX fixtures for the self-test. `good` files are named by
# sbom_filename() and describe their own child; `foreign` are named correctly
# and describe a DIFFERENT child; `trname` reproduce the blind tr-substitution
# the producer used to emit.
_mk_sboms() {
  # `local` BEFORE the pipeline. Declared between the pipe and the `while` it
  # feeds, it becomes the pipeline's right-hand side and swallows every row —
  # the fixtures silently came out empty and three sabotage cases passed
  # vacuously for "no SBOM at all".
  local fam ver plat key subj tr name
  rm -rf "$2"; mkdir -p "$2"
  python3 - "$1" "$2" "$3" <<'PY' |
import json, sys
ev = json.load(open(sys.argv[1]))
mode = sys.argv[3]
other = ev["children"][-1]["manifest_digest"]
first = ev["children"][0]["manifest_digest"]
for c in ev["children"]:
    fam, _, ver = c["image_label"].partition("/")
    subj = c["manifest_digest"]
    if mode == "foreign":
        subj = other if c["manifest_digest"] != other else first
    tr = c["digest_reference"].replace("/", "_").replace(":", "_").replace("@", "_")
    print("\t".join([fam, ver, c["platform"], c["child_key"], subj, tr]))
PY
  while IFS="$(printf '\t')" read -r fam ver plat key subj tr; do
    if [ "$3" = "trname" ]; then name="$tr.spdx.json"
    else name="$(sbom_filename "$fam" "$ver" "$plat" spdx-json)"; fi
    python3 - "$2/$name" "$key" "$subj" <<'PY'
import json, sys
json.dump({"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT",
           "name": sys.argv[2], "documentDescribes": [sys.argv[3]],
           "packages": [{"name": "zlib1g", "versionInfo": "1:1.2.13.dfsg-1",
                         "licenseConcluded": "Zlib", "licenseDeclared": "Zlib"}]},
          open(sys.argv[1], "w"), indent=2)
PY
  done
}

# =============================================================================
_geb_self_test() {
  local tmp ok=0 bad=0
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" EXIT
  # Sabotage cases assert refusals; the diagnostic cases pipe a refusing command
  # into grep, which reports the refusal's status under pipefail.
  set +e
  set +o pipefail
  t() { if eval "$2"; then ok=$((ok+1)); echo "ok   - $1"; else bad=$((bad+1)); echo "FAIL - $1"; fi; }
  # die() calls exit. Inside a function that is the SCRIPT's exit, so every case
  # below runs in a subshell — otherwise the first refusal ends the suite and
  # every later assertion silently never runs.
  gen() {
    case " $* " in
      *" --authorization "*|*" --authorization-absent "*) : ;;
      *) set -- "$@" --authorization "$AUTHREC" ;;
    esac
    ( geb_generate "$@" )
  }
  ver() { ( geb_verify "$@" ); }

  local EV="$GEB_ROOT/docs/audits/acceptance-multiarch-2026-08-20/acceptance-evidence.json"
  if [ ! -f "$EV" ]; then echo "SKIP - accepted evidence absent"; return 0; fi
  if ! python3 -c 'import yaml' 2>/dev/null; then echo "SKIP - PyYAML absent"; return 0; fi
  local DAY=2026-08-25
  # The canonical post-build authorization the bundle now requires. This run's
  # own record was a 30-day workflow artifact and expired — the exact retention
  # failure the bundle exists for — so the offline fixture is reconstructed from
  # the accepted evidence. The builder lives under tests/ deliberately: a tool
  # in scripts/ that derived a canonical-looking authorization from any
  # acceptance record would be a bypass of the gate, not a fixture generator.
  local AUTHREC="$tmp/post-build-authorization.json"
  python3 "$GEB_ROOT/tests/lib/make_authorization_fixture.py" "$EV" "$AUTHREC" \
    || { echo "SKIP - authorization fixture unavailable"; return 0; }

  # --- H happy path, from the REAL committed accepted run -------------------
  t "H1 generates a bundle from the real accepted run" \
    "gen --evidence '$EV' --out '$tmp/b1' --evidence-class staged-candidate --today '$DAY' >/dev/null"
  t "H2 the bundle verifies offline" "ver '$tmp/b1' >/dev/null"
  t "H3 the VEX document is INSIDE checksum coverage" \
    "grep -q 'content/vex/openvex.json' '$tmp/b1/SHA256SUMS'"
  t "H4 the manifest indexes every content file" \
    "[ \"\$(python3 -c 'import json;print(len(json.load(open(\"$tmp/b1/manifest.json\"))[\"files\"]))')\" \
      = \"\$(find '$tmp/b1/content' -type f | wc -l | tr -d ' ')\" ]"
  t "H5 one child record per matrix image per platform" \
    "[ \"\$(python3 -c 'import json;print(len(json.load(open(\"$tmp/b1/manifest.json\"))[\"children\"]))')\" \
      = \"\$(( MATRIX_COUNT * 2 ))\" ]"
  t "H6 regeneration is byte-identical (no wall clock in the record)" \
    "gen --evidence '$EV' --out '$tmp/b2' --evidence-class staged-candidate --today '$DAY' >/dev/null \
     && cmp -s '$tmp/b1/manifest.json' '$tmp/b2/manifest.json' \
     && cmp -s '$tmp/b1/BUNDLE.sha256' '$tmp/b2/BUNDLE.sha256'"
  t "H7 the bundle survives relocation (path-independent aggregate)" \
    "cp -r '$tmp/b1' '$tmp/moved' && ver '$tmp/moved' >/dev/null"

  # --- S1 a file added after sealing ---------------------------------------
  cp -r "$tmp/b1" "$tmp/s1"; printf 'planted\n' > "$tmp/s1/content/extra.txt"
  t "S1 a file added after sealing is REFUSED" "! ver '$tmp/s1' >/dev/null 2>&1"
  t "S1 ...with the 'covered by no checksum' diagnostic" \
    "ver '$tmp/s1' 2>&1 | grep -q 'covered by no checksum'"

  # --- S2 a mutated evidence file ------------------------------------------
  cp -r "$tmp/b1" "$tmp/s2"
  python3 - "$tmp/s2" <<'PY'
import json, os, glob
p = sorted(glob.glob(os.path.join(os.sys.argv[1], "content/children/*.json")))[0]
d = json.load(open(p)); d["record"]["severity_counts"] = {"HIGH": 0}
json.dump(d, open(p, "w"), indent=2)
PY
  t "S2 one altered child record is REFUSED" "! ver '$tmp/s2' >/dev/null 2>&1"

  # --- S3 the index rewritten to match the tampered file --------------------
  cp -r "$tmp/s2" "$tmp/s3"
  python3 - "$tmp/s3" <<'PY'
import hashlib, os, sys
d = sys.argv[1]
out = []
for ln in open(os.path.join(d, "SHA256SUMS")).read().splitlines():
    dig, _sp, path = ln.partition("  ")
    h = hashlib.sha256(open(os.path.join(d, path), "rb").read()).hexdigest()
    out.append("%s  %s" % (h, path))
open(os.path.join(d, "SHA256SUMS"), "w").write("\n".join(out) + "\n")
PY
  t "S3 an index rewritten to bless the tampering is REFUSED by BUNDLE.sha256" \
    "! ver '$tmp/s3' >/dev/null 2>&1"
  t "S3 ...with the 'changed after the bundle was sealed' diagnostic" \
    "ver '$tmp/s3' 2>&1 | grep -q 'changed after the bundle was sealed'"

  # --- S4 a removed file ----------------------------------------------------
  cp -r "$tmp/b1" "$tmp/s4"; rm "$tmp/s4/content/vex/openvex.json"
  t "S4 a deleted disposition document is REFUSED" "! ver '$tmp/s4' >/dev/null 2>&1"

  # --- S5 mixed source revisions -------------------------------------------
  cp -r "$tmp/b1" "$tmp/s5"
  python3 - "$tmp/s5" <<'PY'
import hashlib, json, os, sys
d = sys.argv[1]
mp = os.path.join(d, "manifest.json")
m = json.load(open(mp))
m["children"][0]["source_revision"] = "0" * 40
json.dump(m, open(mp, "w"), indent=2)
# re-index so the failure is the CONSISTENCY rule, not the checksum rule
lines = []
for ln in open(os.path.join(d, "SHA256SUMS")).read().splitlines():
    _dig, _sp, path = ln.partition("  ")
    lines.append("%s  %s" % (hashlib.sha256(open(os.path.join(d, path), "rb").read()).hexdigest(), path))
open(os.path.join(d, "SHA256SUMS"), "w").write("\n".join(lines) + "\n")
open(os.path.join(d, "BUNDLE.sha256"), "w").write(
    "%s  SHA256SUMS\n" % hashlib.sha256(open(os.path.join(d, "SHA256SUMS"), "rb").read()).hexdigest())
PY
  t "S5 a bundle mixing source revisions is REFUSED even with a valid index" \
    "! ver '$tmp/s5' >/dev/null 2>&1"
  t "S5 ...with the 'mixes source revisions' diagnostic" \
    "ver '$tmp/s5' 2>&1 | grep -q 'mixes source revisions'"

  # --- S6 an undeclared evidence class -------------------------------------
  t "S6 an undeclared evidence class is REFUSED" \
    "! gen --evidence '$EV' --out '$tmp/s6' --evidence-class shipped-probably --today '$DAY' >/dev/null 2>&1"

  # --- S7 published-artifact without a release version ---------------------
  t "S7 class 'published-artifact' without --release is REFUSED" \
    "! gen --evidence '$EV' --out '$tmp/s7' --evidence-class published-artifact --today '$DAY' >/dev/null 2>&1"

  # --- S8 a failing gate ----------------------------------------------------
  python3 - "$EV" "$tmp/ev-fail.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); d["children"][3]["smoke_test"] = "FAIL"
json.dump(d, open(sys.argv[2], "w"), indent=2)
PY
  t "S8 a run with a failing gate cannot become an evidence bundle" \
    "! gen --evidence '$tmp/ev-fail.json' --out '$tmp/s8' --evidence-class staged-candidate --today '$DAY' >/dev/null 2>&1"

  # --- S9 an unfrozen database ---------------------------------------------
  python3 - "$EV" "$tmp/ev-thaw.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); d["frozen_vulnerability_database"]["frozen"] = False
json.dump(d, open(sys.argv[2], "w"), indent=2)
PY
  t "S9 an unfrozen vulnerability database is REFUSED" \
    "! gen --evidence '$tmp/ev-thaw.json' --out '$tmp/s9' --evidence-class staged-candidate --today '$DAY' >/dev/null 2>&1"

  # --- S10 refusing to overwrite an existing bundle ------------------------
  t "S10 writing a bundle over an existing path is REFUSED" \
    "! gen --evidence '$EV' --out '$tmp/b1' --evidence-class staged-candidate --today '$DAY' >/dev/null 2>&1"

  # --- S11..S16 the bill of materials ---------------------------------------
  # ONE identity, derived by sbom_filename(), producer and consumer. Every case
  # below is paired with the non-vacuity line that follows it.
  _mk_sboms "$EV" "$tmp/sbom" good
  _mk_sboms "$EV" "$tmp/sbom-foreign" foreign
  _mk_sboms "$EV" "$tmp/sbom-trname" trname
  t "S11 a complete SBOM set produces a COMPLETE bundle, not a silent false" \
    "gen --evidence '$EV' --out '$tmp/sb' --evidence-class staged-candidate \
        --sbom-dir '$tmp/sbom' --today '$DAY' >/dev/null \
     && python3 -c 'import json,sys
m=json.load(open(sys.argv[1]))
s=m[\"sbom\"]
sys.exit(0 if s[\"present\"] and s[\"complete\"]
             and s[\"children_with_sbom\"]==s[\"children_total\"]==len(m[\"children\"]) else 1)' \
        '$tmp/sb/manifest.json'"
  t "S11 ...and it verifies, with every SBOM inside checksum coverage" \
    "ver '$tmp/sb' >/dev/null \
     && [ \"\$(grep -c 'content/sbom/.*\.spdx\.json' '$tmp/sb/SHA256SUMS')\" = \"\$(( MATRIX_COUNT * 2 ))\" ]"
  t "S11 ...each child bound to the digest its own SBOM describes" \
    "python3 -c 'import json,sys
m=json.load(open(sys.argv[1]))
sys.exit(0 if all(c[\"sbom\"][\"subject_digest\"]==c[\"manifest_digest\"] for c in m[\"children\"]) else 1)' \
        '$tmp/sb/manifest.json'"
  t "S12 the filename scripts/generate-sbom.sh USED to write is a MISSING SBOM" \
    "! gen --evidence '$EV' --out '$tmp/sb-tr' --evidence-class staged-candidate \
        --sbom-dir '$tmp/sbom-trname' --today '$DAY' >/dev/null 2>&1"
  t "S12 ...fatally, naming the one identity function both sides derive from" \
    "gen --evidence '$EV' --out '$tmp/sb-tr2' --evidence-class staged-candidate \
        --sbom-dir '$tmp/sbom-trname' --today '$DAY' 2>&1 | grep -q 'sbom_filename()'"
  t "S13 an SBOM whose SUBJECT is another child is REFUSED at generate" \
    "! gen --evidence '$EV' --out '$tmp/sb-fg' --evidence-class staged-candidate \
        --sbom-dir '$tmp/sbom-foreign' --today '$DAY' >/dev/null 2>&1"
  t "S13 ...for the subject diagnostic, not a checksum one" \
    "gen --evidence '$EV' --out '$tmp/sb-fg2' --evidence-class staged-candidate \
        --sbom-dir '$tmp/sbom-foreign' --today '$DAY' 2>&1 | grep -q 'not this child'"
  rm -rf "$tmp/sbom-short"; cp -R "$tmp/sbom" "$tmp/sbom-short"
  rm -f "$tmp/sbom-short/$(child_slug nginx prod linux/arm64).spdx.json"
  t "S14 ONE missing SBOM is FATAL — never sbom.present=false with exit 0" \
    "! gen --evidence '$EV' --out '$tmp/sb-short' --evidence-class staged-candidate \
        --sbom-dir '$tmp/sbom-short' --today '$DAY' >/dev/null 2>&1"
  rm -rf "$tmp/sbom-extra"; cp -R "$tmp/sbom" "$tmp/sbom-extra"
  cp "$tmp/sbom/$(child_slug nginx prod linux/amd64).spdx.json" \
     "$tmp/sbom-extra/$(child_slug php-cli 8.5 linux/amd64).spdx.json"
  t "S15 an SBOM bound to no child in the bundle is REFUSED (8.5 is not shipped)" \
    "! gen --evidence '$EV' --out '$tmp/sb-extra' --evidence-class staged-candidate \
        --sbom-dir '$tmp/sbom-extra' --today '$DAY' >/dev/null 2>&1"
  # A foreign SBOM planted into a SEALED bundle and re-sealed COMPLETELY
  # honestly: the file's own digest, the manifest's copy of it, the file index,
  # the path-independent aggregate and BUNDLE.sha256 all agree afterwards. This
  # is the attacker's best case, so only re-reading the document's SUBJECT can
  # refuse it.
  rm -rf "$tmp/sb-swap"; cp -R "$tmp/sb" "$tmp/sb-swap"
  local swapped
  swapped="$(python3 - "$tmp/sb-swap" "$tmp/sbom-foreign" <<'PY2'
import glob, os, shutil, sys
b, foreign = sys.argv[1], sys.argv[2]
tgt = sorted(glob.glob(os.path.join(b, "content/sbom/*.spdx.json")))[0]
shutil.copyfile(os.path.join(foreign, os.path.basename(tgt)), tgt)
print(os.path.relpath(tgt, b))
PY2
)"
  local swap_sum; swap_sum="$(evidence_checksum "$tmp/sb-swap/content")"
  python3 - "$tmp/sb-swap" "$swapped" "$swap_sum" <<'PY2'
import hashlib, json, os, sys
b, rel, content_sum = sys.argv[1], sys.argv[2], sys.argv[3]
h = hashlib.sha256(open(os.path.join(b, rel), "rb").read()).hexdigest()
mp = os.path.join(b, "manifest.json")
m = json.load(open(mp))
for c in m["children"]:
    if c["sbom"] and c["sbom"]["file"] == rel:
        c["sbom"]["sha256"] = h
for f in m["files"]:
    if f["path"] == rel:
        f["sha256"] = h
m["checksums"]["content_checksum"] = content_sum
json.dump(m, open(mp, "w"), indent=2)
lines = []
for dp, _d, ns in os.walk(b):
    for n in ns:
        ap = os.path.join(dp, n)
        r = os.path.relpath(ap, b)
        if r in ("SHA256SUMS", "BUNDLE.sha256"):
            continue
        lines.append("%s  %s" % (hashlib.sha256(open(ap, "rb").read()).hexdigest(), r))
lines.sort(key=lambda s: s.split("  ", 1)[1])
mn = [l for l in lines if l.endswith("  manifest.json")]
open(os.path.join(b, "SHA256SUMS"), "w").write(
    "\n".join(mn + [l for l in lines if l not in mn]) + "\n")
open(os.path.join(b, "BUNDLE.sha256"), "w").write(
    "%s  SHA256SUMS\n"
    % hashlib.sha256(open(os.path.join(b, "SHA256SUMS"), "rb").read()).hexdigest())
PY2
  t "S16 a foreign SBOM swapped in and honestly re-sealed is REFUSED by verify" \
    "! ver '$tmp/sb-swap' >/dev/null 2>&1"
  t "S16 ...because the SUBJECT is re-read, not just the file's own digest" \
    "ver '$tmp/sb-swap' 2>&1 | grep -q 'not this child'"
  t "NON-VACUOUS: the honest SBOM bundle still verifies after S12-S16" \
    "ver '$tmp/sb' >/dev/null"

  # --- NON-VACUITY ---------------------------------------------------------
  t "NON-VACUOUS: the untampered bundle still verifies after every sabotage above" \
    "ver '$tmp/b1' >/dev/null"
  t "NON-VACUOUS: verify can fail — an empty directory is not a valid bundle" \
    "mkdir -p '$tmp/hollow' && ! ver '$tmp/hollow' >/dev/null 2>&1"

  echo "self-test: $ok ok, $bad failed"
  [ "$bad" -eq 0 ]
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-}" in
    generate) shift; geb_generate "$@" ;;
    verify)   shift; geb_verify "${1:-}" ;;
    --self-test) _geb_self_test && echo "generate-evidence-bundle.sh: SELF-TEST OK" ;;
    *) cat >&2 <<'EOF'
usage:
  generate-evidence-bundle.sh generate --evidence <acceptance.json> --out <dir>
       --evidence-class <class> [--release vYYYY.MM.DD --candidate rcN]
       [--sbom-dir DIR] [--provenance FILE] [--ledger FILE] [--today YYYY-MM-DD]
  generate-evidence-bundle.sh verify <dir>
  generate-evidence-bundle.sh --self-test
EOF
       exit 2 ;;
  esac
fi
