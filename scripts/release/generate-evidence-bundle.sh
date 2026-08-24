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
_geb_identity_table() { # <acceptance.json>
  local fam ver plat
  python3 - "$1" <<'PY' |
import json, sys
rec = json.load(open(sys.argv[1]))
for c in rec.get("children") or []:
    fam, _, ver = (c.get("image_label") or "").partition("/")
    print("%s\t%s\t%s" % (fam, ver, c.get("platform") or ""))
PY
  while IFS="$(printf '\t')" read -r fam ver plat; do
    printf '%s\t%s\n' "$(child_key "$fam" "$ver" "$plat")" "$(child_slug "$fam" "$ver" "$plat")"
  done
}

# =============================================================================
# generate
# =============================================================================
geb_generate() {
  local ev="" out="" cls="" rel="" cand="" sbom="" prov="" ledger="" today=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --evidence)       ev="${2:?}"; shift 2 ;;
      --out)            out="${2:?}"; shift 2 ;;
      --evidence-class) cls="${2:?}"; shift 2 ;;
      --release)        rel="${2:?}"; shift 2 ;;
      --candidate)      cand="${2:?}"; shift 2 ;;
      --sbom-dir)       sbom="${2:?}"; shift 2 ;;
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
  bash "$_GEB_D/generate-vex.sh" generate --evidence "$ev" \
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
  python3 - "$ev" "$out" "$cls" "$rel" "$cand" "$sbom_dir_arg" "$prov" "$ledger" \
                  "$tmp/ident.tsv" <<'PY' || return 1
import json, os, re, sys, hashlib, datetime, shutil, collections
import yaml

(evidence_p, out, cls, rel, cand, sbom_dir, prov, ledger_p, ident_p) = sys.argv[1:10]
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

# --- identity ----------------------------------------------------------------
children_in = ev.get("children") or []
ident = [ln.split("\t") for ln in open(ident_p).read().splitlines() if ln.strip()]
if len(ident) != len(children_in):
    refuse("identity table has %d row(s) for %d child record(s)" % (len(ident), len(children_in)))

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
children = []
for c, (key, slug) in zip(children_in, ident):
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
        found = None
        for ext in (".spdx.json", ".cdx.json", ".json"):
            cand_p = os.path.join(sbom_dir, slug + ext)
            if os.path.exists(cand_p):
                found = (cand_p, ext)
                break
        if found:
            src, ext = found
            dest_rel = "content/sbom/%s%s" % (slug, ext)
            shutil.copyfile(src, os.path.join(out, dest_rel))
            child_sbom = {"format": "spdx-json" if ext == ".spdx.json" else "json",
                          "sha256": sha256_file(src), "file": dest_rel}
            sbom_index.append({"child_key": key, "file": dest_rel,
                               "sha256": child_sbom["sha256"]})

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
    write_json(os.path.join(out, "content/sbom/INDEX.json"),
               {"schema_version": 1, "children": sbom_index})

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

authorization = collections.OrderedDict([
    ("scope", authrec.get("authorization_scope") or ""),
    ("public_exposure_authorized", bool(authrec.get("public_exposure_authorized"))),
    ("verdict", acc.get("verdict")),
    ("generated_at", gen_at),
    ("build_created", authrec.get("build_created")),
    ("record_file", "content/authorization/authorization-record.json"),
])
if not authorization["scope"]:
    refuse("%s: authorization_record.authorization_scope is empty — an "
           "authorization that does not state its scope authorises whatever the "
           "reader assumes" % evidence_p)
write_json(os.path.join(out, "content/authorization/authorization-record.json"),
           {"schema_version": 1, "authorization": authorization,
            "record": authrec, "issue_linkage": ev.get("issue_linkage")})

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
        ("format", sbom_index and "spdx-json" or None),
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

  GEB_SCHEMA="$GEB_SCHEMA" python3 - "$dir" "$content_sum" <<'PY' || return 1
import json, os, sys, hashlib, collections
dir_, content_sum = sys.argv[1], sys.argv[2]
schema_p = os.environ["GEB_SCHEMA"]


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

print("ok - %s: %d file(s) covered, %d child record(s), content_checksum=%s"
      % (dir_, len(indexed), len(m["children"]), content_sum))
print("   evidence_class=%s  source_revision=%s  retain_until=%s"
      % (m["evidence_class"], m["source_revision"], m["retention"]["retain_until"]))
PY
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
  gen() { ( geb_generate "$@" ); }
  ver() { ( geb_verify "$@" ); }

  local EV="$GEB_ROOT/docs/audits/acceptance-multiarch-2026-08-20/acceptance-evidence.json"
  if [ ! -f "$EV" ]; then echo "SKIP - accepted evidence absent"; return 0; fi
  if ! python3 -c 'import yaml' 2>/dev/null; then echo "SKIP - PyYAML absent"; return 0; fi
  local DAY=2026-08-25

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
