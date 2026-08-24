#!/usr/bin/env bash
# =============================================================================
# scripts/release/generate-vex.sh — machine-readable vulnerability dispositions.
# -----------------------------------------------------------------------------
# THE DEFECT THIS EXISTS FOR (#115).
#
# This repository already decides, per image and per architecture, whether every
# CRITICAL/HIGH finding is an accepted risk or does not apply. That decision is
# recorded in policies/vulnerability-exceptions.yaml and enforced by
# scripts/reconcile-vulnerabilities.sh. None of it reaches a consumer. A customer
# scanning ghcr.io/zenchron-dynamics/foundry-php-fpm:8.4 sees 47 CRITICAL/HIGH
# and has two bad options: block a clean deployment, or learn to ignore the
# scanner. Both are worse than telling them what we already know.
#
# So this emits OpenVEX. What matters is not the format — it is the four rules
# that stop a VEX document from becoming a laundering mechanism for claims
# nobody made:
#
#   1. EVERY statement is derived from an OBSERVED finding. The universe of
#      statements is exactly the set of (image digest, advisory, package,
#      version) tuples that the accepted acceptance run actually recorded. A
#      statement wider than the evidence is refused, not trimmed.
#
#   2. EVERY statement is bound to ONE immutable manifest digest, ONE platform,
#      and the exact package@version observed in THAT image. Tags are refused:
#      a tag can be moved after the statement is written.
#
#   3. AN ACCEPTED RISK IS `affected`. The ledger's `reachability` field
#      ("not-reachable-under-intended-use") is internal risk-acceptance
#      rationale. Mapping it onto the OpenVEX justification
#      `vulnerable_code_not_in_execute_path` would publish a reachability
#      analysis to a standard nobody performed. Only `not_affected` RECORDS —
#      which carry an evidenced `classification` and a version binding — become
#      `not_affected` STATEMENTS. Everything else is `affected` with an action
#      statement.
#
#   4. AMBIGUITY REFUSES. If zero ledger records, or two records disagreeing on
#      status, cover an observed tuple, generation fails. It does not pick one.
#
# Identity comes from child_key()/child_slug() in scripts/lib/common.sh, and the
# derived key is CHECKED against the key the acceptance record carries. There is
# one identity derivation in this repository; a second one is what produced
# cancelled run 32123758374.
#
# Usage:
#   generate-vex.sh generate --evidence <acceptance.json> --out <openvex.json>
#                            [--ledger FILE] [--today YYYY-MM-DD]
#   generate-vex.sh verify   --vex <openvex.json> --evidence <acceptance.json>
#                            [--ledger FILE] [--today YYYY-MM-DD]
#   generate-vex.sh --self-test
#
# Exit 0 only when every observed finding has exactly one governing record and
# every emitted statement is re-derivable from the inputs.
# =============================================================================
set -euo pipefail
_VEX_D="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VEX_ROOT="${VEX_ROOT:-$(cd "$_VEX_D/../.." && pwd)}"
# shellcheck source=../lib/common.sh
. "$_VEX_D/../lib/common.sh"

VEX_SCHEMA="$VEX_ROOT/schemas/vex-openvex-v1.schema.json"
DEFAULT_LEDGER="$VEX_ROOT/policies/vulnerability-exceptions.yaml"

_vex_need_py() {
  python3 -c 'import yaml' 2>/dev/null \
    || die "python3 with PyYAML is required to read the exception ledger"
}

# --- the ONE identity derivation --------------------------------------------
# Emits, for every child in the acceptance record and in record order:
#   <child_key>\t<child_slug>
# computed by common.sh from (family, selector, platform). The caller compares
# the derived key with the key the record carries; a divergence is a refusal,
# because two spellings of one child is the defect that lost 10 of 20 evidence
# files in run 32123758374.
_vex_identity_table() { # <acceptance.json>
  local fam ver plat
  python3 - "$1" <<'PY' |
import json, sys
rec = json.load(open(sys.argv[1]))
for c in rec.get("children") or []:
    label = c.get("image_label") or ""
    fam, _, ver = label.partition("/")
    print("%s\t%s\t%s" % (fam, ver, c.get("platform") or ""))
PY
  while IFS="$(printf '\t')" read -r fam ver plat; do
    printf '%s\t%s\n' "$(child_key "$fam" "$ver" "$plat")" "$(child_slug "$fam" "$ver" "$plat")"
  done
}

# --- the contract, stated once, in python ------------------------------------
_vex_py() { # _vex_py <mode> <evidence> <ledger> <today> <identity-tsv> <out|vex>
  _vex_need_py
  PYTHONPATH="$VEX_ROOT/scripts/lib${PYTHONPATH:+:$PYTHONPATH}" \
  python3 - "$@" <<'PY'
import json, os, re, sys, hashlib, datetime, collections

mode, evidence_p, ledger_p, today_s, ident_p, target_p = sys.argv[1:7]
schema_p = os.environ["VEX_SCHEMA"]
matrix_families = [f for f in os.environ.get("VEX_MATRIX_FAMILIES", "").split() if f]

import yaml
try:
    import strict_yaml
except ImportError:
    strict_yaml = None
from exception_id import exc_id


def refuse(msg):
    print("REFUSE: " + msg, file=sys.stderr)
    sys.exit(1)


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# --- inputs. An unreadable input is a failure, never an empty clean result. ---
try:
    with open(evidence_p) as fh:
        ev = json.load(fh)
except Exception as exc:                                    # noqa: BLE001
    refuse("cannot read acceptance evidence %r: %s" % (evidence_p, exc))

try:
    # STRICT: yaml.safe_load keeps the LAST of a duplicated key, so a record
    # could declare verified_architectures twice and enforce the list nobody
    # read. The ledger gate already reads it this way; so does this.
    led = (strict_yaml.load(ledger_p) if strict_yaml else yaml.safe_load(open(ledger_p))) or {}
except Exception as exc:                                    # noqa: BLE001
    refuse("cannot read exception ledger %r: %s" % (ledger_p, exc))

if led.get("schema_version") != 1:
    refuse("exception ledger %r: schema_version must be 1" % ledger_p)
if not isinstance(led.get("exceptions"), list):
    refuse("exception ledger %r has no 'exceptions' list — an absent ledger is "
           "not an empty one" % ledger_p)

try:
    today = datetime.date.fromisoformat(today_s)
except ValueError:
    refuse("--today %r is not YYYY-MM-DD" % today_s)

if ev.get("record_type") != "post-acceptance-evidence":
    refuse("%s: record_type is %r, expected 'post-acceptance-evidence' — VEX is "
           "generated from an acceptance run's findings, not from an arbitrary "
           "JSON document" % (evidence_p, ev.get("record_type")))
if (ev.get("acceptance") or {}).get("verdict") != "PASS":
    refuse("%s: acceptance verdict is %r — dispositions are published for an "
           "ACCEPTED run only" % (evidence_p, (ev.get("acceptance") or {}).get("verdict")))

source_revision = ev.get("source_revision") or ""
if not re.match(r"^[0-9a-f]{40}$", source_revision):
    refuse("%s: source_revision %r is not 40 lowercase hex" % (evidence_p, source_revision))

children = ev.get("children") or []
if not children:
    refuse("%s: no children — a VEX document with no product is a claim about "
           "nothing" % evidence_p)

# --- identity: derived by common.sh, checked against the record --------------
ident = [ln.split("\t") for ln in open(ident_p).read().splitlines() if ln.strip()]
if len(ident) != len(children):
    refuse("identity table has %d row(s) for %d child record(s)"
           % (len(ident), len(children)))
for c, (key, slug) in zip(children, ident):
    if c.get("child_key") != key:
        refuse("child identity mismatch: the record says %r, child_key() in "
               "scripts/lib/common.sh derives %r from (%s, %s). There is exactly "
               "ONE identity derivation; a record that disagrees with it is a "
               "record about a child nobody can name twice the same way"
               % (c.get("child_key"), key, c.get("image_label"), c.get("platform")))
    c["_slug"] = slug

# =============================================================================
# SCOPE. The ledger's `image` selector, read with the SAME grammar the
# reconciler enforces, and no more permissive anywhere.
#
# The grammar is read off the selector itself rather than from a hardcoded
# cohort table, so it cannot drift from the ledger: a trailing run of
# `-<major>.<minor>` components IS the version cohort, and the prefix is the
# family (or, for the bare prefix `php`, any PHP family).
#
#   nginx                    -> family nginx, any version
#   php-8.3-8.4              -> any PHP family, versions {8.3, 8.4}
#   php-frankenphp-8.3-8.4   -> family php-frankenphp, versions {8.3, 8.4}
#
# `all` and `php-all` are MOVING selectors: `all` would absorb a family added
# tomorrow, `php-all` a PHP version added tomorrow. The reconciler already
# refuses `php-all`. A VEX statement is published to third parties and cannot be
# retracted from their caches, so this refuses BOTH — a published disposition
# must name the artifacts it was evidenced on.
# =============================================================================
PHP_FAMILIES = frozenset(f for f in matrix_families if f.startswith("php"))
if not PHP_FAMILIES:
    refuse("no PHP families derived from the matrix in scripts/lib/common.sh — "
           "refusing rather than falling back to a hardcoded family list")
_VER_RE = re.compile(r"^[0-9]+\.[0-9]+$")


def selector_scope(sel, fam, ver):
    """True/False if the selector decides; None if the selector is unusable."""
    if sel in ("all", "php-all"):
        return None
    parts = sel.split("-")
    versions = []
    while parts and _VER_RE.match(parts[-1]):
        versions.insert(0, parts.pop())
    base = "-".join(parts)
    if versions:
        if base == "php":
            return fam in PHP_FAMILIES and ver in versions
        return base == fam and ver in versions
    if base in PHP_FAMILIES:
        return None                    # bare PHP family: unbounded, refuse
    return base == fam


def packages_of(rec):
    p = rec.get("package")
    if p is None:
        return []
    return list(p) if isinstance(p, (list, tuple)) else [p]


def version_pin_holds(rec, pkg, ver):
    """EXACT observed-version membership only.

    `package_versions` binds each package to its own observed builds;
    `installed_version` binds the whole record. A record carrying neither is
    unusable here and is reported as such by `version_pin_kind`, rather than
    being silently treated as matching everything.
    """
    pv = rec.get("package_versions")
    if pv:
        allowed = pv.get(pkg)
        return bool(allowed) and ver in allowed
    iv = rec.get("installed_version")
    if iv:
        allowed = iv if isinstance(iv, (list, tuple)) else [iv]
        return ver in allowed
    return False


def has_version_pin(rec):
    return bool(rec.get("package_versions")) or bool(rec.get("installed_version"))


def ledger_records():
    for r in led.get("exceptions") or []:
        yield "exception", r
    for r in led.get("not_affected") or []:
        yield "not_affected", r


# --- the observed universe ---------------------------------------------------
# (digest, cve, package, version) -> the child that carries it. This is the ONLY
# set a statement may speak about.
Observed = collections.namedtuple("Observed", "child cve pkg ver")
observed = []
by_digest = {}
for c in children:
    dig = c.get("manifest_digest") or ""
    if not re.match(r"^sha256:[0-9a-f]{64}$", dig):
        refuse("child %s has manifest_digest %r — a disposition must be bound to "
               "an immutable digest; a tag can be repointed after the statement "
               "is published" % (c.get("child_key"), dig))
    if dig in by_digest and by_digest[dig]["child_key"] != c["child_key"]:
        refuse("digest %s is claimed by two children (%s and %s)"
               % (dig, by_digest[dig]["child_key"], c["child_key"]))
    by_digest[dig] = c
    for cve, pkgs in sorted((c.get("governed_findings") or {}).items()):
        for spec in pkgs:
            pkg, sep, ver = spec.rpartition("@")
            if not sep or not pkg or not ver:
                refuse("child %s advisory %s: finding %r is not <package>@<version>"
                       % (c.get("child_key"), cve, spec))
            observed.append(Observed(c, cve, pkg, ver))

if not observed:
    refuse("%s: no governed findings recorded — an empty disposition set from a "
           "run that scanned %d children is a parsing failure, not a clean bill "
           "of health" % (evidence_p, len(children)))


def resolve(o):
    """The ONE ledger record governing an observed tuple, or a refusal reason."""
    fam, _, ver = (o.child.get("image_label") or "").partition("/")
    ver = "" if ver == "prod" else ver
    plat = o.child.get("platform") or ""
    matches, near = [], []
    for kind, rec in ledger_records():
        if rec.get("cve") != o.cve:
            continue
        if o.pkg not in packages_of(rec):
            continue
        rid = "%s:%s" % (kind, exc_id(rec))
        if not has_version_pin(rec):
            return None, ("record %s covers %s/%s but carries no exact version "
                          "pin (installed_version or package_versions). A "
                          "disposition without a version binding keeps applying "
                          "after the package moves into the vulnerable range"
                          % (rid, o.cve, o.pkg))
        if not version_pin_holds(rec, o.pkg, o.ver):
            near.append("%s (pinned to a different version)" % rid)
            continue
        va = rec.get("verified_architectures") or []
        if va and plat not in va:
            near.append("%s (verified on %s, not %s)" % (rid, ",".join(va), plat))
            continue
        scoped = selector_scope(str(rec.get("image") or ""), fam, ver)
        if scoped is None:
            return None, ("record %s uses the unbounded image selector %r. A "
                          "published disposition cannot be retracted from a "
                          "consumer's cache, so it must name the image cohort it "
                          "was evidenced on — %r would silently absorb an image "
                          "or version added after the statement shipped"
                          % (rid, rec.get("image"), rec.get("image")))
        if not scoped:
            near.append("%s (scoped to %r)" % (rid, rec.get("image")))
            continue
        matches.append((kind, rec, rid))
    if not matches:
        detail = ("; nearest: " + ", ".join(sorted(set(near)))) if near else ""
        return None, ("no ledger record governs %s / %s@%s on %s%s"
                      % (o.cve, o.pkg, o.ver, o.child.get("child_key"), detail))
    kinds = set(k for k, _, _ in matches)
    if len(kinds) > 1:
        return None, ("AMBIGUOUS: %s / %s@%s on %s is covered by records of "
                      "conflicting kinds (%s). A finding is either an accepted "
                      "risk or not applicable; it cannot be published as both"
                      % (o.cve, o.pkg, o.ver, o.child.get("child_key"),
                         ", ".join(sorted(r for _, _, r in matches))))
    if len(matches) > 1:
        ids = sorted(set(r for _, _, r in matches))
        if len(ids) > 1:
            return None, ("AMBIGUOUS: %s / %s@%s on %s is covered by %d distinct "
                          "records (%s); which one authorises the statement is "
                          "not determined" % (o.cve, o.pkg, o.ver,
                                              o.child.get("child_key"), len(ids),
                                              ", ".join(ids)))
    return matches[0], None


# --- staleness ---------------------------------------------------------------
def expiry_of(rec):
    v = rec.get("expires_at")
    if v is None:
        return None
    if isinstance(v, datetime.date):
        return v
    try:
        return datetime.date.fromisoformat(str(v))
    except ValueError:
        return "invalid"


# --- classification -> OpenVEX justification ---------------------------------
# ONLY evidenced determinations map. Anything unmapped refuses: inventing a
# justification is how a VEX document becomes worse than no VEX document.
JUSTIFICATION = {
    "vulnerable-component-not-installed": "component_not_present",
    "vulnerable-code-not-present": "vulnerable_code_not_present",
    "false-positive-disputed-range": "vulnerable_code_not_present",
}

TS = (ev.get("authorization_record") or {}).get("generated_at") \
     or (ev.get("acceptance") or {}).get("concluded_at") or ""
if not re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", str(TS)):
    refuse("%s: authorization_record.generated_at %r is not RFC3339 UTC; the "
           "document timestamp is derived from the run, never from this "
           "machine's clock" % (evidence_p, TS))


def purl_for(child):
    fam, _, ver = (child.get("image_label") or "").partition("/")
    arch = (child.get("platform") or "").rsplit("/", 1)[-1]
    dig = child["manifest_digest"].replace(":", "%3A")
    return ("pkg:oci/%s@%s?arch=%s&tag=%s" % (fam, dig, arch, ver))


def build_document():
    """Resolve every observed tuple, then group into statements."""
    groups = collections.OrderedDict()
    for o in observed:
        match, why = resolve(o)
        if why:
            refuse(why)
        kind, rec, rid = match
        exp = expiry_of(rec)
        if exp == "invalid":
            refuse("record %s has an unparseable expires_at %r" % (rid, rec.get("expires_at")))
        if kind == "exception":
            if exp is None:
                refuse("record %s is an accepted risk with no expires_at. An "
                       "acceptance that never expires is never re-reviewed" % rid)
            if exp <= today:
                refuse("record %s EXPIRED on %s (evaluating as of %s). Publishing "
                       "a disposition backed by a lapsed acceptance tells a "
                       "consumer a decision is current when nobody has re-made it"
                       % (rid, exp.isoformat(), today.isoformat()))
        if kind == "not_affected":
            cls = rec.get("classification")
            if cls not in JUSTIFICATION:
                refuse("record %s has classification %r, which maps to no OpenVEX "
                       "justification. Add an explicit mapping — a not_affected "
                       "statement without a justification from the fixed "
                       "vocabulary is an unfalsifiable claim" % (rid, cls))
        groups.setdefault((o.cve, rid), {"kind": kind, "rec": rec, "products": collections.OrderedDict()})
        prods = groups[(o.cve, rid)]["products"]
        prods.setdefault(o.child["manifest_digest"], (o.child, []))[1].append("%s@%s" % (o.pkg, o.ver))

    statements = []
    for (cve, rid), g in groups.items():
        rec, kind = g["rec"], g["kind"]
        products = []
        for dig, (child, subs) in g["products"].items():
            products.append(collections.OrderedDict([
                ("@id", purl_for(child)),
                ("identifiers", {"purl": purl_for(child)}),
                ("hashes", {"sha256": dig.split(":", 1)[1]}),
                ("foundry", collections.OrderedDict([
                    ("child_key", child["child_key"]),
                    ("child_slug", child["_slug"]),
                    ("platform", child["platform"]),
                    ("image_label", child["image_label"]),
                ])),
                ("subcomponents", [{"@id": _sub_purl(child, s)} for s in sorted(set(subs))]),
            ]))
        st = collections.OrderedDict([
            ("vulnerability", {"name": cve}),
            ("products", products),
            ("status", "not_affected" if kind == "not_affected" else "affected"),
        ])
        if kind == "not_affected":
            st["justification"] = JUSTIFICATION[rec["classification"]]
            st["impact_statement"] = _one_line(rec.get("evidence"))
        else:
            controls = rec.get("compensating_controls") or []
            st["action_statement"] = _one_line(
                "Risk accepted for this digest until %s. %s Compensating controls: %s."
                % (rec.get("expires_at"), rec.get("reason") or "", "; ".join(str(c) for c in controls)))
            st["action_statement_timestamp"] = TS
        st["timestamp"] = TS
        st["foundry"] = collections.OrderedDict([
            ("record_kind", kind),
            ("record_id", rid),
            ("record_image_selector", str(rec.get("image"))),
            ("classification", rec.get("classification")),
            ("expires_at", str(rec.get("expires_at")) if rec.get("expires_at") else None),
            ("release_blocking", rec.get("release_blocking")),
            ("fix_available", rec.get("fix_available")),
            ("verified_architectures", list(rec.get("verified_architectures") or [])),
        ])
        statements.append(st)

    doc = collections.OrderedDict([
        ("@context", "https://openvex.dev/ns/v0.2.0"),
        ("@id", "https://openvex.dev/docs/zenchron-foundry/%s-%s"
                % (source_revision[:12], (ev.get("acceptance") or {}).get("workflow_run_id"))),
        ("author", "Zenchron Dynamics / Platform Security"),
        ("role", "Document Creator"),
        ("timestamp", TS),
        ("version", 1),
        ("tooling", "scripts/release/generate-vex.sh"),
        ("foundry", collections.OrderedDict([
            ("source_revision", source_revision),
            ("evidence_record_sha256", sha256_file(evidence_p)),
            ("exception_policy", os.path.relpath(ledger_p, os.environ.get("VEX_ROOT", "."))),
            ("exception_policy_sha256", sha256_file(ledger_p)),
            ("generated_from", os.path.basename(evidence_p)),
            ("evaluated_on", today.isoformat()),
            ("observed_tuples", len(observed)),
        ])),
        ("statements", statements),
    ])
    return doc


def _sub_purl(child, spec):
    pkg, _, ver = spec.rpartition("@")
    arch = (child.get("platform") or "").rsplit("/", 1)[-1]
    # Distro packages carry a Debian/Alpine version shape; language packages do
    # not. The namespace is derived from the observed version string rather than
    # asserted, and an unrecognised shape falls back to `pkg:generic`, which
    # claims nothing about the ecosystem.
    if re.search(r"(deb\d+u\d+|\+deb|~deb)", ver):
        return "pkg:deb/debian/%s@%s?arch=%s" % (pkg, ver, arch)
    if re.search(r"-r\d+$", ver):
        return "pkg:apk/alpine/%s@%s?arch=%s" % (pkg, ver, arch)
    if pkg.startswith(("golang.org/", "google.golang.org/", "github.com/")) or pkg == "stdlib":
        return "pkg:golang/%s@%s" % (pkg, ver)
    return "pkg:generic/%s@%s" % (pkg, ver)


def _one_line(text):
    return re.sub(r"\s+", " ", str(text or "")).strip()


def validate_schema(doc, where):
    try:
        from jsonschema import Draft202012Validator
    except ImportError:
        return
    errs = sorted(Draft202012Validator(json.load(open(schema_p))).iter_errors(doc),
                  key=lambda e: list(e.path))
    if errs:
        e = errs[0]
        loc = "/".join(str(x) for x in e.path) or "<root>"
        refuse("%s: does not satisfy %s at %s: %s"
               % (where, os.path.basename(schema_p), loc, e.message))


# =============================================================================
if mode == "generate":
    doc = build_document()
    validate_schema(doc, target_p)
    with open(target_p, "w") as fh:
        json.dump(doc, fh, indent=2, sort_keys=False)
        fh.write("\n")
    counts = collections.Counter(s["status"] for s in doc["statements"])
    print("ok - %s: %d statement(s) over %d observed tuple(s) [%s]"
          % (target_p, len(doc["statements"]), len(observed),
             ", ".join("%s=%d" % kv for kv in sorted(counts.items()))))

elif mode == "verify":
    try:
        with open(target_p) as fh:
            doc = json.load(fh)
    except Exception as exc:                                # noqa: BLE001
        refuse("cannot read VEX document %r: %s" % (target_p, exc))
    validate_schema(doc, target_p)

    fd = doc.get("foundry") or {}
    if fd.get("source_revision") != source_revision:
        refuse("%s: document binds source_revision %r, the evidence is for %r — a "
               "disposition set is only meaningful for the revision it was "
               "derived from" % (target_p, fd.get("source_revision"), source_revision))
    if fd.get("exception_policy_sha256") != sha256_file(ledger_p):
        refuse("%s: document was generated from an exception policy whose sha256 "
               "was %s; %s now hashes to %s. The dispositions no longer match the "
               "decisions they claim to publish"
               % (target_p, fd.get("exception_policy_sha256"), ledger_p, sha256_file(ledger_p)))
    if fd.get("evidence_record_sha256") != sha256_file(evidence_p):
        refuse("%s: document was generated from evidence hashing %s; %s hashes to "
               "%s" % (target_p, fd.get("evidence_record_sha256"), evidence_p,
                       sha256_file(evidence_p)))

    # Every observed tuple must be covered ...
    covered = set()
    for si, st in enumerate(doc.get("statements") or []):
        cve = (st.get("vulnerability") or {}).get("name")
        for prod in st.get("products") or []:
            m = re.search(r"@sha256(?:%3A|:)([0-9a-f]{64})", prod.get("@id") or "")
            if not m:
                refuse("%s statement %d: product %r is not digest-bound"
                       % (target_p, si, prod.get("@id")))
            dig = "sha256:" + m.group(1)
            if dig not in by_digest:
                refuse("%s statement %d (%s): product digest %s is not one of the "
                       "%d child digests in %s. A statement about a digest this "
                       "run never produced is a claim with no evidence behind it"
                       % (target_p, si, cve, dig, len(by_digest), evidence_p))
            child = by_digest[dig]
            declared = ((prod.get("foundry") or {}).get("platform"))
            if declared and declared != child.get("platform"):
                refuse("%s statement %d (%s): product %s is declared %s, the "
                       "evidence records it as %s"
                       % (target_p, si, cve, dig, declared, child.get("platform")))
            gf = (child.get("governed_findings") or {}).get(cve)
            if not gf:
                refuse("%s statement %d: the document claims %s on %s, but that "
                       "advisory was NOT reported for that image in %s — the "
                       "document is inconsistent with the scan"
                       % (target_p, si, cve, child.get("child_key"), evidence_p))
            # Reconstruct the expected package identifiers with the SAME function
            # that emitted them. A second parser here is a second grammar, and
            # two grammars for one identifier is how a tuple stops matching
            # itself.
            expected = {}
            for spec in gf:
                pkg_, _sep, ver_ = spec.rpartition("@")
                expected[_sub_purl(child, spec)] = (pkg_, ver_)
            for sub in prod.get("subcomponents") or []:
                sid = sub.get("@id") or ""
                if sid not in expected:
                    refuse("%s statement %d (%s): package identifier %r was NEVER "
                           "OBSERVED on %s; the scan reported %s. A disposition may "
                           "not be broader than the evidence"
                           % (target_p, si, cve, sid, child.get("child_key"),
                              ", ".join(sorted(expected))))
                pkg, ver = expected[sid]
                covered.add((dig, cve, pkg, ver))

        # the backing record must still be live
        f = st.get("foundry") or {}
        if f.get("record_kind") == "exception":
            exp = f.get("expires_at")
            try:
                d = datetime.date.fromisoformat(str(exp))
            except (TypeError, ValueError):
                refuse("%s statement %d: accepted-risk statement carries "
                       "expires_at %r" % (target_p, si, exp))
            if d <= today:
                refuse("%s statement %d (%s): backed by record %s which EXPIRED on "
                       "%s (checked as of %s) — a stale acceptance must not remain "
                       "published as a current disposition"
                       % (target_p, si, cve, f.get("record_id"), d.isoformat(),
                          today.isoformat()))

    want = set((o.child["manifest_digest"], o.cve, o.pkg, o.ver) for o in observed)
    uncovered = want - covered
    if uncovered:
        s = sorted(uncovered)[:3]
        refuse("%s: %d observed finding tuple(s) have no disposition, e.g. %s. A "
               "partial VEX document is read as 'everything else is fine'"
               % (target_p, len(uncovered),
                  "; ".join("%s %s@%s on %s" % (c, p, v, d[:19]) for d, c, p, v in s)))

    print("ok - %s: %d statement(s), %d observed tuple(s) all covered, no "
          "statement wider than the evidence"
          % (target_p, len(doc.get("statements") or []), len(want)))

else:
    refuse("unknown mode %r" % mode)
PY
}

# --- CLI ---------------------------------------------------------------------
vex_generate() { # <evidence> <out> [ledger] [today]
  local ev="$1" out="$2" ledger="${3:-$DEFAULT_LEDGER}" today="${4:-$(date -u +%F)}"
  [ -f "$ev" ] || die "acceptance evidence not found: $ev"
  [ -f "$ledger" ] || die "exception ledger not found: $ledger"
  local tmp; tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" EXIT
  _vex_identity_table "$ev" > "$tmp/ident.tsv"
  mkdir -p "$(dirname "$out")"
  VEX_SCHEMA="$VEX_SCHEMA" VEX_ROOT="$VEX_ROOT" \
    VEX_MATRIX_FAMILIES="$(matrix_families | tr '\n' ' ')" \
    _vex_py generate "$ev" "$ledger" "$today" "$tmp/ident.tsv" "$out"
}

vex_verify() { # <vex> <evidence> [ledger] [today]
  local vx="$1" ev="$2" ledger="${3:-$DEFAULT_LEDGER}" today="${4:-$(date -u +%F)}"
  [ -f "$vx" ] || die "VEX document not found: $vx"
  [ -f "$ev" ] || die "acceptance evidence not found: $ev"
  local tmp; tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" EXIT
  _vex_identity_table "$ev" > "$tmp/ident.tsv"
  VEX_SCHEMA="$VEX_SCHEMA" VEX_ROOT="$VEX_ROOT" \
    VEX_MATRIX_FAMILIES="$(matrix_families | tr '\n' ' ')" \
    _vex_py verify "$ev" "$ledger" "$today" "$tmp/ident.tsv" "$vx"
}

_vex_self_test() {
  # Every case runs against a DISPOSABLE COPY of the real inputs. A self-test
  # that mutates the ambient checkout has already destroyed a policy file in
  # this repository once.
  local tmp ok=0 bad=0
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" EXIT
  # `set +e` because every sabotage case asserts a REFUSAL, and `set +o pipefail`
  # because the diagnostic cases are `<refusing command> 2>&1 | grep -q ...`:
  # under pipefail that pipeline reports the REFUSAL's status, so a correct
  # diagnostic would still read as a failure.
  set +e
  set +o pipefail
  t() { if eval "$2"; then ok=$((ok+1)); echo "ok   - $1"; else bad=$((bad+1)); echo "FAIL - $1"; fi; }

  local EV="$VEX_ROOT/docs/audits/acceptance-multiarch-2026-08-20/acceptance-evidence.json"
  local LED="$VEX_ROOT/policies/vulnerability-exceptions.yaml"
  if [ ! -f "$EV" ]; then echo "SKIP - accepted evidence absent"; return 0; fi
  if ! python3 -c 'import yaml' 2>/dev/null; then echo "SKIP - PyYAML absent"; return 0; fi

  cp "$EV" "$tmp/ev.json"; cp "$LED" "$tmp/led.yaml"
  # The accepted run's acceptances expire 2026-08-31 / 2026-09-01; evaluate on a
  # date inside that window so the happy path is about the DATA, not the clock.
  local DAY=2026-08-25

  # --- H1 happy path, against the REAL committed ledger and REAL evidence ----
  t "H1 generates from the real accepted run and real ledger" \
    "vex_generate '$tmp/ev.json' '$tmp/vex.json' '$tmp/led.yaml' '$DAY' >/dev/null"
  t "H1 the document is valid JSON with statements" \
    "python3 -c 'import json,sys;d=json.load(open(\"$tmp/vex.json\"));sys.exit(0 if d[\"statements\"] else 1)'"
  t "H2 verify accepts what generate produced" \
    "vex_verify '$tmp/vex.json' '$tmp/ev.json' '$tmp/led.yaml' '$DAY' >/dev/null"
  t "H3 generation is deterministic (byte-identical on a second run)" \
    "vex_generate '$tmp/ev.json' '$tmp/vex2.json' '$tmp/led.yaml' '$DAY' >/dev/null && cmp -s '$tmp/vex.json' '$tmp/vex2.json'"
  t "H4 every statement is digest-bound (no tag-scoped product)" \
    "! grep -Eq '\"@id\": \"pkg:oci/[^@]*\\?' '$tmp/vex.json'"
  t "H5 no reachability justification was invented from the ledger" \
    "! grep -q 'vulnerable_code_not_in_execute_path' '$tmp/vex.json'"
  t "H6 accepted risks are published as 'affected', not 'not_affected'" \
    "python3 -c 'import json,sys
d=json.load(open(\"$tmp/vex.json\"))
bad=[s for s in d[\"statements\"] if s[\"foundry\"][\"record_kind\"]==\"exception\" and s[\"status\"]!=\"affected\"]
sys.exit(1 if bad else 0)'"

  # --- S1 statement broader than the evidence: a foreign digest -------------
  python3 - "$tmp/vex.json" "$tmp/s1.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
p = d["statements"][0]["products"][0]
fake = "sha256%3A" + "0" * 64
p["@id"] = p["@id"].split("@")[0] + "@" + fake + "?arch=amd64&tag=prod"
p["identifiers"]["purl"] = p["@id"]
json.dump(d, open(sys.argv[2], "w"), indent=2)
PY
  t "S1 a statement about a digest the run never produced is REFUSED" \
    "! vex_verify '$tmp/s1.json' '$tmp/ev.json' '$tmp/led.yaml' '$DAY' >/dev/null 2>&1"
  t "S1 ...with the 'not one of the child digests' diagnostic" \
    "vex_verify '$tmp/s1.json' '$tmp/ev.json' '$tmp/led.yaml' '$DAY' 2>&1 | grep -q 'not one of the'"

  # --- S2 a package/version tuple never observed ----------------------------
  python3 - "$tmp/vex.json" "$tmp/s2.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["statements"][0]["products"][0]["subcomponents"][0]["@id"] = "pkg:deb/debian/never-installed@9.9.9?arch=amd64"
json.dump(d, open(sys.argv[2], "w"), indent=2)
PY
  t "S2 a package/version tuple never observed is REFUSED" \
    "! vex_verify '$tmp/s2.json' '$tmp/ev.json' '$tmp/led.yaml' '$DAY' >/dev/null 2>&1"
  t "S2 ...with the 'NEVER OBSERVED' diagnostic" \
    "vex_verify '$tmp/s2.json' '$tmp/ev.json' '$tmp/led.yaml' '$DAY' 2>&1 | grep -q 'NEVER OBSERVED'"

  # --- S3 a statement about an advisory the scan did not report -------------
  python3 - "$tmp/vex.json" "$tmp/s3.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["statements"][0]["vulnerability"]["name"] = "CVE-2999-99999"
json.dump(d, open(sys.argv[2], "w"), indent=2)
PY
  t "S3 a disposition for an advisory the scan never reported is REFUSED" \
    "! vex_verify '$tmp/s3.json' '$tmp/ev.json' '$tmp/led.yaml' '$DAY' >/dev/null 2>&1"
  t "S3 ...with the 'inconsistent with the scan' diagnostic" \
    "vex_verify '$tmp/s3.json' '$tmp/ev.json' '$tmp/led.yaml' '$DAY' 2>&1 | grep -q 'inconsistent with the scan'"

  # --- S4 an expired acceptance -------------------------------------------
  t "S4 generation REFUSES once an acceptance has lapsed" \
    "! vex_generate '$tmp/ev.json' '$tmp/s4.json' '$tmp/led.yaml' 2099-01-01 >/dev/null 2>&1"
  t "S4 ...naming the expiry" \
    "vex_generate '$tmp/ev.json' '$tmp/s4.json' '$tmp/led.yaml' 2099-01-01 2>&1 | grep -q 'EXPIRED on'"
  t "S4 verification REFUSES a published document backed by a lapsed record" \
    "! vex_verify '$tmp/vex.json' '$tmp/ev.json' '$tmp/led.yaml' 2099-01-01 >/dev/null 2>&1"

  # --- S5 an unbounded selector -------------------------------------------
  python3 - "$tmp/led.yaml" "$tmp/led-all.yaml" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
d["exceptions"][0]["image"] = "all"
yaml.safe_dump(d, open(sys.argv[2], "w"), default_flow_style=False, allow_unicode=True)
PY
  t "S5 an unbounded 'all' image selector is REFUSED for publication" \
    "! vex_generate '$tmp/ev.json' '$tmp/s5.json' '$tmp/led-all.yaml' '$DAY' >/dev/null 2>&1"
  t "S5 ...with the 'unbounded image selector' diagnostic" \
    "vex_generate '$tmp/ev.json' '$tmp/s5.json' '$tmp/led-all.yaml' '$DAY' 2>&1 | grep -q 'unbounded image selector'"

  # --- S6 a record whose version pin was removed ---------------------------
  python3 - "$tmp/led.yaml" "$tmp/led-nopin.yaml" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
for e in d["exceptions"]:
    e.pop("installed_version", None)
    e.pop("package_versions", None)
yaml.safe_dump(d, open(sys.argv[2], "w"), default_flow_style=False, allow_unicode=True)
PY
  t "S6 a record with no exact version pin is REFUSED" \
    "! vex_generate '$tmp/ev.json' '$tmp/s6.json' '$tmp/led-nopin.yaml' '$DAY' >/dev/null 2>&1"
  t "S6 ...with the 'no exact version pin' diagnostic" \
    "vex_generate '$tmp/ev.json' '$tmp/s6.json' '$tmp/led-nopin.yaml' '$DAY' 2>&1 | grep -q 'no exact version pin'"

  # --- S7 an ungoverned finding -------------------------------------------
  python3 - "$tmp/led.yaml" "$tmp/led-thin.yaml" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
d["exceptions"] = d["exceptions"][1:]
yaml.safe_dump(d, open(sys.argv[2], "w"), default_flow_style=False, allow_unicode=True)
PY
  t "S7 an observed finding with no governing record is REFUSED" \
    "! vex_generate '$tmp/ev.json' '$tmp/s7.json' '$tmp/led-thin.yaml' '$DAY' >/dev/null 2>&1"
  t "S7 ...with the 'no ledger record governs' diagnostic" \
    "vex_generate '$tmp/ev.json' '$tmp/s7.json' '$tmp/led-thin.yaml' '$DAY' 2>&1 | grep -q 'no ledger record governs'"

  # --- S8 an ambiguous pair (same tuple, two conflicting kinds) ------------
  python3 - "$tmp/led.yaml" "$tmp/led-amb.yaml" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
src = d["exceptions"][0]
d.setdefault("not_affected", []).append({
    "cve": src["cve"], "image": src["image"], "package": src["package"],
    "installed_version": src.get("installed_version"),
    "verified_architectures": src.get("verified_architectures"),
    "classification": "vulnerable-code-not-present",
    "evidence": "fixture conflict", "references": ["fixture"],
})
yaml.safe_dump(d, open(sys.argv[2], "w"), default_flow_style=False, allow_unicode=True)
PY
  t "S8 one tuple covered as BOTH accepted-risk and not-affected is REFUSED" \
    "! vex_generate '$tmp/ev.json' '$tmp/s8.json' '$tmp/led-amb.yaml' '$DAY' >/dev/null 2>&1"
  t "S8 ...with the AMBIGUOUS diagnostic" \
    "vex_generate '$tmp/ev.json' '$tmp/s8.json' '$tmp/led-amb.yaml' '$DAY' 2>&1 | grep -q 'AMBIGUOUS'"

  # --- S9 a dropped statement (partial document read as 'all clear') -------
  python3 - "$tmp/vex.json" "$tmp/s9.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["statements"] = d["statements"][1:]
json.dump(d, open(sys.argv[2], "w"), indent=2)
PY
  t "S9 a document missing a disposition for an observed finding is REFUSED" \
    "! vex_verify '$tmp/s9.json' '$tmp/ev.json' '$tmp/led.yaml' '$DAY' >/dev/null 2>&1"
  t "S9 ...with the 'no disposition' diagnostic" \
    "vex_verify '$tmp/s9.json' '$tmp/ev.json' '$tmp/led.yaml' '$DAY' 2>&1 | grep -q 'have no disposition'"

  # --- S10 a mutated ledger after publication ------------------------------
  python3 - "$tmp/led.yaml" "$tmp/led-mut.yaml" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
d["exceptions"][0]["reason"] = "silently rewritten after the document shipped"
yaml.safe_dump(d, open(sys.argv[2], "w"), default_flow_style=False, allow_unicode=True)
PY
  t "S10 a document is REFUSED once its source policy's bytes change" \
    "! vex_verify '$tmp/vex.json' '$tmp/ev.json' '$tmp/led-mut.yaml' '$DAY' >/dev/null 2>&1"

  # --- S11 identity divergence ---------------------------------------------
  python3 - "$tmp/ev.json" "$tmp/ev-badkey.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["children"][0]["child_key"] = "caddy/linux/amd64"      # the pre-platform spelling
json.dump(d, open(sys.argv[2], "w"), indent=2)
PY
  t "S11 a child whose recorded key disagrees with child_key() is REFUSED" \
    "! vex_generate '$tmp/ev-badkey.json' '$tmp/s11.json' '$tmp/led.yaml' '$DAY' >/dev/null 2>&1"
  t "S11 ...with the identity-mismatch diagnostic" \
    "vex_generate '$tmp/ev-badkey.json' '$tmp/s11.json' '$tmp/led.yaml' '$DAY' 2>&1 | grep -q 'ONE identity derivation'"

  # --- NON-VACUITY ---------------------------------------------------------
  # Each sabotage must fail ONLY because of the sabotage: the unmutated document
  # passes the very same verification in the very same conditions.
  t "NON-VACUOUS: the unmutated document still verifies under every check above" \
    "vex_verify '$tmp/vex.json' '$tmp/ev.json' '$tmp/led.yaml' '$DAY' >/dev/null"

  echo "self-test: $ok ok, $bad failed"
  [ "$bad" -eq 0 ]
}

_vex_usage() {
  cat >&2 <<'EOF'
usage:
  generate-vex.sh generate --evidence <acceptance.json> --out <openvex.json>
                           [--ledger FILE] [--today YYYY-MM-DD]
  generate-vex.sh verify   --vex <openvex.json> --evidence <acceptance.json>
                           [--ledger FILE] [--today YYYY-MM-DD]
  generate-vex.sh --self-test
EOF
  exit 2
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  _mode="${1:-}"; shift || true
  _ev=""; _out=""; _vx=""; _led="$DEFAULT_LEDGER"; _today="$(date -u +%F)"
  while [ $# -gt 0 ]; do
    case "$1" in
      --evidence) _ev="${2:?--evidence needs a path}"; shift 2 ;;
      --out)      _out="${2:?--out needs a path}"; shift 2 ;;
      --vex)      _vx="${2:?--vex needs a path}"; shift 2 ;;
      --ledger)   _led="${2:?--ledger needs a path}"; shift 2 ;;
      --today)    _today="${2:?--today needs a date}"; shift 2 ;;
      *) die "unknown argument: $1" ;;
    esac
  done
  case "$_mode" in
    generate) [ -n "$_ev" ] && [ -n "$_out" ] || _vex_usage
              vex_generate "$_ev" "$_out" "$_led" "$_today" ;;
    verify)   [ -n "$_vx" ] && [ -n "$_ev" ] || _vex_usage
              vex_verify "$_vx" "$_ev" "$_led" "$_today" ;;
    --self-test) _vex_self_test && echo "generate-vex.sh: SELF-TEST OK" ;;
    *) _vex_usage ;;
  esac
fi
