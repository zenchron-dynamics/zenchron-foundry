#!/usr/bin/env bash
# =============================================================================
# scripts/release/verify-storage-receipt.sh <receipt.json> --authorization FILE
#     [--retention-policy FILE] [--schema FILE] [--today YYYY-MM-DD]
# -----------------------------------------------------------------------------
# A CLAIMED UPLOAD IS NOT EVIDENCE. This consumes a storage receipt and refuses
# unless the storage authority OBSERVED, after the write, everything the policy
# requires. Every check below is against something the authority reported back,
# never against what Foundry asked for.
#
# WHAT THIS IS NOT. It provisions nothing, uploads nothing, and talks to no
# provider. It reads a receipt somebody else produced. The provider decision is
# the owner's (#241) and nothing here presumes one — `provider` and `region` are
# recorded and never constrained.
#
# THE REQUIRED PERIOD AND THE REQUIRED STORAGE PROPERTIES COME FROM
# policies/retention.yaml, not from numbers written here. A floor hardcoded in a
# verifier is a second copy of the policy and the first thing to disagree with
# it — which is how a seven-year requirement nobody approved survived for a week.
#
# RETENTION FOLLOWS LIFECYCLE. Three models, and the class picks one:
#
#   repository-artifact          unpublished. The repository's own artifact
#                                period. Evidence MAY EXPIRE. No lock required,
#                                no versioning required, no encryption claim
#                                required — a GitHub artifact offers none of them
#                                and demanding them would refuse the only
#                                mechanism actually in use.
#   supported-release-lifetime   published. retain-until is computed from the
#                                RELEASE's own support end plus the notice
#                                buffers, never from the date the bundle was
#                                written, because two releases of different lines
#                                have different support ends.
#   regulated-worm               compliance-mode lock, versioning, encryption —
#                                and ONLY where the class records a named
#                                external obligation with a duration, a
#                                jurisdiction or contract, an approver and a
#                                date. A WORM class with no authority REFUSES.
#                                That refusal exists because the previous
#                                seven-year rule was assigned silently.
#
# COMPLIANCE MODE IS NOT THE DEFAULT AND IS NOT REQUIRED OF ORDINARY EVIDENCE.
# Where a class DOES require it, governance mode still refuses: under governance
# a privileged principal can shorten or delete before the retain-until date, so
# it is a retention control and not immutability. Both halves matter — requiring
# it everywhere was the old defect; allowing it to be claimed loosely would be a
# new one.
#
# EVERY REFUSAL CARRIES ITS OWN CODE. "It failed" is not a diagnostic.
#
#   SR-RECEIPT-ABSENT        no receipt was presented at all
#   SR-RECEIPT-MALFORMED     it is not a foundry.storage-receipt/v1 record
#   SR-AUTHORITY-UNAVAILABLE the authority reported no observation to check
#   SR-UNBOUND               it is a receipt for a DIFFERENT authorization record
#   SR-REVISION-MISMATCH     it is a receipt for a different source tree
#   SR-CANDIDATE-MISMATCH    its child set, digests or platforms are not these
#   SR-RETENTION-SHORT       retain_until is sooner than the policy requires
#   SR-RETENTION-MODEL       the class names a model this verifier cannot enforce
#   SR-RELEASE-BINDING-ABSENT  a supported-release class with no release identity
#   SR-PUBLISHED-INCOMPLETE  a published bundle is missing required evidence, or
#                            names it without carrying its bytes
#   SR-PUBLISHED-REFERENCES-TRANSIENT  a published bundle points at something
#                            that expires before the bundle must
#   SR-EVIDENCE-EXPIRED      retention lapsed on a class that may NOT expire
#   SR-REGULATED-UNAUTHORIZED  a WORM class with no named external obligation
#   SR-LOCK-MODE-WEAK        the lock is weaker than the class requires
#   SR-VERSIONING-ABSENT     without versioning an overwrite is invisible
#   SR-CHECKSUM-MISMATCH     the stored object is not the bytes handed over
#   SR-FILE-MISSING          a file in the bundle did not reach storage
#   SR-READBACK-ABSENT       nothing was read back
#   SR-READBACK-FAILED       what was read back did not verify
#   SR-EXPIRY-BEFORE-SUPPORT retention ends inside the supported period
#   SR-ENCRYPTION-ABSENT     the object is not encrypted at rest
#
# Usage:
#   verify-storage-receipt.sh RECEIPT --authorization FILE [--retention-policy F]
#       [--schema F] [--today YYYY-MM-DD] [--support-until YYYY-MM-DD]
# =============================================================================
set -uo pipefail
_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$_d/../.." && pwd)"

RECEIPT="" AUTH="" POLICY="$ROOT/policies/retention.yaml"
SCHEMA="$ROOT/schemas/storage-receipt-v1.schema.json"
TODAY="" SUPPORT_UNTIL=""
usage() { sed -n '/^# Usage:/,/^# ===/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//' >&2; exit 64; }
while [ $# -gt 0 ]; do
  case "$1" in
    --authorization)    AUTH="${2-}"; shift 2 ;;
    --retention-policy) POLICY="${2-}"; shift 2 ;;
    --schema)           SCHEMA="${2-}"; shift 2 ;;
    --today)            TODAY="${2-}"; shift 2 ;;
    --support-until)    SUPPORT_UNTIL="${2-}"; shift 2 ;;
    -h|--help)          usage ;;
    *)                  RECEIPT="$1"; shift ;;
  esac
done
[ -n "$AUTH" ] || usage

# A missing validator must NOT pass. Turning "the tool is absent" into success is
# the fail-open shape this repository keeps removing.
python3 -c 'import yaml, jsonschema' 2>/dev/null || {
  echo "REFUSE: PyYAML and jsonschema are required to verify a storage receipt" >&2
  exit 1; }

SR_RECEIPT="$RECEIPT" SR_AUTH="$AUTH" SR_POLICY="$POLICY" SR_SCHEMA="$SCHEMA" \
SR_TODAY="$TODAY" SR_SUPPORT_UNTIL="$SUPPORT_UNTIL" python3 <<'PY'
import datetime, hashlib, json, os, sys

import jsonschema
import yaml

rec_p = os.environ["SR_RECEIPT"]
auth_p = os.environ["SR_AUTH"]
pol_p = os.environ["SR_POLICY"]
schema_p = os.environ["SR_SCHEMA"]
today_s = os.environ.get("SR_TODAY") or ""
support_s = os.environ.get("SR_SUPPORT_UNTIL") or ""


def refuse(code, msg):
    sys.stderr.write("REFUSE [%s]: %s\n" % (code, msg))
    raise SystemExit(1)


def parse_dt(v, what):
    try:
        s = str(v).replace("Z", "+00:00")
        d = datetime.datetime.fromisoformat(s)
        return d if d.tzinfo else d.replace(tzinfo=datetime.timezone.utc)
    except (TypeError, ValueError):
        refuse("SR-RECEIPT-MALFORMED", "%s is not an ISO-8601 instant: %r" % (what, v))


if not rec_p or not os.path.isfile(rec_p) or os.path.getsize(rec_p) == 0:
    refuse("SR-RECEIPT-ABSENT",
           "a storage receipt was REQUIRED and none was presented (%s). An "
           "absent receipt is a refusal, never a skip: authorization that "
           "proceeds without one asserts a durability nobody observed"
           % (rec_p or "<empty path>"))
try:
    rec = json.load(open(rec_p))
except ValueError as e:
    refuse("SR-RECEIPT-MALFORMED", "%s is not readable JSON: %s" % (rec_p, e))

errs = sorted(jsonschema.Draft202012Validator(json.load(open(schema_p))).iter_errors(rec),
              key=lambda e: list(e.path))
if errs:
    refuse("SR-RECEIPT-MALFORMED",
           "%s does not satisfy storage-receipt-v1: %s"
           % (rec_p, "; ".join("%s: %s" % ("/".join(str(x) for x in e.path) or "<root>",
                                           e.message) for e in errs[:4])))

b, req, st, rb = rec["bundle"], rec["request"], rec["storage"], rec["readback"]

# --- the authority actually observed something ------------------------------
if not st.get("audit_event_id") or not st.get("version_id"):
    refuse("SR-AUTHORITY-UNAVAILABLE",
           "the receipt carries no audit event or object version, so nothing in "
           "it was observed by a storage authority. A receipt Foundry could have "
           "written for itself proves nothing about durability")

# --- BOUND to this candidate, not merely filed beside it --------------------
auth = json.load(open(auth_p))
want = hashlib.sha256(open(auth_p, "rb").read()).hexdigest()
if b.get("authorization_record_sha256") != want:
    refuse("SR-UNBOUND",
           "%s is a receipt for authorization record %s; this record hashes to "
           "%s. A receipt about another candidate decides nothing about this one"
           % (rec_p, str(b.get("authorization_record_sha256"))[:16], want[:16]))

if b.get("source_revision") != auth.get("source_revision"):
    refuse("SR-REVISION-MISMATCH",
           "the receipt is for source revision %s and this record was written "
           "for %s" % (b.get("source_revision"), auth.get("source_revision")))

by_key = {str(c.get("child_key")): c for c in auth.get("children") or []}
declared = (auth.get("expected_matrix") or {}).get("expected_children") or len(by_key)
if b["candidate"].get("children_expected") != declared:
    refuse("SR-CANDIDATE-MISMATCH",
           "the receipt covers %s children and this record declares %s. A "
           "receipt over a partial matrix stores evidence for the images it "
           "happened to see" % (b["candidate"].get("children_expected"), declared))
seen = set()
for c in b["candidate"]["children"]:
    k = str(c.get("child_key"))
    seen.add(k)
    r = by_key.get(k)
    if r is None:
        refuse("SR-CANDIDATE-MISMATCH",
               "the receipt names child %r, which this record does not stage" % k)
    if c.get("manifest_digest") != r.get("manifest_digest"):
        refuse("SR-CANDIDATE-MISMATCH",
               "child %s: the receipt names digest %s and this record stages %s"
               % (k, str(c.get("manifest_digest"))[:23], str(r.get("manifest_digest"))[:23]))
    if c.get("platform") != r.get("platform"):
        refuse("SR-CANDIDATE-MISMATCH",
               "child %s: the receipt names platform %r and this record stages %r"
               % (k, c.get("platform"), r.get("platform")))
missing = sorted(set(by_key) - seen)
if missing:
    refuse("SR-CANDIDATE-MISMATCH",
           "%d staged child(ren) have no evidence in this receipt: %s"
           % (len(missing), ", ".join(missing[:4])))

# --- the retention floor comes from the POLICY ------------------------------
pol = yaml.safe_load(open(pol_p)) or {}
classes = {c.get("evidence_class"): c for c in pol.get("classes") or []}
cls = classes.get(b.get("retention_class"))
if cls is None:
    refuse("SR-RECEIPT-MALFORMED",
           "retention_class %r is not a class declared in %s. A retention rule "
           "for a class nobody declares is a rule about nothing"
           % (b.get("retention_class"), os.path.basename(pol_p)))
models = pol.get("retention_models") or {}
model_name = cls.get("retention_model")
model = models.get(model_name)
if model is None:
    refuse("SR-RETENTION-MODEL",
           "class %r names retention model %r, which %s does not declare. A "
           "retention rule whose model nothing defines is a rule nothing enforces"
           % (b.get("retention_class"), model_name, os.path.basename(pol_p)))

need_days = int(cls.get("retention_days") or 0)
need_worm = bool(model.get("worm_required"))
need_immutable = bool(model.get("immutable_storage_required")) or \
    bool(cls.get("immutable_storage_required"))

# --- regulated retention cannot be assigned silently ------------------------
# The seven-year rule arrived with no named obligation and no approver, and
# survived because nothing checked. This is that check.
if need_worm:
    ob = cls.get("external_obligation") or {}
    missing = [k for k in ("name", "duration", "jurisdiction_or_contract",
                           "approved_by", "approved_on") if not ob.get(k)]
    if missing:
        refuse("SR-REGULATED-UNAUTHORIZED",
               "class %r uses retention model %r, which is write-once storage, "
               "and its external_obligation is missing %s. WORM retention is "
               "available only where a NAMED obligation demands it, with a "
               "duration, a jurisdiction or contract, a named approver and a "
               "date. A regulated class nobody authorised is exactly the defect "
               "this repository has already paid for once"
               % (b.get("retention_class"), model_name, ", ".join(missing)))

today = (datetime.datetime.fromisoformat(today_s).replace(tzinfo=datetime.timezone.utc)
         if today_s else datetime.datetime.now(datetime.timezone.utc))
uploaded = parse_dt(st.get("uploaded_at"), "storage.uploaded_at")
retain_until = parse_dt(st.get("retain_until"), "storage.retain_until")
required_until = parse_dt(req.get("required_retain_until"), "request.required_retain_until")

# CALENDAR DAYS, not a timedelta. GitHub stamps an artifact's `expires_at` from
# when the upload STARTED and its `created_at` from when the upload FINISHED, so
# a genuine 90-day artifact reports 89 days and 23-something hours and a
# timedelta's `.days` truncates that to 89. The first real observation this
# verifier ever saw refused for that reason and nothing was wrong with it.
# Comparing dates is not a relaxation: an artifact actually granted 89 days
# still measures 89 here, which is what the 89-day sabotage proves.
actual_days = (retain_until.date() - uploaded.date()).days

if model_name == "supported-release-lifetime":
    # The floor is the RELEASE's support end plus the notice buffers the support
    # policy already promises — not `uploaded + retention_days`, which would give
    # every release the same lifetime regardless of what it is.
    rel = b.get("release") or {}
    if not rel.get("supported_until"):
        refuse("SR-RELEASE-BINDING-ABSENT",
               "class %r is retained for the supported lifetime of a release and "
               "the receipt names no release support end. Evidence cannot track a "
               "lifecycle it does not identify"
               % b.get("retention_class"))
    supported_until = parse_dt(rel.get("supported_until"), "bundle.release.supported_until")
    buffer_days = int(cls.get("buffer_deprecation_days") or 0) + \
        int(cls.get("buffer_withdrawal_days") or 0)
    floor = supported_until + datetime.timedelta(days=buffer_days)
    if retain_until < floor:
        refuse("SR-RETENTION-SHORT",
               "release %s is supported to %s and class %r adds a %d-day notice "
               "buffer, so the evidence must be retained to %s. The receipt says "
               "%s. Evidence that dies before the support commitment it justifies "
               "cannot answer a question asked during it"
               % (rel.get("release", "<unnamed>"), supported_until.date(),
                  b["retention_class"], buffer_days, floor.date(),
                  retain_until.date()))
elif actual_days < need_days:
    refuse("SR-RETENTION-SHORT",
           "the object is retained for %d day(s) (%s to %s) and class %r requires "
           "%d. Authorization cannot complete when the evidence expires before "
           "the period policy assigns it"
           % (actual_days, uploaded.date(), retain_until.date(),
              b["retention_class"], need_days))

# --- DETECTION: evidence that has already lapsed ---------------------------
# The published mechanism has no expiry timer and no immutability, so its failure
# mode is silent absence rather than clean expiry, and a lapsed published receipt
# describes something nobody can rely on being there.
#
# An UNPUBLISHED class is different and the difference is the whole lifecycle
# argument: a staged candidate is private and undistributed, its policy says
# `may_expire: true`, and its expiry is an accepted outcome rather than a
# release-retention violation. Refusing it here would re-import the deleted
# requirement through the back door.
may_expire = bool(cls.get("may_expire"))
if retain_until < today:
    if not may_expire:
        refuse("SR-EVIDENCE-EXPIRED",
               "the retention for class %r lapsed on %s and today is %s. A "
               "receipt for evidence past its retention is a record of something "
               "that may no longer exist"
               % (b["retention_class"], retain_until.date(), today.date()))
    sys.stderr.write(
        "NOTE: class %r lapsed on %s and its policy permits expiry "
        "(may_expire: true). Nothing was distributed, so no release retention is "
        "violated.\n" % (b["retention_class"], retain_until.date()))
# Calendar dates here too, and for the same reason as actual_days above: the
# request is computed from `created_at` and the grant is stamped from the start
# of the upload, so an artifact that got exactly what was asked for can arrive a
# few seconds short of it. A grant that is short by a DAY still refuses.
if retain_until.date() < required_until.date():
    refuse("SR-RETENTION-SHORT",
           "the authority returned retain_until %s and Foundry required %s. What "
           "was asked for is not the check; what came back is"
           % (retain_until.date(), required_until.date()))

if support_s:
    support_until = datetime.datetime.fromisoformat(support_s).replace(
        tzinfo=datetime.timezone.utc)
    if retain_until < support_until:
        refuse("SR-EXPIRY-BEFORE-SUPPORT",
               "the evidence expires %s and the supported release period runs to "
               "%s. Evidence that dies inside the support window cannot answer a "
               "question asked during it"
               % (retain_until.date(), support_until.date()))

# --- A PUBLISHED BUNDLE CARRIES ITS EVIDENCE, IT DOES NOT POINT AT IT --------
# A bundle is only as durable as the shortest-lived thing it depends on. If the
# published record merely referenced the 90-day transport artifacts, it would be
# incomplete long before the support commitment it justifies ends — and it would
# LOOK complete on the day it was written, which is the failure mode worth
# refusing.
if cls.get("lifecycle") == "published-supported":
    pe = b.get("published_evidence")
    if not pe:
        refuse("SR-PUBLISHED-INCOMPLETE",
               "class %r is retained for a release's supported lifetime and the "
               "bundle carries no published_evidence block. Evidence that is not "
               "in the bundle is evidence the bundle does not have"
               % b["retention_class"])
    have = {f["sha256"] for f in b["files"]}
    for v in pe.get("scan_verdicts") or []:
        if v["sha256"] not in have:
            refuse("SR-PUBLISHED-INCOMPLETE",
                   "the scan verdict for %s is named as sha256 %s and no file in "
                   "this bundle has those bytes. Naming evidence is not carrying "
                   "it" % (v["child_key"], v["sha256"][:16]))
    if pe["authorization_record_sha256"] not in have:
        refuse("SR-PUBLISHED-INCOMPLETE",
               "the authorization record is named as sha256 %s and no file in "
               "this bundle has those bytes"
               % pe["authorization_record_sha256"][:16])
    transient = pe.get("transient_references") or []
    if transient:
        worst = min(parse_dt(t["expires_at"], "transient_references.expires_at")
                    for t in transient)
        refuse("SR-PUBLISHED-REFERENCES-TRANSIENT",
               "this published bundle points at %d transient artifact(s) instead "
               "of carrying them — %s — the earliest expiring on %s, while the "
               "bundle must stay complete until %s. A bundle is only as durable "
               "as the shortest-lived thing it depends on"
               % (len(transient), ", ".join(t["name"] for t in transient[:3]),
                  worst.date(), retain_until.date()))

# --- COMPLIANCE MODE IS NOT GOVERNANCE MODE ---------------------------------
mode = st.get("lock_mode")
if need_worm and mode == "none":
    refuse("SR-LOCK-MODE-WEAK",
           "class %r requires write-once storage and the object carries no lock "
           "at all. A retain-until date with no lock behind it is a label"
           % b["retention_class"])
if need_immutable and mode != "compliance":
    refuse("SR-LOCK-MODE-WEAK",
           "class %r requires immutable storage and the object is in %r mode. "
           "Under governance mode a sufficiently privileged principal can shorten "
           "the retention or delete the object before %s, so the evidence is "
           "retained by POLICY and not by the storage. That is a retention "
           "control; it is not immutability, and this refusal exists so the two "
           "are not reported as the same thing"
           % (b["retention_class"], mode, retain_until.date()))
if need_worm and req.get("required_lock_mode") == "compliance" \
        and mode != "compliance":
    refuse("SR-LOCK-MODE-WEAK",
           "compliance mode was required and %r was returned" % mode)

# Versioning and an encryption claim are properties of WORM storage. A GitHub
# artifact and a release asset offer neither, and demanding them of ordinary
# evidence would refuse the only mechanism actually in use — which is how a
# policy ends up describing a system nobody runs.
if need_worm:
    if st.get("versioning") != "enabled":
        refuse("SR-VERSIONING-ABSENT",
               "class %r requires write-once storage and object versioning is %r. "
               "Without it an overwrite is indistinguishable from the original "
               "object, and object lock has nothing to pin"
               % (b["retention_class"], st.get("versioning")))
    enc = st.get("encryption") or {}
    if not enc.get("at_rest"):
        refuse("SR-ENCRYPTION-ABSENT",
               "class %r requires write-once storage and the object is not "
               "encrypted at rest" % b["retention_class"])

# --- the bytes that arrived are the bytes handed over -----------------------
if st["object_checksum"]["value"] != b["manifest_sha256"]:
    refuse("SR-CHECKSUM-MISMATCH",
           "the stored object checksums to %s and the bundle manifest hashes to "
           "%s. An object that is not the bundle is not this bundle's receipt"
           % (st["object_checksum"]["value"][:16], b["manifest_sha256"][:16]))

# --- the readback is the observation that makes it evidence -----------------
if rb.get("performed") is not True:
    refuse("SR-READBACK-ABSENT",
           "no readback was performed. An upload that was never read back is a "
           "claim about durability, not a measurement of it")
if rb.get("files_expected") != len(b["files"]):
    refuse("SR-FILE-MISSING",
           "the bundle carries %d file(s) and the readback expected %s. A readback "
           "over fewer files than were handed over verifies the ones it happened "
           "to look at" % (len(b["files"]), rb.get("files_expected")))
if rb.get("files_verified") != rb.get("files_expected"):
    refuse("SR-FILE-MISSING",
           "%s of %s file(s) verified on readback"
           % (rb.get("files_verified"), rb.get("files_expected")))
if rb.get("checksum_match") is not True:
    refuse("SR-READBACK-FAILED",
           "the readback reports checksum_match=%r" % rb.get("checksum_match"))
if rb.get("manifest_sha256") != b["manifest_sha256"]:
    refuse("SR-READBACK-FAILED",
           "the readback manifest hashes to %s and the bundle manifest to %s"
           % (str(rb.get("manifest_sha256"))[:16], b["manifest_sha256"][:16]))

print("storage receipt VERIFIED: class %s, model %s, %s %s/%s, lock=%s, "
      "retained %d day(s) to %s, %d file(s) read back"
      % (b["retention_class"], model_name, st["provider"], st["container"],
         st["object_key"], mode, actual_days, retain_until.date(),
         rb["files_verified"]))
PY
