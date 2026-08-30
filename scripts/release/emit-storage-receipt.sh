#!/usr/bin/env bash
# =============================================================================
# scripts/release/emit-storage-receipt.sh — #241 phase D, ACTIVE STAGED PATH.
# -----------------------------------------------------------------------------
# Write a foundry.storage-receipt/v1 record describing an evidence bundle that
# was ACTUALLY uploaded, from facts the storage authority reported and from
# bytes read back out of it. Nothing here uploads, provisions or configures
# anything.
#
# THE MECHANISM IS A GITHUB ACTIONS ARTIFACT, AND THE RECEIPT SAYS SO. It has:
#
#   no object lock            -> storage.lock_mode  = "none"
#   no versioning             -> storage.versioning = "not-applicable"
#   no immutability, no WORM  -> nothing here claims either
#   an expiry GitHub assigns  -> storage.retain_until comes from the API's
#                                `expires_at`, NOT from a number this script
#                                computed and hoped matched
#
# That last point is the whole reason this file exists. The repository can set
# `retention-days: 90` on an upload and still be wrong about what happened —
# an organisation policy can cap it lower. The receipt therefore records what
# the authority reported and lets verify-storage-receipt.sh compare THAT against
# policies/retention.yaml. A number the workflow asked for is a request; a
# number the API returned is an observation.
#
# WHAT `version_id` AND `audit_event_id` MEAN HERE. GitHub assigns each artifact
# an `id` and a `node_id`. Neither is a tamper-evident audit-log entry and this
# script does not pretend otherwise — they are identifiers this repository could
# not have invented, retrieved by reading the API back, which is what
# SR-AUTHORITY-UNAVAILABLE exists to require. If GitHub ever stops returning
# them, this refuses rather than inventing a value.
#
# REFUSALS, all producer-side and all named:
#
#   SE-OBSERVATION-ABSENT  the authority reported nothing, or reported a record
#                          missing the fields that make it an observation
#   SE-READBACK-ABSENT     nothing was read back out of the uploaded artifact
#   SE-READBACK-FAILED     what came back is not what was handed over
#   SE-RECORD-UNUSABLE     the authorization record carries no candidate to bind
#
# Usage:
#   emit-storage-receipt.sh --authorization FILE --observation FILE
#       --readback-dir DIR --out FILE [--evidence-class CLASS]
#       [--repository OWNER/REPO] [--retention-policy FILE]
# =============================================================================
set -uo pipefail
_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$_d/../.." && pwd)"

AUTH="" OBS="" RBDIR="" OUT="" CLASS="staged-candidate" REPO=""
POLICY="$ROOT/policies/retention.yaml"
usage() { sed -n '/^# Usage:/,/^# ===/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//' >&2; exit 64; }
while [ $# -gt 0 ]; do
  case "$1" in
    --authorization)    AUTH="${2-}"; shift 2 ;;
    --observation)      OBS="${2-}"; shift 2 ;;
    --readback-dir)     RBDIR="${2-}"; shift 2 ;;
    --out)              OUT="${2-}"; shift 2 ;;
    --evidence-class)   CLASS="${2-}"; shift 2 ;;
    --repository)       REPO="${2-}"; shift 2 ;;
    --retention-policy) POLICY="${2-}"; shift 2 ;;
    -h|--help)          usage ;;
    *)                  echo "unknown argument: $1" >&2; usage ;;
  esac
done
[ -n "$AUTH" ] && [ -n "$OBS" ] && [ -n "$RBDIR" ] && [ -n "$OUT" ] || usage

# A missing validator must NOT pass, for the same reason it must not in the
# verifier: turning "the tool is absent" into success is fail-open.
python3 -c 'import yaml' 2>/dev/null || {
  echo "REFUSE: PyYAML is required to emit a storage receipt" >&2; exit 1; }

SE_AUTH="$AUTH" SE_OBS="$OBS" SE_RB="$RBDIR" SE_OUT="$OUT" SE_CLASS="$CLASS" \
SE_REPO="$REPO" SE_POLICY="$POLICY" SE_SELF="$_d/emit-storage-receipt.sh" \
python3 <<'PY'
import datetime, hashlib, json, os, sys

import yaml


def refuse(code, msg):
    sys.stderr.write("REFUSE [%s]: %s\n" % (code, msg))
    raise SystemExit(1)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


auth_p = os.environ["SE_AUTH"]
obs_p = os.environ["SE_OBS"]
rb = os.environ["SE_RB"]
out_p = os.environ["SE_OUT"]
cls_name = os.environ["SE_CLASS"]
repo = os.environ.get("SE_REPO") or "unknown/unknown"
self_p = os.environ["SE_SELF"]

# --- the authority's own report ---------------------------------------------
# An observation is not "a file exists". It is a record carrying the fields only
# the authority can assign. Any one of them missing means we are about to write
# a durability claim nobody observed.
if not os.path.exists(obs_p) or os.path.getsize(obs_p) == 0:
    refuse("SE-OBSERVATION-ABSENT",
           "no artifact observation at %s. The upload may have happened; this "
           "script cannot say so, and a receipt that guesses is worse than none"
           % obs_p)
try:
    obs = json.load(open(obs_p))
except Exception as exc:                                  # noqa: BLE001
    refuse("SE-OBSERVATION-ABSENT", "%s is not readable JSON: %s" % (obs_p, exc))

for field in ("id", "node_id", "created_at", "expires_at"):
    if not obs.get(field):
        refuse("SE-OBSERVATION-ABSENT",
               "the artifact observation carries no %r. Without it the receipt "
               "would record an expiry, an identity or an upload time this "
               "repository chose for itself" % field)
if obs.get("expired") is True:
    refuse("SE-OBSERVATION-ABSENT",
           "the authority reports artifact %s as ALREADY EXPIRED; there is "
           "nothing to write a retention receipt about" % obs.get("id"))

# --- what came back out of it ------------------------------------------------
sums = os.path.join(rb, "SHA256SUMS")
if not os.path.isfile(sums):
    refuse("SE-READBACK-ABSENT",
           "no SHA256SUMS in the read-back copy at %s. An upload that was never "
           "read back is a claim about durability rather than a measurement" % rb)

files, verified = [], 0
for line in open(sums):
    line = line.strip()
    if not line:
        continue
    want, _, rel = line.partition("  ")
    rel = rel.strip().lstrip("./")
    if len(want) != 64:
        refuse("SE-READBACK-FAILED", "unparseable checksum line: %r" % line)
    disk = os.path.join(rb, rel)
    if not os.path.isfile(disk):
        refuse("SE-READBACK-FAILED",
               "%s is listed in the manifest and is NOT in the read-back copy" % rel)
    got = sha256_file(disk)
    if got != want:
        refuse("SE-READBACK-FAILED",
               "%s came back as %s, was handed over as %s" % (rel, got[:16], want[:16]))
    verified += 1
    files.append({"path": rel, "sha256": got, "bytes": os.path.getsize(disk)})
if not files:
    refuse("SE-READBACK-ABSENT", "the manifest in the read-back copy lists no files")

manifest_sha = sha256_file(sums)

# --- bound to THIS candidate --------------------------------------------------
auth = json.load(open(auth_p))
children = auth.get("children") or []
if not children:
    refuse("SE-RECORD-UNUSABLE",
           "the authorization record names no children, so there is no candidate "
           "for this receipt to be about")
declared = (auth.get("expected_matrix") or {}).get("expected_children") or len(children)
cand = []
for c in children:
    for k in ("child_key", "platform", "manifest_digest"):
        if not c.get(k):
            refuse("SE-RECORD-UNUSABLE",
                   "child %r carries no %r" % (c.get("child_key"), k))
    cand.append({"child_key": c["child_key"], "platform": c["platform"],
                 "manifest_digest": c["manifest_digest"]})

# --- what policy REQUIRES of this class --------------------------------------
pol = yaml.safe_load(open(os.environ["SE_POLICY"]))
klass = next((c for c in pol["classes"] if c["evidence_class"] == cls_name), None)
if klass is None:
    refuse("SE-RECORD-UNUSABLE",
           "policies/retention.yaml declares no class %r" % cls_name)
model = pol["retention_models"][klass["retention_model"]]
days = int(klass["retention_days"])
uploaded = datetime.datetime.fromisoformat(obs["created_at"].replace("Z", "+00:00"))
required_until = uploaded + datetime.timedelta(days=days)

rev = auth.get("source_revision") or ""
# `storage.object_checksum` is DEFINED as the checksum of the bundle: the
# verifier compares it against `bundle.manifest_sha256` and refuses
# SR-CHECKSUM-MISMATCH otherwise. GitHub does return its own `digest` for newer
# artifacts, but that is the hash of the ZIP IT BUILT, over a repacked directory
# — a different object, not a second opinion about this one. Preferring it made
# the drill's first real run refuse a bundle nothing was wrong with. What is
# recorded here is the manifest hash computed from the bytes that came BACK,
# which is a measurement and is the thing the field means.
obj_sum = manifest_sha

rec = {
    "schema": "foundry.storage-receipt/v1",
    "record_type": "storage-receipt",
    "schema_version": 1,
    "bundle": {
        "bundle_id": "%s-%s" % (cls_name, rev[:12]),
        "evidence_class": cls_name,
        "retention_class": cls_name,
        "source_revision": rev,
        "authorization_record_sha256": sha256_file(auth_p),
        "manifest_sha256": manifest_sha,
        "candidate": {"children_expected": declared, "children": cand},
        "producers": [
            {"name": "scripts/release/emit-storage-receipt.sh",
             "sha256": sha256_file(self_p)},
        ],
        "schemas": [str(auth.get("schema") or "foundry.post-build-authorization/v1")],
        "files": files,
    },
    "request": {
        "required_retain_until": required_until.isoformat().replace("+00:00", "Z"),
        # A GitHub artifact offers neither, and asking for them here would be a
        # request this repository knows cannot be met — which is how a policy
        # ends up describing a system nobody runs.
        "required_lock_mode": "none" if not model["worm_required"] else "compliance",
        "required_versioning": bool(model["worm_required"]),
        "required_min_retention_days": days,
    },
    "storage": {
        "provider": "github-actions-artifact",
        "region": "not-applicable",
        "container": repo,
        "object_key": str(obs.get("name") or ""),
        "version_id": str(obs["id"]),
        "audit_event_id": str(obs["node_id"]),
        "retain_until": obs["expires_at"],
        "uploaded_at": obs["created_at"],
        "lock_mode": "none",
        "versioning": "not-applicable",
        "object_checksum": {"algorithm": "SHA256", "value": obj_sum},
    },
    "readback": {
        "performed": True,
        "at": datetime.datetime.now(datetime.timezone.utc)
             .isoformat(timespec="seconds").replace("+00:00", "Z"),
        "files_expected": len(files),
        "files_verified": verified,
        "checksum_match": True,
        "manifest_sha256": manifest_sha,
        # The copy was fetched back FROM GitHub. That proves the bytes survived
        # the round trip; it is NOT an offline restore and is not recorded as one.
        "network_isolated": False,
    },
}

d = os.path.dirname(out_p)
if d:
    os.makedirs(d, exist_ok=True)
with open(out_p, "w") as fh:
    json.dump(rec, fh, indent=2, sort_keys=True)
    fh.write("\n")
sys.stderr.write(
    "storage receipt written: %s (class %s, %d file(s) read back, retained to %s "
    "by the authority's own report)\n"
    % (out_p, cls_name, verified, obs["expires_at"]))
PY
