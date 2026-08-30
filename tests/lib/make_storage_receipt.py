#!/usr/bin/env python3
"""Build a storage receipt for a given authorization record, and sabotage it.

WHY A BUILDER AND NOT A COMMITTED FIXTURE. The receipt is BOUND to an
authorization record by that record's own sha256, so a committed fixture would
be bound to a record committed beside it and would prove only that two files
agree. Building it from whatever record the test is holding is what makes the
binding assertions mean something.

Everything it writes is a FIXTURE. No provider was contacted, nothing was
uploaded, and no `version_id` or `audit_event_id` here came from a storage
authority — the values are shaped like the real ones so the SCHEMA and the
VERIFIER can be exercised, and that is all. A receipt produced by this tool must
never be presented as evidence of durable storage.
"""
import argparse
import datetime
import hashlib
import json
import sys

MUTATIONS = (
    "none", "retention-short", "governance-mode", "no-lock", "versioning-off",
    "checksum-mismatch", "readback-absent", "readback-failed", "file-missing",
    "wrong-candidate", "wrong-digest", "wrong-platform", "wrong-revision",
    "unbound", "authority-unavailable", "encryption-off", "unknown-class",
    "expiry-before-support", "required-not-met",
)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--authorization", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--mutate", choices=MUTATIONS, default="none")
    ap.add_argument("--retention-days", type=int, default=2555)
    ap.add_argument("--uploaded-at", default="2026-08-20T17:10:00Z")
    a = ap.parse_args()

    auth = json.load(open(a.authorization))
    auth_sha = hashlib.sha256(open(a.authorization, "rb").read()).hexdigest()
    children = auth.get("children") or []
    if not children:
        sys.stderr.write("REFUSE: the authorization record stages no children\n")
        return 2

    up = datetime.datetime.fromisoformat(a.uploaded_at.replace("Z", "+00:00"))
    retain = up + datetime.timedelta(days=a.retention_days)

    files = [{"path": "manifest.json", "sha256": "a" * 64, "bytes": 4096},
             {"path": "content/sbom/caddy-prod-linux-amd64.spdx.json",
              "sha256": "b" * 64, "bytes": 466030},
             {"path": "SHA256SUMS", "sha256": "c" * 64, "bytes": 2048}]
    manifest_sha = "d" * 64

    rec = {
        "schema": "foundry.storage-receipt/v1",
        "record_type": "storage-receipt",
        "schema_version": 1,
        "bundle": {
            "bundle_id": "staged-candidate-%s" % auth.get("source_revision", "0" * 40)[:12],
            "evidence_class": "staged-candidate",
            "retention_class": "staged-candidate",
            "source_revision": auth.get("source_revision"),
            "authorization_record_sha256": auth_sha,
            "manifest_sha256": manifest_sha,
            "candidate": {
                "children_expected": len(children),
                "children": [{"child_key": c["child_key"], "platform": c["platform"],
                              "manifest_digest": c["manifest_digest"]} for c in children],
            },
            "producers": [
                {"name": "scripts/release/generate-evidence-bundle.sh", "sha256": "e" * 64},
                {"name": "scripts/generate-sbom.sh", "sha256": "f" * 64},
            ],
            "schemas": ["foundry.release-evidence-bundle/v1", "SPDX-2.3", "CycloneDX-1.5"],
            "files": files,
        },
        "request": {
            "required_retain_until": retain.isoformat().replace("+00:00", "Z"),
            "required_lock_mode": "compliance",
            "required_versioning": True,
            "required_min_retention_days": 2555,
        },
        "storage": {
            "provider": "FIXTURE-provider-not-selected",
            "region": "FIXTURE-region",
            "container": "fixture-evidence-bucket",
            "object_key": "staged-candidate/%s/bundle.tar" % auth.get("source_revision"),
            "version_id": "FIXTUREVERSIONID0001",
            "retain_until": retain.isoformat().replace("+00:00", "Z"),
            "lock_mode": "compliance",
            "versioning": "enabled",
            "encryption": {"at_rest": True, "algorithm": "AES256",
                           "key_management": "customer-managed",
                           "key_deletion_protection": True},
            "object_checksum": {"algorithm": "SHA256", "value": manifest_sha},
            "uploaded_at": up.isoformat().replace("+00:00", "Z"),
            "audit_event_id": "FIXTURE-audit-event-0001",
        },
        "readback": {
            "performed": True,
            "at": (up + datetime.timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
            "files_expected": len(files),
            "files_verified": len(files),
            "checksum_match": True,
            "manifest_sha256": manifest_sha,
            "network_isolated": True,
        },
    }

    m = a.mutate
    if m == "retention-short":
        short = up + datetime.timedelta(days=90)
        rec["storage"]["retain_until"] = short.isoformat().replace("+00:00", "Z")
    elif m == "required-not-met":
        # the class floor is met, but LESS than Foundry itself required
        rec["request"]["required_retain_until"] = (
            (up + datetime.timedelta(days=3000)).isoformat().replace("+00:00", "Z"))
    elif m == "governance-mode":
        rec["storage"]["lock_mode"] = "governance"
    elif m == "no-lock":
        rec["storage"]["lock_mode"] = "none"
    elif m == "versioning-off":
        rec["storage"]["versioning"] = "suspended"
    elif m == "checksum-mismatch":
        rec["storage"]["object_checksum"]["value"] = "9" * 64
    elif m == "readback-absent":
        rec["readback"]["performed"] = False
    elif m == "readback-failed":
        rec["readback"]["checksum_match"] = False
    elif m == "file-missing":
        rec["readback"]["files_verified"] = len(files) - 1
    elif m == "wrong-candidate":
        rec["bundle"]["candidate"]["children"] = \
            rec["bundle"]["candidate"]["children"][:-1]
    elif m == "wrong-digest":
        rec["bundle"]["candidate"]["children"][0]["manifest_digest"] = "sha256:" + "0" * 64
    elif m == "wrong-platform":
        rec["bundle"]["candidate"]["children"][0]["platform"] = "linux/s390x"
    elif m == "wrong-revision":
        rec["bundle"]["source_revision"] = "0" * 40
    elif m == "unbound":
        rec["bundle"]["authorization_record_sha256"] = "0" * 64
    elif m == "authority-unavailable":
        rec["storage"]["audit_event_id"] = ""
        rec["storage"]["version_id"] = ""
    elif m == "encryption-off":
        rec["storage"]["encryption"]["at_rest"] = False
    elif m == "unknown-class":
        rec["bundle"]["retention_class"] = "published-artifact"
        rec["bundle"]["evidence_class"] = "published-artifact"
    elif m == "expiry-before-support":
        pass  # exercised by passing --support-until beyond retain_until

    with open(a.out, "w") as fh:
        fh.write(json.dumps(rec, indent=2, sort_keys=True) + "\n")
    sys.stderr.write("storage receipt fixture: %s (mutate=%s, %d day(s))\n"
                     % (a.out, m, a.retention_days))
    return 0


if __name__ == "__main__":
    sys.exit(main())
