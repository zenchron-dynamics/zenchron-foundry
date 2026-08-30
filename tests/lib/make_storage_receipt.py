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
    # lifecycle model cases (2026-08-30 correction)
    "no-release-binding", "release-short", "already-expired", "bad-model",
    # published-bundle independence (2026-08-30)
    "published-no-evidence", "published-verdict-not-carried",
    "published-auth-not-carried", "published-references-transient",
)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--authorization", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--mutate", choices=MUTATIONS, default="none")
    ap.add_argument("--retention-days", type=int, default=90)
    ap.add_argument("--retention-class", default="staged-candidate")
    ap.add_argument("--lock-mode", default="none",
                    choices=("none", "governance", "compliance"))
    ap.add_argument("--versioning", default="not-applicable",
                    choices=("enabled", "suspended", "disabled", "not-applicable"))
    ap.add_argument("--published-evidence", action="store_true",
                    help="compose the published-artifact evidence INTO the bundle")
    ap.add_argument("--supported-until", default=None,
                    help="set to make this a supported-release-lifetime receipt")
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
            "evidence_class": a.retention_class,
            "retention_class": a.retention_class,
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
            "required_lock_mode": "compliance" if a.lock_mode == "compliance"
                                  else "governance",
            "required_versioning": True,
            "required_min_retention_days": a.retention_days,
        },
        "storage": {
            "provider": "FIXTURE-provider-not-selected",
            "region": "FIXTURE-region",
            "container": "fixture-evidence-bucket",
            "object_key": "staged-candidate/%s/bundle.tar" % auth.get("source_revision"),
            "version_id": "FIXTUREVERSIONID0001",
            "retain_until": retain.isoformat().replace("+00:00", "Z"),
            "lock_mode": a.lock_mode,
            "versioning": a.versioning,
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

    if a.published_evidence:
        # The published bundle CARRIES its evidence: every sha256 named below is
        # also a file in the bundle, which is what makes "carried" checkable.
        verdicts = [{"child_key": c["child_key"], "sha256": "%064x" % (0x5CA4 + i)}
                    for i, c in enumerate(children[:3])]
        authsha = "%064x" % 0xA07
        for v in verdicts:
            files.append({"path": "content/scan/%s.trivy.json" % v["child_key"].replace("/", "-"),
                          "sha256": v["sha256"], "bytes": 228458})
        files.append({"path": "content/authorization/post-build-authorization.json",
                      "sha256": authsha, "bytes": 44946})
        rec_pe = {
            "image_digests": [c["manifest_digest"] for c in children],
            "scan_verdicts": verdicts,
            "authorization_record_sha256": authsha,
            "scanner": {"image": "anchore/syft",
                        "digest": "sha256:" + "f9" * 32},
            "vulnerability_database": {
                "identity": "v2+updated:2026-08-20T13:14:11Z+next:2026-08-21T13:14:11Z",
                "observed_at": "2026-08-20T13:14:11Z"},
            "source_revision": auth.get("source_revision"),
            "policy_identity": {"licence_policy_sha256": "%064x" % 0x11,
                                "retention_policy_sha256": "%064x" % 0x12},
            "ledger_identity": {"vulnerability_exceptions_sha256": "%064x" % 0x13},
        }
        rec["bundle"]["published_evidence"] = rec_pe
        rec["bundle"]["files"] = files
        rec["readback"]["files_expected"] = len(files)
        rec["readback"]["files_verified"] = len(files)

    if a.supported_until:
        su = datetime.datetime.fromisoformat(a.supported_until.replace("Z", "+00:00"))
        rec["bundle"]["release"] = {
            "release": "v2026.07.24",
            "supported_until": su.isoformat().replace("+00:00", "Z"),
            "support_state": "active",
        }

    m = a.mutate
    pe = rec["bundle"].get("published_evidence")
    if m == "published-no-evidence":
        rec["bundle"].pop("published_evidence", None)
    elif m == "published-verdict-not-carried" and pe:
        # named, but its bytes are not in files[] — a reference wearing the word
        pe["scan_verdicts"][0]["sha256"] = "%064x" % 0xDEAD
    elif m == "published-auth-not-carried" and pe:
        pe["authorization_record_sha256"] = "%064x" % 0xBEEF
    elif m == "published-references-transient" and pe:
        pe["transient_references"] = [
            {"name": "child-caddy-prod-linux-amd64-32395890071-1",
             "kind": "github-actions-artifact",
             "expires_at": "2026-11-18T17:07:58Z"}]
    elif m == "no-release-binding":
        rec["bundle"].pop("release", None)
    elif m == "release-short":
        # retained past the class floor in days, but short of support end + buffer
        rec["storage"]["retain_until"] = (up + datetime.timedelta(days=300)) \
            .isoformat().replace("+00:00", "Z")
    elif m == "already-expired":
        past = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
        rec["storage"]["uploaded_at"] = (past - datetime.timedelta(days=400)) \
            .isoformat().replace("+00:00", "Z")
        rec["storage"]["retain_until"] = past.isoformat().replace("+00:00", "Z")
        rec["request"]["required_retain_until"] = past.isoformat().replace("+00:00", "Z")
    elif m == "bad-model":
        pass  # exercised by pointing at a policy whose class names an unknown model
    elif m == "retention-short":
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
