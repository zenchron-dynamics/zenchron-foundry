#!/usr/bin/env python3
# =============================================================================
# tests/lib/make_authorization_fixture.py
# -----------------------------------------------------------------------------
# TEST FIXTURE ONLY. THIS IS NOT A WAY TO MINT AN AUTHORIZATION.
#
# It reconstructs, from an already-accepted acceptance-evidence record, the
# post-build authorization record that scripts/release/authorize-staged-
# candidates.sh produced for that same run — so the OFFLINE self-tests can
# exercise the authorization binding without a surviving workflow artifact. The
# real record is a 30-day GitHub artifact, and for the committed multiarch run
# it has expired; that expiry is the whole reason the evidence bundle exists.
#
# WHY IT LIVES UNDER tests/ AND NOT UNDER scripts/.
#
# A tool in scripts/ that derives a canonical-looking authorization from an
# acceptance record would let anybody manufacture an "authorization" for any
# acceptance record they hold. That is not a fixture generator, it is a bypass
# of the gate the record exists to be. Nothing under scripts/ may call this
# outside its own --self-test, and a self-test that cannot find it SKIPS the
# case rather than passing it.
#
# The record it emits is derived ENTIRELY from the acceptance evidence, so it
# asserts nothing the accepted run did not already record. It is never written
# into docs/audits/: a reconstruction filed beside real audit records is a
# reconstruction somebody will later read as one.
#
# Usage:
#   make_authorization_fixture.py <acceptance.json> <out.json> [sabotage ...]
#
# Sabotages, each producing a record that is internally consistent and WRONG in
# exactly one way, so a refusal can be attributed:
#   --revision SHA        a record describing a different source revision
#   --malformed-revision  source_revision that is not 40 lowercase hex
#   --drop-source-revision   omit the property entirely (schema-invalid)
#   --drop-child N        authorize one fewer child than the run produced
#   --extra-child         authorize a child the run never produced
#   --verdict FAIL        a refused authorization
#   --db-identity S       a different frozen vulnerability database
#   --platforms A,B       a different declared platform set
#   --evidence-sha SHA    replace the first child's evidence checksum
#   --schema-invalid      a type violation the aggregator never inspects
# =============================================================================
import argparse
import json
import sys

REPOSITORY = "zenchron-dynamics/zenchron-foundry"
WORKFLOW_REF = (
    "zenchron-dynamics/zenchron-foundry/.github/workflows/"
    "stage-and-authorize.yml@refs/heads/master"
)
STAGING_PACKAGE = "ghcr.io/zenchron-dynamics/foundry-staging"


def _native_gate(ev):
    """Reconstruct the native-architecture gate result from the evidence."""
    arm = [c for c in ev["children"] if c["platform"] == "linux/arm64"]
    native = [c for c in arm if c.get("execution_mode") == "native"]
    if not arm:
        verdict = "NOT_REQUIRED"
    elif len(native) == len(arm):
        verdict = "PASS"
    else:
        verdict = "FAIL"
    return {
        "policy": "policies/native-arch-requirements.yaml",
        "required": "true" if arm else "false",
        "platform": "linux/arm64",
        "verdict": verdict,
        "evidence_records": len(native),
        "covered_images": len({c["image_label"] for c in native}),
        "expected_images": len({c["image_label"] for c in arm}),
    }


def build(ev):
    ar = ev["authorization_record"]
    acc = ev["acceptance"]
    mx = ev["matrix"]
    db = ev["frozen_vulnerability_database"]["identity"]
    rev = ev["source_revision"]
    run_id = int(acc["workflow_run_id"])
    attempt = int(acc.get("workflow_run_attempt") or 1)
    return {
        "schema_version": 1,
        "repository": REPOSITORY,
        "source_revision": rev,
        "workflow_run_id": run_id,
        "workflow_run_attempt": attempt,
        "workflow_ref": WORKFLOW_REF,
        "generated_at": ar["generated_at"],
        "build_created": ar["build_created"],
        "trivy_db_snapshot": {"identity": db, "frozen": True},
        "staging_package": STAGING_PACKAGE,
        "expected_matrix": {
            "images": len({c["image_label"] for c in ev["children"]}),
            "platforms": sorted({c["platform"] for c in ev["children"]}),
            "expected_children": int(mx["expected_children"]),
        },
        "children": [
            {
                "child_key": c["child_key"],
                "image_label": c["image_label"],
                "platform": c["platform"],
                "manifest_digest": c["manifest_digest"],
                "digest_reference": c["digest_reference"],
                "staging_tag": c["staging_tag"],
                "tag_resolved_digest": c["manifest_digest"],
                "visibility": "private",
                "manifest_media_type": "application/vnd.oci.image.manifest.v1+json",
                "config_architecture": c["config_architecture"],
                "trivy_db_identity": db,
                "source_revision": rev,
                "workflow_run_id": run_id,
                "workflow_run_attempt": attempt,
                "repository": REPOSITORY,
                "smoke_test": c["smoke_test"],
                "scan": c["scan"],
                "reconciliation": c["reconciliation"],
                "metadata_contract": c["metadata_contract"],
                "execution_mode": c["execution_mode"],
                "host_architecture": c["host_architecture"],
                "runner_name": c["runner_name"],
                "evidence_sha256": c["evidence_sha256"],
            }
            for c in ev["children"]
        ],
        # The #111 native-architecture gate's result, DERIVED from the evidence
        # rather than asserted: an emulated run reconstructs as a FAILING gate,
        # a native one as a passing gate. A fixture that always reported PASS
        # would let the seal's native requirement pass over emulated evidence,
        # which is the exact thing it exists to refuse.
        "native_arch_gate": _native_gate(ev),
        "authorization_scope": ar["authorization_scope"],
        "public_exposure_authorized": bool(ar["public_exposure_authorized"]),
        "verdict": acc["verdict"],
    }


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("evidence")
    ap.add_argument("out")
    ap.add_argument("--revision")
    ap.add_argument("--malformed-revision", action="store_true")
    ap.add_argument("--drop-source-revision", action="store_true")
    ap.add_argument("--drop-child", type=int)
    ap.add_argument("--extra-child", action="store_true")
    ap.add_argument("--verdict")
    ap.add_argument("--db-identity")
    ap.add_argument("--platforms")
    ap.add_argument("--evidence-sha")
    ap.add_argument("--schema-invalid", action="store_true")
    ap.add_argument("--native-gate", choices=["PASS", "FAIL", "NOT_REQUIRED"],
                    help="force native_arch_gate.verdict, independently of the evidence")
    a = ap.parse_args(argv)

    rec = build(json.load(open(a.evidence)))

    if a.native_gate:
        rec["native_arch_gate"]["verdict"] = a.native_gate
    if a.revision:
        rec["source_revision"] = a.revision
        for c in rec["children"]:
            c["source_revision"] = a.revision
    if a.malformed_revision:
        rec["source_revision"] = "not-a-revision"
    if a.drop_source_revision:
        rec.pop("source_revision", None)
    if a.drop_child is not None:
        del rec["children"][a.drop_child]
    if a.extra_child:
        extra = dict(rec["children"][0])
        extra["child_key"] = "php-cli/8.5/linux/amd64"
        extra["image_label"] = "php-cli/8.5"
        extra["manifest_digest"] = "sha256:" + "5" * 64
        extra["tag_resolved_digest"] = extra["manifest_digest"]
        extra["digest_reference"] = "%s@%s" % (STAGING_PACKAGE, extra["manifest_digest"])
        rec["children"].append(extra)
    if a.verdict:
        rec["verdict"] = a.verdict
    if a.db_identity:
        rec["trivy_db_snapshot"]["identity"] = a.db_identity
    if a.platforms:
        rec["expected_matrix"]["platforms"] = sorted(a.platforms.split(","))
    if a.evidence_sha:
        rec["children"][0]["evidence_sha256"] = a.evidence_sha
    if a.schema_invalid:
        # A type the aggregator never inspects and the schema does. This is the
        # class the runtime validator was added for.
        rec["workflow_run_id"] = str(rec["workflow_run_id"])

    with open(a.out, "w") as fh:
        json.dump(rec, fh, indent=2)
        fh.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
