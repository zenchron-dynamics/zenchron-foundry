#!/usr/bin/env python3
"""Generate the Kubernetes admission policies FROM the existing policy files (#124).

The identities, the runtime posture and the required attestations are already
declared in this repository and already enforced at build and release time. An
admission policy that RESTATED them would be a fourth copy, and the copy is what
drifts — a consumer would then enforce yesterday's identity regexp against
today's images.

So the YAML under policy/kubernetes/ is GENERATED, and
tests/governance/test_admission_policy.sh regenerates it and fails if the
committed output differs. Change the source policy and the admission policy
follows; change the admission policy by hand and CI rejects it.

Sources:
  policies/cosign-identities.yaml   issuer, per-role identity regexps
  policies/runtime-contract.yaml    the hardened runtime posture
  policies/repository-governance.yaml  the repository images may come from

Usage: generate-admission-policy.py [--check]
"""
import pathlib
import subprocess
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "policy" / "kubernetes"

BANNER = """# GENERATED — do not edit by hand.
#
# Produced by scripts/generate-admission-policy.py from:
#   policies/cosign-identities.yaml      (issuer, per-role identity regexps)
#   policies/runtime-contract.yaml       (the hardened runtime posture)
#
# Those files are the source of truth and are enforced at build and release time
# as well. Editing this file by hand makes a consumer enforce something the
# platform itself does not; tests/governance/test_admission_policy.sh regenerates
# and diffs, so a hand edit fails CI.
"""


def load():
    ci = yaml.safe_load((ROOT / "policies" / "cosign-identities.yaml").read_text())
    rt = yaml.safe_load((ROOT / "policies" / "runtime-contract.yaml").read_text())
    gov = yaml.safe_load((ROOT / "policies" / "repository-governance.yaml").read_text())
    return ci, rt, gov


def kyverno_image_provenance(ci, rt, gov):
    """Digest pinning and repository scope. Pure `validate` — evaluable offline.

    Kept SEPARATE from the signature rules on purpose: Kyverno skips a whole
    policy file when any rule in it needs registry credentials, so mixing these
    with verifyImages meant these never evaluated. They were passing in the worst
    possible way — by not running at all.
    """
    registry = "ghcr.io/zenchron-dynamics"
    rc = ci["roles"]["rc-publisher"]["identity_regexp"]
    rel = ci["roles"]["release"]["identity_regexp"]
    # A candidate/rebuild signature must NOT satisfy production. The policy names
    # the production identities explicitly rather than excluding the rebuild one:
    # an allowlist cannot be defeated by a role nobody thought to exclude.
    prod_identities = [rc, rel]

    rules = [
        {
            "name": "images-must-be-digest-pinned",
            "match": {"any": [{"resources": {"kinds": ["Pod"]}}]},
            "validate": {
                "message": (
                    "Zenchron Foundry images must be referenced by digest. A tag is "
                    "mutable; every guarantee this platform makes is about a digest."
                ),
                "foreach": [{
                    "list": "request.object.spec.containers",
                    "deny": {"conditions": {"all": [
                        {"key": "{{ element.image }}", "operator": "AnyIn",
                         "value": ["*%s/*" % registry]},
                        {"key": "{{ element.image }}", "operator": "AnyNotIn",
                         "value": ["*@sha256:*"]},
                    ]}},
                }],
            },
        },
        {
            "name": "images-must-come-from-the-declared-repository",
            "match": {"any": [{"resources": {"kinds": ["Pod"]}}]},
            "validate": {
                "message": (
                    "Only %s images are admitted by this policy. An image from another "
                    "repository has none of this platform's guarantees." % registry
                ),
                "pattern": {"spec": {"containers": [{"image": "%s/*" % registry}]}},
            },
        },
    ]
    return {
        "apiVersion": "kyverno.io/v1",
        "kind": "ClusterPolicy",
        "metadata": {
            "name": "zenchron-foundry-image-provenance",
            "annotations": {
                "policies.kyverno.io/title": "Zenchron Foundry image provenance",
                "policies.kyverno.io/severity": "high",
                "policies.kyverno.io/description": (
                    "Digest pinning and repository scope. Evaluable without a "
                    "registry, so CI can prove these rules actually fire."
                ),
            },
        },
        "spec": {"validationFailureAction": "Enforce", "background": True, "rules": rules},
    }


def kyverno_signatures(ci):
    """Signature identity and required attestations. NEEDS a registry to evaluate."""
    registry = "ghcr.io/zenchron-dynamics"
    rc = ci["roles"]["rc-publisher"]["identity_regexp"]
    rel = ci["roles"]["release"]["identity_regexp"]
    prod_identities = [rc, rel]
    rules = [
        {
            "name": "images-must-be-signed-by-a-production-identity",
            "match": {"any": [{"resources": {"kinds": ["Pod"]}}]},
            "verifyImages": [{
                "imageReferences": ["%s/*" % registry],
                "mutateDigest": False,
                "required": True,
                "attestors": [{"entries": [{"keyless": {
                    "issuer": ci["issuer"],
                    "subject": i,
                }} for i in prod_identities]}],
            }],
        },
        {
            "name": "images-must-carry-sbom-and-provenance",
            "match": {"any": [{"resources": {"kinds": ["Pod"]}}]},
            "verifyImages": [{
                "imageReferences": ["%s/*" % registry],
                "required": True,
                "attestations": [
                    {"type": "https://spdx.dev/Document",
                     "attestors": [{"entries": [{"keyless": {
                         "issuer": ci["issuer"], "subject": rc}}]}]},
                    {"type": "https://slsa.dev/provenance/v1",
                     "attestors": [{"entries": [{"keyless": {
                         "issuer": ci["issuer"], "subject": rc}}]}]},
                ],
            }],
        },
    ]

    return {
        "apiVersion": "kyverno.io/v1",
        "kind": "ClusterPolicy",
        "metadata": {
            "name": "zenchron-foundry-signatures",
            "annotations": {
                "policies.kyverno.io/title": "Zenchron Foundry supply chain",
                "policies.kyverno.io/severity": "high",
                "policies.kyverno.io/description": (
                    "Admits only digest-pinned Zenchron Foundry images signed by a "
                    "PRODUCTION identity and carrying SBOM and provenance "
                    "attestations. A scheduled-rebuild candidate signature does not "
                    "satisfy it."
                ),
            },
        },
        "spec": {"validationFailureAction": "Enforce", "background": False, "rules": rules},
    }


def kyverno_runtime(rt):
    """Kyverno ClusterPolicy: the runtime posture, from the runtime contract."""
    p = rt["profile"]
    rules = [
        {
            "name": "must-run-as-non-root",
            "match": {"any": [{"resources": {"kinds": ["Pod"]}}]},
            "validate": {
                "message": "Containers must run as non-root (runAsNonRoot: true).",
                "pattern": {"spec": {"=(securityContext)": {"=(runAsNonRoot)": True},
                                     "containers": [{"=(securityContext)": {
                                         "=(runAsNonRoot)": True}}]}},
            },
        },
        {
            "name": "root-filesystem-must-be-read-only",
            "match": {"any": [{"resources": {"kinds": ["Pod"]}}]},
            "validate": {
                "message": "readOnlyRootFilesystem must be true; writable paths are tmpfs.",
                "pattern": {"spec": {"containers": [
                    {"securityContext": {"readOnlyRootFilesystem": True}}]}},
            },
        },
        {
            "name": "privilege-escalation-must-be-disabled",
            "match": {"any": [{"resources": {"kinds": ["Pod"]}}]},
            "validate": {
                "message": "allowPrivilegeEscalation must be false (no-new-privileges).",
                "pattern": {"spec": {"containers": [
                    {"securityContext": {"allowPrivilegeEscalation": False}}]}},
            },
        },
        {
            "name": "must-not-be-privileged",
            "match": {"any": [{"resources": {"kinds": ["Pod"]}}]},
            "validate": {
                "message": "privileged containers are not admitted.",
                "pattern": {"spec": {"containers": [
                    {"=(securityContext)": {"=(privileged)": False}}]}},
            },
        },
        {
            "name": "all-capabilities-must-be-dropped",
            "match": {"any": [{"resources": {"kinds": ["Pod"]}}]},
            "validate": {
                "message": "capabilities.drop must include ALL; no capability may be added.",
                "pattern": {"spec": {"containers": [{"securityContext": {
                    "capabilities": {"drop": p["cap_drop"], "X(add)": "null"}}}]}},
            },
        },
        {
            "name": "seccomp-must-be-the-runtime-default",
            "match": {"any": [{"resources": {"kinds": ["Pod"]}}]},
            "validate": {
                "message": ("seccompProfile.type must be RuntimeDefault or Localhost; "
                            "Unconfined removes the syscall filter."),
                "pattern": {"spec": {"=(securityContext)": {
                    "=(seccompProfile)": {"type": "RuntimeDefault | Localhost"}}}},
            },
        },
        {
            "name": "host-namespaces-must-not-be-shared",
            "match": {"any": [{"resources": {"kinds": ["Pod"]}}]},
            "validate": {
                "message": "hostPID, hostIPC and hostNetwork are not admitted.",
                "pattern": {"spec": {"=(hostPID)": False, "=(hostIPC)": False,
                                     "=(hostNetwork)": False}},
            },
        },
        {
            "name": "the-container-runtime-socket-must-not-be-mounted",
            "match": {"any": [{"resources": {"kinds": ["Pod"]}}]},
            "validate": {
                "message": "Mounting the container runtime socket defeats the boundary.",
                "foreach": [{
                    "list": "request.object.spec.volumes[]",
                    "deny": {"conditions": {"any": [
                        {"key": "{{ element.hostPath.path || '' }}", "operator": "AnyIn",
                         "value": ["/var/run/docker.sock", "/run/docker.sock",
                                   "/var/run/containerd/containerd.sock",
                                   "/run/containerd/containerd.sock"]},
                    ]}},
                }],
            },
        },
    ]
    return {
        "apiVersion": "kyverno.io/v1",
        "kind": "ClusterPolicy",
        "metadata": {
            "name": "zenchron-foundry-runtime",
            "annotations": {
                "policies.kyverno.io/title": "Zenchron Foundry runtime posture",
                "policies.kyverno.io/severity": "high",
                "policies.kyverno.io/description": (
                    "The same hardened runtime contract scripts/runtime-contract.sh "
                    "proves on every image, expressed as admission rules."
                ),
            },
        },
        "spec": {"validationFailureAction": "Enforce", "background": True, "rules": rules},
    }


def policy_controller(ci):
    """Sigstore policy-controller ClusterImagePolicy, for clusters not running Kyverno."""
    return {
        "apiVersion": "policy.sigstore.dev/v1beta1",
        "kind": "ClusterImagePolicy",
        "metadata": {"name": "zenchron-foundry-signed"},
        "spec": {
            "images": [{"glob": "ghcr.io/zenchron-dynamics/**"}],
            "authorities": [{
                "name": "production-identities",
                "keyless": {
                    "url": "https://fulcio.sigstore.dev",
                    "identities": [
                        {"issuer": ci["issuer"],
                         "subjectRegExp": ci["roles"]["rc-publisher"]["identity_regexp"]},
                        {"issuer": ci["issuer"],
                         "subjectRegExp": ci["roles"]["release"]["identity_regexp"]},
                    ],
                },
                "attestations": [
                    {"name": "must-have-sbom", "predicateType": "https://spdx.dev/Document"},
                    {"name": "must-have-provenance",
                     "predicateType": "https://slsa.dev/provenance/v1"},
                ],
            }],
        },
    }


def render():
    ci, rt, gov = load()
    files = {
        "kyverno-image-provenance.yaml": kyverno_image_provenance(ci, rt, gov),
        "kyverno-signatures.yaml": kyverno_signatures(ci),
        "kyverno-runtime.yaml": kyverno_runtime(rt),
        "policy-controller-cluster-image-policy.yaml": policy_controller(ci),
    }
    out = {}
    for name, doc in files.items():
        out[name] = BANNER + "\n" + yaml.safe_dump(doc, sort_keys=False, width=100)
    return out


def main():
    check = "--check" in sys.argv
    OUT.mkdir(parents=True, exist_ok=True)
    drift = []
    for name, text in render().items():
        path = OUT / name
        if check:
            if not path.exists() or path.read_text() != text:
                drift.append(name)
        else:
            path.write_text(text)
    if check:
        if drift:
            print("ADMISSION POLICY DRIFT: regenerate with "
                  "scripts/generate-admission-policy.py", file=sys.stderr)
            for d in drift:
                print("  %s" % d, file=sys.stderr)
            return 1
        print("admission policies match their sources")
    else:
        print("wrote %d admission policy file(s) to %s" % (len(render()), OUT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
