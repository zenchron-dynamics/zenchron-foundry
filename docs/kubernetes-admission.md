# Kubernetes admission policies

**Issue:** #124 · **Generated from:** `policies/cosign-identities.yaml`, `policies/runtime-contract.yaml`
**Generator:** `scripts/generate-admission-policy.py` · **Tests:** `scripts/test-admission-policy.sh`

## Generated, not written

The identities, the runtime posture and the required attestations are already
declared in this repository and already enforced at build and release time. An
admission policy that **restated** them would be a fourth copy, and the copy is
what drifts — a consumer would end up enforcing yesterday's identity regexp
against today's images.

So `policy/kubernetes/*.yaml` is generated, and CI regenerates and diffs. Change
the source policy and the admission policy follows; hand-edit the admission
policy and CI rejects it.

## Three files, because one of them cannot be tested offline

| file | enforces | evaluable without a registry |
| --- | --- | --- |
| `kyverno-image-provenance.yaml` | digest pinning, repository scope | **yes** |
| `kyverno-runtime.yaml` | the hardened runtime contract | **yes** |
| `kyverno-signatures.yaml` | signing identity, SBOM + provenance attestations | no — needs the registry |
| `policy-controller-cluster-image-policy.yaml` | the same, for clusters running Sigstore policy-controller instead | no |

> **This split exists because of a real bug.** The digest and repository rules
> originally lived in the same file as the signature rules. **Kyverno skips an
> entire policy file when any rule in it needs registry credentials**, so those
> two rules never evaluated at all — they were passing in the worst possible way,
> by not running. The negative fixtures found it; splitting the files is what
> made them testable.

## What is rejected

Proven with the real Kyverno engine against fixtures under `policy/kubernetes/tests/`:

| fixture | why it is rejected |
| --- | --- |
| `tag-only` | a mutable tag instead of a digest |
| `foreign-registry` | an image this platform makes no guarantees about |
| `writable-rootfs` | `readOnlyRootFilesystem: false` |
| `privileged` | the whole capability bounding set restored |
| `privilege-escalation` | no-new-privileges disabled |
| `added-capability` | a capability added back |
| `run-as-root` | `runAsNonRoot: false` |
| `host-pid`, `host-network` | host namespaces shared |
| `seccomp-unconfined` | the syscall filter removed |
| `docker-socket` | the container runtime socket mounted |

Plus, structurally on the signature policy: **a `scheduled-rebuild` candidate
identity does not satisfy the production policy** — asserted by matching the
candidate subject against every production attestor regexp and requiring no
match.

## The positive control

A policy that denies everything passes every negative test and is worthless.
`policy/kubernetes/tests/compliant.yaml` is a Pod that satisfies the whole
contract and **must be admitted**, and the harness additionally asserts that a
meaningful number of rules actually evaluated, so "matched nothing" cannot look
like "passed".

```text
compliant           pass: 9, fail: 0
11 violations       each fail >= 1
admission policy:   17 ok, 0 failed
```

Run it:

```bash
make admission-policy      # regenerate + diff + evaluate
```

## Rollout

1. **Audit mode first.** Change `validationFailureAction: Enforce` to `Audit`,
   apply, and watch for a week. A cluster with existing workloads will have
   violations you did not expect, and discovering them through rejected
   deployments is the wrong way.
2. **Enforce namespace by namespace**, not cluster-wide on day one.
3. **Break-glass** is a namespace exclusion in the policy `match` block —
   recorded and time-boxed, the same way `policies/governance-model.yaml`
   treats a break-glass in this repository.
4. **The signature rules need registry credentials** in the cluster. They will
   fail closed without them, which is correct and will look like an outage if
   you enable them before configuring the pull secret.

## What these policies do not do

They admit images. They do not verify that a **release** was approved: that is
release evidence (#128, #130), and it is not something an admission controller
can check today because publication and signing are closed (#139).
