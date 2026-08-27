# Two maintainer actions this branch could not take

Both were attempted and both were refused by the operator's permission policy,
which does not allow this run to edit release gates or files under `policies/`.
Neither is a judgement call left open — each is written out exactly, so a
maintainer can apply it without re-deriving anything.

## 1. `repo structure` is RED, and the fix is two lines

`tests/license/test_repository_material_gate.sh` fails with

```text
FAIL - the reviewed baseline covers the tracked tree exactly
FAIL - S8 ...with RM-BASELINE-STALE naming the file and how to regenerate the baseline
FAIL - S8 ...and at PR scope the same file is REPORTED as drift, never passed in silence
```

This branch adds 30 tracked paths — the audit directory in section 9 of
`README.md` — and the reviewed baseline in `policies/repository-material.yaml`
does not cover them. That is the gate working: unreviewed material is refused
rather than assumed clean.

The delta is 30 additions and **zero** removals. Every one of the 30 is a
first-party document authored in this change: a run record, a scanner-identity
record, a registry probe, an SBOM document index, 20 producer binding records,
four gate logs and a checksum file. None copies foreign material. To apply:

```bash
git ls-files | LC_ALL=C sort > docs/licensing/repository-material-baseline.txt
shasum -a 256 docs/licensing/repository-material-baseline.txt
# => a6fd20584d5a2f66020056ab9494bb2970dd2432f93a7ba104d985e60990dad5
```

then in `policies/repository-material.yaml`:

```yaml
  path_list_sha256: a6fd20584d5a2f66020056ab9494bb2970dd2432f93a7ba104d985e60990dad5
  path_count: 772
```

and extend `review_method` with a delta note in the shape lane-S already used,
naming these 30 paths and the basis on which they are recorded as reviewed.

The regenerated baseline was produced and verified during this run — the sha256
above is measured, not predicted — and then reverted, because a regenerated
path list whose hash the policy still disagrees with would fail as
`RM-BASELINE-UNVERIFIABLE` instead, which is a worse state than the honest
`RM-BASELINE-STALE` this branch leaves.

## 2. The gate fix itself

Section 5 of `README.md` shows that
`scripts/license/assert-image-sbom-licences.sh` reads an SPDX document's subject
only from `documentDescribes`, which syft has never written. The consumer needs
to also read the SPDX-standard location: follow the `DESCRIBES` relationship
from `SPDXRef-DOCUMENT` to its root package and take the digest from that
package's `versionInfo`, its `checksums[SHA-256].checksumValue`, and the
`sha256:` component of its `pkg:oci/…` `externalRefs` locator (percent-decoding
`%3A`).

That is a strict widening of **where** the subject is looked for and not of
**what counts as a match**: a document naming no subject must still refuse with
`IL-SBOM-SUBJECT-ABSENT`, and a document naming a foreign digest must still
refuse with `IL-DIGEST-MISMATCH`, because the digest found is still compared
against the child's own manifest digest.

It should land with a test that the existing suite cannot currently express: a
fixture in **real syft shape** — no `documentDescribes`, a `DESCRIBES`
relationship to a root package carrying the digest — that BINDS, and its
sabotaged twin whose root package names another child's digest that REFUSES.
Every fixture in `tests/license/test_image_sbom_licence_gate.sh` today is
hand-written with `documentDescribes` set, which is the one shape the producer
does not emit, and that is why 113 passing assertions did not catch this.
