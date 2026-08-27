# Real image package inventories for the 20 accepted production children

**Run date:** 2026-08-28 · **Source revision under evidence:**
`7061caafb3ea09bd5b2342a1daf022151b33f822` · **Verdict: REFUSED.**

This is the run record for a *buildless* attempt to produce real image package
inventories for every child of the accepted multi-architecture run
(`docs/audits/acceptance-multiarch-2026-08-20/`) and to put the composed licence
gate over them. Nothing was rebuilt, no image definition was touched, no
acceptance was dispatched, no package was installed, and no mutable tag was
substituted for a digest anywhere in the run.

The inventories are real and complete: 20 of 20 children, enumerated from the
image filesystem contents by one digest-pinned scanner. **The composed gate
refuses them**, with exactly one refusal code, for a reason that is a defect in
the gate rather than in the evidence. That refusal is the substance of this
record.

---

## 1. Recoverability — 20 of 20, by immutable digest

`registry-recoverability-probe.json` is a live probe of
`ghcr.io/zenchron-dynamics/foundry-staging`, one HTTP request per child plus one
per staging tag plus one per image config blob.

| fact | result |
|---|---|
| children probed | 20 |
| manifests served (HTTP 200) | 20 / 20 |
| `Docker-Content-Digest` equals the recorded digest | 20 / 20 |
| distinct digests | 20 |
| `mediaType` | `application/vnd.oci.image.manifest.v1+json` for all 20 |
| index digests encountered | 0 — every object is a **platform** manifest |
| staging tag still resolving to the same digest | 20 / 20 |
| config `architecture` read from the config blob | 10 amd64, 10 arm64 |
| package visibility | `private` |

Nothing here is partial, so nothing in this record needs the partial-recovery
refusal. Had any child been missing, this section would name it and the run
would have stopped: a composed PASS over 19 of 20 is a verdict that reports
clean about an image it never saw.

## 2. The frozen scanner identity

`scanner-identity.json`, in full. In short:

* **`anchore/syft@sha256:f94e5d9fce1f2278491a8e3a63bd5f6ddb81fdfdbb8bf7a1637565c1d5344357`**
  (resolves from `anchore/syft:v1.33.0`; every document records
  `Tool: syft-1.33.0` in its own `creationInfo`). Pinned by digest, not by tag.
* Producer: **`scripts/generate-sbom.sh`, unmodified.** Only the `syft` binary
  it finds on `PATH` was replaced, by a shim that execs the pinned container.
  Filenames therefore come from `sbom_filename()` in `scripts/lib/common.sh` —
  the same function the consumer calls. No second spelling of the identity was
  introduced anywhere in this run.
* Source scheme `registry:` — syft reads each child straight out of the registry
  by immutable digest. Reading through a local daemon instead would have made
  the document's subject the local image ID rather than the manifest digest, so
  the daemon path was deliberately not used.
* Config: `policies/syft.yaml`, unmodified. Formats: `spdx-json` and
  `cyclonedx-json`, i.e. the two the policy declares.

## 3. The inventories

40 documents, 20 SPDX + 20 CycloneDX, 86,781,974 bytes. They are **not**
committed: `*.cdx.json` is gitignored repository-wide and a bill of materials of
that size belongs in an evidence bundle. Their names, byte sizes and sha256 are
committed in `sbom-document-index.json` and in `sbom-bindings/*.binding.json`,
so the run is checkable without them.

Every document is bound on the five facts the gate requires — image name and
version, platform, immutable digest, source revision, content hash — and
`sbom-document-index.json` records, per child, that

```text
sbom_subject_equals_manifest_digest = true      20 / 20
```

The subject is the digest of that child's own platform manifest, not an index
digest and not another child's.

### Cross-check against the accepted run's own package counts

`syft` enumerated the packages independently of the trivy-derived
`package_inventory.package_count` the accepted run recorded. The two agree
exactly on both Alpine children and differ by a fixed amount on all eighteen
Debian ones:

| child | syft | accepted run | delta |
|---|---|---|---|
| `caddy/prod` (both platforms) | 178 | 178 | 0 |
| `nginx/prod` (both platforms) | 94 | 94 | 0 |
| `php-cli`, `php-fpm` (8 children) | 144 | 127 | +17 |
| `php-worker` (4 children) | 145 | 128 | +17 |
| `php-frankenphp` (4 children) | 382 | 364 | +18 |

The delta is characterised, not assumed. For `php-cli/8.4/linux/amd64` the
CycloneDX purl namespaces are `pkg:deb` 127, `pkg:pear` 5, `pkg:generic` 12.
**127 is exactly the accepted run's count.** The extra components are the PEAR
packages and the binary-cataloguer entries (`pkg:generic`) that syft sees and
the trivy-derived count did not. The images are the same images; a "package
inventory" is scanner-relative, and any comparison across the two tools has to
say which cataloguers were in scope.

## 4. The composed gate — REFUSED, 20 of 20, one code

Run exactly as `.github/workflows/stage-and-authorize.yml` runs it, against the
real documents above and the canonical authorization record for the accepted
run.

| gate | command | result |
|---|---|---|
| image binding | `scripts/license/assert-image-sbom-licences.sh --authorization … --sbom-dir … --binding-dir … --out …` | **rc=1**, 20 findings, one code: `IL-SBOM-SUBJECT-ABSENT` |
| image policy | `scripts/license/assert-license-policy.sh --inventory … --require-image-binding --expect-source-revision 7061caa…` | **rc=1** — the inventory carries no `image_binding`, because the step above never wrote one |
| repository half, composed | `scripts/license/assert-repository-material.sh --inventory policies/repository-material.yaml --image-inventory … --require-image-evidence` | **rc=1**, `RM-INVENTORY-UNREADABLE` — the image inventory does not exist |
| composed licence authorization | the workflow's own `jq` composition | `verdict: REFUSED`, `children_bound: 0 / 0` |
| canonical authorization | `scripts/release/validate-authorization-record.sh <record> --require-licence-authorization <licence record>` | record **satisfies schema v1** (verdict=PASS, children=20); the licence verdict is then **refused**: `AR-LICENCE-INCOMPLETE` |

The full gate output is in `licence/image-sbom-binding-gate.log` and the
verdict chain is reproduced in section 6.

Nothing was composed into a PASS. Both halves refuse, the composed record is
written for the refusal (a refusal that produces no record is a refusal nobody
can read afterwards), and the canonical validator consumes it and refuses.

## 5. Why it refused — the finding

`scripts/license/assert-image-sbom-licences.sh` reads an SPDX document's subject
from exactly two places:

```python
for v in doc.get("documentDescribes") or []: ...          # SPDX
comp = ((doc.get("metadata") or {}).get("component") or {})   # CycloneDX
```

**syft has never written `documentDescribes`.** Verified directly against three
releases spanning more than two years — `v0.105.1`, `v1.0.1` and `v1.33.0` — all
three emit SPDX 2.3 with no such key. A real syft document names its subject the
SPDX-standard way instead:

```json
"relationships": [{"spdxElementId": "SPDXRef-DOCUMENT",
                   "relationshipType": "DESCRIBES",
                   "relatedSpdxElement": "SPDXRef-DocumentRoot-Image-…"}]
```

and that root package carries the manifest digest three times over — in
`versionInfo`, in `checksums[SHA-256].checksumValue`, and in the `pkg:oci/…`
purl in `externalRefs`.

So the subject is present, correct, and equal to the accepted manifest digest in
all 20 documents (`sbom_subject_equals_manifest_digest: true`, 20/20) — and the
consumer looks for it somewhere the producer has never written it. Every other
bound fact agreed: filenames, content hashes, digests, platforms, source
revision, matrix identity, media types. Exactly one code came back, twenty
times.

This is the same shape of defect the repository has already paid for once, one
field further in: `scripts/generate-sbom.sh` used to *name* its outputs in a way
`generate-evidence-bundle.sh` never looked for, producing `sbom.present: false`
on a complete SBOM directory. `child_slug()` fixed the filename. The **subject**
was never brought under one derivation, and
`tests/license/test_image_sbom_licence_gate.sh` cannot see it because its
fixtures are hand-written with `documentDescribes` set — the one shape syft does
not produce.

**Consequence.** The image half of the licence gate cannot bind any SBOM the
shipped producer actually writes. It can bind fixtures. Until the consumer reads
the SPDX-standard subject location, no dispatch of `stage-and-authorize.yml`
will ever produce a passing licence authorization either — the defect is not
local to this buildless run.

**The fix is not applied in this branch.** Widening the consumer's subject
extraction to the `DESCRIBES`-relationship location is a strict addition — a
document naming no subject still refuses, a document naming a foreign digest
still refuses — but it edits a release gate, and that is a maintainer decision
with its own review. What is filed here is the evidence that it is needed.

### A second, independent measurement defect

`scripts/license/license-inventory.sh` folds CycloneDX components of
`type: "file"` into the licence inventory as though they were software
components. `policies/syft.yaml` sets `file.metadata.selection:
"owned-by-package"`, so syft emits 70,028 file components across the cohort.
The resulting inventory reads:

```text
components: 8527, unknown: 8292, conflicting: 196
```

and a diagnostic policy run over it reports **8,507 findings, of which 8,292 are
file paths** — `/etc/adduser.conf`, `/etc/debian_version`, `../`. The real
signal is the remaining 215: 19 components whose licence needs legal review and
196 whose SBOMs conflict. Filtering to real packages gives **535 package
components**, of which 300 carry no licence assertion.

Neither defect is fixed here. Both are reported with the measurement that shows
them.

## 6. Verdict chain, verbatim

```text
image-SBOM licence binding REFUSED: 20 finding(s), codes: IL-SBOM-SUBJECT-ABSENT

licence authorization: REFUSED (bind=failure image-policy=failure composed=failure)

record satisfies schema v1 (verdict=PASS, children=20)
REFUSE [AR-LICENCE-INCOMPLETE]: … binds 0 of 0 expected children. A licence
verdict over a partial matrix reports clean for the images it happened to see
```

## 7. The authorization record is deliberately not committed

The accepted run's own `post-build-authorization.json` was a 30-day workflow
artifact and has expired. It was reconstructed for this run by the **shipped**
fixture builder, `tests/lib/make_authorization_fixture.py`, so that no second
derivation of the record's shape exists:

```bash
python3 tests/lib/make_authorization_fixture.py \
  docs/audits/acceptance-multiarch-2026-08-20/acceptance-evidence.json <out.json>
```

`sha256 = d592904c189e21efcd2d228406ead57dbe75e8132d72fced4a9fd45a2a15fcd3`,
20 children, schema-valid against `schemas/post-build-authorization-v1.schema.json`.

It is **not** committed, because that builder's own header says a reconstruction
filed beside real audit records is a reconstruction somebody will later read as
one. Its hash and the command that reproduces it are recorded instead.

Two fields the builder *asserts* rather than checks — `tag_resolved_digest` and
`manifest_media_type` — were verified independently and live for all 20 children
in section 1.

## 8. Pinned gaps

Two gaps are pinned in the test suites. **This run closes neither, and weakens
neither.**

* *(a) the REQUIRED CI path does not itself RUN `stage-and-authorize.yml`* —
  `tests/integration/test_evidence_path_e2e.sh`. Untouched. It is a deliberate
  architectural consequence and nothing in this branch goes near it.
* *(b) no committed run record shows the composed gate over REAL image package
  inventories* — `tests/license/test_image_sbom_licence_gate.sh`. Still open.
  The gap names its own closure condition: *one dispatch of
  `stage-and-authorize.yml` on master, whose licence-authorization artifact is
  then committed as an audit record.* That is a maintainer action which builds
  images, and this run was required to build nothing, so the condition is not
  met. Beyond that, there is no passing composed verdict to commit: the gate
  refuses.

  What this record does add is the reason it refuses. Gap (b) was pinned as
  *unmeasured*. It is now measured, and the measurement says the gate cannot
  pass over real producer output at all. Dispatching the workflow today would
  not close (b) either; it would reproduce `IL-SBOM-SUBJECT-ABSENT` twenty
  times on a runner instead of on a laptop.

## 9. Files

| file | what it is |
|---|---|
| `registry-recoverability-probe.json` | live per-child registry probe, 20/20 |
| `scanner-identity.json` | the one frozen scanner identity, pinned by digest |
| `sbom-document-index.json` | every document by name, size, sha256, subject and child |
| `sbom-bindings/*.binding.json` | 20 producer binding records, one per child |
| `licence/image-sbom-binding-gate.log` | the gate's own refusal output, verbatim |
| `licence/identifier-reconciliation.json` | the four-way identifier classification |
| `licence-identifier-reconciliation.md` | that classification, with the discrepancies investigated |
