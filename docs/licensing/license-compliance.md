# Licence compliance and the publication question

Two separate questions live here, and most licence-compliance failures come from answering them as if they
were one:

1. **Are the third-party licences in our images accounted for?** That is an engineering question. It is
   answered by the pipeline described below, and the pipeline fails closed.
2. **May Zenchron Foundry itself be distributed, and to whom?** That is a legal question. It is **not
   answered anywhere in this repository**, it is tracked in issue #98, and nothing in this document,
   this pipeline, or `policies/license-policy.yaml` decides it.

Passing the licence gate means the first question is answered. It does not grant permission to publish
anything.

## The unresolved contradiction (#98)

Recorded as observed facts in `policies/license-policy.yaml` under `publication.observed`:

| fact | value |
| --- | --- |
| repository visibility | `public` |
| `LICENSE` grant | `INTERNAL / PROPRIETARY — NOT FOR PUBLIC DISTRIBUTION` |
| GHCR package visibility | `private` |

So the source is world-readable under a licence that forbids redistributing it, while the images it
documents are private. Anyone reading the repository has no grant to use what they can see.

`publication.decision` is `undetermined` and `publication.decided_by` is `null`. Those fields exist so the
decision has somewhere to live when an owner makes it — not so that engineering can make it. While
`decision` is `undetermined`, `generate-notice.sh` emits a document whose first line says
`THIRD-PARTY NOTICE CANDIDATE — DRAFT, NOT APPROVED FOR DISTRIBUTION`, and no tooling here will call it
approved.

## The pipeline

```text
artifacts/sbom/*.json              SPDX + CycloneDX, from scripts/generate-sbom.sh
        │
        ▼  scripts/license/license-inventory.sh --sbom-dir DIR --out inv.json
normalised inventory               per component: every asserted licence, and WHICH field asserted it
        │                          flags: unknown (nothing asserted) / conflict (sources disagree)
        ▼  scripts/license/assert-license-policy.sh --inventory inv.json
verdict                            PASS, or REFUSE naming every finding
        │
        ▼  scripts/license/generate-notice.sh --inventory inv.json --out NOTICE.txt
notice candidate                   refuses to render over an unresolved inventory
```

### Why provenance is kept per assertion

SPDX carries both `licenseDeclared` (what the package says about itself) and `licenseConcluded` (what the
scanner decided). When those disagree, **the disagreement is the finding**. An inventory that flattened
them into one string would erase it, so each assertion is recorded with the file, format and field that
made it.

### Why an SPDX expression is never split

`MIT OR Apache-2.0` is a *choice*. Splitting it into two components would misrepresent it as two
simultaneous sets of obligations. The expression is kept whole and treated as its own identifier.

## The four refusals

The gate refuses on four conditions. They differ in who must act, not in whether the release may proceed.

| finding | meaning |
| --- | --- |
| `unknown` | no SBOM asserted any licence — `NOASSERTION`, `NONE`, or nothing at all |
| `conflicting` | two sources each named something, and named different things |
| `denied` | the owner has affirmatively refused this licence |
| `legal-review-required` | classified, and the classification is "ask a lawyer" |

**`legal-review-required` is not a soft state.** A component sitting there is exactly as unshippable as a
denied one. Treating "we have not looked yet" as "probably fine" is the failure this gate exists to
prevent.

Anything not listed in the policy resolves to `legal-review-required` via `default_state`. An unrecognised
SPDX identifier is an open question, and an open question must not be able to ship a release. The gate
refuses to run at all against a policy whose `default_state` is not fail-closed.

## What the policy does and does not contain

`policies/license-policy.yaml` classifies licences into `allowed`, `denied` and `legal-review-required`.

- **`allowed`** is restricted to licences whose only distribution obligation is to retain a notice — MIT,
  ISC, BSD-2/3-Clause, Apache-2.0, Zlib, 0BSD, Unlicense, CC0-1.0. Each records its `obligations`.
- **`legal-review-required`** covers every reciprocal, weak-copyleft, source-offer, advertising or naming
  obligation — GPL, LGPL, AGPL, MPL, EPL, CDDL, PHP-3.01, OpenSSL, Artistic-2.0, BSD-4-Clause. Each
  records a `reason`, and every reason reduces to the same thing: whether the obligation is satisfiable
  depends on how #98 resolves.
- **`denied` is empty by design.** Denying a licence is a legal conclusion, and nothing in this repository
  is authorised to reach one. The state is live and enforced — it is exercised by fixtures in
  `tests/license/` — it simply has no entries an engineer invented. Populating it is an owner action.

### Exceptions

`exceptions[]` is empty. The validator refuses any entry missing `component`, `license`, `granted_by`,
`expires` or `tracked_issue`, and refuses an exception whose `expires` has passed. An exception without an
owner and an expiry is a silent allow, and an exception that outlives its review is indistinguishable from
an unreviewed licence.

## Running it

```bash
# offline: the gate's own fail-closed behaviour
bash scripts/license/assert-license-policy.sh --self-test
bash tests/license/test_license_gate.sh

# against real SBOMs (needs syft output; see docs/sbom-and-signing.md)
IMAGE=ghcr.io/zenchron-dynamics/php-fpm:8.4-prod \
  FAMILY=php-fpm VERSION=8.4 PLATFORM=linux/amd64 \
  bash scripts/generate-sbom.sh
bash scripts/license/license-inventory.sh --sbom-dir artifacts/sbom --out artifacts/license-inventory.json
bash scripts/license/assert-license-policy.sh --inventory artifacts/license-inventory.json
bash scripts/license/generate-notice.sh --inventory artifacts/license-inventory.json --out artifacts/NOTICE-candidate.txt
```

### The release path, where the verdict is actually a control

The three lines above decide nothing about a release: they read whatever SBOMs are in a directory. The
release form binds the inventory to the candidate images a run staged, and requires the repository half
alongside it. This is what `.github/workflows/stage-and-authorize.yml`'s **`authorize`** job runs, in the same job that
emits the canonical `post-build-authorization.json` — not in a downstream job that files a report:

```bash
# 1. bind every candidate SBOM to a staged child — image, version, platform,
#    immutable digest, source revision, and the bytes the producing run hashed
bash scripts/license/assert-image-sbom-licences.sh \
  --authorization authorization/post-build-authorization.json \
  --sbom-dir sbom --binding-dir sbom-bindings --out licence/image-inventory.json

# 2. the IMAGE-SBOM gate over that inventory, refusing one that names no candidate
bash scripts/license/assert-license-policy.sh --inventory licence/image-inventory.json \
  --require-image-binding --expect-source-revision "$GITHUB_SHA"

# 3. compose with the repository half, which the image half cannot see, and require it
bash scripts/license/assert-repository-material.sh --inventory policies/repository-material.yaml \
  --image-inventory licence/image-inventory.json --require-image-evidence
```

The composed verdict is then **consumed**, not filed:

```bash
bash scripts/release/validate-authorization-record.sh authorization/post-build-authorization.json \
  --require-licence-authorization authorization/licence/licence-authorization.json
```

The canonical record does not validate unless that verdict is present, `PASS`, and bound to the record's
own sha256 and source revision. An absent one is `AR-LICENCE-EVIDENCE-ABSENT` — a refusal, never a skip.

Neither half compensates for the other. Image evidence beside an empty repository verdict is
`RM-REPOSITORY-EVIDENCE-ABSENT`; repository evidence with no image evidence is `RM-IMAGE-EVIDENCE-ABSENT`;
either half refusing is `AR-LICENCE-REFUSED`. A licence PASS authorizes nothing for publication —
publication stays refused by its own independent control, and the validator refuses a licence record that
claims `public_exposure_authorized` at all.

## Known gaps

- **The composed authorization runs in the release path, and the required CI path does not run that
  workflow.** `.github/workflows/stage-and-authorize.yml`'s `authorize` job is where a real candidate
  inventory is gated; CI is buildless and holds no candidate image, so the required `repo
  structure` job instead EXECUTES that job's extracted step bodies against the accepted production run
  (`tests/license/test_image_sbom_licence_gate.sh`). Closing the remainder would need CI to hold a
  candidate image, which is the boundary `trusted-validation.yml` exists to keep it away from.
- **Licence *texts* are not preserved.** The inventory records identifiers and their provenance, not the
  full text of each licence. Notice obligations that require reproducing the text are therefore only
  partially served by the generated candidate.
- **Nothing here establishes a right to publish.** See #98.
