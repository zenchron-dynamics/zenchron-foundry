# Release evidence — the authoritative schema (DC-25)

Every artifact the release pipeline emits as *evidence*, who produces it, what
format it has, and which fields are required. Companion to
[release-process.md](release-process.md) (ceremony order) and
[release-security.md](release-security.md) (what the gates enforce). If a
document and this file disagree about an evidence file's name or fields, this
file wins.

Two invariants apply to every file below:

- **Derived, never asserted.** Counts and results are parsed from the run that
  produced them (step outcomes, verifier output, artifact contents) — never
  typed in as literals. `validate-release-evidence.sh` refuses any partial
  counted result (`9/10`) and any `absent` required field.
- **Bound to the exact commit.** Evidence is only meaningful for the revision
  it was produced from; the equality chain
  `tag commit == manifest.revision == provenance revision == OCI revision`
  is what every verifier checks.

## Evidence inventory

| Evidence file | Producer (workflow / stage) | Format | Required fields |
|---|---|---|---|
| `rc-manifest-<version>-<rc>` artifact: `release-manifest.yaml` + `.sha256` + `.sig` + `.pem` | `publish-rc.yml` (RC build + sign) | YAML + checksum + cosign sig/cert | `schema_version`, `release`, `candidate`, `revision`, `source_repository`, `source_ref`, `workflow_run_id`, `created_at`, `images{}` (10 entries: `repository`, `immutable_tag`, `digest`, `reference`, `revision`, `platforms`) — schema `schemas/release-manifest.schema.json` |
| `publish-results-<fam>-<ver>` artifact: `publish-results.json` | `publish-ghcr.yml` publish leg (after sign + attest) | JSON | `image`, `digest`, `signed`, `sbom_attested`, `provenance_attested` (booleans proven by the step-success chain) |
| `build-results` artifact: `build-results.json` + `smoke-results.json` (per-leg `build-result-<image>` artifacts feed it) | `ci.yml` `build-test` legs + `aggregate build+smoke results` job | JSON | build: `image_count`, `images[]` (`name`, `dockerfile`, `result`); smoke: `image_count`, `images[]` (`name`, `result`) |
| `scan-results-<fam>-<ver>-<sha>` artifact: `scan-results.json` | `scan-images.yml` scan leg (after Trivy gate + Grype) | JSON | `image`, `commit`, `trivy_gate`, `trivy_gate_passed`, `grype_completed` |
| `verify-rc-results` artifact: `verify-rc-results.json` (per-leg `verify-rc-result-<fam>-<ver>` artifacts feed it) | `verify-rc.yml` certify legs + `certified` aggregation | JSON | `version`, `rc`, `certify_result`, `platforms_result`, `image_count`, `images[]` (`image`, `digest` = local image ID, `build`, `smoke`, `contract`) |
| `promotion-evidence-<version>` artifact: `rollback-<version>.yaml` (+ sidecars) | `promote-stable.yml` Phase 1 (pre-mutation) | YAML (signed/checksummed) | `schema_version`, `release`, `candidate`, `revision`, `created_at`, `aliases[]` (`ref`, `prior_digest`; `NONE` = alias did not exist) |
| `promotion-evidence-<version>` artifact: `promotion-journal-<version>.txt` | `promote-stable.yml` Phase 2 (one line per successful mutation, canonical prod LAST) | text, one alias ref per line | mutation order is the content; rollback replays it in reverse |
| `promotion-evidence-<version>` artifact: `promotion-<version>.yaml` (+ sidecars) | `promote-stable.yml` Phase 3 (`verify-promotion-state.sh`) | YAML (signed/checksummed) | `schema_version`, `release`, `candidate`, `revision`, `created_at`, `aliases[]` (`ref`, `digest`, `verified`) |
| `promotion-evidence-<version>` artifact: `promotion-results.json` | `promote-stable.yml` (derived from the three files above) | JSON | `version`, `rc`, `aliases_promoted`, `aliases_verified`, `canonical_last_proven` (journal-derived), `rollback_manifest_sha256` |
| `rollback-results-<version>` artifact: `rollback-results.json` | `rollback-exercise.yml` (automated ceremony step 11; v2026.07.21 produced it manually) | JSON | `version`, `rc`, `revision`, `run_ids{}`, `rollback{restored,left_tagged,failed}`, `prior_restore_verified` (`n/n`), `restore{binding_pass_aliases,binding_result}` |
| Release asset `release-manifest.yaml` | `release.yml` (re-fetched from the `publish-rc` artifact — never regenerated) | YAML | identical to the RC manifest above, byte for byte |
| Release assets `<image>.spdx.json` × 10 + `checksums.txt` | `release.yml` (syft over the promoted digests, strict 10/10) | SPDX JSON + sha256 list | one SBOM per matrix image; `checksums.txt` covers all attached `*.json` |
| Release assets `evidence.json` (+ `.sha256`) / `EVIDENCE.md` / `VERIFY.md` | `release.yml` (`build-release-evidence.sh`, validated by `validate-release-evidence.sh`) | JSON + checksum / Markdown | `release`, `candidate`, `revision`, `created_at`, `governance{model}`, `identity{rc_publisher_regexp,issuer}` (exact, never wildcard/unknown), `artifacts{*_sha256}`, `runs{*_RUN_ID}`, `verification{sig,sbom,prov,ocirev,arch,runtime,vuln}` (counted results must be full `n/n`), `rollback_exercise`, `environment_config` |
| Release asset `release-evidence-summary.json` | `release.yml` (final step before the GitHub Release) | JSON | `version`, `rc`, `revision`, `run_ids{rc_manifest_run_id,verify_rc_run_id,release_run_id}`, `verification{}` (from `RESULTS_JSON` + guard-derived `runtime_result`), `assets[]`; must match `evidence.json` (validated) |
| Release asset `DEVIATION.md` | manual, owner-approved (v2026.07.21 one-off) | Markdown | statement of what deviated (manual seal), why, and the re-proof performed. NOT a standing evidence file — present only on releases with an approved deviation |

The intermediate results file `release-verify-results.json` (`RESULTS_JSON`,
written by `verify-release-artifacts.sh` inside the `release` job) is the
source the evidence package derives its five verification counts from; it is
consumed in-job and republished inside `evidence.json` /
`release-evidence-summary.json` rather than attached separately.

## Audit canonical names → actual names

The audit refers to 13 canonical evidence names. They map to the actual
artifacts as follows; where the names differ the files are equivalent in
content and role.

| # | Audit canonical name | Actual name (this repo) | Equivalence |
|---|---|---|---|
| 1 | `build-results.json` | `build-results.json` in the `build-results` artifact (ci.yml) | same |
| 2 | `smoke-results.json` | `smoke-results.json` in the same `build-results` artifact | same (one artifact carries both files) |
| 3 | `scan-results.json` | `scan-results.json` in `scan-results-<fam>-<ver>-<sha>` (per leg) | same file name; sharded per image, commit-stamped artifact name |
| 4 | `publish-results.json` | `publish-results.json` in `publish-results-<fam>-<ver>` (per leg) | same file name; sharded per image |
| 5 | RC manifest | `release-manifest.yaml` in `rc-manifest-<version>-<rc>` | the "RC manifest" IS `release-manifest.yaml` — never committed, only the signed artifact |
| 6 | `verify-rc-results.json` | `verify-rc-results.json` in the `verify-rc-results` artifact | same |
| 7 | rollback manifest | `rollback-<version>.yaml` in `promotion-evidence-<version>` | same content: prior digest per alias |
| 8 | promotion journal | `promotion-journal-<version>.txt` in `promotion-evidence-<version>` | same |
| 9 | stable/promotion manifest | `promotion-<version>.yaml` in `promotion-evidence-<version>` | the audit's "stable manifest" is the Phase-3 promotion manifest (`STABLE_MANIFEST` in `build-release-evidence.sh`) |
| 10 | `promotion-results.json` | `promotion-results.json` in `promotion-evidence-<version>` | same |
| 11 | `rollback-results.json` | `rollback-results.json` in `rollback-results-<version>` (rollback-exercise.yml) and in the release assets | same |
| 12 | evidence package | `evidence.json` + `evidence.json.sha256` + `EVIDENCE.md` + `VERIFY.md` release assets | the audit's single "evidence package" is these four files; `evidence.json` is the machine-readable member |
| 13 | release summary | `release-evidence-summary.json` release asset | same |

## Retention and location

- Workflow artifacts (`rc-manifest-*`, `promotion-evidence-*`,
  `verify-rc-results`, `build-results`, `scan-results-*`, `publish-results-*`,
  `rollback-exercise-*`, `rollback-results-*`) live on their producing run —
  which is why run IDs are release inputs and are recorded in `evidence.json`
  and `release-evidence-summary.json`.
- Release assets (manifest, SBOMs, checksums, evidence package, summary,
  `rollback-results.json`, and any `DEVIATION.md`) live on the GitHub Release
  and are the durable, consumer-facing copy.

## The durable evidence bundle, dispositions and the release seal

Everything above describes evidence that lives on a **workflow run** or a
**GitHub Release**. Both expire or can be deleted. This section describes the
layer that does not: a self-contained bundle that verifies with no network, no
GitHub API, no registry and no surviving run, the machine-readable
vulnerability dispositions generated from it, and the release-role seal over
the whole thing.

Three issues, one system:

| Issue | What it asked for | What is now executable |
|---|---|---|
| [#128](https://github.com/zenchron-dynamics/zenchron-foundry/issues/128) | immutable retention + one tamper-evident bundle | `scripts/release/generate-evidence-bundle.sh`, `scripts/release/restore-evidence.sh`, `policies/retention.yaml`, `schemas/release-evidence-bundle-v1.schema.json` |
| [#115](https://github.com/zenchron-dynamics/zenchron-foundry/issues/115) | signed machine-readable VEX, digest-bound | `scripts/release/generate-vex.sh`, `schemas/vex-openvex-v1.schema.json` |
| [#130](https://github.com/zenchron-dynamics/zenchron-foundry/issues/130) | the reserved `release` role, and a verifier that consumes it | `scripts/release/release-seal.sh` (test-only), `scripts/release/verify-release-seal.sh` |

They are one system because they share one input — an accepted acceptance
record such as
`docs/audits/acceptance-multiarch-2026-08-20/acceptance-evidence.json` — and
one identity derivation, `child_key()` / `child_slug()` from
`scripts/lib/common.sh`. Nothing here re-derives child identity, re-implements
the per-child evidence checksum (`scripts/release/evidence-checksum.sh`), or
re-defines the artifact classes declared in `policies/evidence-classes.yaml`.

The class contract is **consumed**, not restated. A bundle's `evidence_class`
must be one the policy declares; where the policy pins a pre-contract record's
class to its bytes (`legacy_records`), the bundle must honour that declaration
and may promote it by exactly one step along the policy's own `parent_class`
chain — `staged-candidate` -> `published-artifact` and nothing else. Sideways
and backwards moves are refused by name.

### Bundle layout

```text
<bundle>/
  manifest.json          the record — schemas/release-evidence-bundle-v1.schema.json
  content/
    acceptance/          the source acceptance record, verbatim
    children/<slug>.json one full evidence extract per child
    vex/openvex.json     the machine-readable dispositions
    policy/              sha256 of every policy that decided the verdict
    provenance/          run + revision binding, and the attestation if supplied
    authorization/       the authorization record and its scope
    retention/           class, retain_until, storage requirement
    sbom/                SBOM bytes + index, when supplied
  SHA256SUMS             manifest.json AND every file under content/
  BUNDLE.sha256          sha256(SHA256SUMS) — the one value to quote in an audit
```

**The write order is the control.** Every generated file — including the VEX
document, which the generator invokes `generate-vex.sh` to produce *into* the
bundle — is written before any checksum is taken. `verify` then refuses on the
inverse condition: a file present on disk that `SHA256SUMS` does not name. A
file outside coverage is a file anybody can add afterwards, which is precisely
the failure the bundle exists to prevent.

**Determinism.** The generator never reads the wall clock; timestamps come from
the acceptance record. Regenerating from the same inputs is byte-identical, so
"this bundle was not altered" is checkable rather than assertable. `--today` is
an input, not a clock: it is the date staleness was evaluated on, it is recorded
in the disposition set, and moving it changes the disposition digest and nothing
derived from the evidence.

```bash
scripts/release/generate-evidence-bundle.sh generate \
  --evidence docs/audits/acceptance-multiarch-2026-08-20/acceptance-evidence.json \
  --out /tmp/bundle --evidence-class staged-candidate
scripts/release/generate-evidence-bundle.sh verify /tmp/bundle     # offline
```

### Dispositions (VEX)

`generate-vex.sh` emits OpenVEX 0.2.0 from the findings the accepted run
actually recorded, joined to the real ledger. Four rules keep it from becoming
a laundering mechanism for claims nobody made:

1. **The evidence is the universe.** Statements exist only for
   `(image digest, advisory, package, version)` tuples the run recorded. On the
   committed accepted run that is 982 tuples across 20 children, published as
   77 statements. A statement wider than the evidence is refused, not trimmed.
2. **Digest-bound, platform-scoped, version-exact.** Every product is a
   `pkg:oci/...@sha256%3A...` with an `arch` qualifier; every subcomponent is
   the exact `package@version` observed *in that image*. Tags are refused: a tag
   can be repointed after the statement is published.
3. **An accepted risk is `affected`.** The ledger's `reachability` field is
   internal risk-acceptance rationale. Mapping it to the OpenVEX justification
   `vulnerable_code_not_in_execute_path` would publish a reachability analysis
   to a standard nobody performed. Only `not_affected` *records*, which carry an
   evidenced `classification` and a version binding, become `not_affected`
   *statements*; everything else is `affected` with an action statement.
4. **Ambiguity refuses.** Zero governing records, two records disagreeing on
   status, an unbounded `image: all` / `php-all` selector, a record with no
   exact version pin, or a lapsed acceptance — each stops generation with its
   own diagnostic. It never picks one.

`verify` re-derives the whole document from the same inputs and additionally
refuses a foreign digest, an unobserved package tuple, an advisory the scan did
not report for that image, a statement backed by an expired record, and a
*partial* document — because a consumer reads "no statement" as "nothing to
worry about".

```bash
scripts/release/generate-vex.sh generate \
  --evidence docs/audits/acceptance-multiarch-2026-08-20/acceptance-evidence.json \
  --out /tmp/openvex.json
scripts/release/generate-vex.sh verify --vex /tmp/openvex.json \
  --evidence docs/audits/acceptance-multiarch-2026-08-20/acceptance-evidence.json
```

### The release seal — TEST-ONLY

`policies/cosign-identities.yaml` describes the `release` role as "RESERVED,
currently consumed by no verifier". `verify-release-seal.sh` is that consumer.
`release-seal.sh` is the seal logic, exercised end to end with **fixture keys**:
there is no flag that makes it emit a production signature, it refuses to run
when `SIGSTORE_ID_TOKEN` / `COSIGN_*` are set or on a tag ref, and every seal it
writes carries `test_only: true` and `not_a_release: true`. Wiring a real
ceremony needs a workflow change and a real OIDC identity — reviewable on their
own, deliberately not in this change.

The seal refuses:

| | refusal |
|---|---|
| R1 | an incomplete child set — counted as `MATRIX_COUNT × platforms`, never a literal |
| R2 | mixed source revisions across children |
| R3 | mixed vulnerability-database identities |
| R4 | a platform set the evidence does not cover |
| R5 | expired governance — a lapsed acceptance, or an elapsed retention window |
| R6 | any checksum mismatch in the bundle (checked last, before signing) |
| R7 | a missing SBOM or missing provenance attestation |
| R8 | the wrong evidence class — a `staged-candidate` is not a release |
| R9 | QEMU evidence presented as native arm64 |
| R10 | an image line outside `MATRIX_IMAGES`, or carrying a `foundry_release_state` in `policies/lifecycle.yaml` — PHP 8.5 is `experimental-amd64-only` and is absent from the shipping matrix, so both layers refuse it |
| R11 | public exposure without a separate public-exposure authorization |
| R12 | an `rc-publisher` or `scheduled-rebuild` identity presented for the release role |

R8 and R12 are the same acceptance criterion from two directions: a candidate
*identity* cannot satisfy the release role, and neither can candidate
*evidence*. `tests/release/test_release_seal.sh` asserts both, plus the hard
case — a seal **validly signed by the right key** that carries an RC subject is
still refused, because the policy pins the role, not the signature.

**Revocation and correction.** A seal is never edited. A correction is a new
seal from a new CalVer tag over a regenerated bundle, recorded in
`docs/audits/withdrawals/`. `verify-release-seal.sh --superseded-by <version>`
refuses a superseded seal so a consumer holding a cached copy learns it was
replaced rather than silently trusting it. There is no in-place revoke flag: a
mutable seal is not a seal.

### Retention

`policies/retention.yaml` states, per evidence class, how long a bundle must
remain restorable and re-verifiable, and where.

> **Corrected 2026-08-30.** This table previously showed 2,555 days and
> immutable storage for the two lower rows. That requirement was never
> authorized — commit `6413eb51`, PR #207, merged in 15 minutes with no review,
> citing no law, contract, customer or standard — and it was inverted: it
> protected the *reproducible* SBOM bytes for seven years while the
> *irreproducible* vulnerability database was kept for one day. The maintainer
> replaced it with the lifecycle model below on 2026-08-30. Provenance:
> `docs/decisions/evidence-retention-architecture.md`.

| class | lifecycle | retention | WORM |
|---|---|---|---|
| `upstream-base` | unpublished | 90 days, may expire | no |
| `foundry-child` | unpublished | 90 days, may expire | no |
| `staged-candidate` | unpublished | 90 days, may expire | no |
| `published-artifact` | published + supported | support end + 180 d + 90 d | no |
| *(regulated)* | — | only on a named external obligation | opt-in |

**What enforces this on the path that runs today.** The `authorize` job of
`stage-and-authorize.yml` observes what the artifact authority actually stored —
`id`, `node_id`, `created_at`, `expires_at`, read back from the artifacts API —
reads the uploaded evidence back, re-verifies every file against the manifest
sealed into it, and verifies a `foundry.storage-receipt/v1` record built from
those two things. A refusal fails the job. `retention-days: 90` in the workflow
is a *request*; the receipt records what was *granted*, and
`verify-storage-receipt.sh` compares that against the table above. The mechanism
is a GitHub Actions artifact: no lock, no versioning, no immutability, and the
receipt says so rather than flattering it.

There is no equivalent for `published-artifact` because nothing is published.
That contract is specified and fixture-tested; it activates with a publication
decision under #98.

Retention follows the lifecycle of the thing the evidence is about. A staged
candidate is private and undistributed, so its evidence may expire; a supported
release has recipients, so its *irreproducible* decision evidence — scan
verdicts, authorization record, execution metadata, ledger and policy identity,
scanner and vulnerability-database identity — lives as long as the support
commitment and its notice periods.

Reproducible evidence is **not** retained: SBOM bytes are regenerated from the
immutable image digest and the pinned producer and checked against the recorded
sha256. Release assets have no expiry timer but are **not permanent and not
immutable** — a privileged principal can delete them — which is why detection of
missing or prematurely deleted evidence is required for the published class.

A second independent location is required only by the regulated-worm model, of
which no class uses; the archive layout is plain
directories and files so restoring needs nothing but a filesystem and
`sha256sum`. Archived trees are set `0555` / `0444`, but permissions are a
guardrail — the control is `INDEX.sha256`, which catches a change that root, a
restore tool or a filesystem migration made anyway.

**Deletion is an act, not an expiry.** There is no prune, no scheduled sweep.
`restore-evidence.sh list` marks what is eligible; removing it is a maintainer's
explicit act after verification. An automatic deleter is an automatic evidence
destroyer the day the clock or the class is wrong.

The exercise that is actually run — by `restore-evidence.sh --self-test` and
again from outside by `tests/release/test_evidence_bundle.sh` — is:

```text
generate -> archive -> DELETE the working copy -> restore -> verify
```

on the real committed accepted evidence, offline. Anything less proves the
archive is writable, not that the evidence survives.

```bash
scripts/release/restore-evidence.sh archive --bundle /tmp/bundle --archive-root /srv/evidence
scripts/release/restore-evidence.sh list    --archive-root /srv/evidence
scripts/release/restore-evidence.sh restore --archive-root /srv/evidence \
  --bundle-id staged-candidate-7061caafb3ea-32395890071 --dest /tmp/restored
scripts/release/restore-evidence.sh verify  --archive-root /srv/evidence
```

### What is not done

- No workflow produces a bundle, a disposition set or a seal yet. Everything
  here is a maintainer-runnable tool with its own refusal suite; wiring it into
  `release.yml` and `stage-and-authorize.yml` is a separate, separately
  reviewable change.
- No production signature exists, and none can be produced by this tooling. The
  `release` role remains unconsumed by a real ceremony;
  `verify-release-seal.sh --reject-test-seal` is the gate that says so out loud
  rather than passing a fixture.
- SBOM bytes are supplied to the generator (`--sbom-dir`); the bundle records
  their digests. Producing them on the acceptance path is `scripts/generate-sbom.sh`'s
  job and is not changed here.
