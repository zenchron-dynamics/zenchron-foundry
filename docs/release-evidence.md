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
