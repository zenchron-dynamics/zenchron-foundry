# Evidence retention audit — do the original image SBOMs survive?

**Date:** 2026-08-30 · **Repository state:** `66966d9` · **Read-only.** Nothing
was rebuilt, no SBOM was regenerated, no workflow was dispatched, no artifact was
created or deleted. The only GitHub calls were `GET`.

**Verdict: there is no durable, tested retention contract for original SBOM
bytes.** The policy that requires one exists and is unimplemented on the release
path. The historical loss is real, it is **not** an expiry, and it cannot be
repaired retroactively.

---

## 1. Where the 40 SBOM documents from `7061caaf` were stored

**Nowhere.** They were never an output of the acceptance workflow.

At revision `7061caafb3ea09bd5b2342a1daf022151b33f822` —
the accepted candidate revision — `.github/workflows/stage-and-authorize.yml`
contained **no SBOM step at all**. The only occurrence of the word in that
revision is the buildx flag `sbom: false`. The SBOM production and binding step
was added later, by `5275c1f` ("compose the image-SBOM and repository-material
licence verdicts into the canonical authorization", #236) — **eight days after**
the accepted run.

The 40 documents were produced on **2026-08-27** by the buildless audit lane
recorded in `docs/audits/real-image-inventories-2026-08-28/`: `scripts/generate-sbom.sh`
unmodified, with a shim execing a digest-pinned `anchore/syft@sha256:f94e5d9f…`
(v1.33.0) against the registry by immutable digest. They were written to a local
scratch directory — 86,781,974 bytes across 20 children — which is gitignored
(`*.cdx.json` repository-wide) and was discarded when that lane finished.

> The binding records carry `workflow_run_id: 32395890071`. That is the id of the
> **run whose images were scanned**, not of a run that produced the documents.
> Reading it as provenance for the bytes is the mistake this section exists to
> prevent.

## 2. Configured retention

| | |
|---|---|
| repository setting | **90 days** (`maximum_allowed_days: 90`) |
| organisation setting | 90 days (`maximum_allowed_days: 400`) |
| `retention-days` on the evidence uploads | **unset** — they inherit the repository setting |
| `policies/retention.yaml`, class `staged-candidate` | **2555 days**, `immutable_storage_required: true` |

The `trivy-db` artifact sets `retention-days: 1` deliberately (a 110 MB database
snapshot whose *identity* is recorded in the authorization record instead).
`scan-images.yml` sets 30. Every other upload is unset.

**The gap is 90 against 2555**, and it was 0 for SBOMs at the accepted revision.

## 3. Why they are no longer available

**Not expiry.** The accepted run's artifacts are still live.

```text
run 32395890071 · stage-and-authorize · head_sha 7061caaf · 2026-08-20
42 artifacts · 41 LIVE · 1 expired · all live ones expire 2026-11-18
  post-build-authorization-32395890071-1   1,730,870 B   expired: false
  child-<slug>-32395890071-1  × 20         1,649 KB tot  expired: false
  trivy-db-32395890071-1                 110,249,731 B   expired: TRUE (retention-days: 1, by design)
```

Both the authorization record and all twenty child-evidence artifacts were
**downloaded during this audit**. Their contents:

```text
post-build-authorization-…/  post-build-authorization.json, SHA256SUMS, records/*.json  (15 MB)
child-caddy-prod-linux-amd64-…/
    caddy-prod-linux-amd64.json
    caddy-prod-linux-amd64-evidence/{trivy.json, scan.log, smoke.log, contract.log,
        oci-labels.json, oci-metadata.log, no-java.log, packages.tsv,
        reconcile.json, reconcile.log, phases.json}
```

**No `sbom/` directory. No `.spdx.json`. No `.cdx.json`.** Consistent with
`sbom: false` at that revision.

> ### A correction to this repository's own audit record
>
> `docs/audits/real-image-inventories-2026-08-28/README.md` §7 states:
>
> > The accepted run's own `post-build-authorization.json` was a 30-day workflow
> > artifact and has expired.
>
> Both halves are wrong. It is a **90-day** artifact and it **has not expired** —
> it is live until 2026-11-18 and was retrieved today. The reconstruction by
> `tests/lib/make_authorization_fixture.py` was therefore unnecessary; it happens
> to be a faithful reconstruction, but it was justified by a fact that was not
> checked. The lesson is the one this audit is about: *nobody had queried the
> retention API before asserting an expiry.*

## 4. What of the lost documents IS preserved

Everything except the bytes.

| preserved | where |
|---|---|
| per-document **sha256** and byte size, 40 of 40 | `sbom-document-index.json`, and again in the 20 `sbom-bindings/*.binding.json` |
| **producer** identity (`scripts/generate-sbom.sh`) | each binding record |
| **scanner** identity, pinned by digest | `scanner-identity.json` — `anchore/syft@sha256:f94e5d9f…`, `syft-1.33.0` |
| **subject** binding | `sbom_declared_subject`, with `sbom_subject_equals_manifest_digest: true` for 20/20 |
| image digest, platform, source revision, execution mode | each binding record |
| derived measurements | the 8,507-finding diagnostic, the identifier reconciliation, the 535/723 reconciliation in this directory |

So a re-scan can be **checked against** the recorded hashes. It cannot be assumed
to reproduce them: SPDX documents carry a document namespace UUID and a creation
timestamp, so byte-identical reproduction is not a property syft offers. The
honest statement is that the *identity* of the lost documents survives and their
*content* does not.

## 5. Do future acceptance runs upload original SBOM bytes to durable storage?

**They upload the bytes. The storage is not durable.**

Since `5275c1f`, the `stage` job writes `evidence/child/sbom/*.json` and
`evidence/child/sbom-bindings/*.json`, copies `evidence/child` into
`evidence/out/<slug>-evidence`, and uploads that as `child-<slug>-<run>-<attempt>`
— with `retention-days` unset, i.e. **90 days**.

`scripts/release/generate-evidence-bundle.sh` is the tool that would place SBOM
bytes into a self-contained, offline-verifiable bundle (`--sbom-dir`, and a
`content/sbom/` tree). **No workflow invokes it.** Its only appearance in
`.github/workflows/` is

```yaml
run: bash scripts/release/generate-evidence-bundle.sh --self-test
```

which is the tool testing itself. `scripts/release/restore-evidence.sh` — the
readback half — is referenced only by `tests/`. The archive layout, the two
independent locations and the 2555-day class in `policies/retention.yaml`
describe a contract that **nothing on the release path executes**.

## 6. Can authorization complete when retention is shorter than the required period?

**Yes.** Nothing in the authorization path reads `policies/retention.yaml` or
checks any retention property. `validate-authorization-record.sh` consumes the
licence verdict and the notice bundle; neither carries a retention claim. A run
whose evidence expires in 90 days authorizes exactly as one whose evidence is
archived for seven years, and nothing distinguishes them.

## 7. Is deletion or expiry detected before evidence becomes unrecoverable?

**No.** No workflow, script or test queries an artifact's `expired` or
`expires_at`. The repository's only `expires_at` handling is in the
vulnerability-exception ledger (`reconcile-vulnerabilities.sh`,
`upstream-monitor.py`), which is a different clock about a different object.

There is no alert at 60 days, no alert at 89, and no signal at all on the day an
artifact goes. The first indication would be a download failing, at the moment
the evidence is already gone.

## 8. What this audit did not do

It did not regenerate the missing SBOMs, rebuild an image, dispatch a workflow,
change any retention setting, or touch publication authority, licence policy,
vulnerability governance, images or release controls. The historical loss
**cannot be repaired retroactively**: the documents were never stored, so there
is nothing to restore.

**Reopening #120 is not appropriate.** #120 is about licence policy, inventory,
notices and gating, and all of it is merged and consumed. Durable evidence
retention is a different control with a different owner, and it is filed as its
own bounded issue.

## 9. Files

| file | what it is |
|---|---|
| `artifact-retention-probe.json` | the live read-only API probe: run identity, both retention settings, all 42 artifacts with `expired`/`expires_at` |
| `notice-reconciliation.json` | 535 implicated components → 723 findings, total in both directions |
