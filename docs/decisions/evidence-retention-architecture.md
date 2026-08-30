# Evidence retention architecture — decision packet (#241)

**Status: DECISION REQUIRED. Nothing here provisions anything.** No bucket, no
account, no credential, no IAM policy, no Object Lock configuration, no upload,
no workflow integration, no acceptance dispatch. This packet compares options,
recommends one, defines the contract, and stops at the point where an owner has
to choose.

Prepared against `a5e5094`. Evidence: `docs/audits/evidence-retention-2026-08-30/`.

---

## 1. Frozen facts

These are measured, not assumed, and nothing below is allowed to contradict them.

| fact | source |
|---|---|
| The original 40 SBOM bytes for `7061caaf` **were never retained** | the workflow at that revision had no SBOM step; only `sbom: false` |
| The loss is **retroactively irreparable** | the bytes were never stored, so there is nothing to restore |
| This was **not artifact expiry** | 41 of 42 artifacts are live to 2026-11-18 and were downloaded during the audit |
| GitHub repository artifact retention is **90 days** | `maximum_allowed_days: 90`; `retention-days` unset on every evidence upload |
| Policy requires **2,555 days** and **immutable** staged-candidate evidence | `policies/retention.yaml` |
| Future workflows upload evidence but **no durable store consumes it** | `generate-evidence-bundle.sh` is invoked by no workflow |
| Authorization **does not verify retention** | nothing on the authorize path reads `policies/retention.yaml` |
| **No expiry or deletion monitor exists** | nothing queries an artifact's `expired`/`expires_at` |
| **#120 remains correctly closed** | it is licence policy, inventory, notices and gating — all merged and consumed |
| **#241 owns the retention defect** | filed 2026-08-30 |
| 535 components reconcile to **723 findings** — 721 component-scoped, 2 project-scoped, **0 orphaned** | `docs/audits/evidence-retention-2026-08-30/notice-reconciliation.json` |

**The lost historical SBOMs are not regenerated or reconstructed anywhere in this
work, and must not be.**

---

## 2. Storage options

Twenty attributes per option. "Satisfies policy" means: 2,555 days of retention
that a privileged principal cannot shorten, plus versioning, integrity and
readback.

### A. AWS S3 with Object Lock (compliance mode)

| attribute | assessment |
|---|---|
| 2,555-day guarantee | **yes** — `retain-until` is set per object version |
| WORM semantics | **yes**, in compliance mode |
| privileged deletion / bypass | **none before retain-until**, including the account root. `s3:BypassGovernanceRetention` applies to *governance* mode only |
| retention mode | compliance (required) or governance (insufficient — see §5) |
| versioning | **mandatory** — Object Lock cannot be enabled without it |
| legal hold | **yes**, independent of and additive to retain-until |
| regional availability | broad; the bucket is single-region, replication is a separate decision |
| encryption | SSE-S3, SSE-KMS or SSE-C; KMS gives key custody and an audit trail, at the cost of a key that must not be lost (§5) |
| integrity verification | `Content-MD5`, and native `ChecksumSHA256` per object and per part |
| restore / readback | immediate for Standard; **Glacier tiers require a restore job** before bytes are readable |
| lifecycle / archive tiers | yes, and this is a hazard as much as a feature (§5) |
| credential / role model | OIDC federation from GitHub Actions to a role with `s3:PutObject` and no `Delete*`; a separate reader role for readback |
| audit logs | CloudTrail data events (opt-in, billed) plus S3 server access logs |
| expiry monitoring | derivable from `GetObjectRetention`; needs a job, it is not built in |
| operational complexity | **moderate** — bucket, lock config, two roles, OIDC trust, logging |
| repository growth | **none** — bytes leave the repository |
| reversibility | the *integration* is revertible; **objects written under compliance lock cannot be deleted until they expire**, and that is the point |
| control-plane owner | cloud account owner |
| **satisfies policy** | **YES** |

### B. Another S3-compatible WORM / object-lock provider

Backblaze B2, Wasabi, MinIO and Cloudflare R2 all speak S3, and their object-lock
support is **not uniform**: some implement governance only, some implement
compliance, and some implement neither. R2 in particular has no S3 Object Lock.

| attribute | assessment |
|---|---|
| 2,555-day guarantee | **provider-dependent** — must be verified per provider, not assumed from "S3-compatible" |
| WORM semantics | provider-dependent; several offer governance-equivalent only |
| privileged deletion | **the question that decides this option.** A provider whose support staff can delete a locked object has governance semantics whatever it is called |
| everything else | broadly as A, with the same shape |
| operational complexity | as A, plus provider due diligence |
| **satisfies policy** | **CONDITIONAL** — only with written confirmation of compliance-mode semantics and no support-side bypass. **Rejected as a default** because "S3-compatible" does not imply "Object Lock compliant", and adopting it on that assumption is exactly the error this packet exists to avoid |

### C. Immutable OCI artifacts in a registry

Push the bundle as an OCI artifact (ORAS) beside the images.

| attribute | assessment |
|---|---|
| 2,555-day guarantee | **no.** GHCR offers no retention lock; retention is a deletion policy, not a lock |
| WORM semantics | **no.** Content-addressing makes a manifest immutable *by identity* — the digest cannot change — but the object can be **deleted**. Immutable content is not retained content |
| privileged deletion | **yes** — any package admin can delete a version |
| retention mode | none |
| versioning | by digest |
| legal hold | none |
| integrity verification | excellent (digest-addressed) |
| restore / readback | immediate |
| credential model | already exists |
| operational complexity | **low** — the lowest of any option |
| repository growth | none |
| **satisfies policy** | **NO — REJECTED.** It cannot guarantee 2,555 days and cannot prevent privileged deletion. Worth revisiting only as a *second* location under §3, never as the authority |

### D. Git-backed or Git LFS evidence

| attribute | assessment |
|---|---|
| 2,555-day guarantee | **no.** Protected branches and signed commits are strong controls but history can be rewritten by an admin, and a repository can be deleted |
| WORM semantics | **no** |
| privileged deletion | **yes** — force-push and repository deletion |
| repository growth | **disqualifying.** ~100 MB of SBOM bytes per accepted run against a repository that already blocks any single file over 512 KB. At 26 runs/year the repository grows ~2.6 GB/year and every clone pays it |
| LFS variant | moves the bytes out of the pack but introduces a separate store with its own quota and *no* lock semantics; deleting the LFS objects is an admin action |
| integrity verification | excellent |
| operational complexity | low |
| **satisfies policy** | **NO — REJECTED** on both immutability and repository growth |

### E. GitHub Actions artifacts — the existing baseline

| attribute | assessment |
|---|---|
| 2,555-day guarantee | **no. 90 days is the hard maximum on this plan** (`maximum_allowed_days: 90`) |
| WORM semantics | **no** |
| privileged deletion | **yes** — an artifact, a run, or the repository can be deleted |
| legal hold | none |
| expiry monitoring | none built in |
| **satisfies policy** | **NO — REJECTED.** 90 against 2,555 is not a gap to be narrowed; it is 3.5 % of the requirement. **This option is not presented as a viable durable solution and must not be adopted as one.** Its only correct role is temporary transport, per §3 |

### Summary

| | A | B | C | D | E |
|---|---|---|---|---|---|
| 2,555 days | ✅ | ⚠️ | ❌ | ❌ | ❌ |
| no privileged bypass | ✅ | ⚠️ | ❌ | ❌ | ❌ |
| repository growth | none | none | none | **disqualifying** | none |
| **verdict** | **recommended** | conditional | rejected | rejected | rejected as durable |

---

## 3. Recommended architecture

| layer | role |
|---|---|
| GitHub Actions artifact | **temporary transport and cache only.** Never the authority, never cited as retention |
| durable authority | object storage with **versioning + Object Lock**, per option A (or B with verified compliance semantics) |
| staging / non-accepted evidence | short retention, or governance-mode lock — it did not ship |
| accepted candidate evidence | **2,555-day compliance-mode lock** |
| index | manifest keyed by candidate and source revision |
| contents | **original producer bytes**, unrewritten |
| integrity | a **separate content-addressed checksum index**, so an index and its objects cannot drift together |
| verification | restore / readback, offline |
| monitoring | deletion and expiry alerting ahead of unrecoverability |
| infrastructure | defined and owned in **`zenchron-infrastructure`** |
| Foundry | **emits and consumes the evidence contract** and owns neither the bucket nor the credentials |

> **`zenchron-infrastructure` does not exist.** It is not in the
> `zenchron-dynamics` organisation as of 2026-08-30. Creating it is an owner
> action and a prerequisite for phase B; this packet does not create it.

---

## 4. The cross-repository contract

### Foundry → infrastructure

| field | why it is required |
|---|---|
| bundle identity | so a receipt can be matched to one bundle and no other |
| original evidence bytes | rewritten bytes are a different artifact |
| SHA256 for every file | per-file, so a partial upload is detectable |
| candidate digest / platform / source revision | so a receipt for another candidate cannot be presented |
| producer and schema identities | so the bytes can be reproduced or challenged |
| evidence class | which control the bundle belongs to |
| retention class | which duration applies |
| required retain-until date | stated *before* the write, so the receipt is checked against it |
| expected object-lock mode | compliance for accepted candidates |
| deterministic manifest | the same inputs must produce the same manifest hash |
| upload completion record | the handover point |

### Infrastructure → Foundry

| field | why it is required |
|---|---|
| immutable object / version identity | without a version, an overwrite is invisible |
| storage provider and region | recorded, never constrained by Foundry |
| **actual** retain-until timestamp | what came back, not what was asked for |
| lock mode | compliance vs governance — the distinction in §5 |
| versioning state | Object Lock has nothing to pin without it |
| encryption state | at rest, algorithm, key custody |
| object checksum | the bytes that landed |
| upload time | to compute the retention interval |
| audit-event identity | proof an authority observed the write |
| readback verification result | the observation that turns a claim into evidence |

### Authorization must refuse when

`SR-RETENTION-SHORT` · `SR-LOCK-MODE-WEAK` · `SR-VERSIONING-ABSENT` ·
`SR-CHECKSUM-MISMATCH` · `SR-READBACK-FAILED` / `SR-READBACK-ABSENT` ·
`SR-FILE-MISSING` · `SR-UNBOUND` / `SR-CANDIDATE-MISMATCH` / `SR-REVISION-MISMATCH` ·
`SR-EXPIRY-BEFORE-SUPPORT` · `SR-AUTHORITY-UNAVAILABLE` · `SR-ENCRYPTION-ABSENT` ·
`SR-RECEIPT-ABSENT` / `SR-RECEIPT-MALFORMED`.

**A claimed upload is not sufficient.** Every field checked is one the authority
reported *after* the write. The schema is
`schemas/storage-receipt-v1.schema.json`; the consumer is
`scripts/release/verify-storage-receipt.sh`; 43 assertions and 23 sabotages are
in `tests/release/test_storage_receipt.sh`.

---

## 5. Threat and failure model

**Compliance mode is immutability. Governance mode is not.** Under governance a
principal holding `BypassGovernanceRetention` — including the account root — can
shorten the retention or delete the object before its date. That is a *retention
control*, and calling it immutable is the misstatement the verifier refuses
(`SR-LOCK-MODE-WEAK`) with that sentence in the diagnostic.

| threat | mitigation | residual |
|---|---|---|
| compromised CI credential | write-only role, no `Delete*`, no lock-config rights, OIDC short-lived | attacker can add objects, not remove them |
| administrator deletion attempt | compliance mode blocks it until retain-until | **none before expiry** — this is the property being bought |
| lifecycle misconfiguration | a lifecycle rule cannot delete a locked object version | a rule can still transition it to a slow tier — see restore failure |
| bucket or account deletion | a bucket with locked objects cannot be deleted; **account closure is the real residual** | mitigate with a second location and organisation-level controls |
| KMS-key loss | key deletion protection; a destroyed key makes objects unreadable while still undeletable — the worst of both | prefer provider-managed keys unless key custody is a stated requirement |
| partial upload | per-file SHA256 plus `files_expected` vs `files_verified` → `SR-FILE-MISSING` | none |
| corrupt object | object checksum vs manifest hash → `SR-CHECKSUM-MISMATCH` | none |
| wrong-region upload | region is recorded in the receipt and can be asserted against policy | policy must state expected regions |
| retention clock error | the interval is computed from `uploaded_at` and `retain_until` **in the receipt**, and checked against the policy floor | provider clock skew |
| duplicate bundle identity | bundle id derives from candidate + source revision; a second write to the same key creates a new *version*, and the receipt names the version | needs a receipt ledger to detect reuse across runs — **open, see phase A follow-up** |
| storage receipt substitution | the receipt is bound to the authorization record's own sha256 → `SR-UNBOUND` | none |
| provider outage | authorization refuses (`SR-AUTHORITY-UNAVAILABLE`) rather than proceeding | releases block during an outage, which is the correct direction |
| restore failure | readback is mandatory and part of the receipt; archive tiers are rejected for the readback path | none if archive tiers are excluded |
| expired temporary GitHub artifact | irrelevant once the durable copy exists — that is the entire point of demoting it to transport | none |
| infrastructure repository drift | the contract is a schema in Foundry and is version-pinned; drift shows up as `SR-RECEIPT-MALFORMED` | needs a contract-version negotiation if the schema evolves |

---

## 6. Volume and cost model

### Measured inputs

| input | measured value |
|---|---|
| SBOM documents per accepted run | 40 documents, **86.8 MB** uncompressed |
| SBOM gzip-9 ratio, real syft SPDX | **8.1×** → ~10.7 MB compressed |
| child evidence, 20 artifacts | 1.65 MB as uploaded |
| authorization record | 1.69 MB as uploaded (≈15 MB expanded) |
| trivy database | 110 MB — **excluded**, `retention-days: 1` by design, identity recorded instead |
| buildx `.dockerbuild` telemetry | 2.2 MB — **excluded**, not evidence |

**Bundle per accepted run ≈ 100 MB raw, ≈ 15 MB compressed.**

### Formula

```text
stored_bytes(7y) = bundle_bytes × runs_per_year × 7 × (1 + copies − 1)
requests(7y)     = runs_per_year × 7 × (puts_per_bundle + readbacks_per_bundle)
                   + restore_tests_per_year × 7
```

Object Lock means **nothing rolls off inside the window**, so storage is strictly
cumulative for seven years.

### Sensitivity

| accepted runs/year | 7-year raw | 7-year compressed | ×2 locations (compressed) |
|---|---|---|---|
| 12 (monthly) | 8.4 GB | 1.26 GB | 2.5 GB |
| 26 (fortnightly) | 18.2 GB | 2.73 GB | 5.5 GB |
| 52 (weekly) | 36.4 GB | 5.46 GB | 10.9 GB |

Historical basis: 11 `stage-and-authorize` runs exist in total and 2 acceptances
are recorded (2026-08-14, 2026-08-20). The weekly row is the pessimistic bound
from the former rebuild cadence; the monthly row matches observed behaviour.

Requests are negligible at any of these rates: one multipart PUT and one readback
GET per bundle, plus periodic restore tests — of the order of 10²–10³ requests
per year, not 10⁶.

**No provider prices are quoted.** At single-digit GB, storage cost is dominated
by per-request and audit-logging charges rather than by bytes, and quoting a
figure without current sourced pricing would be fabrication. The owner should
price the table above against a current rate card.

**Staging vs accepted.** Retaining every staging run at the accepted-candidate
class would multiply the table by the staging-to-acceptance ratio for evidence
that did not ship. `policies/retention.yaml` already separates them —
`foundry-child` at 400 days, `staged-candidate` at 2,555 — and that separation is
what keeps the volume bounded.

---

## 7. Migration and historical truth

- The **historical missing bytes cannot be recreated as originals.** A re-scan
  today produces *new* documents from the same images, not the documents that
  were made in August, and SPDX carries a namespace UUID and a creation
  timestamp, so byte-identity is not even theoretically available.
- The surviving **hashes and binding records remain useful** — they identify what
  was measured and would detect a substitution — but they are **not a substitute
  for the bytes** and must never be described as one.
- **The first fully retained acceptance becomes the new durable-evidence
  baseline.** Before it, there is no durable evidence; after it, there is.
- The **earlier acceptance keeps its documented limitation**, including the
  correction annotations already merged into
  `docs/audits/real-image-inventories-2026-08-28/README.md`.
- **History is not rewritten to imply durable retention existed.** No record is
  backdated, no bundle is manufactured for a past run, and no audit document is
  edited to remove the gap.

**No acceptance is dispatched to establish the baseline.** That requires separate
authorization (phase E).

---

## 8. Implementation sequence

| phase | scope | status |
|---|---|---|
| **A** | Foundry storage-receipt schema and fail-closed tests | **done in this packet** — schema, verifier, 43 assertions, 23 sabotages, 2 pinned gaps |
| **B** | `zenchron-infrastructure` provisioning and IAM | **not started; requires the repository to exist and an owner decision** |
| **C** | canary upload, lock, readback and simulated failure tests | not started |
| **D** | workflow integration — `--require-storage-receipt` on the authorize path | **not started, and pinned as a gap** in `tests/release/test_storage_receipt.sh` |
| **E** | one separately authorized acceptance establishing the first durable baseline | not started |

Phases B–E are **not implemented in this packet** and must not be started under
it.

---

## 9. Decisions only the owner can make

1. **Provider** — option A, or option B with written confirmation of
   compliance-mode semantics and no support-side bypass.
2. **Account and region**, and whether a second location is required now or later.
3. **Create `zenchron-infrastructure`** — it does not exist today.
4. **Key custody** — provider-managed keys, or customer-managed with the
   key-loss risk in §5 accepted and mitigated.
5. **Compliance mode is irreversible for the objects it covers.** Nothing written
   under a 2,555-day compliance lock can be deleted for seven years, including by
   the account owner, including if the account is meant to be closed. This is the
   property being bought and it is the one to be sure about.
6. **Audit-log scope** — data-event logging is opt-in and billed.
7. **Accepted-run cadence** to size the model in §6.
8. **Whether staging evidence is retained at all**, and under which class.
9. **Authorization of phases B–E**, separately from this packet.
