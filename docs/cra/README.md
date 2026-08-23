# CRA control set

**Nothing in this directory is a compliance claim, a legal determination, or a certification.**

CRA applicability is **undetermined**. `policies/cra-applicability.yaml` records `status: undetermined`
and `determined_by: null`, and `scripts/cra/assert-cra-controls.sh` refuses if that ever changes to an
assertion without a named author and a date.

What this control set does is narrower and checkable: it states the factual product boundary, maps CRA
obligations onto controls that **already run in this repository**, names who performs each incident duty,
and refuses incident records that omit the things a report is built from.

## Why this was built before the determination

Reporting obligations commence **2026-09-11**. If the determination is "the CRA applies", the clock starts
at 24 hours and there is no time to build a process then. If it is "it does not apply", a working incident
process is still worth having and nothing was lost.

## The three policies

| file | what it holds |
| --- | --- |
| `policies/cra-applicability.yaml` | product boundary inventory, and the applicability **decision template** — every answer `null` |
| `policies/cra-roles.yaml` | incident roles, responsibilities, backups, and the customer-impact vocabulary |
| `policies/cra-control-matrix.yaml` | 14 obligations mapped to controls, with an honest `enforced` / `partial` / `absent` status |

### The anti-drift rule

Every row of the control matrix must cite `evidence` paths that **exist on disk**. The validator refuses a
row pointing at an absent file:

```text
obligation 'x' cites evidence 'scripts/this-file-does-not-exist.sh' which DOES NOT EXIST — a
matrix pointing at absent files is how a repository convinces itself it is covered
```

A `partial` or `absent` obligation must also state a `gap`. A shortfall without a stated gap reads as
coverage, which is worse than an admitted hole. The shipped matrix currently reports **7 partial and 1
absent** — it is not a clean sheet, and it is not supposed to be.

## Roles, and the backup problem

Foundry has **one maintainer**. `policies/governance-model.yaml` already records
`single_maintainer: true`, `independent_review_available: false` and `segregation_of_duties: unavailable`,
and explicitly rejects "a second GitHub account held by the same person" as a mitigation.

So all six roles resolve to one person and **none has a backup**. Inventing deputies to fill the matrix
would be exactly the failure the governance model exists to prevent. Instead each role must resolve its
backup one of two ways, and the validator refuses anything else:

```yaml
backup: <a real, distinct person>
# or
backup_gap: true
gap_reason: ...      # all three required
gap_owner: ...
gap_tracked_in: ...
```

A missing `backup` key, a backup naming the primary, or an undeclared gap all refuse. This mirrors the
`integrity_gap` idiom already used in `policies/supply-chain-inputs.yaml`: gaps are declared and owned,
never absent.

**The concentration is a reportable fact.** Any filing must state that classification, decision and
submission authority rest with one individual rather than implying a team.

## Customer-impact classification

Distinct from the regulatory classification in `policies/incident-reporting.yaml`. That one decides whether
a **regulator** is told; this one decides what a **customer** is told. They are not the same question — an
incident can be non-reportable and still require customer action, or reportable with none.

| value | means |
| --- | --- |
| `action-required` | recipients must upgrade, re-pin or reconfigure to be safe |
| `informational` | recipients are affected but need take no action |
| `no-customer-impact` | nothing reaching any recipient is affected — **rationale required** |
| `undetermined` | permitted only while the incident is open |

A **closed** incident carrying `undetermined` is refused. "We never worked out who this hurt" is not an
acceptable final state.

## Independent deadline recomputation

`scripts/incident.sh` computes the 24h / 72h / final-report clocks. `assert-cra-controls.sh --check-record`
**recomputes them independently** from `policies/incident-reporting.yaml` and refuses when a record's
written-down deadline disagrees:

```text
early_warning_due is 2026-08-20T09:00:00+00:00 but policy computes
2026-08-14T09:00:00+00:00 from the recorded times — a deadline written
down by hand is a deadline that can be wrong
```

Two implementations that must agree catch a drift that one implementation checking itself never can.

## The synthetic tabletop

```bash
bash scripts/cra/assert-cra-controls.sh --tabletop
```

**It is a fixture, and it says so on every run.** It is not evidence that a tabletop exercise was conducted
with real participants, and it must never be recorded as one. It runs offline and exercises all five
refusal conditions — missing awareness time, naive timestamp, miscomputed deadline, absent evidence,
missing customer impact — plus the roles-without-backup refusal, then re-asserts that applicability is
still undetermined.

## What is still missing, and who owns it

| gap | owner | blocks |
| --- | --- | --- |
| the applicability determination and economic role | legal / business | #113 |
| the competent CSIRT and submission route | legal | #114 |
| a submission account and named filing authority | Bogdan Olteanu | #114 |
| conformity documentation | depends on classification | #113 |
| a real backup for any role | Bogdan Olteanu | #113 |

## See also

- [`notification-templates.md`](notification-templates.md) — early warning, full notification, final
  report and customer notice drafts
- [`submission-checklist.md`](submission-checklist.md) — what must be true before anything is filed
- `docs/incident-response.md` — the incident state machine itself
