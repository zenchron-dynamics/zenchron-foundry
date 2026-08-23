# CSIRT / ENISA submission checklist

**Nothing can be submitted today.** This checklist exists so that the reason is specific rather than vague,
and so the first real submission is not also the first time anyone works out the route.

## Blocking preconditions — none of these are engineering tasks

| # | precondition | current state | owner |
| --- | --- | --- | --- |
| 1 | CRA applicability determined | `undetermined` (`policies/cra-applicability.yaml`) | legal / business |
| 2 | economic role determined | `null` | legal / business |
| 3 | member state of establishment identified | `null` | legal |
| 4 | competent CSIRT identified | `csirt: undetermined` (`policies/incident-reporting.yaml`) | legal |
| 5 | single reporting platform account exists | `submission_account: undetermined` | Bogdan Olteanu |
| 6 | named person authorised to file | `submission-authority` role has no backup | Bogdan Olteanu |

Until 1–6 are resolved, `scripts/incident.sh` produces packets and **files nothing**. That separation is
deliberate: producing a report and submitting it are different acts, and the second needs an account and a
person.

## Pre-submission checklist — run before any real filing

### A. The clock

- [ ] `awareness_at` is recorded, RFC3339, **with a timezone**
- [ ] deadlines were **computed**, not typed — `assert-cra-controls.sh --check-record` agrees with them
- [ ] the correct final-report branch applies (14 days from corrective measure, or 30 days from full
      notification) for the recorded classification
- [ ] no deadline is already `MISSED`; if one is, say so in the filing rather than smoothing it over

### B. The evidence

- [ ] every mandatory field for this packet kind is present — `incident.sh packet` generated without
      refusing
- [ ] affected artefacts are identified by **digest**, never by tag
- [ ] `affected_source_revisions` are full 40-hex revisions
- [ ] `sbom_references` resolve to real SBOM documents
- [ ] `vex_status` is set
- [ ] where the affected component is upstream and Foundry does not compile it, the ownership boundary is
      referenced explicitly (`policies/component-ownership.yaml`)

### C. The classification

- [ ] regulatory classification recorded, with `classification_rationale`
- [ ] a `not-reportable` outcome carries a rationale — deciding **not** to report must be as auditable as
      reporting
- [ ] `customer_impact` recorded and not `undetermined`
- [ ] `no-customer-impact` carries `customer_impact_rationale`

### D. The honesty checks

- [ ] the packet does **not** carry the `SIMULATED` banner (a real filing must not; a fixture must)
- [ ] the packet does **not** carry `CRA APPLICABILITY UNDETERMINED` — if it does, precondition 1 is unmet
      and this is not ready to file
- [ ] the governance disclosure is present: roles collapse onto one individual, no segregation of duties
- [ ] no statement claims a certification, conformity assessment or third-party review that has not
      occurred

### E. After submission

- [ ] submission timestamp recorded on the incident record (`*_submitted_at`)
- [ ] `assert-cra-controls.sh --check-record` re-run and clean
- [ ] the record retained per `policies/incident-reporting.yaml` `retention` (10 years,
      `docs/audits/incidents`)
- [ ] the next clock's due time re-derived from the newly recorded timestamp

## What ENISA / the single reporting platform expects

Recorded here as **structure**, not as legal guidance — confirm against the current official guidance
before filing, since the platform's fields are authoritative and this file is not:

1. **Early warning (24h)** — that something happened, whether exploitation is known, and which member
   states may be affected. Expected to be incomplete.
2. **Full notification (72h)** — severity, impact, indicators of compromise, and corrective measures.
3. **Final report** — description, root cause, applied mitigations, and residual risk.

The intermediate-update obligation, where a CSIRT requests one, is not modelled by the state machine.
`scripts/incident.sh` covers the three scheduled reports only. **That is a known gap**, and it should be
handled manually until the reporting route is known well enough to model.

## Escalation if the deadline cannot be met

Do not let a deadline pass silently. If the 24h or 72h clock will be missed:

1. file what exists, incomplete, before the deadline
2. record on the incident why it was incomplete
3. supply the remainder as soon as it exists

`scripts/incident.sh status` reports a passed deadline as `MISSED` rather than rounding it away, so the
record stays truthful even when the process failed.
