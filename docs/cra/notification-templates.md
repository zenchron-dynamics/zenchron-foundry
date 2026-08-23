# CRA notification templates

**DRAFT TEMPLATES. Not approved submissions, and not legal advice.** CRA applicability is undetermined
(#113) and no competent CSIRT or submission account is established (#114). Nothing here may be filed until
those exist.

Every template below carries a placeholder banner. **Remove the banner only when the notification is real
and authorised** — its presence is what stops a draft being mistaken for a filing.

The evidence fields referenced by name (`affected_image_digests`, `sbom_references`, `vex_status`, …) are
the ones `scripts/incident.sh packet` refuses to omit, so a template field left blank here corresponds to
a packet that will not generate.

---

## 1. Early warning — due 24h from awareness

> **[DRAFT — NOT A SUBMISSION — CRA APPLICABILITY UNDETERMINED]**

```text
Subject: Early warning — actively exploited vulnerability / severe incident

Entity            : Zenchron Dynamics
Economic role     : <UNDETERMINED — see policies/cra-applicability.yaml>
Contact           : <named submission authority>
Incident ID       : <id>
Awareness at      : <awareness_at, RFC3339 WITH timezone>
This notification : early warning (24h)

Nature of the event
  <summary>

Member states affected, if known
  <affected_distribution>

Is the vulnerability being actively exploited?
  <known_exploitation>

Assessment status
  Initial. Classification is <classification>; the full notification will
  follow within 72 hours of awareness.

Measures taken so far
  <mitigations>
```

**Note on timing.** An early warning is expected to be incomplete. Withholding it until the picture is
clear is the failure mode; the 72-hour notification is where completeness is owed.

---

## 2. Full notification — due 72h from awareness

> **[DRAFT — NOT A SUBMISSION — CRA APPLICABILITY UNDETERMINED]**

```text
Subject: Full notification — <incident id>

Entity            : Zenchron Dynamics
Incident ID       : <id>
Awareness at      : <awareness_at>
This notification : full notification (72h)

Affected products
  <suspected_affected_products>

Affected artefacts, by digest
  <affected_image_digests>          # digests, never tags — a tag moves

Affected source revisions
  <affected_source_revisions>

Software bill of materials
  <sbom_references>

Exploitation status
  <known_exploitation>

VEX status
  <vex_status>

Severity and impact assessment
  <classification> — <classification_rationale>
  Customer impact: <customer_impact>

Distribution reach
  <affected_distribution>

Mitigations and corrective measures
  <mitigations>
  <corrective_measures_taken>

Governance disclosure
  Zenchron Foundry is maintained by one individual. Classification,
  decision and submission authority rest with the same person; no
  segregation of duties exists. Recorded in policies/governance-model.yaml
  and policies/cra-roles.yaml.
```

**The governance disclosure is not optional.** A filing that names roles without stating that they collapse
onto one person implies a resilience that does not exist.

---

## 3. Final report

> **[DRAFT — NOT A SUBMISSION — CRA APPLICABILITY UNDETERMINED]**

Two different clocks, and they differ in **length and in origin event** — `scripts/incident.sh` computes
whichever applies from the recorded classification:

| classification | due |
| --- | --- |
| `actively-exploited-vulnerability` | **14 days** from `corrective_measure_available_at` |
| `severe-incident` | **30 days** from `full_notification_submitted_at` |

```text
Subject: Final report — <incident id>

Incident ID       : <id>
Awareness at      : <awareness_at>
Final report due  : <computed, not written by hand>

Description of the vulnerability or incident
  <summary> / <classification_rationale>

Root cause
  <root cause>

Applied corrective measures
  <corrective_measures_taken>
  Corrective release: <corrective release and digests>

Remaining risk and residual exposure
  <residual risk>
  Where the affected component is upstream and Foundry does not compile it,
  state that plainly and reference the ownership boundary
  (policies/component-ownership.yaml).

Customer notification performed
  <customer_notifications>

Decision log
  <decision_log>
```

---

## 4. Customer notice

Not a regulatory filing — this is what recipients receive. It must survive being read quickly.

> **[DRAFT — NOT A REAL NOTICE]**

```text
Subject: [ACTION REQUIRED] Zenchron Foundry security update — <id>

What happened
  <one plain sentence>

What you are running that is affected
  <image digests>

What you must do
  1. Re-pin to <corrective digest>
  2. <any configuration change>
  3. <verification step — digest, not tag>

What you do NOT need to do
  <explicitly state this — it prevents unnecessary emergency change>

If you take no action
  <consequence, stated plainly>
```

For `customer_impact: no-customer-impact`, no notice is sent, but a **rationale must be recorded** on the
incident record. `assert-cra-controls.sh --check-record` refuses that value without
`customer_impact_rationale`.

---

## Why every template is a draft

Producing a packet and filing it are different acts, and the second needs an account and a person. Neither
exists yet:

- `reporting_route.csirt: undetermined`
- `reporting_route.submission_account: undetermined`

`scripts/incident.sh` never submits anything, by design.
