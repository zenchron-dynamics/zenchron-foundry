# Incident response and CRA reporting

**Issue:** #114
**State machine:** [`policies/incident-reporting.yaml`](../policies/incident-reporting.yaml)
**Tooling:** `scripts/incident.sh`

## Read this first

**Whether the CRA applies to this product, and in which economic role, has not
been determined.** That is a legal and business decision tracked in **#113**.
Nothing in this repository makes it, and every artefact `scripts/incident.sh`
produces is stamped `CRA APPLICABILITY UNDETERMINED` until it is.

The machinery was built before the determination on purpose. If the answer is
"it applies", the clock starts at 24 hours and there is no time to build a
process then. If the answer is "it does not", a working incident process is
still worth having.

Reporting obligations commence **11 September 2026**.

## The state machine

```text
DISCOVERED
    ↓
AWARENESS_RECORDED ──── t0, and every clock is computed from it
    ├── early warning       t0 + 24h
    └── full notification   t0 + 72h
    ↓
CLASSIFIED
    ├── actively-exploited-vulnerability
    ├── severe-incident
    └── not-reportable  ──→ terminal, rationale REQUIRED
    ↓
EARLY_WARNING → FULL_NOTIFICATION → CORRECTIVE_ACTION → FINAL_REPORT → CLOSED
```

The final-report clock branches, and the two branches start from different
events:

| classification | deadline |
| --- | --- |
| actively-exploited-vulnerability | **14 days** after a corrective measure is available |
| severe-incident | **1 month** after the incident notification |

## Using it

```bash
# What are my deadlines?
bash scripts/incident.sh deadlines 2026-08-13T09:00:00+00:00

# Open a record. t0 is recorded once; changing it is itself a decision-log entry.
bash scripts/incident.sh new INC-2026-001 2026-08-13T09:00:00+00:00 "summary"

# Where am I, and have I missed anything?
bash scripts/incident.sh status docs/audits/incidents/INC-2026-001.yaml

# Produce a packet. REFUSED if required evidence is missing.
bash scripts/incident.sh packet docs/audits/incidents/INC-2026-001.yaml full_notification
```

`awareness_at` **must carry a timezone**. A naive timestamp starts a regulatory
clock nobody can defend, and the tool refuses one.

## Why packets are refused

A report assembled from whatever was at hand is how a wrong digest reaches a
regulator. The evidence schema is in the policy file; a full notification needs
12 fields including affected image **digests**, source revisions, SBOM
references, VEX status, known exploitation, mitigations and distribution.

## The tabletop

```bash
bash scripts/incident.sh --tabletop
```

Runs a complete simulated incident with a fixed `t0` of 2026-08-13T09:00Z,
classified as actively-exploited to exercise the tighter 14-day branch. It binds
**real current image digests** so the evidence path is exercised against reality,
generates all three packets, and asserts every artefact is marked both
`SIMULATED` and `APPLICABILITY UNDETERMINED`.

Last run: 3 packets (5, 12 and 18 evidence fields), all deadlines **MET**, 5/5
honesty assertions passed.

## What is deliberately missing

These are human facts this repository does not hold, and none was invented:

| gap | who |
| --- | --- |
| CRA applicability and economic role | legal / business (#113) |
| competent CSIRT and submission route | legal — depends on member state of establishment |
| an account on the CRA Single Reporting Platform | Bogdan Olteanu |
| who decides classification, who signs a submission | Bogdan Olteanu — and with one maintainer these roles collapse onto one person, which must be **stated** in a filing rather than implied |

`scripts/incident.sh` **never submits anything.** Producing a packet and filing
it are different acts; the second needs an account and a person.
