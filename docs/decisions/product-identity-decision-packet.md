# Decision packet: what is Zenchron Foundry?

**For:** Bogdan Olteanu (sole maintainer, and the only person who can decide this)
**Blocks:** #98 → #97 → #113 → #114
**Prepared:** 2026-08-13 · **Prepared by:** engineering. **The answer is not chosen here.**

---

## Why this is one decision, not four tickets

```text
#98  what Foundry IS commercially  ──┐
                                     ├─→ #97  repository/licensing consistency
                                     ├─→ #113 CRA economic role
                                     └─→ #114 CRA reporting activation
```

You cannot make a defensible CRA economic-role assessment while the project has
not decided what it is commercially. #113 asks which economic operator Zenchron
is; that answer depends on whether Foundry is distributed, to whom, and under
what terms — which is #98. And #114 cannot activate reporting obligations whose
applicability #113 has not established.

So: **one decision session, four tickets closing behind it.**

## The contradiction, stated plainly

| fact | value | measured |
| --- | --- | --- |
| repository visibility | **public** | GitHub API, 2026-08-13 |
| `LICENSE` | *"INTERNAL / PROPRIETARY — NOT FOR PUBLIC DISTRIBUTION"* | repository root |
| GitHub-detected licence | `NOASSERTION` | GitHub API |
| forks / stars | 0 / 0 | GitHub API |
| image `org.opencontainers.image.licenses` | `LicenseRef-Zenchron-Internal` | all ten images |
| GHCR packages | private; repo token cannot write them | `docs/audits/package-acl-2026-08-03/` |

**The repository is world-readable and its licence says it must not be publicly
distributed.** Anyone reading it today has no granted rights to it — not to use
it, not to fork it, not to build from it. That is the whole of #98, and no
engineering change resolves it.

## The options

Each changes different things downstream. **None is recommended here** — the
trade-offs are commercial, not technical.

### A. Public open-source project

- Replace `LICENSE` with an OSI licence (Apache-2.0 and MIT are the conventional
  choices for infrastructure images).
- Change every image's `licenses` label and the ten image contracts.
- **CRA:** likely relevant as an **open-source steward** if there is no
  commercial activity — a materially lighter obligation set than manufacturer,
  but *not nothing*, and the boundary depends on how the images are monetised.
- Downstream: #97 becomes a consistency pass; #120 (licence compliance) becomes
  more demanding, because you are now redistributing under obligations you must
  honour and document.

### B. Public source, proprietary/commercial product

- Keep source visible, keep a proprietary licence, but make it a *real* one —
  a source-available licence granting inspection and forbidding redistribution,
  rather than a notice that says "not for public distribution" on a public page.
- **CRA:** likely **manufacturer**, because commercial activity is present. The
  heaviest obligation set, and the one #114's machinery was built for.
- Downstream: customer distribution terms, support contract (#125, already
  built), advisory channel obligations become contractual rather than
  best-effort.

### C. Private proprietary / internal platform

- Flip the repository to **private**. The licence then matches reality with no
  other change.
- **CRA:** likely out of scope while there is no placing on the market — but
  "internal use" must genuinely mean internal, and that is a factual question
  about who consumes the images.
- Downstream: #97 resolves by making visibility match the licence rather than
  the reverse. Several controls built for public consumption (advisory channels,
  admission policies for consumers, shared responsibility) become internal
  documentation rather than product surface.
- **Note:** this would *reverse* the 2026-07-28 decision recorded in
  `policies/repository-governance.yaml`, which moved the project to public and
  built the whole governance model on that basis.

### D. Proprietary, distributed only to customers

- Repository private or source-available; images distributed under contract.
- **CRA:** likely **manufacturer**, same as B.
- Downstream: the distribution mechanism becomes a controlled surface — which is
  what #139's protected exposure path is for, and it would need to align with the
  customer terms rather than being purely a technical boundary.

## What engineering has already prepared, whichever way it goes

Nothing below needs redoing after the decision. All of it is conditional on it,
and all of it is already built and exercised:

| | ready |
| --- | --- |
| product support contract, deprecation, withdrawal | #125 — exercised |
| PSIRT contact, advisories, security.txt | #125 — contacts verified |
| CRA incident state machine, deadlines, packets, tabletop | #114 — exercised |
| single-maintainer governance and its compensating controls | #112 |
| SBOM, provenance, signing identities | existing |
| runtime and admission assurance for consumers | #110, #124 |

The CRA machinery deliberately carries `applicability: undetermined` and stamps
every artefact accordingly. Making the determination is a *data change* to one
policy file, not a rebuild.

## What is needed from you

1. **Pick A, B, C or D** — or state a different answer.
2. If A or B: the specific licence.
3. If C: confirm the repository should go private, accepting that this reverses
   the July decision and that several public-facing controls become internal.
4. For #113, additionally: the **member state of establishment**, which
   determines the competent CSIRT for #114.

Everything else follows mechanically.

## What engineering must NOT do, and has not done

- Choose the licence or the commercial model.
- Assert a CRA economic role.
- Change repository visibility.
- Declare CRA applicability in `policies/incident-reporting.yaml`.

Those are recorded as `required_human_inputs` / `required_human_decisions` in the
relevant policy files, and every one of them is still unset.
