# Decision packet: publication and licence (issue #98)

**For:** the repository owner (maintainer role) together with the legal owner.
**Prepared by:** engineering, 2026-08-25, against master `663ab93d`. **No option is chosen here, and this
document does not recommend one.**

Issue #98 is the common blocker in front of the remaining publication work: `.github/workflows/release.yml:31-58`
and `.github/workflows/publish-rc.yml:43-45` are refusal stubs, and
`policies/license-policy.yaml:53` holds `notices_approved_for_distribution: false`. Nothing downstream of
publication can move until one of A, B or C is recorded at `policies/license-policy.yaml:43`.

This document is itself public. It states the governance posture as measured facts; it does not describe how to
defeat any control.

## The conflict, as the repository actually holds it

| fact | value | where |
| --- | --- | --- |
| repository visibility | `public` (`private: false`) | live API; declared `policies/repository-governance.yaml:50` |
| GitHub-detected licence | `NOASSERTION` | live API (`.license.spdx_id`) |
| `LICENSE` heading | `INTERNAL / PROPRIETARY — NOT FOR PUBLIC DISTRIBUTION` | `LICENSE:3` |
| `LICENSE` grant | use/copy/modify limited to "authorized internal users"; redistribution "in source or binary (image) form" prohibited | `LICENSE:9-13` |
| image licence label | `org.opencontainers.image.licenses="LicenseRef-Zenchron-Internal"` | 14 Dockerfiles + 10 `contracts/images/*.yaml`, asserted at `scripts/release/verify-oci-metadata.sh:156,170` |
| GHCR container packages | all `private` (incl. `php-fpm`, `php-cli`, `php-worker`, `php-frankenphp`, `nginx`, `caddy`) | live org packages API |
| recorded decision | `decision: undetermined`, `decided_by: null`, `decided_on: null` | `policies/license-policy.yaml:43-45` |

World-readable source under a licence that forbids redistributing it, documenting images nobody outside can
pull. `docs/licensing/license-compliance.md:25-26` states the consequence: "Anyone reading the repository has no
grant to use what they can see."

**Free-tier controls key on visibility, not on plan.** `docs/audits/free-tier-governance-accepted-risk.md:9-16`
records that the earlier accepted risk was superseded precisely because it assumed Free + *private*; on Free +
*private*, rulesets, branch protection and environment reviewers return HTTP 403/422
(`docs/audits/free-tier-governance-accepted-risk.md:64-76`). Both live rulesets — `master-protection`
(id `19853431`, `active`) and `release-tags-immutable` (id `19853433`, `active`), each with `bypass_actors: []`
(`policies/repository-governance.yaml:142-158`, `:195-205`) — exist because the repository is public. That makes
visibility a load-bearing input to option choice, not a cosmetic one.

## A / B / C — the three options from #98

Option labels are the ones `policies/license-policy.yaml:43` can record (`A | B | C | undetermined`). No fourth
option is introduced here; see "Preconditions" for the D discrepancy.

| dimension | A — public open source | B — public source-visible, proprietary | C — private proprietary |
| --- | --- | --- | --- |
| repository visibility | `public` — unchanged | `public` — unchanged | **`private`** — control-plane change |
| source-code licence | replace `LICENSE` with an OSI licence (owner + legal pick which) | replace `LICENSE:3-13` prose with an explicit source-available grant: inspection permitted, redistribution prohibited | `LICENSE` unchanged |
| container-image distribution | public redistribution permitted under the same licence | images stay under `LicenseRef-Zenchron-Internal`, delivered under separate commercial terms | internal/authorized systems only, per `LICENSE:9-11` |
| package visibility | must flip 6 production packages to `public`, else an OSI-licensed project ships images nobody can pull — a *new* inconsistency | `private` — unchanged | `private` — unchanged |
| GitHub ruleset impact | none; both rulesets stay enforceable | none; both rulesets stay enforceable | **both rulesets stop being enforceable** on the free org plan (`free-tier-governance-accepted-risk.md:64-70`); `environment_required_reviewers` (`repository-governance.yaml:220`, currently `pending`) becomes unavailable again |
| signing / release impact | `release.yml` stays a refusal stub (#139 is a separate gate); `policies/cosign-identities.yaml:32-48` `release` role stays reserved | identical to A | identical to A, plus `org_runner_group.allows_public_repositories: true` (`repository-governance.yaml:88`) becomes moot and must be re-declared |
| repository file changes | `LICENSE`; `policies/license-policy.yaml:43-45,49,50,53`; 14 Dockerfile label lines; 10 `contracts/images/*.yaml`; `scripts/release/verify-oci-metadata.sh:156,170`; `tests/reproducibility/evidence/php-cli-8.4-linux-amd64.lock.json:715`; `README.md:148-154`; `CONTRIBUTING.md` (CLA/DCO) | `LICENSE`; `policies/license-policy.yaml:43-45,49,53`; `README.md:148-154`; new customer-terms document. **No image-label churn** | `policies/repository-governance.yaml:50` and the `branch_ruleset`/`tag_ruleset` blocks → `pending` (`:214`); `README.md`/`CONTRIBUTING.md` become internal docs |
| control-plane changes | 6 package visibility flips | **none** | 1 repository visibility flip (+ plan decision) |
| reversibility | **effectively irreversible** for the grant — copies distributed under an OSI licence keep it permanently | **fully reversible** — file-only; revert the commit | setting is reversible, but the source has been public since 2026-07-28 and is forkable/indexed; and both rulesets must be **re-verified, and probably re-created, on any return to public** — whether ids `19853431`/`19853433` survive the round trip is untested and should not be assumed |
| legal review | required — outbound grant + all 17 `legal-review-required` third-party licences (`policies/license-policy.yaml:91-144`) | required — enforceability of the source-available grant | required — whether prior public exposure leaves residual obligation |

## Per-option consequence notes

### A — public open source

The only option that makes `NOASSERTION` go away and lets the repository state a real inbound/outbound position.
It is also the only one that touches image identity: every `org.opencontainers.image.licenses` label is asserted
by `scripts/release/verify-oci-metadata.sh:156,170` and frozen into reproducibility lock evidence, so the label
change is a coordinated edit across Dockerfiles, contracts, the verifier and regenerated locks — not a
find-and-replace. It also raises the bar on #120: `policies/license-policy.yaml:16-20` keeps `denied: []` by
design, and all 17 reciprocal / advertising-clause entries at `:91-144` become obligations to honour rather than
questions to defer. Flipping the 6 production packages to public is required for coherence, and that is the
step with no undo.

### B — public source-visible, proprietary

The only option needing zero control-plane change: visibility, package ACLs, rulesets and environments all stay
exactly as measured. It replaces a *notice* ("not for public distribution", printed on a public page) with a
*grant* that says what a reader may actually do. `LICENSE:22-23` already anticipates that the current file is a
placeholder. Image labels stay `LicenseRef-Zenchron-Internal`, so `verify-oci-metadata.sh` and the reproducibility
locks are untouched. Cost: customer distribution terms become a real deliverable, and inbound contributions must
be either refused or CLA'd — `CONTRIBUTING.md:3-4` currently assumes internal-only contributors.

### C — private proprietary

Makes the licence true by changing reality instead of text, and is the cheapest in repository files — but the
most expensive in controls. It reverses the 2026-07-28 visibility decision recorded at
`policies/repository-governance.yaml:42-50`, and on the free org plan it silently disables both active rulesets
and re-closes the `environment_required_reviewers` gap that `:214-220` currently tracks as closable. Two
consequences that must be accepted explicitly, not discovered: (1) either accept the loss of enforced branch and
tag protection, or upgrade the org plan; (2) `scripts/verify-repo-governance.sh` fails closed in *both*
directions (`policies/repository-governance.yaml:6-9`), so `visibility: public` at `:50` and the two ruleset
blocks must be edited in the *same* change, or governance verification breaks the moment the flip lands.

## Exact control-plane changes, by option

These cannot be made from repository code. They are hand actions for the infrastructure owner, after the
decision is recorded.

- **A** — GHCR package visibility, per package, for the 6 production packages `php-fpm`, `php-cli`, `php-worker`,
  `php-frankenphp`, `nginx`, `caddy` (org package settings → Change visibility → Public). The remaining org
  packages (`foundry-staging`, `zenchron-website`, `zenchron-tools`, `proxyflux-app`, `proxyflux-worker`,
  `proxyflux-cli`) are out of scope for #98 and stay private.
- **B** — none. This is the option's defining property.
- **C** — repository visibility `public` → `private` (repository settings, or `PATCH /repos/{owner}/{repo}`
  with `{"private": true}`). Consequential and separate: an org plan decision, because rulesets `master-protection`
  and `release-tags-immutable` cease to be enforceable on Free + private. Neither environment
  (`foundry-rc`, `foundry-production`, both live with `branch_policy` only) gains or loses a rule by the flip
  itself, but `environment_required_reviewers` stops being attainable without a paid plan.

No option changes anything about publication itself: `release.yml` and `publish-rc.yml` remain refusal stubs
under #139 regardless of which is picked.

## What legal is actually being asked

One question per option, phrased so it can be answered yes/no with conditions.

- **A** — "May Zenchron Dynamics grant the public a perpetual, irrevocable licence over the Foundry source and
  the images built from it, and can we simultaneously satisfy the obligations of the 17 licences classified
  `legal-review-required` at `policies/license-policy.yaml:91-144` — specifically the reciprocal (GPL/LGPL/AGPL/
  MPL/EPL/CDDL) and advertising-clause (`OpenSSL`, `BSD-4-Clause`, `PHP-3.01`) entries — once we are a
  redistributor?"
- **B** — "Is a source-available grant — inspection and internal evaluation permitted, redistribution in source
  or image form prohibited — enforceable for us, and does publishing the source while delivering images only
  under contract constitute placing a product on the market for the purposes of #113's economic-role
  determination?"
- **C** — "If the repository becomes private and images are delivered only to authorized internal systems, does
  Foundry stay outside 'placing on the market', and does the public exposure that has existed since 2026-07-28
  create any residual obligation to parties who read or forked it during that window?"

All three additionally need the **member state of establishment**, which #113 and #114 also require.

## Preconditions before the decision can be recorded

Small, repository-side, and not blocked on legal:

1. `policies/license-policy.yaml:43` accepts `A | B | C | undetermined`, while
   `docs/decisions/product-identity-decision-packet.md:113` offers "A, B, C or D". If the owner picks D, there is
   no field that can hold it. Either widen the enum or state that D is out of scope for #98.
2. `CONTRIBUTING.md:21-27` still asserts "the repo is on GitHub Free (private), where branch protection cannot
   enforce it" and that CODEOWNERS cannot be enforced "on a private repo". That is false today and is exactly the
   class of stale distribution claim #98 exists to remove. It becomes true again only under C.
3. No `NOTICE` artifact exists and `scripts/license/generate-notice.sh` is referenced by no workflow, so
   acceptance criterion 2 of #98 has repository-side work in front of it under every option.

## Recording the decision

```yaml
# policies/license-policy.yaml
publication:
  decision: A            # or B / C
  decided_by: <role or entity>
  decided_on: 2026-MM-DD
```

The licence gate and `scripts/license/generate-notice.sh` switch behaviour off that one field
(`docs/licensing/license-compliance.md:28-32`). Everything else in the table above is an ordinary file change or
one of the named control-plane actions. Engineering does not make this choice and has not made it here.
