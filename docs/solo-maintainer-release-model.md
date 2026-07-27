# Solo-maintainer release model

Zenchron Foundry uses a **single-maintainer release model**. Independent human
separation of duties is unavailable because there is only one maintainer: GitHub
forbids self-approval, so a required reviewer would block every release instead
of adding oversight. (Corrected 2026-07-28, issue #97 — this was previously
blamed on billing; environment reviewers *are* available now that the repo is
public. The blocker is people, not plan: issue #112.) We do **not** fake a second
reviewer.
Instead the risk is mitigated by technical and procedural controls that a lone
maintainer cannot bypass by mistake:

- **Immutable, SHA-bound RC images** — an RC tag embeds the version, rc id and
  source revision (`8.4-v2026.07.03-rc1-sha-<short>`); it can never be reused for
  different content, and the pre-publish immutability probe fails closed on a
  conflict (`scripts/lib/registry-probe.sh`).
- **Exact source-revision binding** — provenance revision, the OCI
  `org.opencontainers.image.revision` label, and the signed RC manifest must all
  equal one 40-hex commit; the release gate re-checks this equality chain across
  all ten images (`scripts/verify-release-binding.sh`).
- **Mandatory CI on the exact tagged commit** — the release queries the GitHub
  Checks API for the tag's commit and requires every check in
  `policies/required-release-checks.yaml` to be green; "latest master run" is
  never accepted (`scripts/check-exact-commit-ci.sh`).
- **Cryptographic attestations** — cosign keyless signatures, SPDX SBOM and SLSA
  provenance, verified against **explicit per-role identities**
  (`policies/cosign-identities.yaml`); a scheduled-rebuild candidate can never
  satisfy the rc-publisher/release identity.
- **Build-free promotion** — promotion retags exact digests, never rebuilds
  (`scripts/promote-stable.sh`), and is a two-phase transaction with an automatic
  compensating rollback (`scripts/rollback-stable.sh`).
- **Typed confirmations** — RC publish requires
  `PUBLISH-<version>-<rc>-<revision>`; stable promotion requires
  `PROMOTE-<version>-<revision>` plus `ACCEPT-RISK`.
- **Immutable evidence** — every release retains a signed/checksummed evidence
  package (`scripts/build-release-evidence.sh`), validated before sealing.
- **Tested rollback** — the compensating rollback is exercised in CI against a
  mock registry (`tests/promotion/`).

## What we deliberately do NOT require

- Two human reviewers. The GitHub plan cannot enforce it; pretending to would be
  security theatre. See [accepted risks](accepted-risks.md).

## Confirmation strings (quick reference)

| Action | Typed confirmation |
|---|---|
| Publish RC | `PUBLISH-<version>-<rc>-<revision>` |
| Promote stable | `PROMOTE-<version>-<revision>` + `ACCEPT-RISK` |

Related: [release-security](release-security.md), [rollback](rollback.md),
[stable-promotion](stable-promotion.md), `policies/release-governance.yaml`.
