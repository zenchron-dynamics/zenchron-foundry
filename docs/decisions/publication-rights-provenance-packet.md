# Rights-provenance packet: is each publication option legally executable? (issue #98)

**For:** the legal owner, with the maintainer role and the release owner.
**Prepared by:** engineering, 2026-08-27, against master `9eae8b1`.

**This document selects nothing and changes no control.** `LICENSE` is unchanged.
`policies/license-policy.yaml:43` still reads `decision: undetermined` and `:53`
`notices_approved_for_distribution: false`. `.github/workflows/release.yml:30-58` remains a refusal stub.
Repository and package visibility, rulesets and `policies/vulnerability-exceptions.yaml` are untouched.

Two documents already exist and are not repeated. `docs/decisions/publication-and-licence-options.md` compares
the consequences of A, B and C. `docs/decisions/licence-legal-review-packet.md` establishes what a lawyer needs
before that comparison can be acted on. Both left one thing open: **provenance evidence**. Who contributed this
repository, under what apparent authority, and what is actually incorporated in it. That is what follows, plus
the question those two documents did not put: not which option is preferable, but **which options can lawfully
be executed at all, today.**

This document is public. It states the position factually, reports contributor identities as roles and counts,
and does not describe how to defeat any control.

## Measurement basis

| item | value |
| --- | --- |
| repository | `zenchron-dynamics/zenchron-foundry` |
| master at measurement | `9eae8b15ba8c3eca7f15401e10fc321c02918173` |
| commits in history | 168 (`git rev-list --count HEAD`) |
| first commit | 2026-05-30 (`7640aac`) |
| repository created | 2026-05-30T11:44:13Z (`gh api repos/zenchron-dynamics/zenchron-foundry`) |
| tracked files | 721 (`git ls-files \| wc -l`) |
| live visibility | `public`, `private: false` |
| live detected licence | `NOASSERTION` (`.license.spdx_id`) |
| live fork count | 0 |

The prior packet measured 164 commits at `f3883b9d`. The count has grown to 168; every figure below is
re-measured, and where a prior figure no longer reproduces this document says so.

## Verdict first

| | A — public open source | B — public source-visible | C — private proprietary |
| --- | --- | --- | --- |
| **executable today?** | **no** | **no** | **yes, as a control-plane act** — but it discharges nothing |
| what blocks it | no licence text exists; inbound rights not established; unmet Apache-2.0 obligations | grant text and customer terms do not exist and have no named drafter; inbound rights not established | nothing blocks the act itself; three obligations survive it |
| whose approval | legal owner (outbound + inbound), OSS-compliance counsel, maintainer role for 6 package flips | legal owner (drafts/commissions grant), commercial counsel (image terms), maintainer role | repository owner (visibility), org-plan decision, legal owner (residual exposure) |
| reversible? | no, for the grant | file-reversible; grant already received is not | setting reversible; public exposure since at least 2026-07-28 is not |

Three findings apply to **all three options** and are not resolved by any of them: the Apache-2.0 obligations in
§6, the absence of an IP-vesting instrument in §7, and the two pinned licence gaps in §13.

## 1. Commit-author and co-author inventory

### Author identities — 3, of which 1 is a bot

| identity class | commits | evidence |
| --- | --- | --- |
| maintainer identity, `user.name` spelled as a personal name | 128 | `git shortlog -sne HEAD` |
| maintainer identity, `user.name` spelled as the same address | 18 | same |
| `dependabot[bot]` | 22 | same |

The two maintainer spellings share **one** email address on the organisation domain, so there are **two
`user.name` spellings and one human author identity**. No third human author identity appears as commit author
anywhere in the 168 commits.

### Committer identities — 2

| committer | commits | what it means |
| --- | --- | --- |
| `GitHub <noreply@github.com>` | 150 | squash-merged through a pull request; every one of the 150 subjects ends in `(#N)` |
| the maintainer identity | 18 | committed locally and pushed directly |

`git rev-list --count --merges HEAD` is **0**. There is no merge commit in the history: every PR landed as a
squash. That fact drives §10.

### Co-authored-by trailers

| measure | value |
| --- | --- |
| `Co-authored-by:` trailer **lines** (all commits) | 376 |
| commits carrying at least one such trailer | 137 of 168 |
| commits carrying at least one **AI** trailer (`noreply@anthropic.com`) | **113** |
| commits carrying a `dependabot[bot]` trailer | 22 (exactly the 22 dependabot-authored commits) |
| commits carrying a second human co-author address | 7 |
| commits with **no** trailer of any kind | 31, all from the maintainer identity |

Distinct co-author entities, counted once per commit:

| entity | commits |
| --- | --- |
| `Claude Opus 4.8 (1M context) <noreply@anthropic.com>` | 45 |
| `Claude Opus 5 <noreply@anthropic.com>` | 38 |
| `dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>` | 22 |
| `Claude Opus 5 (1M context) <noreply@anthropic.com>` | 19 |
| `Claude Fable 5 <noreply@anthropic.com>` | 12 |
| a second human address on a consumer email domain | 7 |

`Signed-off-by:` appears on **22** commits, all `dependabot[bot] <support@github.com>`. No human commit in the
history carries a sign-off.

### Two corrections to the prior packet

1. **`docs/decisions/licence-legal-review-packet.md:183` reads "133 of 164 commits name an AI assistant as
   co-author"; `:162` records "133 of 164" as the count of commits carrying a `Co-authored-by:` trailer. Those
   are two different measurements and they are not the same number.** The 133 figure (now 137) counts commits with *any*
   `Co-authored-by:` trailer, and 22 of those name only `dependabot[bot]`. The AI-trailer figure is **113 of
   168**, and 0 of the 113 also carry a dependabot trailer. The task framing of "133 AI co-author trailers" is
   therefore also off in two directions at once: the number of AI-trailer *commits* is 113, and the number of AI
   trailer *lines* is 287 (376 minus 22 dependabot minus 7 second-human, before de-duplication).
2. **The second human co-author address is not accounted for anywhere in the prior work.** It appears on 7
   commits, 5 of which also carry an AI trailer and 2 of which (`7dc6b54`, `7f7f4e0`) do not. Its display name
   matches the maintainer's given name and its domain is a consumer mail provider. **Whether it is the same
   natural person as the maintainer identity is not established from the repository.** If it is, nothing
   changes. If it is not, there is a second contributor with no CLA, no DCO and no sign-off, and §7's vesting
   question has two subjects rather than one. The legal owner should be asked which it is; the maintainer role
   can answer it in one sentence.

## 2. Contribution provenance for all 168 commits

Every commit falls into exactly one of four submission paths. This is the complete partition; the counts sum to
168.

| # | path | commits | dates | apparent authority |
| --- | --- | --- | --- | --- |
| 1 | direct push to `master`, committed locally by the maintainer identity | 18 | 2026-05-30 to 2026-06-01 | repository owner acting directly, before branch protection existed |
| 2 | squash-merge of a maintainer-authored PR | 128 | 2026-06-01 onward | maintainer role, self-approved — `policies/governance-model.yaml:30-34` records `single_maintainer: true`, `maintainer_count: 1`, `independent_review_available: false` |
| 3 | squash-merge of a `dependabot[bot]` PR | 22 | throughout | GitHub App configured by `.github/dependabot.yml`, merged by the maintainer role; each carries `Signed-off-by: dependabot[bot]` |
| 4 | merge commits | 0 | — | — |

**Authority, stated precisely.** For all 146 human-authored commits the submitting party is one identity acting
as repository owner and sole maintainer. `policies/governance-model.yaml:34-35` records that segregation of
duties is `unavailable` and that no independent review exists; `:40-51` explicitly refuses to count
self-approval, green CI or CODEOWNERS routing as independent review. So the authority under which every
contribution entered is **self-asserted repository-owner authority**, which is a fact about the process and not
a defect in it — but it means there is no second party whose acceptance could be pointed at as evidence that the
submitter held the rights.

**What is not established:** whether that identity submitted under an employment relationship, a contractor
relationship, or in a personal capacity. See §7.

**Commit signatures are not established.** `gpg` is absent from the measurement environment, so
`git log --format='%G?'` returns `N` for all 168 commits and proves nothing in either direction.
`CONTRIBUTING.md:20-23` states signing is policy enforced by local hooks only. GitHub's own verification status
was not queried and should not be inferred from this document.

## 3. Commits containing third-party or generated material

### Third-party material, by the commit that introduced it

| file | added by | date | trailers on that commit |
| --- | --- | --- | --- |
| `security/seccomp/zenchron-default.json` | `ba892c8` — `feat(runtime): one hardened runtime contract, executed on all ten (#110, #107, #129) (#165)` | 2026-08-12 | AI co-author |
| `security/apparmor/zenchron-container` | `ba892c8` (same commit) | 2026-08-12 | AI co-author |
| `security/seccomp/NOTICE` | `93fbefa` — `fix(licensing): attribute the two copied upstream files (#231)` | 2026-08-27 | AI co-author |
| `docs/audits/libaom3-ownership-2026-08-26/evidence/installer-helper.txt` | `5cfe665` — `evidence(libaom3): true ownership and remediation path for the FrankenPHP children (#224)` | 2026-08-26 | **none** |

`93fbefa` is the attribution commit referred to in the task framing. It landed 15 days after the material it
attributes. For 15 days the repository redistributed a byte-identical copy of an Apache-2.0 file with no notice
of any kind.

### Generated material

`docs/audits/**` contains machine-generated scanner output committed as evidence — four Trivy JSON reports under
`docs/audits/caddy-openssl-2026-08-27/evidence/`, plus SBOM and inventory files elsewhere. These embed verbatim
third-party advisory prose (NVD, OpenSSL project and Go project descriptions; e.g.
`docs/audits/caddy-openssl-2026-08-27/evidence/trivy-control-linux-amd64.json:2206`). Whether reproducing
advisory text carries any obligation is **not established** and is a question for counsel, not for engineering;
it is raised here because it is third-party text physically present in the tree, which is the §6 test.

### Confirmed absent

- No `.gitmodules`; no submodules.
- No `vendor/`, `third_party/` or `node_modules/` directory (`git ls-files` returns nothing under those paths).
- Three tracked binary files only: `docs/audits/package-acl-2026-08-03/package-acl-probe-30837370041-1.zip` and
  two audit `.txt` files that `file --mime` classifies binary because of control characters. No keys,
  certificates or compiled artefacts.
- **`AGENTS.md:5-7` records the standing rule** that Foundry "does not fork, patch, vendor, or compile
  upstream-owned runtime/server binaries", and `policies/component-ownership.yaml` `approved_adrs` is empty.
  The sweep found nothing contradicting that rule.

## 4. Current copyright notices — what exists and what is absent

Complete inventory. `git grep -InE '(Copyright|\(c\) [12][0-9]{3}|©)'` over all tracked files returns five
lines, one of which is this packet's own predecessor document:

| # | location | text |
| --- | --- | --- |
| 1 | `LICENSE:1` | `Copyright (c) 2026 Zenchron Dynamics. All rights reserved.` |
| 2 | `README.md:154` | `© 2026 Zenchron Dynamics — Internal / Proprietary.` |
| 3 | `security/seccomp/NOTICE:12` | `Copyright: Copyright 2012-2017 Docker, Inc.` |
| 4 | `security/apparmor/zenchron-container:10` | `Copyright 2012-2017 Docker, Inc.` |
| 5 | `docs/audits/libaom3-ownership-2026-08-26/evidence/installer-helper.txt:8` | the upstream author's line, intact inside a quoted excerpt |

**What is absent:**

- **No per-file copyright header on any first-party file.** 721 tracked files, 0 headers.
- **No `SPDX-License-Identifier` line anywhere.** `git grep -I 'SPDX-License-Identifier'` returns exactly one
  hit, and it is the sentence in `docs/decisions/licence-legal-review-packet.md:112` asserting there are none.
  That assertion still holds.
- **No Apache-2.0 licence text.** `git grep -Il 'Apache License, Version 2.0'` returns **0 files**. See §6.
- **No `NOTICE` at the repository root.** The only `NOTICE` file is `security/seccomp/NOTICE`, scoped to one
  file. `scripts/license/generate-notice.sh` exists and is invoked by no workflow.
- **No copyright year range.** Both first-party notices say `2026` only; the history begins 2026-05-30 and is
  entirely within that year, so this is currently correct and will need maintenance rather than correction.

## 5. Current repository licence state

| fact | value | where |
| --- | --- | --- |
| `LICENSE` heading | `INTERNAL / PROPRIETARY — NOT FOR PUBLIC DISTRIBUTION` | `LICENSE:3` |
| grant | use/copy/modify to "authorized internal users under the terms of their employment or contractual agreement" | `LICENSE:9-11` |
| redistribution | prohibited in source **or** image form without prior written consent | `LICENSE:11-13` |
| self-declared status | placeholder — "replace this file before publication. Do not assume any OSI license applies by default." | `LICENSE:22-23` |
| GitHub-detected licence | `NOASSERTION`, `license.key: other` | live API |
| recorded publication decision | `undetermined`, `decided_by: null`, `decided_on: null` | `policies/license-policy.yaml:43-45` |
| notices approved for distribution | `false` | `policies/license-policy.yaml:53` |
| image licence label | `LicenseRef-Zenchron-Internal` | Dockerfiles and `contracts/images/*.yaml` |
| visibility | `public`, verified 2026-07-28 and again 2026-08-27 | `policies/repository-governance.yaml:43,50`; live API |

Two points a legal owner should be handed directly.

1. **`LICENSE:9-11` conditions the entire grant on "employment or contractual agreement with Zenchron
   Dynamics".** The repository contains no such agreement and no evidence one exists (§7). The operative licence
   therefore points at an instrument that is not in evidence — for its *outbound* grant to internal users, and,
   read together with §7, for its *inbound* claim of ownership.
2. **Public since at least 2026-07-28, and possibly since 2026-05-30.**
   `policies/repository-governance.yaml:43` records `gh repo view` returning PUBLIC on 2026-07-28 and `:45-49`
   records the rationale as an access decision. **Whether the repository was public between its creation on
   2026-05-30 and that verification is not established** — no record in the repository fixes the date it first
   became public. If the residual-exposure question in option C turns on the length of the exposure window, that
   date must be recovered from GitHub's audit log, which is a control-plane query, not a repository fact.

## 6. Dependency and copied-material licence obligations

### The Moby attribution — verified, and incomplete

`security/seccomp/NOTICE` (added 2026-08-27 by `93fbefa`) asserts that
`security/seccomp/zenchron-default.json` is a pinned copy of the Moby default seccomp profile at v27.3.1,
Apache-2.0, `Copyright 2012-2017 Docker, Inc.`, with "CHANGES FROM UPSTREAM … none recorded".

Every one of those claims was independently verified:

```text
$ gh api "repos/moby/moby/contents/profiles/seccomp/default.json?ref=v27.3.1" \
    --jq '.content' | base64 -d > /tmp/moby-default.json
$ shasum -a 256 /tmp/moby-default.json security/seccomp/zenchron-default.json
9c1025c88ccaa517b648da571961838744ea2137f176bfe6a48b21294cae9c76  /tmp/moby-default.json
9c1025c88ccaa517b648da571961838744ea2137f176bfe6a48b21294cae9c76  security/seccomp/zenchron-default.json
$ gh api repos/moby/moby/license --jq '.license.spdx_id'
Apache-2.0
```

**The copy is byte-identical to upstream v27.3.1 and the "no changes" claim is true.** The licence claim is
correct. The copyright line matches the upstream `NOTICE`. That part of the attribution is sound and the
verification is reproducible.

**It is nonetheless incomplete.** `policies/license-policy.yaml:73-75` classifies `Apache-2.0` `allowed` with
four obligations. Measured against the tree:

| obligation (`license-policy.yaml:75`) | satisfied? | evidence |
| --- | --- | --- |
| `retain-copyright-notice` | **yes** | `security/seccomp/NOTICE:12`; `security/apparmor/zenchron-container:10` |
| `state-changes` | **yes** | `NOTICE:19-22` records "none recorded", verified above; the AppArmor header states its changes at `:12-22` |
| `retain-license-text` | **no** | `git grep -Il 'Apache License, Version 2.0'` → 0 files. Upstream ships a 10,765-byte `LICENSE` at v27.3.1; no copy exists here |
| `retain-notice-file` | **no** | upstream ships a 642-byte `NOTICE` at v27.3.1. Its content — the Docker attribution line, a `creack/pty` MIT attribution, and an export-control paragraph — is **not** carried forward. `security/seccomp/NOTICE` reproduces only the copyright line |

`security/seccomp/NOTICE:14-15` states the obligation in its own words — "Apache-2.0 requires that a
redistributor retain the copyright notice **and the licence text**" — and the licence text is not there. The
file names an obligation it does not meet. This is two file additions away from being closed and is **not
blocked on the A/B/C decision**.

### Scope check — is anything else copied in?

The sweep in §3 found nothing further. Specifically:

- `security/apparmor/zenchron-container` is derived from Moby's `profiles/apparmor/template.go` (path confirmed
  present at v27.3.1 by `gh api`). It is a restatement rather than a copy, its header at `:7-22` states the
  derivation, the licence and the changes, and it inherits the same two unmet obligations.
- `docs/audits/libaom3-ownership-2026-08-26/evidence/installer-helper.txt:8,10,12` carries the upstream
  copyright, source URL and MIT licence reference intact inside a quoted excerpt. Compliant on its face.
- Everything else third-party reaches the product at **build time** and lands in the image, not the tree —
  base images, distribution packages, PECL extensions, CI tooling, pinned Actions. That inventory is at
  `policies/supply-chain-inputs.yaml` and is unchanged by this packet.

### Why the existing gate cannot see any of this

`docs/licensing/license-compliance.md:36-47` describes a pipeline that reads SBOMs of **built images**.
`security/seccomp/` is repository source that no image SBOM enumerates. The licence gate is therefore
structurally incapable of detecting copied in-repo material, and it did not detect this. That is a gap in
control coverage, and §13 shows the gate is not wired into any workflow either.

## 7. Employment, assignment or IP-vesting instrument

**Absent from the repository. Stated plainly, with the searches that establish it.**

| search | files hit (excluding this packet and its predecessor) |
| --- | --- |
| `Contributor License Agreement` | 0 |
| `Developer Certificate of Origin` | 0 |
| `vesting` / `vests` | 0 |
| `work made for hire` / `work for hire` | 0 |
| `employment agreement` | 0 |
| `intellectual property` | 0 |
| `contractor` | 0 |

The only text in the repository that touches the relationship at all:

- `LICENSE:10-11` conditions the internal grant on "their employment or contractual agreement with Zenchron
  Dynamics" — it presumes such an instrument, it is not one.
- `policies/governance-model.yaml:177` records a risk owner as a person and the organisation jointly — an
  accountability record, not an assignment.
- `CONTRIBUTING.md:3-4` asserts contributions "come from authorized platform/security engineers" — a statement
  of practice, not a grant.

**This document does not assume an instrument exists elsewhere.** It may; the repository cannot tell. What the
legal owner must be told is the negative in exactly this form: *nothing in the repository evidences that the
146 human-authored commits are owned by Zenchron Dynamics, and the operative `LICENSE` assumes they are.*

## 8. CLA / DCO coverage

**No inbound-licensing mechanism of any kind exists.**

| mechanism | present? | evidence |
| --- | --- | --- |
| CLA text or CLA bot | **no** | 0 grep hits; `ls .github` returns `workflows/`, `actionlint.yaml`, `dependabot.yml` only |
| DCO requirement | **no** | 0 grep hits; no DCO check among the 17 files in `.github/workflows/` |
| sign-off convention for humans | **no** | 22 `Signed-off-by:` trailers, all from `dependabot[bot]`; 0 human sign-offs in 146 human commits |
| pull-request template | **no** | no `.github/PULL_REQUEST_TEMPLATE*` |
| inbound term in `CONTRIBUTING.md` | **no** | the file has no licensing section at all |
| statement that outside PRs are refused | **no** | `CONTRIBUTING.md:3-4` assumes internal contributors; it neither invites nor refuses outside ones |

The repository is public, accepts pull requests, and defines no inbound term. That is the same defect as the
historical one, still open prospectively. **Fixing it prospectively does not fix it retroactively** and the two
should not be conflated in the decision.

Separately: `CONTRIBUTING.md:21-27` still asserts the repository "is on GitHub Free (private)" and that
CODEOWNERS "cannot be enforced on a private repo". Both are false today. This was already flagged at
`docs/decisions/publication-and-licence-options.md:135-137` and remains uncorrected at `9eae8b1`.

## 9. The exact rights uncertainty created by the AI co-author trailers

**Framed precisely, and this framing is load-bearing.**

The question is **not** whether an AI co-author trailer confers copyright on the named assistant. It does not,
and nothing in this document should be read as suggesting otherwise. A `Co-authored-by:` trailer is a Git
message convention with no legal operation; it transfers nothing, reserves nothing and creates no party.

The question is: **for each of the 113 commits carrying such a trailer, did the human or organisation submitting
it hold the right to license all of the material it introduced?** The trailer bears on that question in exactly
one way — it is on-the-record evidence, published permanently, that the material was produced with the
assistance of a generative tool. Every downstream uncertainty flows from that single fact, not from the trailer
itself.

Three distinct uncertainties, which must not be collapsed into one:

1. **Subsistence.** Does copyright subsist in AI-assisted output at all, and to what extent, in the member state
   of establishment? That member state is itself **not established** — `docs/decisions/publication-and-licence-options.md:126`
   records it as required under all three options and `docs/decisions/licence-legal-review-packet.md:400`
   repeats it. Until the jurisdiction is fixed, the question cannot even be asked of the right law. **If some
   portion of
   the output is uncopyrightable, the consequence is not that the licence fails — it is that the licence has
   nothing to operate on for that portion, and a recipient's freedom to use it comes from the public domain
   rather than from the grant.** For option B, whose entire value is a *restriction*, that is the more serious
   direction: a restriction cannot attach to material in which no right subsists.
2. **Third-party material in generated output.** Generative tools can reproduce training material. If any of the
   111,412 surviving lines attributable to AI-trailer commits (§11) reproduces third-party expression, the
   submitter did not hold the right to license it, and no amount of internal vesting cures that. **Nothing in
   this repository measures this**, and the licence gate cannot (§6). This is the uncertainty with the largest
   tail and it is unquantified.
3. **Authorship of record.** Does the trailer's presence create any ambiguity about whether the named human is
   the author of record for the purposes of a relicensing warranty? See §10.

**What is not uncertain**, and should be said so counsel does not spend time on it: the assistants named are not
legal persons, hold nothing, and cannot be parties to any assignment. There is no missing signature from them.
There is no chain-of-title gap *through* them. The gap, if any, is between the submitting human and Zenchron
Dynamics (§7), and separately between the submitting human and any third party whose expression the tool may
have reproduced (point 2 above).

**Neither overclaim is supported by the evidence.** "AI trailers void the copyright" is not established —
subsistence is a live legal question, not a settled negative. "The trailers are meaningless boilerplate" is not
established either — they are the only record that a tool was involved, and point 2 above is a real, unmeasured
exposure that the trailers are the sole evidence of.

## 10. Do the trailers represent authorship, tooling attribution, or both?

**Analysis, from the repository's own mechanics and its own recorded position.**

### Evidence that the trailers function as tooling attribution

- **The repository has already taken this position, in writing, for a closely analogous case.**
  `policies/governance-model.yaml:185-188` lists what does *not* count as independent review, and includes:
  "An AI review, including this one. **It is a tool the author is using, not a second party.**" That is the
  organisation's own recorded characterisation of an AI's role in this repository. It concerns review rather
  than authorship, so it is not dispositive — but it is the only in-repo statement of position and it points one
  way.
- **The trailers are inserted mechanically, not deliberately.** No hook, script or `.pre-commit-config.yaml`
  entry in this repository produces them (`grep -rn -i 'co-authored' scripts/ .pre-commit-config.yaml` → no
  hits). They originate in the authoring tool's own configuration, which is outside the repository. **Which
  mechanism inserts them is therefore not established from the repository.**
- **They accumulate as an artefact of squash-merging, not as a considered credit.** 376 trailer lines across 137
  commits, with a long tail — one commit carries 15, another 14, another 13, while 82 carry exactly one. That
  distribution is the signature of per-branch-commit trailers concatenated by GitHub's squash. A deliberate
  authorship credit would not scale with the number of commits in a branch.
- **53 of the 137 commits carry both `Co-authored-by:` and `Co-Authored-By:` spellings.** Two casings in one
  message is tool-version drift surviving a squash, not an authorship statement.
- **Only 1 commit names more than one distinct model identity**, while four different model identities appear
  across the history — consistent with "whichever tool version was in use that day", not with a stable set of
  collaborators.

### Evidence that the trailers do more than attribute tooling

- **They occupy a field whose defined meaning is authorship.** `Co-authored-by:` is interpreted by GitHub as a
  co-author claim and is rendered as such in the public commit view. Whatever was intended, the published record
  asserts co-authorship in the vocabulary the platform defines.
- **They correlate with substantial content, not with incidental edits.** The AI-trailer commits account for
  119,748 of 171,957 total insertions (69.6%) and 111,412 of 161,519 surviving lines (69.0%) — see §11. If the
  trailers were pure tool-noise they would be uncorrelated with volume; they are not.
- **The tool's involvement is a fact regardless of what the trailer means.** Even read as pure tooling
  attribution, the trailer evidences that generative output entered the tree, which is precisely the predicate
  for §9 point 2.

### Conclusion, stated as a finding rather than an assertion

**Both, and the distinction does not resolve the rights question either way.** The mechanics point strongly at
tooling attribution: mechanical insertion, squash accumulation, casing drift, model drift, and the
organisation's own recorded position at `policies/governance-model.yaml:188`. The field's defined semantics
point at authorship. But **nothing turns on which reading wins**, because:

- Read as *tooling attribution*, the trailers evidence generative involvement in 113 commits, and §9 point 2 is
  live regardless.
- Read as *authorship*, the named co-authors still cannot hold or transfer copyright, so no assignment is
  missing and no chain-of-title gap opens through them.

The reading that would matter is a third one nobody has proposed: that the trailer is an admission the human
submitter is *not* the author of record. **That is not established, and this document does not advance it.**
It should be put to counsel as a question, not carried as an assumption. If counsel confirms the
`governance-model.yaml:188` reasoning extends from review to authorship, the question closes — and that closure
should be recorded in the repository, because at present the position exists only for review.

## 11. Files materially affected by contributions whose rights are uncertain

Measured two ways, because "touched" and "materially affected" are different questions.

### By reachability — which files an AI-trailer commit ever touched

| measure | value |
| --- | --- |
| distinct paths ever touched by an AI-trailer commit | 748 (includes paths since deleted or renamed) |
| of those, still present in the tree | **614** |
| tracked files **never** touched by an AI-trailer commit | 107 |
| tracked files total | 721 |

**85.2% of the current tree has been touched by at least one commit carrying an AI co-author trailer** —
including `LICENSE`, `README.md`, `CONTRIBUTING.md`, `Makefile`, `CODEOWNERS`, all 29 files under `policies/`,
all 19 under `.github/`, all 14 under `contracts/` and all 5 under `security/`.

### By surviving content — `git blame` over every text file in the tree

| commit class | surviving lines | share |
| --- | --- | --- |
| commits carrying an AI trailer | **111,412** | 69.0% |
| commits carrying only a second-human trailer | 28,890 | 17.9% |
| commits carrying no trailer | 21,193 | 13.1% |
| `dependabot[bot]` commits | 24 | 0.015% |
| **total blamed lines** | **161,519** | |

Commits carrying **any** co-author trailer account for 140,326 surviving lines — **86.9% of the tree**.

**How to read this.** These are the files and lines that would be covered by whatever relicensing warranty the
organisation gives. They are not "files with a defect": no defect is established in any of them. They are the
scope over which §7 (is it owned?) and §9 point 2 (does it include anything the submitter could not license?)
would have to be answered if either question is answered anywhere other than "yes, entirely".

**The practical consequence.** Because the affected set is 85% of the tree and includes every governance and
policy file, **no remediation that works file-by-file is available.** Carve-out, rewrite or re-authorship of the
affected material is not a realistic path at this scale. The only proportionate remediations are ones that
operate on the whole history at once — a confirmation of vesting (§7), or a decision that the residual risk is
accepted and recorded. Legal should be told this before being asked the question, because the answer "we would
need to re-author the affected files" is not available here.

`dependabot[bot]`'s contribution is 24 surviving lines across 12 workflow files, all Action SHA pins. Whether
those clear the originality threshold is a legal question; at 24 lines it is not a practical obstacle under any
answer.

## 12. Per-option executability

For each option: is it legally executable **today**, whose approval is required, what exactly blocks it, how it
is remediated, whether it can be undone, and what it does to source distribution and container distribution
respectively — which differ, and are conflated in most discussion of this decision.

### A — public open source

**Currently executable: no.** Four independent blockers, any one of which is sufficient.

| # | blocking evidence | who clears it |
| --- | --- | --- |
| A1 | **No licence text exists.** `git grep -I 'SPDX-License-Identifier'` → 0. No SPDX identifier is named anywhere for Foundry's outbound grant. A category is not a licence and cannot be adopted, reviewed or enforced | legal owner (outbound) — selects an identifier and adopts the verbatim SPDX text |
| A2 | **Inbound rights not established.** §7: zero evidence of any vesting instrument. §11: the affected scope is 85% of the tree. An OSI grant is irrevocable, so this must be answered *before*, not after | legal owner (inbound) — confirms the instrument exists and covers 2026-05-30 onward, and answers §1's second-identity question |
| A3 | **Unmet Apache-2.0 obligations on redistributed material.** §6: `retain-license-text` and `retain-notice-file` are both unsatisfied for `security/seccomp/zenchron-default.json`. Publishing under an OSI licence while failing another project's notice terms is a defect the grant would carry outward | maintainer role — two file additions; not blocked on the decision |
| A4 | **Self-consistency constraint on the choice.** `policies/license-policy.yaml:91-144` classifies 17 identifiers `legal-review-required`. Adopting an outbound licence from a family the project's own policy holds unresolvable would be internally inconsistent, and `:16-20` reserves editing that policy to the owner | legal owner + OSS-compliance counsel |

**Approval or representation required:** the legal owner must represent that Zenchron Dynamics holds or has been
granted the rights in every copyrightable contribution in 168 commits, and may grant them perpetually and
irrevocably. That is a representation about material the legal owner cannot inspect from the repository alone —
§7 and §9 are exactly what they would be representing over.

**Remediation path:** (1) confirm vesting; (2) answer §1's second-identity question; (3) select an SPDX
identifier and adopt its text; (4) close §6's two obligations; (5) run a real licence inventory so counsel
clears measured licences rather than a policy table (§13); (6) add an inbound term to `CONTRIBUTING.md`;
(7) record the decision at `policies/license-policy.yaml:43-45`; (8) flip 6 package visibilities.

**Reversibility: none, for the grant.** Copies distributed under an OSI licence keep it permanently. The file
can be reverted; the grant cannot be recalled. Steps (1)-(6) are all reversible; step (7) onward is not.

**Effect on source distribution:** grants readers what they can already do — resolves the coherence defect at
`docs/licensing/license-compliance.md:25-26` by permitting rather than by concealing.

**Effect on container distribution:** materially different and materially harder. It requires the 6 package
visibility flips (control-plane, no undo), a label change across 14 Dockerfiles, 10 `contracts/images/*.yaml`,
`scripts/release/verify-oci-metadata.sh:156,170` and regenerated reproducibility locks — **and** it makes
Foundry a redistributor of every third-party binary in each image, engaging the §6.1-§6.6 obligation classes in
the prior packet, including a source-offer mechanism that does not exist.

### B — public source-visible, proprietary

**Currently executable: no.** Its defining property — no control-plane change — is true and is not the
constraint.

| # | blocking evidence | who clears it |
| --- | --- | --- |
| B1 | **The grant text does not exist and has no named drafter.** `docs/decisions/licence-legal-review-packet.md:236-241` establishes this and it is unchanged at `9eae8b1`. Engineering cannot write it | legal owner (outbound) drafts or commissions |
| B2 | **The customer image-distribution terms do not exist.** B's model is source published, images delivered under separate contract. The second document is a deliverable, not a formality | commercial / product counsel |
| B3 | **No source-available licence is classified in `policies/license-policy.yaml`.** Any such identifier resolves to `legal-review-required` through `default_state` at `:28`. Adopting one requires adding it to the policy, which `:16-20` reserves to the owner | owner + OSS-compliance counsel |
| B4 | **Inbound rights not established** — §7, same as A2, but for a narrower purpose: B does not grant reuse, so it needs the right to *distribute* rather than the right to *sublicense* | legal owner (inbound) |
| B5 | **Enforceability is unestablished and is the option's central risk.** There is no click-through, no acceptance step and no privity with a reader who clones. `Makefile:162-165` gives that reader `make build-test`, which builds all ten images with no registry access. B's grant must survive being asserted against someone already handed a working build | legal owner (outbound) |

**A point the prior work does not make.** §9 point 1 bears on B more sharply than on A. A restriction cannot
attach to material in which no right subsists. If any portion of the AI-assisted 69% is uncopyrightable in the
member state of establishment, B's "you may look but not redistribute" has nothing to operate on for that
portion — while A's permission would simply be redundant there. **B is the option most exposed to the
subsistence question, and it is currently framed as the least legally demanding option.**

**Reversibility:** the files revert cleanly and no control-plane state changes. But a grant a reader has already
received is not withdrawn by a later commit, and the source has been public since at least 2026-07-28. B is
file-reversible, not effect-reversible.

**Effect on source distribution:** replaces a *notice* ("not for public distribution", printed on a public page)
with a *grant* stating what a reader may do. That is the change B exists to make. It is only worth making if B5
is answered.

**Effect on container distribution:** none in the repository — labels stay `LicenseRef-Zenchron-Internal`,
`verify-oci-metadata.sh` and the reproducibility locks are untouched. But the third-party obligations attach on
the **first image delivered to any legal entity other than Zenchron Dynamics**, commercial terms or not. B does
not avoid them; it defers them to the first customer.

### C — private proprietary

**Currently executable: yes, as a control-plane act — and it discharges nothing.**

This is the only option where the answer differs, and the reason matters. **Making a repository private is not a
licensing act.** It requires no grant text, no representation about inbound rights, and no third party's
consent. Nothing in §1-§11 blocks it.

What it does not do:

| # | survives C | evidence |
| --- | --- | --- |
| C1 | **The Apache-2.0 obligations survive.** They attach to material incorporated in the repository, not to how the repository is distributed. `security/seccomp/NOTICE:27-29` says exactly this, in the repository, already | §6 |
| C2 | **The vesting question survives.** `LICENSE:9-11` grants to "authorized internal users under the terms of their employment or contractual agreement" — a private repository still relies on an instrument that is not in evidence | §7 |
| C3 | **The residual public-exposure question survives and is not answerable from the repository.** Live `forks: 0` at 2026-08-27; clone counts are not observable, and the date the repository first became public is not established (§5) | live API; `policies/repository-governance.yaml:43` |
| C4 | **`LICENSE:22-23`'s self-declared placeholder becomes the organisation's final terms by omission**, unless removed deliberately | `LICENSE:22-23` |

**Approval required:** the repository owner for the visibility flip; an **org-plan decision**, because both live
rulesets stop being enforceable on Free + private
(`docs/audits/free-tier-governance-accepted-risk.md:64-76`); and the legal owner on C3.

**Engineering constraint that must land in the same change.**
`scripts/verify-repo-governance.sh` fails closed in both directions, so `policies/repository-governance.yaml:50`
and the two ruleset blocks must be edited in the *same* commit as the flip, or governance verification breaks
the moment it lands. This is stated at `docs/decisions/publication-and-licence-options.md:85-88` and is repeated
here because it is the one way C fails in practice.

**Reversibility:** the setting reverts; the exposure does not; and whether ruleset ids `19853431`/`19853433`
survive a public → private → public round trip is untested and must not be assumed.

**Effect on source distribution:** removes it prospectively. Says nothing about copies already taken.

**Effect on container distribution:** unchanged — packages are already private. The third-party obligations are
unaffected: delivery of an image to any legal entity other than Zenchron Dynamics is still conveyance, and
network-facing operation engages the AGPL class with no conveyance at all.

## 13. The two pinned licence gaps — confirmed

`tests/integration/test_evidence_path_e2e.sh` reports `assertions: N proven, M pinned gaps` at its final line.
**The task's characterisation is correct and was verified statically, without running the suite** (CI's required
`repo structure` job is the authority for execution):

```text
$ grep -cE '^[[:space:]]*ck '  tests/integration/test_evidence_path_e2e.sh   → 227
$ grep -nE  '^[[:space:]]*gap ' tests/integration/test_evidence_path_e2e.sh
1315:gap "no workflow invokes the licence gate against a real inventory" \
1317:gap "...ci.yml runs it only as --self-test, which gates no artifact" \
```

226 of the 227 `ck` call sites are top-level; the one at `:1420` sits inside a `for` loop over 5 items
(`:1417-1419`), so the runtime count is 226 + 5 = **231 proven**. There are exactly **2** `gap()` call sites,
and **both are the licence gate not being invoked against a real inventory** — `:1315` that no workflow calls it
at all outside `--self-test`, and `:1317` that `ci.yml`'s only invocation is the gate testing itself, which
gates no artifact. The arithmetic reproduces 231/2 exactly. **Confirmed.**

**Confirmed independently by the authority.** CI's required `repo structure` job on this branch
(run `33080410669`, job `98545760776`, 2026-08-27) printed:

```text
assertions: 231 proven, 2 pinned gaps
test_evidence_path_e2e: PASS
```

`:1303-1310` explains why this is pinned rather than quietly passing: the previous assertion matched `ci.yml`'s
`--self-test` line and was "literally true, substantively false, and green forever".

### ADDENDUM 2026-08-27 — the two pinned gaps are closed; T5 is not

Everything above is the state as of run `33080410669` and is left unedited, because a dated audit record
that gets rewritten stops being evidence. What changed after it:

`.github/workflows/stage-and-authorize.yml` now carries a `licence-authorization` job. The `stage` job
produces a per-child SBOM with `scripts/generate-sbom.sh` against the digest the registry resolved, and
the licence job binds each document to image, version, platform, immutable digest and source revision,
runs `scripts/license/assert-license-policy.sh` over the resulting inventory, and composes that with
`scripts/license/assert-repository-material.sh --require-image-evidence` so that neither half can stand
alone. Both `gap()` lines at `:1315` and `:1317` are therefore promoted to `ck()`, with their predicates
unchanged, and the counts quoted above no longer reproduce.

**T5 is NOT closed by this, and the distinction matters to the decision.** Wiring a gate is not running
it. No dispatch has yet executed the composed authorization over real Foundry images, so which of the 17
`legal-review-required` identifiers are actually present in any image remains unmeasured. What exists now
is the control; what is still owed is the measurement, and it is still a maintainer-role action that is
not blocked on this decision. Options A, B and C are affected exactly as the table below says, with
"wiring defect" replaced by "the run has not happened yet".

### Effect of each option on the two gaps

**None of A, B or C closes either gap.** They are wiring defects in the release path, not consequences of the
licence decision. What each option changes is how much the gaps cost:

| option | effect |
| --- | --- |
| **A** | The gaps become **blocking preconditions**. Under an OSI grant, images are conveyed publicly; conveying them without a licence gate having run against a real inventory means shipping unmeasured obligations under an irrevocable grant. A cannot responsibly execute with these open |
| **B** | The gaps become **live at the first customer delivery**, which is exactly when the reciprocal obligations attach. B's model makes conveyance a commercial event rather than a public one, which changes the audience, not the obligation |
| **C** | The gaps remain **dormant but unclosed**. Publication stays disabled and packages stay private, so nothing is conveyed — until the first delivery to any entity other than Zenchron Dynamics, at which point B's position applies |

The prior packet's §6.7 finding is confirmed and sharpened by this: **the gate has never run against a real
artefact, so which of the 17 `legal-review-required` identifiers are actually present in any Foundry image is
unknown under every option.** Asking counsel to clear 17 abstractions is more expensive and less useful than
running `scripts/license/license-inventory.sh` first and clearing the ones that are real. That run is a
maintainer-role action, it is not blocked on the decision, and it would convert the largest open item in this
decision from a policy table into a measurement.

## 14. What the legal owner must decide, must be told, and what is not established

### Must decide

| # | decision | why it cannot be deferred |
| --- | --- | --- |
| D1 | Which option, recorded at `policies/license-policy.yaml:43-45` | Every downstream gate reads that one field |
| D2 | For A: which SPDX identifier. For B: who drafts the grant and the customer terms | Neither option is executable as a category |
| D3 | Whether an IP-vesting instrument exists and covers 2026-05-30 onward | Blocks A outright; narrows B; survives C |
| D4 | Whether the `governance-model.yaml:188` position ("a tool the author is using, not a second party") extends from AI *review* to AI *authorship* | Resolves §9 point 3 and §10 in one sentence, and should then be recorded in the repository |
| D5 | The member state of establishment | Required under all three options; §9 point 1 cannot be asked of the right law without it |
| D6 | Whether outside pull requests are accepted, and under what inbound term | The repository is public and accepts PRs today with no inbound term at all |

### Must be told

| # | fact | evidence to hand over |
| --- | --- | --- |
| T1 | The repository redistributes a byte-identical copy of Apache-2.0 material and satisfies 2 of the 4 obligations its own policy names | §6; `security/seccomp/NOTICE`; the `shasum` and `gh api` commands in §6; `policies/license-policy.yaml:75` |
| T2 | 85% of the tree and 69% of surviving lines come from commits recording generative-tool involvement, so no file-by-file remediation is available | §11 |
| T3 | Nothing in the repository evidences that the 146 human-authored commits are owned by Zenchron Dynamics, and `LICENSE:10-11` presumes they are | §7; the seven zero-hit searches |
| T4 | There is a second human co-author identity on 7 commits whose relationship to the maintainer identity is not established | §1, correction 2; commits `7dc6b54`, `7f7f4e0` |
| T5 | The licence gate has never run against a real inventory, so the 17 `legal-review-required` identifiers are a policy table, not a measurement of this product | §13; `test_evidence_path_e2e.sh:1315,1317` |
| T6 | Option C is executable today; A and B are not — and C discharges none of T1, T3 or the third-party obligations | §12 |

### Not established

Written as **not established** rather than inferred, per the standard this packet is held to:

1. Whether any IP-vesting instrument exists outside the repository. **Not established.**
2. Whether the second human co-author identity is the same natural person as the maintainer identity.
   **Not established.**
3. Whether any AI-assisted line reproduces third-party expression. **Not established, and unmeasured.**
4. Whether copyright subsists in AI-assisted output in the relevant jurisdiction — which is itself
   **not established.**
5. The date the repository first became public. Verified public 2026-07-28; created 2026-05-30; the interval is
   **not established** from the repository.
6. Commit signature validity. `gpg` absent from the measurement environment; `%G?` returns `N` for all 168
   commits and proves nothing. **Not established.**
7. Whether reproducing third-party advisory text in `docs/audits/**` scanner evidence carries any obligation.
   **Not established.**
8. Which of the 17 `legal-review-required` identifiers are actually present in any Foundry image.
   **Not established** — and measurable without a decision.

## 15. What this document did not do

- Did not select or write a licence, and did not edit `LICENSE`.
- Did not edit `policies/license-policy.yaml`, `policies/vulnerability-exceptions.yaml`, any ruleset, or any
  governance policy.
- Did not change repository or package visibility.
- Did not enable publication: `release.yml` and `publish-rc.yml` remain refusal stubs. No image was rebuilt, no
  base re-pinned, no acceptance dispatched, nothing promoted, signed, released or tagged.
- Did not redo the A/B/C consequence comparison (`docs/decisions/publication-and-licence-options.md`) or the
  first-pass legal groundwork (`docs/decisions/licence-legal-review-packet.md`). It extends both and corrects
  two counts in the second.
