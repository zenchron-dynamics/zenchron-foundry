# Legal decision packet: what must be established before a licence is selected (issue #98)

**For:** the legal owner, with the maintainer role. **Prepared by:** engineering, 2026-08-27, against master
`f3883b9d`.

**This document selects nothing.** `policies/license-policy.yaml:43` still reads `decision: undetermined` and this
change does not touch it. `LICENSE` is unchanged. `.github/workflows/release.yml:31-58` and
`.github/workflows/publish-rc.yml:43-45` remain refusal stubs and publication stays disabled. No option is
recommended, and none is treated as a default — including the one that needs no control-plane change.

The A/B/C comparison already exists at `docs/decisions/publication-and-licence-options.md` and is not repeated
here. That document compares consequences. This one establishes the facts a lawyer needs *before* the comparison
can be acted on: what we currently grant, what we would be redistributing, whether we own what we would be
relicensing, what text is actually proposed, and what obligations attach.

This document is public. It states the position factually and does not describe how to defeat any control.

## 0. Summary of what is and is not established

| # | question | status |
| --- | --- | --- |
| 1 | current licence and copyright state | **established** — proprietary, one copyright holder asserted, no per-file headers |
| 2 | material we would redistribute vs build inputs we consume | **established** — and it surfaced a live attribution defect in three in-repo files, see §2a |
| 3 | contributor rights sufficient to relicense | **not established** — no CLA, no DCO, AI co-authorship unresolved |
| 4 | the exact licence text proposed, per option | **not established** — no SPDX id is named anywhere in the repository |
| 5 | reader-facing coherence of public source + restricted images | **established as a defect** — see §5 |
| 6 | obligations imposed by the 17 `legal-review-required` licences | **established as obligation classes** — see §6; whether any component actually asserts them is **not established** |
| 7 | legal-review ownership | **stated as roles** in §7; no role is currently filled by a named reviewer, and this document does not fill one |

The single most consequential finding is in §6: the merged comparison assigns the 17-licence problem to option A.
That framing is too narrow. Reciprocal obligations attach on **conveyance to any third party**, not on
publicness, so they are live under B and C as well from the first image delivered to any legal entity other than
Zenchron Dynamics.

## 1. Current licence and copyright state

### The operative grant

`LICENSE:9-13` is the whole of it:

> Permission to use, copy, or modify this software and its associated images is granted only to authorized
> internal users under the terms of their employment or contractual agreement with Zenchron Dynamics.
> Redistribution outside the organization, in source or binary (image) form, is prohibited without prior written
> consent.

The restriction heading is `LICENSE:3` — `INTERNAL / PROPRIETARY — NOT FOR PUBLIC DISTRIBUTION`. Warranty
disclaimer at `LICENSE:15-20`.

### Facts

| fact | value | where |
| --- | --- | --- |
| copyright holder asserted | `Zenchron Dynamics`, 2026, "All rights reserved" | `LICENSE:1` |
| grant recipients | "authorized internal users" under employment or contract | `LICENSE:10-11` |
| redistribution | prohibited in **source or binary (image) form** without prior written consent | `LICENSE:11-13` |
| the file's own status | self-declared placeholder: "If you require an open-source license for a public fork, replace this file before publication. Do not assume any OSI license applies by default." | `LICENSE:22-23` |
| second copyright assertion | `© 2026 Zenchron Dynamics — Internal / Proprietary` | `README.md:154` |
| image licence field | `LicenseRef-Zenchron-Internal` (an SPDX `LicenseRef`, not a registered SPDX identifier) | `org.opencontainers.image.licenses` labels; see `docs/decisions/publication-and-licence-options.md:23` |
| per-file copyright headers | **none in first-party source** — see §2 | repository-wide grep, §2 |
| files asserting different terms | see §2 | |

Two things follow that a lawyer should be told explicitly.

1. **`LICENSE` is not a considered licence; it is a stated placeholder.** `LICENSE:22-23` says so in the file
   itself. Option C in the merged comparison is described as "`LICENSE` unchanged", but leaving a file that
   declares itself provisional is still a decision, and it should be made deliberately rather than by omission.
2. **`LicenseRef-Zenchron-Internal` has no text behind it.** The identifier is asserted on images and verified by
   `scripts/release/verify-oci-metadata.sh`, but a `LicenseRef` is only a pointer; the terms it points at are
   `LICENSE`, which forbids the redistribution that shipping a labelled image would constitute. Any option that
   keeps this label needs the label to resolve to terms that permit whatever delivery actually happens.

## 2. Incorporated material versus build inputs

The distinction that matters legally: **material physically present in this repository would be redistributed
under whatever licence is chosen; material fetched during a build is consumed as an input, and ends up in the
image rather than in the repository.** The two carry different obligations and they are not interchangeable.

Method: repository-wide sweep of all tracked files for upstream copyright headers, SPDX identifiers,
provenance statements (`adapted from` / `based on` / `copied from` / `pinned copy`), submodules, lockfiles and
non-text blobs; plus a read of all 14 Dockerfiles for build-time acquisition.

### 2a. Material physically present in the repository and not first-party

**Three findings. One is material.**

| # | path | what it is | stated provenance | attribution present in the file |
| --- | --- | --- | --- | --- |
| 1 | `security/seccomp/zenchron-default.json` (832 lines) | the runtime seccomp profile, consumed by `scripts/assert-runtime-profiles.sh` | "a pinned copy of the moby v27.3.1 default profile, not a hand-written per-image allowlist" — `security/README.md:26-27` | **none** — no header, no licence notice, no copyright line, and the filename reads as first-party |
| 2 | `security/apparmor/zenchron-container` | AppArmor reference profile | "This is docker-default plus the things the runtime contract already promises… deliberately close to docker-default" — `security/apparmor/zenchron-container:7-9` | **none** |
| 3 | `docs/audits/libaom3-ownership-2026-08-26/evidence/installer-helper.txt` and two sibling files in the same `evidence/` directory | forensic excerpts of the `install-php-extensions` helper script | `:10` names the upstream repository; `:12` names the licence | **yes** — the upstream author's copyright line is intact at `:8` and the licence is named at `:12` |

**Finding 1 is the one to act on.** `security/README.md:26-27` states the provenance honestly in a neighbouring
document, but the file itself carries no notice. The upstream project it names distributes under a permissive
licence with explicit notice-retention and state-changes obligations; **which licence, and what it requires, is
not established from anything inside this repository** and must be confirmed against upstream. If it is the
licence the project's own policy already classifies at `policies/license-policy.yaml:73-75` with obligations
`[retain-copyright-notice, retain-license-text, state-changes, retain-notice-file]`, then **none of those four
obligations is currently satisfied for this file**, and that is true today, under the current proprietary
`LICENSE`, before any option is chosen. Finding 2 is the same issue at lower exposure: restated rather than
copied, but derivative of the same upstream. Finding 3 is already compliant on its face.

**Why the existing gate does not catch this.** The compliance pipeline
(`docs/licensing/license-compliance.md:36-47`) runs over SBOMs of built images. `security/seccomp/` is in-repo
source, not an image component, so it never enters an inventory. **The repository's licence gate is structurally
incapable of seeing copied in-repo material.** That is a gap in the control, not a failure of the control, and
it should be recorded as such.

### 2b. What is confirmed absent

- No `vendor/`, `third_party/` or `node_modules/` directory.
- No git submodules — no `.gitmodules`.
- No `SPDX-License-Identifier` line anywhere in the repository (0 occurrences), so **no source file asserts terms
  different from `LICENSE`**, and no first-party file carries a per-file copyright header either.
- No conventional dependency lockfile (`package-lock.json`, `composer.lock`, `go.sum`, `Gemfile.lock`,
  `requirements.txt`).
- One committed binary: a 764-byte zip of first-party CI output under `docs/audits/package-acl-2026-08-03/`,
  whose contents are also present unzipped alongside it. No keys, certificates or compiled artefacts.

### 2c. Build inputs we consume — in the image, not in the repository

All third-party executable code reaches the product at build time and lands in the **image**. None of it is in
the git tree.

| input class | examples | where declared |
| --- | --- | --- |
| base images (digest-pinned) | `php:8.{3,4,5}-{cli,fpm}-bookworm`, `dunglas/frankenphp:1-php8.x-bookworm`, `nginxinc/nginx-unprivileged:1.28-bookworm`, `caddy:2-alpine` | per-family `ARG *_BASE` + `FROM` in each of the 14 Dockerfiles; inventory at `config/base-images.env` |
| Debian/Alpine packages | build-stage `-dev` headers and runtime `lib*` packages, per family | Dockerfile `apt-get install` stanzas |
| PHP extensions compiled from source | `phpredis`, fetched from PECL and sha256-verified before build | `policies/supply-chain-inputs.yaml:51-69` |
| helper script inherited inside a base image | `install-php-extensions`, MIT, shipped inside the FrankenPHP base rather than downloaded by our build | `policies/supply-chain-inputs.yaml:71-94` |
| CI tooling | trivy, hadolint, shellcheck, semgrep, gitleaks, yamllint, `gh`, `jq`, `yq` | `policies/supply-chain-inputs.yaml:99-192` |
| GitHub Actions | pinned by commit SHA | `.github/workflows/*.yml` |
| pre-commit hooks | six external hook repositories pinned by tag, cloned at hook-install time | `.pre-commit-config.yaml:9-59` |

The declared integrity gap on the Debian package index is recorded at
`policies/supply-chain-inputs.yaml:217-242` (`integrity: none`, `integrity_gap: true`).

### 2d. The distinction that decides §6

**Nothing in the git tree carries a reciprocal licence.** The licence obligations discussed in §6 attach to
material that enters at build time and ships inside the image. Therefore:

- **Relicensing the repository's own files** is constrained by §2a (three files needing attribution) and §3
  (contributor rights) — **not** by the 17 licences at `policies/license-policy.yaml:91-144`.
- **Delivering an image to anyone** is what engages those 17. That is a separate act from choosing a licence for
  the source, and it is governed by whether Foundry conveys images, not by which option is recorded. See §6.7.

Counsel should be given both statements together, because the merged comparison presents the third-party licence
question as a consequence of the licence choice, and it is not.

## 3. Contributor rights — can this history be relicensed?

Relicensing requires the relicensing party to hold, or to have been granted, the rights in every copyrightable
contribution. Evidence measured on master `f3883b9d`:

| measure | value | command |
| --- | --- | --- |
| commits in history | 164 | `git rev-list --count HEAD` |
| distinct author identities | 3 | `git log --format='%an <%ae>' \| sort -u` |
| commits from the maintainer identity | 142, across two `user.name` spellings sharing one email address | `git shortlog -sne HEAD` |
| commits from `dependabot[bot]` | 22 | `git shortlog -sne HEAD` |
| files ever touched by `dependabot[bot]` | 12, all `.github/workflows/*.yml` (action SHA pin bumps) | `git log --author=dependabot --name-only` |
| commits carrying a `Co-authored-by:` trailer | 133 of 164 | `git log --grep='Co-authored-by' -i --format='%H' \| wc -l` |
| distinct `Co-authored-by:` entities | AI assistants (several model identities) plus `dependabot[bot]` | `git log --format='%B' \| grep -i '^Co-authored-by:'` |
| `Signed-off-by:` trailers | 22, all from `dependabot[bot]` | `git log --format='%B' \| grep -ci 'Signed-off-by'` |
| CLA in the repository | **none** | `grep -rIn 'Contributor License Agreement' .` — no hit outside a cross-reference in `docs/decisions/publication-and-licence-options.md:52` |
| DCO requirement | **none** | same grep for `Developer Certificate of Origin` / `DCO`: no hit |
| commit-signature verification | **not established locally** — `gpg` is absent in this environment, so `git log --format='%G?'` returns `N` for all 164 commits and proves nothing either way | `git log --format='%G?'` |

`CONTRIBUTING.md` has no inbound-licensing section at all. It asserts contributions "come from authorized
platform/security engineers" (`CONTRIBUTING.md:3-4`) and imposes commit signing (`CONTRIBUTING.md:20-23`), but
signing establishes *who committed*, not *what rights were assigned*.

### What this means

**Provisionally favourable, but not established.** Three separate questions, none answered in the repository:

1. **Employment/contract vesting.** All 142 human-authored commits come from one identity, and
   `policies/governance-model.yaml:29-34` records `single_maintainer: true`, `maintainer_count: 1`. If the
   maintainer role's output vests in Zenchron Dynamics by employment or by a contractor IP-assignment clause,
   the human contribution is held by one legal entity and is freely relicensable. **The instrument that does
   that vesting is not in this repository and its existence is not established here.** Legal must confirm it
   exists and covers work from 2026-05-30 onward (`git log --reverse --format='%ad' --date=short | head -1`).
2. **AI co-authorship.** 133 of 164 commits name an AI assistant as co-author. This is a trailer convention,
   not an assignment, and no assistant is a legal person capable of holding or transferring copyright. The
   practical question for counsel is narrow: does the presence of these trailers create any ambiguity about
   whether the named human is the author of record, and does the jurisdiction of establishment recognise
   copyright in AI-assisted output at all? Note that `policies/governance-model.yaml:188` already takes the
   position that an AI review "is a tool the author is using, not a second party" — the same reasoning applied
   to authorship would resolve this, but that is counsel's call, not engineering's.
3. **Bot commits.** `dependabot[bot]`'s 22 commits touch only workflow YAML and consist of dependency SHA pin
   updates. Whether such changes clear the originality threshold is a legal question; if they do not, they are
   not an obstacle. If counsel prefers not to rely on that, the 12 affected files are enumerable and the
   changes are mechanically reproducible.

### What would be required if vesting is not confirmed

- A signed IP assignment or confirmation of the employment/contract clause covering the full history, **or**
- Retroactive contributor sign-off for the affected commits, **or**
- Rewriting or re-authoring the affected material.

### What is required regardless, before accepting any outside contribution

`CONTRIBUTING.md` currently has no inbound term. Under any option that leaves the repository public and open to
pull requests, an inbound mechanism must be added: a DCO sign-off requirement, a CLA, or an explicit statement
that outside pull requests are not accepted. Which one is a legal choice. Adding **none** of them while
accepting outside PRs would leave inbound rights undefined, which is the same defect this packet documents for
the existing history.

Separately and already flagged at `docs/decisions/publication-and-licence-options.md:135-137`:
`CONTRIBUTING.md:21-27` states the repository is "on GitHub Free (private)". That is false today. It is a stale
distribution claim in a contributor-facing document and should be corrected independently of the licence
decision.

## 4. What licence text is actually proposed

**Nothing in this repository names an SPDX identifier for Foundry's own outbound licence.** This is the largest
gap in the decision as currently framed: A, B and C are categories, and a category cannot be reviewed, adopted,
or enforced. Legal cannot answer "may we grant this" until "this" is a specific text.

| option | what the merged comparison proposes | SPDX id | canonical text source | who drafts |
| --- | --- | --- | --- | --- |
| A | "replace `LICENSE` with an OSI licence (owner + legal pick which)" (`publication-and-licence-options.md:47`) | **not established** | **not established** | not drafted — an existing licence is adopted verbatim from `spdx.org/licenses/<id>.html`; no drafting required, only selection |
| B | "an explicit source-available grant: inspection permitted, redistribution prohibited" (`publication-and-licence-options.md:47`) | **not established** | **not established** | **not established** — see below |
| C | "`LICENSE` unchanged" (`publication-and-licence-options.md:47`) | `LicenseRef-Zenchron-Internal`, which is a repository-local reference, not a registered SPDX id | `LICENSE:1-23` — which declares itself a placeholder at `:22-23` | already drafted; but adopting it as final is a decision, not the absence of one |

### What must be produced before the decision is recordable

- **For A:** a specific SPDX identifier and the verbatim text from the SPDX licence list. Selection is not free:
  Foundry's own policy already classifies which licence families it treats as notice-only
  (`policies/license-policy.yaml:61-87`) versus requiring counsel (`:91-144`). Adopting an outbound licence
  from a family the project's own policy holds to be unresolvable would be internally inconsistent, and legal
  should be told that constraint exists. Engineering does not pick from the set.
- **For B:** either (a) an existing published source-available licence adopted verbatim, or (b) bespoke terms.
  If (a), note that **no source-available licence is classified in `policies/license-policy.yaml` at all**, so
  any such identifier resolves to `legal-review-required` through `default_state`
  (`policies/license-policy.yaml:28`) — adopting one requires adding it to the policy, which is an owner action
  per that file's header (`:16-20`). If (b), **the drafter must be named, and it is not engineering.** The
  `legal owner` role drafts or commissions the terms; engineering can state the technical facts the terms must
  match but cannot write an enforceable grant. B additionally requires a *second* document — customer
  distribution terms for the images (`publication-and-licence-options.md:52,76-77`) — which is also
  legal-owner-drafted and does not exist.
- **For C:** a decision that `LICENSE:1-23` is final text, and removal or amendment of the self-declared
  placeholder sentence at `LICENSE:22-23`. Leaving that sentence in a licence the organisation has affirmatively
  adopted is a contradiction on its face.

## 5. What a reader who clones and builds actually encounters

This is not hypothetical; the repository is public and permanently indexed, and every step below is available to
any reader today.

1. `README.md:90-105` instructs the reader to `docker login ghcr.io` and `docker pull
   ghcr.io/zenchron-dynamics/php-fpm:8.3-prod`. All six production packages are private
   (`publication-and-licence-options.md:24`), so the pull fails. The document that tells a reader how to consume
   the product is world-readable; the product is not.
2. `Makefile:162-165` provides `make build-test`, which builds all ten images locally with no push and no
   registry access. A reader who cannot pull **can** build. The build is not gated by anything in this
   repository.
3. The images so built carry `org.opencontainers.image.licenses="LicenseRef-Zenchron-Internal"`, an identifier
   that resolves to `LICENSE`, which grants use only to "authorized internal users" (`LICENSE:10-11`).
4. `README.md:148-151` says "Internal only", and `README.md:1` still titles the project `docker-platform`
   while the repository is `zenchron-foundry` — a second, unrelated identity mismatch a reader meets in the
   first line.

**The resulting position.** A reader can lawfully read the source (it is published), can technically build the
images, and has no grant to use the result. `docs/licensing/license-compliance.md:25-26` states this outcome
plainly: "Anyone reading the repository has no grant to use what they can see."

Two consequences legal should rule on, because engineering cannot:

- **Enforceability.** No click-through, no acceptance step, no contractual privity exists between the project
  and a reader who clones. The only notice is a file in the tree. Whether "you may look but not use, and we have
  handed you the build instructions" is enforceable against such a reader is a legal question, and it is the
  question option B's grant would have to survive.
- **Implied-licence exposure.** Publishing build tooling, a `make` target that builds everything, and consumer
  documentation, while denying a use grant, is at minimum a mixed signal. Whether it supports any argument of
  implied licence or estoppel is for counsel.

Note this defect is **present today and is not created by any option**. Option A resolves it by granting what the
reader can already do. Option C resolves it by removing the source from public view going forward, though
`publication-and-licence-options.md:54` records that the source has been public since 2026-07-28 and is forkable
and indexed. Option B resolves it only if the source-available grant is both drafted and enforceable — which is
precisely what is unestablished in §4.

## 6. The 17 `legal-review-required` licences, by obligation class

`policies/license-policy.yaml:91-144` classifies 17 identifiers as `legal-review-required`. The policy records
*why each was deferred*; it does not record *what each would require*. That is what follows. Grouped by the
obligation that actually attaches, because the groups differ in who must act and in what Foundry would have to
build to comply.

The trigger for every group is the same: **conveying a copy to a third party.** Not publishing, not
open-sourcing — conveying. This matters for §6.7.

### 6.1 Whole-work reciprocal — complete corresponding source (4 identifiers)

`GPL-2.0-only`, `GPL-2.0-or-later`, `GPL-3.0-only`, `GPL-3.0-or-later` (`license-policy.yaml:91-102`)

Obligation on conveying a binary — and a container image containing GPL binaries is a conveyance of those
binaries: provide the complete corresponding source for the conveyed work, either alongside the image or by a
written offer valid to any third party. GPL-3.0 additionally carries an express patent grant and, for "User
Products", installation information. GPL-2.0 has no express patent grant, which is a different risk profile
rather than a lesser one.

**What Foundry would have to operate:** a source-offer mechanism — a durable, addressable location serving the
exact source corresponding to each conveyed image digest, for as long as the offer runs. **No such mechanism
exists in this repository.** This is infrastructure, not paperwork.

### 6.2 Library reciprocal — source plus a right to relink (4 identifiers)

`LGPL-2.1-only`, `LGPL-2.1-or-later`, `LGPL-3.0-only`, `LGPL-3.0-or-later` (`license-policy.yaml:103-114`)

Obligation: source for the library itself, plus the recipient's ability to replace it with a modified version
and relink. In an image built from unmodified distribution packages that are dynamically linked, this is
ordinarily satisfiable, and considerably lighter than §6.1. It stops being light if any such library is
statically linked or modified during the build — which is a **build-composition question this packet does not
answer**; see §2.

### 6.3 Network reciprocal — obligation reaches users who never receive a copy (2 identifiers)

`AGPL-3.0-only`, `AGPL-3.0-or-later` (`license-policy.yaml:115-120`)

Obligation: everything in §6.1, extended to users who interact with the software over a network without ever
receiving a copy. The `reason` field already flags this: "network-use obligations reach hosted deployments"
(`:117`). The distinguishing property is that this obligation cannot be avoided by not distributing — operating
the software as a service triggers it. It is therefore the one group whose obligation is **not** confined to
conveyance, and the only group that could attach to Foundry's own internal hosted use.

### 6.4 File-level reciprocal — source for modified files (3 identifiers)

`MPL-2.0`, `EPL-2.0`, `CDDL-1.0` (`license-policy.yaml:121-129`)

Obligation: on distribution, make available the source of the *covered files* as modified — not the whole work.
Substantially narrower than §6.1: unmodified covered files carry a notice obligation and little else. Each adds
one distinct term counsel should note: MPL-2.0 has patent-termination on assertion; EPL-2.0 places an indemnity
obligation on a "Commercial Contributor" who offers warranties or support; CDDL-1.0 carries choice-of-law and
venue terms that a party may not wish to accept by default.

### 6.5 Advertising / acknowledgement in materials (2 identifiers)

`OpenSSL`, `BSD-4-Clause` (`license-policy.yaml:136-138,142-144`)

Obligation: a specified acknowledgement must appear in **advertising and promotional materials** mentioning
features or use of the software — an obligation that lands on marketing copy, not on the artefact. It is the
only group in this list whose compliance surface is outside the repository.

One fact that may narrow this group considerably: the `OpenSSL` SPDX identifier covers the historic dual
OpenSSL/SSLeay licence used up to OpenSSL 1.1.1. OpenSSL 3.x is Apache-2.0, which
`policies/license-policy.yaml:73-75` already classifies `allowed`. **Whether any component in any Foundry image
actually asserts `OpenSSL` rather than `Apache-2.0` is not established** — see §6.7.

### 6.6 Naming and renaming restrictions (2 identifiers)

`PHP-3.01`, `Artistic-2.0` (`license-policy.yaml:133-135,139-141`)

Obligation: constraints on what a derived product may be called, and on distributing modified versions under the
original name. PHP-3.01 restricts use of the name "PHP" in derived product names and requires an acknowledgement
that the product includes PHP software. Artistic-2.0 requires modified versions to be renamed or otherwise
clearly distinguished.

Directly relevant here: this project ships image families named `php-fpm`, `php-cli`, `php-worker` and
`php-frankenphp` (`Makefile:162-165`). Whether those names engage PHP-3.01's naming restriction is a legal
question with a concrete answer, and it is one the packet should get answered rather than left as a category —
the policy's own `reason` at `:135` says exactly that.

### 6.7 What is not established about all 17

- **No inventory exists.** The classification is a *policy table of identifiers*, not a measurement of this
  product. Producing a real inventory requires SBOMs and the pipeline at
  `docs/licensing/license-compliance.md:36-47`; that pipeline exists but has never been run against a published
  artefact in-repo. Which of the 17 identifiers actually appear, and on which components, is therefore
  **unknown**. Counsel should not be asked to clear 17 abstractions when a run of
  `scripts/license/license-inventory.sh` would reduce the list to the ones that are real.
- **Notice text is not preserved.** `docs/licensing/license-compliance.md:123-124` states that the inventory
  records identifiers and provenance, not licence texts, so "notice obligations that require reproducing the
  text are therefore only partially served". Every group above except §6.5 requires reproducing text.
- **No `NOTICE` artifact exists**, and `scripts/license/generate-notice.sh` is wired into no workflow
  (`publication-and-licence-options.md:138-139`). The gate is also not in the publish path
  (`docs/licensing/license-compliance.md:119-121`).
- **The obligations are not option-A-only.** `publication-and-licence-options.md:55` assigns "all 17
  `legal-review-required` third-party licences" to option A's legal review, and gives B and C different
  questions. That understates B and C. Reciprocal obligations in §6.1, §6.2 and §6.4 attach on **conveyance to
  any third party**, including delivery of an image to a customer under commercial terms (option B) or to any
  legal entity other than Zenchron Dynamics (option C). §6.3 attaches on network-facing operation with no
  conveyance at all. The obligations are dormant today only because publication is disabled and every package
  is private — not because of anything a licence choice does. **Under every option, the first delivery of an
  image to an outside party makes Foundry a redistributor.** Legal should be asked the third-party-obligation
  question under all three options, not under A alone.

## 7. Legal-review ownership, by role

No role below is currently filled by a named reviewer. This document does not fill one; recording who holds each
is an owner action.

| role | question this role is being asked | evidence to hand them |
| --- | --- | --- |
| **legal owner** (outbound grant) | May Zenchron Dynamics grant the terms proposed under the selected option, and is the specific text adequate? Under B, **who drafts** the source-available grant and the separate customer image-distribution terms? | §1, §4; `LICENSE:1-23`; `publication-and-licence-options.md:113-124` |
| **legal owner** (inbound rights) | Does an employment or contractor instrument vest all contributions from 2026-05-30 onward in Zenchron Dynamics, such that the history can be relicensed? Do the AI co-authorship trailers on 133 of 164 commits create any ambiguity? Are `dependabot[bot]`'s 22 workflow-pin commits copyrightable? | §3 |
| **open-source compliance counsel** | For each obligation class in §6, is the obligation satisfiable given how Foundry delivers images — and under **which** options, given that reciprocal obligations attach on conveyance rather than on publicness? Specifically: must Foundry operate a source-offer mechanism (§6.1), and does PHP-3.01's naming restriction reach image families named `php-*` (§6.6)? | §6; `policies/license-policy.yaml:91-144` |
| **commercial / product counsel** | If images are delivered under separate terms, what must those terms say, and do they interact with the source-side grant a reader has already received from the public repository? | §4, §5 |
| **regulatory counsel** | The CRA economic-role determination (#113, #114) and the **member state of establishment**, which `publication-and-licence-options.md:126` records as required under all three options. Does publishing source while delivering images only under contract constitute placing a product on the market? | `policies/governance-model.yaml:159-161`; `publication-and-licence-options.md:118-126` |
| **maintainer role** | Decides no legal question. Owes the repository-side preconditions: the `A\|B\|C\|undetermined` enum versus the "A, B, C or D" discrepancy (`publication-and-licence-options.md:132-134`), the false GitHub-Free claim at `CONTRIBUTING.md:21-27`, an inbound-contribution term in `CONTRIBUTING.md`, attribution notices for the three files in §2a, and a real licence inventory run so counsel reviews measured licences rather than a policy table. | §2a, §3, §6.7 |
| **release owner** | Keeps publication disabled until `policies/license-policy.yaml:43` records a decision **and** `:53` `notices_approved_for_distribution` is set by the owner. Neither is changed by this document. | `release.yml:31-58`; `publish-rc.yml:43-45` |

## 8. Unresolved questions, consolidated

1. Does an IP-vesting instrument cover the full commit history? — **legal owner (inbound)**. Blocks A and B.
2. Do AI co-authorship trailers on 133 of 164 commits affect authorship of record? — **legal owner (inbound)**.
3. What SPDX identifier and text is proposed for A? — **legal owner (outbound)**. The decision is not recordable
   without one.
4. Who drafts B's source-available grant, and the separate customer image terms? — **legal owner (outbound)** and
   **commercial counsel**. Neither document exists.
5. Is a look-but-do-not-use grant enforceable against a reader who clones a public repository and runs
   `make build-test`? — **legal owner (outbound)**.
6. Which of the 17 identifiers are actually present in the images? — **maintainer role** to measure, then
   **open-source compliance counsel** to clear.
7. Must Foundry operate a source-offer mechanism, and under which options? — **open-source compliance counsel**.
   This is the answer with the largest engineering consequence in the packet.
8. Does PHP-3.01's naming restriction reach the `php-*` image family names? — **open-source compliance counsel**.
9. Member state of establishment and CRA economic role. — **regulatory counsel**. Required under all three
   options.
10. Under which licence is the upstream seccomp profile copied into `security/seccomp/zenchron-default.json`
    distributed, and what notice must this repository carry for it? — **open-source compliance counsel** to
    confirm the terms, **maintainer role** to add the notice. This one is not blocked on the A/B/C decision and
    is a defect today.

## 9. What makes an option harder than the merged comparison suggests

Stated as findings, not as a recommendation, and deliberately covering all three.

- **A** is harder than a licence-file swap and a label change. It requires a source-offer mechanism that does
  not exist (§6.1), licence texts that the pipeline explicitly does not preserve
  (`docs/licensing/license-compliance.md:123-124`), a `NOTICE` artifact that does not exist, and a licence gate
  that is not yet in the publish path (`:119-121`). It also requires inbound rights to be established first
  (§3), because an OSI grant is, as the comparison notes at `:54`, effectively irreversible.
- **B** is harder than "no control-plane change" implies. Its defining property is operational, not legal. It
  requires two documents that do not exist and have no named drafter (§4), it needs the resulting grant to be
  enforceable against a reader who has already been handed a working build (§5), and it does **not** avoid the
  third-party reciprocal obligations — those attach when an image is delivered to a customer, commercial terms
  or not (§6.7). Reversibility of a file is not reversibility of a grant already received by readers.
- **C** does not extinguish the third-party obligations either: delivering an image to any legal entity other
  than Zenchron Dynamics is still conveyance, and §6.3 attaches on network-facing operation regardless. It also
  leaves `LICENSE:22-23`'s self-declared placeholder standing as the organisation's final terms unless that is
  addressed deliberately (§4).

**All three** inherit §2a. The three files copied or derived from upstream travel with the repository under any
option, and two of them carry no attribution at all. Under A they are an open-source notice failure; under B
they are an unlicensed redistribution of third-party code inside a source-available tree; under C they remain a
defect that has already been public since 2026-07-28. This is the only finding in the packet that is a problem
**today**, independently of the decision, and it is also the cheapest to fix.

The common factor: **the third-party obligation question is not a function of which licence Foundry picks. It is
a function of whether Foundry conveys images to anyone.** That question should be put to counsel on its own,
independently of A/B/C.

## 10. What this document did not do

- Did not select a licence, and did not edit `LICENSE` or `policies/license-policy.yaml`.
- Did not change repository visibility, package visibility, rulesets or any publication control.
- Did not enable publication: `release.yml` and `publish-rc.yml` remain refusal stubs, and no tag, signature,
  promotion or release was created.
- Did not redo the A/B/C consequence comparison, which stands at
  `docs/decisions/publication-and-licence-options.md`.
