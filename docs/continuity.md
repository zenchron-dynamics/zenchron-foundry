# Registry continuity and disaster recovery

**Issue:** #116 (**open**) · **Policy:** `policies/continuity.yaml`
**Tooling:** `scripts/continuity-export.sh`

## The honest headline

**Foundry has one registry.** GHCR, under one GitHub organization. There is no
independent second registry today, and **a second GHCR package under the same
account is not one** — it shares the outage domain, the account, the billing
relationship and the suspension risk that continuity planning exists to survive.

So the acceptance criterion — *a customer can pull and verify an approved release
during GHCR unavailability* — **is not met, and #116 stays open.**

## What is built anyway, and why

Everything that does not require a second provider:

| | status |
| --- | --- |
| export every shipping digest | built, exercised |
| digest-equality verification on restore | built, exercised |
| restore procedure | this document |
| RTO / RPO targets | declared as numbers |
| local-registry disaster exercise | **executed** (needs docker + network) |
| offline OCI-layout disaster drill | **executed on every test run** |
| mirror consistency verifier | built — `scripts/continuity-verify.sh` |
| registry-neutral mirror manifest | declared — `policies/continuity-mirror.yaml` |
| critical-release inventory | declared, derived from the matrix |
| signature/evidence backup | **not yet possible** — nothing is signed (#139) |
| independent mirror | **absent** — requires a procurement decision |

Standing up a mirror is a procurement decision. Proving that a mirror would
actually restore a *verifiable* release is engineering — and it is the part that
fails silently if nobody tries it. Doing the engineering first means the mirror,
when it exists, is plugged into a mechanism that has already been run.

## Targets

| | value | meaning |
| --- | --- | --- |
| RTO | **24 hours** | from declaring registry loss to a consumer pulling a verifiable release elsewhere |
| RPO | **0 released digests** | no released digest may be unrecoverable |

Both are achievable only once a mirror exists. They are recorded now so the
mirror is specified against a number rather than chosen and then justified.

## Why OCI layout, and not `docker save`

An OCI layout preserves the **manifest and its digest exactly**. A `docker save`
tarball does not preserve the registry manifest digest — so a restored image
would have a *different* digest, which breaks every digest-pinned consumer
reference and invalidates every signature over the original.

Digest equality is the whole point of the restore, not a detail of it.

## The exercise

```bash
bash scripts/continuity-export.sh --exercise
```

Starts a local registry, exports the shipping matrix **by digest**, restores each
one into that alternate registry, and asserts the restored digest equals the
source digest.

```text
exported 10/10 image digest(s)
ok - every image in the matrix was exported
ok - every exported digest was restored to the alternate registry
ok - every restored digest EQUALS its source digest
ok - the policy still declares that no independent mirror exists
continuity exercise: 4 ok, 0 failed  (10/10 digests restored, 0 mismatched)
```

That last assertion is deliberate: an exercise against a local registry must not
be readable, later, as evidence that a mirror was created.

## What closes #116

Two human decisions, recorded in `policies/continuity.yaml`:

1. **Select and fund an independent registry** with a separate account — a
   different provider, so a GitHub outage, an organization suspension, a billing
   failure or a credential compromise does not take both.
2. **Provision credentials held outside the GitHub account.** Credentials stored
   only in GitHub secrets share the failure domain with the thing they are meant
   to survive.

Then: mirror on publish, verify digest equality continuously, and re-run the
exercise against the real mirror rather than a local container.

## The mirror manifest, and why it names no vendor

`policies/continuity-mirror.yaml` describes **what must survive the loss of GHCR** and **how a copy is
proven faithful**, in OCI terms that any conformant registry satisfies. It deliberately names no provider.

Writing the manifest against a specific vendor's API would mean rewriting it at the exact moment it is
needed — during an outage. So the destination is described by the properties it must have, not by who
sells it:

| requirement | why |
| --- | --- |
| separate provider | a provider-wide outage must not take both copies |
| separate account and billing | organisation suspension and billing failure are the loss modes continuity exists for |
| credentials held outside GitHub | credentials that live only in the thing they must survive do not survive it |
| immutable retention at the destination | a mirror an attacker can overwrite is a second copy of the compromise |

`mirror.status` is `not-provisioned` and every artifact class records `mirrored: false`. Nothing in this
repository should ever be read as evidence that a mirror exists.

The critical-release inventory is **derived**, not hand-listed: a hand-maintained digest list goes stale
silently, so the selector is evaluated against the live matrix (`contracts/images/*.yaml`) at export time.
Two classes are declared as blocked rather than satisfied — cosign signatures (#139, nothing is signed
yet) and VEX documents (#115).

## The consistency verifier

```bash
bash scripts/continuity-verify.sh --verify <source-layout> <mirror-layout>
```

`policies/continuity.yaml` has named this file as `restore.verification` since the continuity work landed.
**It did not exist.** A policy pointing at an absent verifier is worse than one pointing at nothing,
because it reads as though restoration is already checked. It exists now, and `tests/continuity/` asserts
that the file the policy names is present and runnable.

It proves five things between two OCI layouts:

1. both are real OCI layouts, not directories that resemble one
2. every manifest the source publishes is present in the mirror
3. every mirrored manifest digest **equals** the source digest
4. every referenced blob — config and layers, transitively — is present
5. every blob's **content still hashes to the digest naming it**

Point 5 is the one a digest list cannot give you. A mirror can hold the right digest *names* over corrupted
bytes; the failover everybody rehearsed then serves artefacts no signature covers. Content is rehashed
here, never assumed from the filename.

## The offline drill

```bash
bash scripts/continuity-verify.sh --drill
```

No docker, no network, no registry — so it runs in CI on every test run rather than living as a transcript
in a document. It builds an OCI layout, mirrors it digest-preserving, verifies equality, and then
**sabotages the mirror three ways** and proves the verifier refuses each:

```text
-- 3. sabotage: corrupt one blob, keep its name
ok   - a mirror with the right digest over WRONG BYTES is refused
ok   - ...and the refusal says the blob is CORRUPT
-- 4. sabotage: drop a blob the index still references
ok   - a mirror missing a referenced blob is refused
-- 5. sabotage: an empty directory is not a mirror
ok   - an empty directory is refused, never reported as a clean mirror
-- 6. the policy must still say no independent mirror exists
continuity drill: 8 ok, 0 failed
```

A drill that only ever passes has not tested anything. The final assertion re-reads the policy, so this run
can never be cited later as evidence that a mirror was created.

## Exports refuse to look successful

`scripts/continuity-export.sh --export <dir>` used to exit **0** having written only `digests.txt` when
every OCI-layout write failed — a "successful" export nothing can be restored from, against a policy
promising `format: OCI layout`. It now refuses:

```text
REFUSE: N image(s) exported no OCI layout — a digest list is an
        inventory, not a backup, and nothing can be restored from it.
        Re-run with --digests-only to record an inventory deliberately.
```

Recording an inventory is a legitimate thing to want. It is not what you should get by accident.

## What still blocks #116

One external decision, unchanged by any of the above: **an independent registry must be selected and
funded**, with credentials held outside the GitHub account and immutable retention enabled. Owner: Bogdan
Olteanu. Until then the acceptance criterion — a customer pulling and verifying an approved release while
GHCR is unavailable — is not met, and no tooling in this repository can meet it.
