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
| local-registry disaster exercise | **executed** |
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
