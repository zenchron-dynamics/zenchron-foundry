# Release withdrawal procedure

**Issue:** #125 · **Schema:** [`policies/support-policy.yaml`](../policies/support-policy.yaml) (`withdrawal:`)
**Exercise:** `scripts/exercise-withdrawal.sh --simulate`

## What withdrawal is, and is not

Withdrawal is **publishing that a digest must not be used**.

It is not deletion. Published digests are immutable, remain pullable, and are
referenced by consumers who pinned them — because this platform tells them to.
Anyone who followed that advice is precisely who a tag-only notice would miss,
so **every withdrawal artefact names digests**.

## Triggers

- a release is found to be compromised or mis-built
- a critical vulnerability with no available fix and no viable mitigation
- a signing identity or key is compromised

## Procedure

1. **Identify every affected digest** — per image, per architecture. The
   exercise script resolves these from the shipping matrix so the set cannot be
   quietly short. An image that will not resolve **blocks** the withdrawal
   rather than being dropped from it.
2. **Publish a security advisory** naming those digests, the reason, the
   mitigations, and the corrective release if one exists.
3. **Notify consumers** on every channel marked `available` in
   `support-policy.yaml`. A channel marked `unavailable` is one this notice does
   **not** reach — which is why the status is recorded there.
4. **Record the withdrawal** in `docs/audits/withdrawals/`.
5. **Name the corrective release** in the same advisory, if one exists. "Stop
   using this" without "use that instead" is not an actionable notice.

## Exercising it

```bash
bash scripts/exercise-withdrawal.sh --simulate
```

Runs the real machinery against a simulated compromised release and asserts the
package is complete: every shipping image represented, every digest resolved,
digests present in the advisory, both artefacts stamped `SIMULATED`, and the
record explicitly claiming that **nothing was published or sent**.

Last run: 10/10 images resolved, 8/8 assertions passed.

## What the exercise cannot prove

That anyone **receives** the notice. Producing a notice and delivering it are
different acts; only the first is automatable here. Confirming that
`security@zenchron.com` is monitored is a tracked human action.
