# Evidence restore drill — committed readback record

**Date:** 2026-08-30 · **Commit:** `84419f239a87` (master) · **Run:**
[33329370235](https://github.com/zenchron-dynamics/zenchron-foundry/actions/runs/33329370235)

This is the readback record #241 asks to be committed. It is a snapshot of one
real run of the drill that `ci.yml` executes on every pull request and every
push to master. It is kept because the artifacts it describes expire in 90 days
and the fact that the round trip was observed should not expire with them.

## What was proven

A staged evidence bundle was built by the production producer, uploaded as a
GitHub Actions artifact, and restored **by a different job on a different
runner** from nothing but the bytes that came back.

| | |
|---|---|
| bundle id | `staged-candidate-7061caafb3ea-32395890071` |
| evidence class | `staged-candidate` |
| source revision | `7061caafb3ea09bd5b2342a1daf022151b33f822` |
| files restored | **30, byte-identical to what was uploaded** |
| restore consumer | `scripts/release/restore-evidence.sh`, exit 0, pinned by content hash |
| artifact (bundle) | id `9737181529`, 83,959 B |
| uploaded at | `2026-08-30T18:54:17Z` |
| retained until | `2026-11-28T18:54:06Z` — **90 calendar days**, as the authority reported it |
| lock / versioning | `none` / `not-applicable` — a GitHub artifact offers neither, and the receipt says so |

The restore itself used **no network, no GitHub and no registry**: the archive
was built on the restore runner from the downloaded bundle, the downloaded
working copy was deleted, and the bundle was restored by id from the archive
alone and re-verified offline against its own manifest.

## What this is NOT

> This is a TRANSPORT AND RESTORATION drill. The bundle is built from a fixture
> authorization record and is NOT production evidence, NOT an accepted candidate
> and NOT a release.

That sentence is carried in `verdict.json` itself, and
`evidence-restore-drill.sh consume` refuses a verdict that does not carry it.
The bundle's inputs are a real accepted run's acceptance evidence and a FIXTURE
authorization record from `tests/lib/make_authorization_fixture.py`. No image was
built, pulled or scanned; no acceptance was dispatched; nothing was published,
tagged or released.

`storage-receipt.json` records `network_isolated: false` for its readback,
because that copy was fetched back over the network. It is a measurement of
transport, not an offline restore claim — the offline part is the restore, above.

## Two defects this drill found that fixtures could not

1. **`SR-RETENTION-SHORT` on a genuinely 90-day artifact.** GitHub stamps
   `expires_at` from the RUN's start and `created_at` from the upload, so the gap
   is however long the workflow had been running — 26 minutes on the run that
   found it. A timedelta truncated 89d23h33m to 89 days. Both retention
   comparisons now use calendar dates; the 89-day sabotage still refuses.
2. **`SR-CHECKSUM-MISMATCH`.** GitHub returns a `digest` for the ZIP it builds,
   and the receipt producer preferred it over the bundle's manifest hash.
   `storage.object_checksum` is defined as the bundle's checksum, so the zip is a
   different object, not a second opinion about this one.

Neither was reachable by reasoning about fixtures. Both are now pinned by
assertions that fail if the behaviour returns.

## Files

| file | what it is |
|---|---|
| `verdict.json` | the drill's own verdict, as consumed by the required `repo structure` check |
| `storage-receipt.json` | the `foundry.storage-receipt/v1` record for the uploaded bundle |
| `artifact-observations.json` | what the artifact authority reported for all three artifacts of that run |

## Reproducing it

Every pull request runs it. To re-read a live run's verdict:

```sh
gh run download <run-id> -n evidence-drill-verdict-<run-id>-1
bash scripts/ci/evidence-restore-drill.sh consume \
  --verdict verdict.json --run-id <run-id> --commit <sha>
```
