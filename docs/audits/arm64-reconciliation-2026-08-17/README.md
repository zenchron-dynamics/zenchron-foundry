# arm64 reconciliation — the evidence behind widening the ledger

Why `linux/arm64` was added to `verified_architectures` and to
`AUTHORIZED_PLATFORMS` on 2026-08-17.

```
accepted amd64 source     run 31792482449   (source 47609df7…, frozen DB 2026-08-14T07:14:31Z)
canonical arm64 evidence  run 31941819983   (source 25669a3c…, frozen DB 2026-08-16T06:57:04Z)
comparison tool           master a027b7e6cad553a1ee680e584f1a84f0123d2010
execution mode            QEMU emulation on a trusted linux/x64 runner
native arm64 execution    NO
```

## The comparison

```
395  transferable — same CVE, package AND installed version on both
  0  version differences
  0  findings absent from arm64
  0  excluded children (all 20 inventories non-empty)
  0  images missing on either side (10 vs 10)
  6  present only in the newer database
```

`same-db=no`, and deliberately so: the two runs froze different snapshots. The
comparison tool therefore refuses to call asymmetric rows architectural, and
labels them `UNMATCHED-IN-AMD64-BASELINE` rather than `ARM64-ONLY`. That
distinction is the whole reason the six below were investigated instead of
being written off as an arm64 quirk.

## The six, and why they are not an architectural difference

All six are Go standard library findings on caddy, published 2026-08-13, at
`stdlib v1.26.3` — the identical package at the identical version on both
architectures.

They were absent from the amd64 baseline only because that run froze a
2026-08-14 database that had not yet ingested them. **This was verified, not
assumed:** the exact accepted amd64 caddy digest

```
sha256:9f0632b2303dcd3c8a99a268beec8c76cf861fb453beb7e541369e65cec2f3b3
```

was re-scanned against current vulnerability data and reports all six, taking
that image from 10 CRITICAL/HIGH findings at acceptance to 19. See
`amd64-caddy-rescan-proof.json`.

They are governed as six separate two-architecture accepted-risk entries
expiring 2026-08-31 — one exact `cve`/`package`/`installed_version` attribution
each, because a shared entry cannot pin an exact installed version and an entry
pinning none would govern any future version. **No reachability mitigation is
claimed**: several are in server-relevant packages (`net/http`, `crypto/tls`,
`net/url`), and a topology argument was not established.

## What was widened, and what was not

```
exceptions     49 / 49  gained linux/arm64
not_affected   18 / 20  gained linux/arm64
```

`CVE-2026-55199` and `CVE-2026-55200` (php-all, libssh2-1) were **not observed**
in the arm64 scan, so they stay `linux/amd64` only. There is nothing to approve
for an architecture where the finding does not appear — granting it would be
inventing an approval, which is precisely what the comparison tool exists to
prevent.

Which entries qualified was determined by running the real reconciler against
the arm64 evidence and collecting what actually matched, not by reading the
ledger and reasoning about it.

## Verification

Both architectures reconciled against the updated ledger, using each run's own
scan data:

```
arm64  reconciled clean: 10   failing: 0
amd64  reconciled clean: 10   failing: 0
```

## What this does and does not authorize

It permits arm64 to be **judged** by the release gate instead of refused
categorically. It is **not** permission to publish arm64.
`public_exposure_authorized` remains false, and every entry still governs only
the architectures it lists, so an unevidenced finding on either architecture
still refuses the whole matrix.

- **#139 stays open** until the new policy is exercised on a same-SHA 20-child run.
- **#111 stays open.** QEMU is not native-arm64 runtime evidence, and nothing here claims otherwise.

## Files

| file | what it is |
|---|---|
| `comparison.json` | machine-readable comparison output from master `a027b7e6` |
| `arm64-execution-a2-authorization.json` | A2's authorization record, incl. all ten child records |
| `arm64-execution-a2-SHA256SUMS` | checksums for A2's collected evidence |
| `amd64-caddy-rescan-proof.json` | current rescan of the accepted amd64 caddy digest |

A2's raw child evidence (scan JSON, package inventories, logs) stays in the
workflow artifact until **2026-11-14**; the `evidence_sha256` values in the
authorization record bind it. The 109 MB raw vulnerability database is not
preserved — its immutable identity is recorded instead:
`v2+updated:2026-08-16T06:57:04.97066803Z`.
