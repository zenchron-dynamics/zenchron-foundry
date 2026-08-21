# Multi-architecture acceptance — run 32395890071

**PASS.** Source revision `7061caafb3ea09bd5b2342a1daf022151b33f822`, 2026-08-20.

This is the durable record of the accepted release candidate. It exists because
GitHub Actions artifacts expire and the release decision must remain
reconstructible afterwards.

| | |
|---|---|
| run | [32395890071](https://github.com/zenchron-dynamics/zenchron-foundry/actions/runs/32395890071) attempt 1, `success` |
| source revision | `7061caafb3ea09bd5b2342a1daf022151b33f822` |
| scanner | `aquasec/trivy:0.71.0@sha256:016eae51…` |
| frozen database | `v2+updated:2026-08-20T13:14:11.601761173Z` (one identity, all 20 children) |
| children | 20 planned, 20 completed, 0 failed |
| platforms | 10 `linux/amd64`, 10 `linux/arm64` |
| gates | smoke, metadata, scan, reconciliation — PASS 20/20 |
| checksums | 20/20 independently recomputed |
| authorizer | verdict **PASS**, scope `immutable-rc-manifest-input` |
| in-job child time | 7.24 h (native 42.4 min, emulated 391.8 min) |

## Scope — read this before reusing it

Acceptance applies to **`7061caaf` only**. It does not authorize any later master
commit, and it is not a publication, signing, promotion or release authorization.
Any subsequent commit needs its own acceptance run.

## QEMU disclosure

Ten `linux/arm64` children ran under **QEMU emulation** on X64 runners. Each child
record carries `execution_mode` and `host_architecture`, so this cannot be blurred
later.

- **#139** — QEMU is explicitly acceptable for multi-architecture build, scan and
  reconciliation evidence. This record closes it.
- **#111** — QEMU is **not** native-arm64 runtime evidence. This record does not
  close it, and no QEMU run can.

## Governance applied

`CVE-2026-14456` (openssl/libssl3) and `CVE-2026-53613` (util-linux) each appear on
exactly 18 children — nine Debian families × both architectures. `caddy/prod`
carries neither and drew no coverage from either exception.

## Validation

`acceptance-evidence.json` is checksummed in `SHA256SUMS` and independently
verified by `tests/release/test_acceptance_evidence_record.sh`, which re-checks
identity uniqueness, the platform split, digest binding, the gates, the QEMU
disclosure, the scope limit, and that timing is positive rather than fabricated.
