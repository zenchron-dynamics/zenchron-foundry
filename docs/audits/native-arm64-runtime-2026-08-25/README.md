# Native linux/arm64 runtime evidence — 2026-08-25

Ten `linux/arm64` production children, pulled **by digest** and smoke-tested on
a GitHub-hosted `ubuntu-24.04-arm` runner. Nothing was built: the images tested
are the exact immutable candidate children recorded in
`docs/audits/acceptance-multiarch-2026-08-20/acceptance-evidence.json`, whose
arm64 evidence up to now was **emulated**.

| fact | value |
|---|---|
| workflow run | `32857950223` (`native arm64 smoke (#111)`) |
| runner | `ubuntu-24.04-arm`, kind `ephemeral-hosted` |
| measured host | `uname -m = aarch64` -> `host_architecture: arm64` |
| candidate source revision | `7061caafb3ea09bd5b2342a1daf022151b33f822` |
| coverage | 10 of 10 production images, `runtime_smoke: PASS` on every one |
| execution mode | `native` on all ten |

## What this is NOT

`authoritative: false` on every record. The run was dispatched on
`feat/native-arm64-release-gate`, not on the default branch, so this is
**branch-validation evidence**. `scripts/release/assert-native-arch-evidence.sh
--gate-release` REFUSES it for release authorization, by name:

```
caddy/prod/linux/arm64: evidence is marked authoritative=false — it was
produced on a non-default ref and cannot gate a release
```

Authorizing a release on native arm64 evidence requires a run of the same
workflow on the default branch. Nothing here shortcuts that, and nothing here
is a release, a promotion, a publication or a signature.

## Why the architecture is a measurement and not a label

`runs-on: ubuntu-24.04-arm` is a **request**. Each record carries
`architecture_source: measured` with the `uname -m` it was derived from, and
`image_config_architecture` read back from the pulled image's own config — a
second, independent check that the registry served the arm64 child and not
another one. `scripts/release/assert-native-arch-evidence.sh` refuses any record
whose architecture came from the label instead of a measurement.

## Reproducing

```
gh workflow run "native arm64 smoke (#111)" --ref master \
  -f candidate_evidence=docs/audits/acceptance-multiarch-2026-08-20/acceptance-evidence.json
```
