# Build reproducibility

**Issue:** #101
**Policy:** [`policies/reproducibility.yaml`](../policies/reproducibility.yaml)
**Input inventory:** [`policies/supply-chain-inputs.yaml`](../policies/supply-chain-inputs.yaml)
**Schemas:** [`schemas/build-input-lock-v1.schema.json`](../schemas/build-input-lock-v1.schema.json),
[`schemas/build-input-lock-evidence-v1.schema.json`](../schemas/build-input-lock-evidence-v1.schema.json)
**Harnesses:** `scripts/reproducibility-check.sh`, `scripts/repro-lock.sh`, `scripts/repro-guarantees.sh`

## "Reproducible" is four questions, not one

They have four different answers, and every earlier version of this page let the
strongest one be read across all four. So they are kept apart by name, by
schema section, and by a gate that refuses to let one become evidence for
another.

| # | guarantee | the question it answers | answer |
| --- | --- | --- | --- |
| 1 | `build-input` | Can the exact declared inputs of a build be recovered and re-presented byte-identically later? | `guaranteed` |
| 2 | `package-resolution` | Would `apt-get install` resolve the same package versions on a rebuild? | `not-guaranteed` |
| 3 | `image-bytes` | Do two isolated builds of the same declared inputs produce the same image bytes? | `conditional` |
| 4 | `vulnerability-verdict` | Does re-scanning the same bytes produce the same vulnerability verdict? | `not-guaranteed` |

The one sentence a consumer may quote:

> Zenchron Foundry guarantees that the declared **inputs** to a build are
> recorded and re-presentable exactly; it does **not** guarantee that Debian
> package resolution, image bytes for the PHP families, or vulnerability
> verdicts reproduce.

### What may not be inferred

Each of these is an inference that was actually made, or nearly made, while this
work was done. They are declared in the policy under `forbidden_inferences`, and
`scripts/repro-guarantees.sh` refuses a policy in which a partial guarantee is
not protected by one.

| from | to | why not |
| --- | --- | --- |
| `build-input` | `image-bytes` | The build tool, the live archive and the compiler all sit between inputs and outputs, and all three were measured changing the result with the inputs held fixed. |
| `image-bytes` | `package-resolution` | Two builds minutes apart agree on packages because the index did not move, not because it is pinned. Agreement inside a window is not a property of the archive. |
| `image-bytes` | `vulnerability-verdict` | The database moves underneath unchanged bytes. Byte stability says nothing about what tomorrow's scan reports. |
| `package-resolution` | `build-input` | Recording what apt resolved is attribution after the fact. A recorded set cannot be replayed. |

## What is bound, and where

`scripts/repro-lock.sh emit` writes one **build-input lock** per image per
platform. It is a record, not a claim; which sections may support which
guarantee is decided by the policy, not by the lock.

| recorded | field | belongs to |
| --- | --- | --- |
| source revision | `build_inputs.source_sha` | 1 |
| commit timestamp | `build_inputs.source_date_epoch` | 1 |
| Dockerfile + context digests | `build_inputs.context_digest`, `build_inputs.dockerfile_digest` | 1 |
| base index digest | `build_inputs.base.manifest_digest` | 1 |
| base **platform child** digest | `build_inputs.base.platform_child_digest` | 1 |
| build args | `build_inputs.build_args` | 1 |
| toolchain (frontend, buildx, dockerd) | `build_inputs.toolchain` | 1 |
| Debian repository identity | `package_resolution.repositories` | 2 |
| archive `InRelease` dates, when the image still has them | `package_resolution.archive_release_dates` | 2 |
| Debian **snapshot** identity, if obtainable | `package_resolution.snapshot_identity` | 2 |
| resolved package inventory + fingerprint | `package_resolution.packages`, `.package_set_sha256` | 2 |
| produced config / layer / manifest digests | `build_outputs.*` | 3 |
| scanner image digest | `vulnerability_verdict.scanner` | 4 |
| frozen vulnerability-database identity | `vulnerability_verdict.vulnerability_database` | 4 |

Two of these are recorded as `null` today, and `null` means **not obtainable**,
never "nothing differed":

- `package_resolution.snapshot_identity` — the archive is live. The schema
  refuses `guaranteed: true` without it, so the flag cannot be flipped without
  the thing that would justify it.
- `vulnerability_verdict.vulnerability_database.identity` — the database is
  fetched at scan time. The schema refuses `frozen: true` without an identity.

`package_resolution.archive_release_dates` comes back **empty** for the hardened
images, and that is not a defect: the Dockerfiles delete `/var/lib/apt/lists`, so
the `InRelease` headers no longer exist by the time the image does. It is
recorded because the Alpine and less-stripped images do keep them, and an empty
array says "the image did not retain this" rather than "nothing was checked".

`build_inputs.base.platform_child_digest` is the one most easily missed: a
`FROM foo@sha256:X` pin names an **index**. The bytes a `linux/amd64` build
consumes are a child manifest with a different digest, and pinning only the
index leaves the platform-specific input unnamed.

## The experiment

Two `--no-cache` `linux/amd64` builds of `images/php-cli/8.4` from identical
declared inputs, on a dedicated `docker-container` buildx builder, with
`SOURCE_DATE_EPOCH` taken from the source commit and the exporter asked for
`rewrite-timestamp=true`. Both locks were emitted and compared field by field.

That the inputs were held fixed is **asserted by comparing the two locks**, not
assumed — the record is in
`tests/reproducibility/evidence/php-cli-8.4-linux-amd64-build-input.json`.

The lock's `source_sha` names the revision the experiment was run against, which
is a branch commit and not necessarily one that survives a squash merge. That is
deliberate: it records what was measured. `repro-lock.sh verify` re-checks the
commit-timestamp binding whenever that object is present and says so explicitly
when it is not — a shallow CI checkout will not have it, and reporting "not
evaluated" is not the same as reporting a pass.

Reproduce it:

```bash
bash scripts/reproducibility-check.sh images/php-cli/8.4 php-cli-8.4 \
     --emit-evidence tests/reproducibility/evidence \
     --family php-cli --selector 8.4 --platform linux/amd64
```

### Result — guarantee 1, `build-input`

All ten recorded input fields **stable** across the two builds — source
revision, commit-derived epoch, context digest, Dockerfile digest, base index
digest, base platform-child digest
(`sha256:3d56210f…`, the `linux/amd64` child of the `php:8.4-cli-bookworm`
index the Dockerfile pins), build args, and toolchain identity.

Record:
[`php-cli-8.4-linux-amd64-build-input.json`](../tests/reproducibility/evidence/php-cli-8.4-linux-amd64-build-input.json).

### Result — guarantee 3, `image-bytes`

| field | result | detail |
| --- | --- | --- |
| `build_outputs.runtime_config_sha256` | **stable** | env, labels, entrypoint, cmd, user, ports, workdir |
| `build_outputs.labels` | **stable** | including `org.opencontainers.image.created`, which is now the commit's time |
| `build_outputs.rootfs_file_count` | **stable** | 4,261 files both times |
| `build_outputs.layer_digests` | **differs** | 1 of 15 layers |
| `build_outputs.config_digest` | **differs** | the config blob commits to `rootfs.diff_ids`, so it moves with the layer |
| `build_outputs.rootfs_file_manifest_sha256` | **differs** | 1 of 4,261 files |
| `build_outputs.manifest_digest` | **not-observed** | a local build exports to the daemon and produces no OCI manifest |

The single differing file:

```text
./usr/local/lib/php/extensions/no-debug-non-zts-20240924/redis.so
  build a  1d19f5d033bf808dc81a9bc440ec0662f69b6ac43c18942da37b49a1cc27fddf
  build b  ff283f009135734014302f980672eb8a1c66f2a9ce3c55dba4d99dca003fab5c
```

Record:
[`php-cli-8.4-linux-amd64-image-bytes.json`](../tests/reproducibility/evidence/php-cli-8.4-linux-amd64-image-bytes.json).
Declared inputs:
[`php-cli-8.4-linux-amd64.lock.json`](../tests/reproducibility/evidence/php-cli-8.4-linux-amd64.lock.json).

### Repeated a second time, from a different commit

The experiment was run twice, as two independent pairs — four `--no-cache`
builds in total, on two different source revisions of this branch. The second
pair reproduced the first exactly: the same fifteen layers with the same one
differing, the same 4,261 files with the same one differing, the same 127
packages resolving identically, `runtime_config_sha256` and `labels` stable.

```text
pair 1   ./usr/local/lib/php/extensions/no-debug-non-zts-20240924/redis.so
         a 1d19f5d033bf808d…   b ff283f0091357340…
pair 2   ./usr/local/lib/php/extensions/no-debug-non-zts-20240924/redis.so
         a e9af6ec9e3214047…   b 1d3a1a1a65694ffb…
```

Four distinct digests for one file compiled four times from one pinned,
checksum-verified source archive. The difference is not drift between commits;
it is per-build.

### The SBOM, and why it is not a separate field

Under [`policies/syft.yaml`](../policies/syft.yaml) an SBOM for these images is
two things: the **package catalogue**, and a **per-file digest catalogue**
(`file.metadata.selection: owned-by-package`). Both are compared here directly:

- the package set — 127 packages, name, version and architecture — was
  **identical** across both builds of both pairs, and the lock records it with a
  fingerprint that recomputes;
- every regular file's sha256 was compared, and **one of 4,261 differed**.

A syft document diff would report exactly those two results plus serialisation
noise — the document identifier and the timestamp syft mints per run. So the
SBOM comparison is performed, by a more direct method than diffing a format that
changes when nothing does; it is not recorded as an extra lock field because a
field whose value is a restatement of two others invites being read as a third
independent result.

### What that means, and what it does not

The **127-package set resolved identically** in both builds. That is *not*
evidence for guarantee 2. The two builds were fifteen minutes apart; the index
did not move because nothing published in that window, not because anything is
pinned. The lock records the archive identity and a recomputable fingerprint so
a future difference is attributable, and `package_resolution.snapshot_identity`
stays `null` because there is no snapshot.

So `image-bytes` is bound to **exactly the two fields measured stable**:
`runtime_config_sha256` and `labels`. Everything else is recorded as
`unclaimed_fields` in the policy with the measurement that stopped it being
claimed. `scripts/repro-guarantees.sh` refuses a policy that claims a field its
evidence reports `differs` or `not-observed`, so the narrowness is enforced
rather than promised — the case is exercised in
`tests/reproducibility/test_repro_refusal_paths.sh` as *"byte reproducibility
asserted over a field measured to differ"*.

Note what is deliberately **not** said: this is not "php-cli 8.4 is
reproducible". One layer of fifteen and one file of 4,261 differ, and the
difference is a compiled binary that ships.

## Earlier findings that still hold

**Timestamps.** Two `caddy` builds once differed in **31 bytes out of
63,187,456** — all of them tar header mtimes for directories created by
`RUN mkdir`. The difference was invisible to `tar -tv`, because the builds were
19 seconds apart *inside the same minute* and that listing prints minute
granularity. `SOURCE_DATE_EPOCH` alone does not fix it: BuildKit uses it for the
config's `created` field and rewrites **layer** timestamps only when the
exporter is asked with `rewrite-timestamp=true`.

**Residue.** With timestamps normalised, `nginx` still differed in one layer of
nine while `tar -tv` reported the filesystem identical across 4,815 entries.
Hashing every file found **8 differing files of 3,505** — `/var/log/apt/*`,
`/var/log/dpkg.log`, `/var/cache/ldconfig/aux-cache`. Same size, same mtime,
different bytes: build logs recording *when* the build ran. They are deleted in
the layer that creates them now, which also stops shipping a record of the build
host's clock to consumers.

> A metadata-only comparison reported "identical" while those 8 files differed.
> The harness hashes every file, because a check that cannot see the difference
> it exists to find is not a check.

**A hypothesis tested and found wrong.** `redis.so` is unstripped (~3.7 MB,
mostly DWARF) and DWARF embeds the temporary directory `pecl` picks per run, so
`strip --strip-unneeded` looked like the fix. A full re-run **with** stripping
still produced two different binaries. The change was reverted rather than kept
for the incidental size win. The nondeterminism is in the code or data sections;
`-frandom-seed` and `-ffile-prefix-map` are the next candidates.

## The controls, and what each refuses

Every one of these was shown to refuse on a deliberately sabotaged copy of the
tree, and to accept the same copy unsabotaged — see
`tests/reproducibility/test_repro_refusal_paths.sh`.

| sabotage | control | refusal |
| --- | --- | --- |
| the integrity pin is recorded but never checked | `repro-lock.sh verify` | `integrity_pin.<id>: records a checksum but never VERIFIES it` |
| the built-in checksum is not the declared one | `repro-lock.sh verify` | `integrity_pin.<id>: does not appear in the executable part` |
| the base moved under the lock (and the inherited helper with it) | `repro-lock.sh verify` | `base.reference: base drift` |
| a COPYed context file changed | `repro-lock.sh verify` | `context_digest: the context has drifted` |
| the recorded epoch is not the commit's | `repro-lock.sh verify` | `source_date_epoch: timestamp drift` |
| the package fingerprint no longer recomputes | `repro-lock.sh verify` | `package_set_sha256: does not recompute` |
| the declared apt gap is erased while apt still resolves live | `repro-guarantees.sh` | `rule-7` |
| a fifth guarantee is added, or one of the four removed | `repro-guarantees.sh` | `rule-1` |
| one field is made evidence for two guarantees | `repro-guarantees.sh` | `rule-3` |
| byte reproducibility claimed over a field measured to differ | `repro-guarantees.sh` | `rule-5` |
| evidence presented from an input set nobody committed | `repro-guarantees.sh` | `rule-9` |

The checksum control **strips comments before searching**, and that is not
tidiness. `images/php-cli/8.4/Dockerfile` carries a line explaining why the
verification is written the way it is, and the pre-existing check greps the whole
file for `sha256sum -c -` — so it is satisfied by that sentence whether or not
the `RUN` step still verifies anything. A grep that matches its own explanatory
comment reports on the documentation, not on the build.

### What these controls do NOT catch

Stated here rather than left to be discovered. A **committed evidence record
edited in place** to read `stable`, with its lock binding left intact, verifies.
Nothing here is signed. What stands against that is that `policies/`, `tests/`
and `schemas/` are security-sensitive paths, so the edit arrives as a reviewed
diff carrying the change checklist — a review control, not a machine check, and
not described as one.

## The two residuals

Both are named in the policy with an owner, and neither is closable as a side
effect of inventory work.

1. **Debian repository snapshot determinism.** `apt-get update` resolves a live
   index, so two builds of one commit a week apart can install different
   versions — and *should*, because that is how security fixes arrive. Measured
   directly: the pinned `nginx` base ships `libssl3 3.0.18-1~deb12u2` while the
   built child carries `3.0.20-1~deb12u2`, because apt pulled the package
   forward at build time. Closing it needs either `snapshot.debian.org` pinned
   to a commit-derived timestamp, or a committed package lock installed with
   `apt-get install pkg=version`. Both change how security updates reach the
   images.
2. **PHP compiled-extension determinism.** `redis.so`, plus `redis.reg` which
   stores an install timestamp. Diagnosed above; the obvious fix was tested and
   does not work.

**Owner:** Zenchron Dynamics / Platform Security. **Tracked in:** #101.

## Running it

```bash
bash scripts/repro-guarantees.sh          # the claims, against the evidence (offline)
bash scripts/repro-lock.sh verify tests/reproducibility/evidence/php-cli-8.4-linux-amd64.lock.json
bash tests/reproducibility/test_repro_guarantees.sh
bash tests/reproducibility/test_repro_refusal_paths.sh
make reproducibility                      # the repeated builds; needs docker
```

The first four are offline and run in CI as part of `tests/run-all.sh` and
`scripts/macro-validate.sh`. The repeated builds are not a CI check: they take
tens of minutes per image under emulation, and a gate that is too slow to run is
a gate that gets skipped.
