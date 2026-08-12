# Build reproducibility

**Issue:** #101
**Inventory:** [`policies/supply-chain-inputs.yaml`](../policies/supply-chain-inputs.yaml)
**Harness:** `scripts/reproducibility-check.sh`

## The claim, stated before the evidence

Two independent `--no-cache` builds of the **same source commit**, against the
**same package index state**, produce:

- **byte-identical file content** — every regular file hashed and compared;
- **identical layer digests** (`RootFS.Layers`);
- **identical image configuration** — env, labels, entrypoint, cmd, user, ports.

What the claim deliberately **excludes**, declared in the inventory under
`known_nondeterminism` rather than discovered after a failure:

- the **BuildKit attestation manifest**, which embeds build-time metadata. The
  staging build sets `sbom: false` and `provenance: false` so the shipped object
  is a plain platform manifest, but a local `docker build` without those flags
  produces an index whose digest differs run to run for reasons that are not the
  source.

And what it is **conditional on**, which is the open part of #101:

- **the Debian package index state.** Two builds minutes apart see the same
  index; two builds a week apart may not. See "The remaining gap" below.

## What was actually wrong

| input | before | after |
| --- | --- | --- |
| build timestamp | `github.event.repository.updated_at` in `build-images.yml`; wall-clock `date -u` in `stage-and-authorize.yml` | `git log -1 --format=%ct` — a property **of the source commit** |
| layer timestamps | wall clock: `RUN mkdir` directories carried the mtime of the build | `SOURCE_DATE_EPOCH` + BuildKit `rewrite-timestamp=true` |
| build residue | apt/dpkg logs and `ldconfig/aux-cache` shipped in the image | removed in the same layer |
| PECL redis | `pecl install "redis-6.1.0"` — version-pinned, integrity-unpinned | fetched, `sha256sum -c`, then installed from the verified file |

### The timestamp finding, measured

Two independent builds of `caddy` differed in **31 bytes out of 63,187,456** —
all of them tar header mtimes for directories created by `RUN mkdir`. The
difference was invisible to `tar -tv`, because the two builds were 19 seconds
apart *inside the same minute* and that listing prints minute granularity.

`SOURCE_DATE_EPOCH` alone does not fix it: BuildKit uses it for the image
config's `created` field, and rewrites **layer** timestamps only when the
exporter is asked with `rewrite-timestamp=true`.

### The residue finding, measured

With timestamps normalised, `nginx` still differed in **one layer of nine**,
while `tar -tv` reported the filesystem identical across 4,815 entries. Hashing
every file found **8 differing files out of 3,505**:

```text
./var/cache/ldconfig/aux-cache
./var/log/apt/history.log
./var/log/apt/term.log
./var/log/dpkg.log
```

Same size, same mtime, different bytes — build logs recording *when* the build
ran. Not content the image serves, and now deleted in the layer that creates
them. That also stops shipping a record of the build host's clock to consumers.

> The metadata-only comparison reported "identical" while those 8 files differed.
> The harness now hashes every file, because a check that cannot see the
> difference it exists to find is not a check.

## Results

Four families, chosen for distinct build paths, two `--no-cache` builds each:

| family | build path | file content | layers | config |
| --- | --- | --- | --- | --- |
| `caddy` | Alpine + bundled binary | **240/240 identical** | identical (9) | identical |
| `nginx` | Debian, non-PHP | **3500/3500 identical** | identical (14) | identical |
| `php-cli 8.4` | Debian + PECL | 4260/4261 — `redis.so` differs | 1 layer differs | identical |
| `php-frankenphp 8.4` | helper / upstream bundled | 6917/6919 — `redis.so`, `redis.reg` | 1 layer differs | identical |

The two non-PHP families are **fully reproducible**. The PHP families have two
identified, deterministic causes, both in the same compiled-extension step:

1. **`redis.so`** — the compiled extension differs between builds of the same
   source. **The obvious hypothesis was tested and is wrong.** The binary is
   unstripped (~3.7 MB, mostly DWARF) and DWARF embeds the temporary directory
   `pecl` picks per run, so `strip --strip-unneeded` looked like the fix. A full
   re-run with stripping applied still produced two different `redis.so` files:

   ```text
   FAIL  file CONTENT differs (2 of 4261 files)
         ./usr/local/lib/php/extensions/no-debug-non-zts-20240924/redis.so
   ```

   So the nondeterminism is in the code or data sections, not in the debug info.
   The next candidates are GCC's `-frandom-seed` (which otherwise derives local
   symbol names partly from a random value) and `-ffile-prefix-map` for paths
   compiled into non-debug sections. The strip change was **reverted**: it was
   made to fix determinism, it does not, and an unverified change to six shipped
   images is not worth carrying for a side benefit nobody asked for.
2. **`redis.reg`** — the PECL registry file, which records the install
   timestamp. It is bookkeeping for `pecl list`; nothing at runtime reads it,
   because the extension is loaded from a compiled `.so` by an `extension=`
   directive. Removing it is the obvious fix and is deliberately **not** made
   here, because it could not be verified in this batch and an unverified change
   to a shipped image is not worth making for an issue that cannot close either
   way.

Reproduce locally:

```bash
make reproducibility            # the four representative families
bash scripts/reproducibility-check.sh images/nginx nginx
```

## The remaining gap: the Debian package index

`apt-get update` resolves a **live** index. Two builds of the same commit a week
apart can install different package versions the moment Debian publishes a point
release — and they *should*, because that is how security fixes arrive.

So the reproducibility claim above is conditional on the index state, and that
condition is not currently pinned. Closing it needs one of:

1. **`snapshot.debian.org`** — pin an archive timestamp per release. Makes builds
   fully hermetic, and makes picking up a security fix an explicit, reviewed
   change of the snapshot pin rather than a side effect of rebuilding.
2. **A committed package lock** — every package and version recorded, installed
   with `apt-get install pkg=version`. Simpler, but has to be regenerated on
   every security update and can wedge when a version disappears from the mirror.

Both are architectural changes with real operational consequences for how
security updates reach the images, so neither is being made as a side effect of
this work.

**#101 stays open with two measured blockers:**

1. **Debian repository snapshot determinism** — architectural, above.
2. **PHP compiled-extension determinism** — `redis.so` and `redis.reg`,
   diagnosed above, one fix applied and awaiting verification.

### What is in place meanwhile

`scripts/record-package-index.sh` captures, per build, the exact resolved package
set and the archive `InRelease` timestamps. That does not make a build hermetic.
It makes a difference between two builds **attributable** — a digest mismatch
resolves to "these three packages moved", instead of standing as an unexplained
mismatch that erodes confidence in the whole claim.
