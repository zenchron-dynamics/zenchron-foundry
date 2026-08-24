# PHP 8.5 experimental cohort — `linux/amd64` child evidence

**Four children built, smoked, SBOM'd and scanned. Source revision
`e84c2155cfcde8e179a007b13653bc8e124535a4`, 2026-08-24.**

This is **not** an acceptance run, a release candidate, or an authorization of
anything. It is the durable record that the four PHP 8.5 image definitions are
reachable, buildable and measurable — and that what they contain has been
measured on the **children**, never on their upstream bases.

| | |
|---|---|
| cohort | `php-8.5` (`policies/experimental-cohorts.yaml`) |
| plan | `scripts/experimental/experimental-plan.sh` |
| source revision | `e84c2155cfcde8e179a007b13653bc8e124535a4` |
| platform | `linux/amd64` only — **no arm64 child exists** |
| execution | `emulated` on an `arm64` host (disclosed per child) |
| scanner | `aquasec/trivy@sha256:016eae51…` (digest-pinned) |
| frozen database | `trivy-db:v2+updated:2026-08-24T13:01:06.952742724Z` — ONE identity, all four children |
| evidence class | `foundry-child` (reused from `policies/evidence-classes.yaml`) |
| children | 4 planned, 4 completed, 0 failed |
| smoke | PASS 4/4 (13 + 11 + 11 + 8 checks) |
| extension contract | 0 missing across all four |
| checksums | `SHA256SUMS`, verified by `tests/experimental/test_experimental_plan.sh` |

## The four children

| child | OCI-layout digest | upstream base digest | pkgs | CRITICAL | HIGH |
|---|---|---|---|---|---|
| `php-cli/8.5/linux/amd64` | `sha256:ec010fe093478791…` | `sha256:b3154b925899c55c…` | 127 | 6 | 41 |
| `php-fpm/8.5/linux/amd64` | `sha256:a707386339945364…` | `sha256:7b1deadd1d73c72d…` | 127 | 6 | 41 |
| `php-worker/8.5/linux/amd64` | `sha256:a34a2462c363e83b…` | `sha256:b3154b925899c55c…` | 128 | 6 | 41 |
| `php-frankenphp/8.5/linux/amd64` | `sha256:b37bdc2f5e0c0afe…` | `sha256:8896df27f5fe22f4…` | 181 | 17 | 64 |

Full digests are in the per-child `*.evidence.json`. Each is an **OCI-layout
manifest digest**, read out of a real OCI layout — not `docker image inspect
.Id` (that is the config digest) and not a local tag (a tag is not an identity).

## THE CHILD WAS SCANNED, NEVER THE BASE

Every record carries `package_inventory_source.kind = image-child` and
`findings_by_package["linux-libc-dev"] = 0`.

That zero is the whole point. The PHP 8.4 **base** reports 241 CRITICAL/HIGH of
which 170 are `linux-libc-dev`; the 8.4 **child** reports 47 and none, because
the Dockerfile runs `apt-get purge -y --auto-remove`. The 8.5 cli/fpm/worker
children report **47** as well, with zero `linux-libc-dev` — the same purge, the
same shape. A base scan describes a different artifact and
`scripts/release/assert-evidence-class.sh` refuses to let one stand in for a
child.

## Runtime identity, per child

| | cli | fpm | worker | frankenphp |
|---|---|---|---|---|
| PHP | 8.5.9 | 8.5.9 | 8.5.9 | 8.5.9 |
| Zend | 4.5.9 | 4.5.9 | 4.5.9 | 4.5.9 |
| extension API | 20250925 | 20250925 | 20250925 | 20250925 |
| serving identity | `PHP 8.5.9 (cli)` | `PHP 8.5.9 (fpm-fcgi)` | `PHP 8.5.9 (cli)` | `FrankenPHP v1.12.7 / Caddy v2.11.4` |
| extensions loaded | 46 | 45 | 46 | 46 |
| required missing | 0 | 0 | 0 | 0 |
| redis | 6.3.0 | 6.3.0 | 6.3.0 | 6.3.0 |
| OPcache provenance | base-builtin | base-builtin | base-builtin | helper-installed |
| SBOM packages | 144 | 144 | 145 | 382 |
| build seconds | 54 | 54 | 54 | 459 |

`fpm` carries 45 extensions rather than 46 because **pcntl is intentionally
absent from PHP-FPM**, which its smoke test asserts positively.

### OPcache: provenance AND a runtime proof

On the cli/fpm/worker cohort OPcache is **not compiled**. The official 8.5 base
ships Zend OPcache linked into the binary, and `docker-php-ext-install opcache`
therefore produces no shared module and dies at `cp: cannot stat 'modules/*'`.
FrankenPHP is different: `install-php-extensions` handles it, so its provenance
is `helper-installed`.

Presence in `php -m` would not have distinguished a working OPcache from an
inert one, so each child was made to **prove it**: a real file is written and
compiled inside the child, under `--read-only` with a tmpfs `/tmp`.

```text
opcache_enabled     true    (all four)
compile_succeeded   true    (all four)
num_cached_scripts  2       (all four)
```

The shipped configuration is recorded separately and unmodified —
`opcache.enable=1`, `opcache.enable_cli=0` — so the forced-on proof settings
cannot be mistaken for what the image ships.

### Build-tool purge, proved by execution

`gcc`, `make`, `phpize` and `apk` are absent from all four children, tested by
attempting to resolve each one inside the image rather than by reading the
Dockerfile.

## Emulation disclosure

All four children are `linux/amd64` and were built and probed **under emulation
on an `arm64` host**. Every record carries `execution_mode: emulated` and
`host_architecture: arm64`.

This is build, extension, SBOM and scan evidence. It is **not** native-runtime
evidence, and it says nothing whatsoever about an arm64 child — no arm64 8.5
child has ever been built, so there is no arm64 digest, no arm64 installed
inventory and no arm64 finding set. The plan refuses `linux/arm64` for this
cohort for exactly that reason.

## Governance status: UNGOVERNED, by construction

35 distinct advisories across the four children. **None of them is governed.**

Every PHP selector in `policies/vulnerability-exceptions.yaml` is bound to the
immutable `php-8.3-8.4` cohort (`in_scope()`,
`scripts/reconcile-vulnerabilities.sh`), so a new PHP version cannot inherit a
decision made from evidence that never contained it. 33 of the 35 have an
**analogous** 8.3/8.4 record at the identical package/version tuple; 2 have no
record anywhere.

Nothing in this record extends, widens or renews any exception. The decisions
this evidence demands are set out in
[../../decisions/php-8.5-experimental-cohort-decision-packet.md](../../decisions/php-8.5-experimental-cohort-decision-packet.md)
and **none of them has been made by writing that file**.

## What this evidence does not authorize

Not acceptance. Not a release manifest. Not promotion. Not sealing. Not signing.
Not publication. Not entry into `MATRIX_IMAGES`. The plan refuses each of those
by name, and `scripts/experimental/assert-experimental-isolation.sh` refuses the
same from the production side.

`assert-evidence-class.sh consumer production-authorization` refuses every record
here: production authorization requires `staged-candidate`, and nothing in this
cohort has been staged.

## Files

```text
frozen-scan-basis.json          the ONE database identity, scanner and execution mode
*.evidence.json                 the classed foundry-child record (schema-validated)
*.child-facts.json              runtime identity, OPcache/redis proofs, purge proof, digests
*.findings.json                 the reviewable finding tuples (advisory, package, version, fix)
*.packages.txt                  the CHILD's dpkg inventory (the 241-vs-47 field)
*.smoke.txt                     the per-family smoke transcript
SHA256SUMS                      over exactly the files in this directory
```

The full SPDX documents (2.7 MB each) and raw scanner reports (~600 KB each) are
**bound by sha256 inside each `child-facts.json` rather than committed**. They
are regenerable from the recorded OCI digest; a repository is not a blob store.

## Reproducing it

```sh
bash scripts/experimental/experimental-plan.sh plan php-8.5 linux/amd64
bash scripts/experimental/experimental-run.sh php-8.5 linux/amd64 --out /tmp/php85
```

`BUILD_DATE` is derived from the commit's `SOURCE_DATE_EPOCH`, matching
`.github/workflows/build-images.yml` (#101), so a re-run of the same revision
does not rebuild from scratch for wall-clock reasons.
