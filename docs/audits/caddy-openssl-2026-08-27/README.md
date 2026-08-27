# CVE-2026-14456 on Alpine `libssl3`/`libcrypto3` in the `caddy:prod` children

Measured **2026-08-27**. Platforms measured: `linux/amd64` **and** `linux/arm64`
(both, natively resolved from the registry — no index digest is compared against
a platform digest anywhere in this document).

Scope: the two production children `caddy:prod` `linux/amd64` and `caddy:prod`
`linux/arm64`, and only those. This document changes no Dockerfile, no policy
file, no exception ledger, and dispatches nothing.

Raw transcripts: [`evidence/`](evidence/).

## 0. The question this document answers

A rescan of the retained cohort on 2026-08-27 found **CVE-2026-14456** on
`libssl3` and `libcrypto3 @ 3.5.7-r0` (Alpine) in both `caddy:prod` children,
scanner `FixedVersion: 3.5.8-r0`. The finding is **ungoverned**: the existing
CVE-2026-14456 ledger records are scoped to `php-8.3-8.4` and `nginx` on Debian
`openssl`/`libssl3 @ 3.0.20-1~deb12u2`. The Alpine case is a different package
build under a different advisory and was deliberately excluded from those
records.

The experiment asked, in order:

1. Does **any** current official Caddy image digest already carry
   `libssl3`/`libcrypto3 >= 3.5.8-r0`?
2. If yes — re-pin to that immutable official digest.
3. If no — can the Foundry-owned Caddy Dockerfile consume the **official Alpine
   patched packages** via a supported package upgrade, without compiling or
   replacing Caddy or OpenSSL?

## 1. Determination

**No remediation that is both safe and inside the permitted Caddy-only
change envelope is available today.** Consequently **no production child was
rebuilt and no production image changed.** The finding must be governed by a
temporary, tightly scoped exception owned by the vulnerability-exception lane —
see §6 for the exact scoping facts.

| Step | Result |
|---|---|
| 1 — newer official digest | **NO.** Every official Caddy *Linux* runtime tag resolves to the same 2026-06-24 content, which ships `3.5.7-r0` on both platforms. §2 |
| 2 — re-pin | **Not applicable.** The `caddy:2-alpine` index digest has not moved; it is byte-identical to the current pin. A re-pin would be a no-op and must not be presented as remediation. §2.2 |
| 3 — official Alpine package upgrade | **Technically works, but is not adoptable here.** `apk upgrade libssl3 libcrypto3` does reach `3.5.8-r0` from the official Alpine v3.23 repository (§4), but it is forbidden by the accepted **ADR-0001** Caddy exception and blocked by the required CI gate `scripts/assert-no-wolfi.sh`. Adopting it is an ADR-level governance change, not a Caddy-only minimum change, and both artefacts are outside this lane's ownership. §5 |

## 2. Registry evidence — official Caddy images

All resolutions performed with `docker buildx imagetools inspect` against
`registry-1.docker.io` at the UTC timestamps shown.

### 2.1 Index digests (2026-08-27T10:03:01Z)

| Tag | Index digest | Hub `last_updated` |
|---|---|---|
| `caddy:2-alpine` | `sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648` | 2026-06-24T05:52:17Z |
| `caddy:alpine` | `sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648` | 2026-06-24T05:52:47Z |
| `caddy:2.11-alpine` | `sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648` | 2026-06-24T05:52:28Z |
| `caddy:2.11.4-alpine` | `sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648` | 2026-06-24T05:52:39Z |
| `caddy:latest` | `sha256:df7f1c2fb114453b951de51a98efc010db1655a92c2e86be6706714e2417a78d` | 2026-08-12T20:53:53Z |
| `caddy:2` / `2.11` / `2.11.4` | `sha256:df7f1c2fb114453b951de51a98efc010db1655a92c2e86be6706714e2417a78d` | 2026-08-12T20:52:20Z |

`caddy:latest` carries a *newer index digest* purely because its index also
lists the Windows manifests, which were rebuilt on 2026-08-12. **Its Linux
platform manifests are the same objects as `2-alpine`'s** — see §2.2. Reading
the `latest` index timestamp as "a newer Linux image exists" is exactly the
index-versus-platform confusion this document refuses to make.

### 2.2 Platform manifests (2026-08-27T10:02:43Z)

`caddy:2-alpine`, `caddy:alpine` and `caddy:latest` publish **identical**
`linux/amd64` and `linux/arm64/v8` manifest digests:

| Platform | Immutable platform digest |
|---|---|
| `linux/amd64` | `sha256:98eb57d882ccd5213d1688764db10c1ca2c58a1ca3a6717a3411ad798f7a423a` |
| `linux/arm64/v8` | `sha256:1172d4213087d3fc30bafc7ff2c2896180eb0c41ff7f75f315568fb36cabdcba` |

The `caddy:2-alpine` **index** digest resolved live equals the digest pinned in
`images/caddy/Dockerfile` (`sha256:5f5c8640…`). The tag has not moved. There is
no newer official Caddy Linux runtime image to move to.

### 2.3 Package inventory of the official base, per platform (2026-08-27T10:04:17Z)

Pulled by platform digest, then `apk info -v` inside each:

| Platform | `/etc/alpine-release` | `libssl3` | `libcrypto3` | `caddy version` |
|---|---|---|---|---|
| `linux/amd64` (`sha256:98eb57d8…`) | `3.23.5` | `3.5.7-r0` | `3.5.7-r0` | `v2.11.4` |
| `linux/arm64` (`sha256:1172d421…`) | `3.23.5` | `3.5.7-r0` | `3.5.7-r0` | `v2.11.4` |

**Step 1 answer: NO.** No current official Caddy image digest carries
`>= 3.5.8-r0` on either platform.

## 3. The patched package does exist upstream

Fetched from the official Alpine CDN at 2026-08-27T10:04:28Z:

```console
$ curl -sfSL https://dl-cdn.alpinelinux.org/alpine/v3.23/main/x86_64/APKINDEX.tar.gz
P:libcrypto3  V:3.5.8-r0
P:libssl3     V:3.5.8-r0
P:openssl     V:3.5.8-r0
$ curl -sfSL https://dl-cdn.alpinelinux.org/alpine/v3.23/main/aarch64/APKINDEX.tar.gz
P:libcrypto3  V:3.5.8-r0
P:libssl3     V:3.5.8-r0
P:openssl     V:3.5.8-r0
```

So the gap is **not** an absent upstream fix. It is that the official Caddy
image has not been rebuilt since 2026-06-24 (the Alpine base line it pins,
`3.23.5`, has since published the fixed packages). The `caddy:*-builder-alpine`
tags *were* rebuilt on 2026-08-20, but a builder image is a Go toolchain image,
not a runtime, and using it would mean compiling Caddy — forbidden.

## 4. What the vulnerable library is actually used for in this image

Measured in the pinned base at 2026-08-27T10:06:00Z. This is exploitability
context for the exception record, **not** an argument that the finding is
harmless.

```console
$ ldd /usr/bin/caddy
/lib/ld-musl-aarch64.so.1: /usr/bin/caddy: Not a valid dynamic program
```

`/usr/bin/caddy` is a **statically linked Go binary**. It does not link
`libssl.so.3` or `libcrypto.so.3` and does not use OpenSSL for anything —
Caddy's TLS stack is Go's `crypto/tls`.

The only files in the image that link the vulnerable libraries are:

| Binary | On the certified serving path? |
|---|---|
| `/sbin/apk` | No — never executed at runtime (ADR-0001: this image runs no `apk` commands) |
| `/usr/bin/c_rehash` | No |
| `/usr/bin/curl` | No — the `HEALTHCHECK` uses `wget` over plain HTTP to `127.0.0.1:8081` |
| `/usr/bin/ssl_client` | No — busybox TLS helper, unreachable in the certified topology |

The certified topology already terminates **no TLS**
(`contracts/images/caddy-prod.yaml`: `tls_termination: forbidden`), so no
attacker-controlled bytes reach any of the four.

## 5. Why the working package upgrade is still not adoptable

The upgrade itself was proven to work, **out of tree**, against the pinned base
(2026-08-27T10:05:12Z, `linux/arm64`):

```console
#7 [2/2] RUN apk upgrade --no-cache libssl3 libcrypto3
(1/2) Upgrading libcrypto3 (3.5.7-r0 -> 3.5.8-r0)
(2/2) Upgrading libssl3 (3.5.7-r0 -> 3.5.8-r0)
OK: 14.2 MiB in 32 packages
libcrypto3-3.5.8-r0
libssl3-3.5.8-r0
```

No compiler ran; Caddy was neither rebuilt nor replaced; the packages came from
the official Alpine v3.23 repository the base already pins. On the technical
question alone, step 3 succeeds.

It is nevertheless **not** a change this lane may make, for three independent
reasons:

1. **ADR-0001 forbids it by name.** The accepted Caddy base exception is
   *conditional* on the image running "**no `apk` commands**" — that condition
   is what buys Caddy its place as the single intentional non-Debian base.
   `docs/base-image-strategy.md` §"The Caddy exception" restates it. Removing
   the condition rewrites the decision, and `docs/decisions/` is not this
   lane's to edit.
2. **A required CI gate blocks it.** `scripts/assert-no-wolfi.sh` — run by the
   `static-gates` job in `.github/workflows/ci.yml` and by
   `scripts/macro-validate.sh` — fails on the regex `apk[[:space:]]+upgrade`
   anywhere under `images/`. Landing the change requires editing that guard.
   `scripts/assert-no-wolfi.sh` is outside this lane's file ownership, and
   weakening a repo-wide supply-chain guard is by definition not a
   "minimum Caddy-only production change".
3. **It converts a build with no package resolution into one with live,
   rolling package resolution.** Today the Caddy child resolves *zero* packages
   at build time; its content is fully determined by one pinned digest. An
   `apk upgrade` makes every future Caddy build depend on whatever
   `dl-cdn.alpinelinux.org/alpine/v3.23` serves that day.
   `policies/reproducibility.yaml` already records `package-resolution` as
   `not-guaranteed` for exactly this reason on the Debian families; extending
   that residual to the one image currently free of it is a deliberate
   reduction in guarantee, which belongs in an ADR, not in a CVE patch PR.

### 5.1 The path that would make it adoptable

Recorded here so the decision is scoped, not so this lane takes it:

- amend ADR-0001's Caddy exception to permit a **security-only, explicitly
  enumerated** `apk upgrade` of named packages (not `apk upgrade` wholesale,
  not `apk add`);
- narrow `scripts/assert-no-wolfi.sh` from a blanket ban to one that still bans
  `apk add` and bare `apk upgrade` but permits an enumerated security upgrade
  in an allowlisted Dockerfile;
- accept and record the reproducibility consequence in
  `policies/reproducibility.yaml`;
- only then rebuild the two Caddy children.

Until upstream Caddy rebuilds, the cheaper outcome is usually the right one:
the finding is governed by a **short-dated** exception and clears itself the
moment the official image is rebuilt.

## 6. Scoping facts for the temporary exception record

This lane does **not** edit `policies/vulnerability-exceptions.yaml`. The
following are the exact facts the owning lane needs:

| Field | Value |
|---|---|
| CVE | `CVE-2026-14456` |
| Packages | `libssl3`, `libcrypto3` |
| Observed version | `3.5.7-r0` (Alpine `3.23.5`) |
| Scanner `FixedVersion` | `3.5.8-r0` |
| Ecosystem | `pkg:apk/alpine` — **distinct** from the Debian `openssl`/`libssl3 @ 3.0.20-1~deb12u2` records already in the ledger for `php-8.3-8.4` and `nginx` |
| Children | `caddy:prod` — exactly two |
| Architectures | `linux/amd64`, `linux/arm64` |
| Base identity | `caddy:2-alpine@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648`; platform manifests `sha256:98eb57d8…` (amd64), `sha256:1172d421…` (arm64) |
| Remediation controller | **Upstream (Caddy image maintainers).** The Alpine fix exists; Foundry cannot consume it without amending ADR-0001. |
| Clearing condition | Official `caddy:2-alpine` publishes a rebuild carrying `libssl3`/`libcrypto3 >= 3.5.8-r0`, on both platforms. |
| Suggested expiry | Short-dated. The upstream image is rebuilt on Alpine's cadence; the last two Alpine rebuilds were 2026-05-14 and 2026-06-24. |

## 7. What did not change

- No production image was rebuilt; **no production child digest changed**.
- `images/caddy/Dockerfile` is untouched — the base pin is still
  `sha256:5f5c8640…`, which remains the current official digest.
- `contracts/images/caddy-prod.yaml` is untouched: nothing in the contract
  changed, so restating it would be noise.
- `scripts/smoke/smoke-caddy.sh` is untouched. It was reviewed against the
  "vacuous gate" hazard and is **not** vacuous: it boots the container under the
  full production profile (`--read-only`, `--cap-drop ALL`,
  `--security-opt no-new-privileges`) and polls `/healthz` over the network for
  a `200`/`ok`, so a Caddy that does not actually serve fails it. It also
  proves the no-TLS topology from the *adapted* config rather than from the
  Caddyfile text.
- No acceptance was dispatched, nothing was signed, published, promoted or
  tagged.

## 8. Acceptance scope that would be owed

**None is owed by this change**, because no production child was rebuilt and
the existing acceptance evidence for the two Caddy children remains bound to
unchanged bytes.

If the ADR-0001 amendment in §5.1 is later taken and the two children are
rebuilt, the acceptance owed at that point is **exactly two children** —
`caddy:prod` `linux/amd64` and `caddy:prod` `linux/arm64` — and nothing else.
No other production image is affected by this finding, so a QEMU-wide or
cohort-wide acceptance would be over-scoped.
