# `libaom3` in the FrankenPHP children — ownership and remediation

Measured 2026-08-26. Platform measured: `linux/amd64`. Scope: the six ledger
records naming `libaom3` against `php-frankenphp-8.3-8.4` (entries 5 and 30-34
of `docs/audits/expiry-refresh-2026-08-25/refresh-classification.json`).

This document **verifies and partly refutes** the disposition recorded in
`docs/audits/expiry-refresh-2026-08-25/README.md` sections 4.1 and G03. It does
not change any Dockerfile, does not change any policy file, and dispatches
nothing.

Raw transcripts: [`evidence/`](evidence/).

## 0. What was already true, and what was assumed

The expiry refresh established, correctly, that `libaom3` is **absent from the
pinned FrankenPHP base** and **present in the children**. From that it drew a
second conclusion that this review does not sustain:

> "a Foundry-side removal path exists today and is not blocked on upstream"
> — `docs/audits/expiry-refresh-2026-08-25/README.md`, row G03

"Introduced during a Foundry step" and "safely removable by a Dockerfile edit"
are different claims. The first is true. The second is false as stated: every
removal path measured here either **destroys the whole `gd` extension** or
**deletes a shipped, consumer-visible API**. Neither is a Dockerfile bug fix.

## 1. The four ownership questions, answered separately

| Question | Answer | Owner class (`policies/component-ownership.yaml`) |
|---|---|---|
| **1. Inclusion owner** — what causes `libaom3` to enter the child? | Foundry's selection of the `gd` extension, executed by the upstream-owned helper `install-php-extensions` bundled in the base. Foundry selects `gd`; the helper decides that `gd` on Debian 12 means AVIF, and apt-installs `libaom3`/`libavif15`/`libdav1d6` unconditionally. Foundry does not select `libaom3` and, on this base, cannot decline it (§4, C3a). | `foundry-selected-extension` (selection) driving `distro-packages` (result) |
| **2. Package owner** — who ships and patches the binary? | Debian. Source package `aom`, binary `libaom3:amd64 3.6.0-1+deb12u2`, maintainer role: Debian Multimedia Maintainers. Installed from `deb.debian.org bookworm/main`. Foundry does not build it and may not compile it. | `upstream-base` |
| **3. Remediation controller** | **Shared, and not Foundry-only.** No configuration exists that removes the vulnerable package from a Debian 12 child while preserving the capability set the children ship today. Foundry controls two options, both of which are governance decisions, not edits: delete AVIF from `gd` (consumer-visible API removal, §4 C3b) or move the family to the Debian 13 base line (§4 C2b). | remediation is `purge-package` / `pin-digest-bump` under `distro-packages`, both permitted but neither cost-free |
| **4. Functional consequence of removal** | Removing the **package** removes `libavif15` with it and makes `gd.so` unloadable — PNG, JPEG, WebP, GIF, FreeType all disappear, not just AVIF. Removing **AVIF at configure time** keeps `gd` fully working minus `imageavif()` / `imagecreatefromavif()`. | — |

## 2. Per-child proofs

Four production children are in scope: `php-frankenphp` 8.3 and 8.4 on
`linux/amd64` and `linux/arm64`. Everything below was measured on `linux/amd64`
in this review. The `linux/arm64` column is **not** re-measured here; it rests on
the reconciliation records of 2026-08-25, which record `libaom3 3.6.0-1+deb12u2`
on both arm64 children
(`docs/audits/expiry-refresh-2026-08-25/reconciliations/php-frankenphp_8.{3,4}_linux_arm64.reconcile.json`).

### 2.1 Absent from the pinned upstream base

```console
$ docker run --rm --platform linux/amd64 --entrypoint sh \
    dunglas/frankenphp@sha256:cef99f10…  -c 'dpkg-query -W "libaom*"'      # 8.4 pinned
dpkg-query: no packages found matching libaom*        (exit 1)
$ docker run --rm --platform linux/amd64 --entrypoint sh \
    dunglas/frankenphp@sha256:dd3ab394…  -c 'dpkg-query -W "libaom*"'      # 8.3 pinned, amd64 manifest
dpkg-query: no packages found matching libaom*        (exit 1)
```

`sha256:dd3ab394…` is the `linux/amd64` child manifest of the index
`sha256:ae143d38…` pinned by `images/php-frankenphp/8.3/Dockerfile`. Neither base
carries `libavif*`, `libwebp*` or `libheif*` either, and `gd` is not loaded in
either base (`extension_loaded("gd") === false`). Full transcript:
[`evidence/base-probe.txt`](evidence/base-probe.txt).

### 2.2 Present in the final child, with exact identity

```console
$ dpkg-query -W "libaom*"
libaom3:amd64   3.6.0-1+deb12u2
$ dpkg -s libaom3
Package: libaom3   Source: aom   Version: 3.6.0-1+deb12u2   Architecture: amd64
Depends: libc6 (>= 2.34)
```

Identical on both 8.3 and 8.4 children. Alongside it:
`libavif15 0.11.1-1+deb12u1`, `libdav1d6 1.0.0-2+deb12u1`, `librav1e0 0.5.1-6`,
`libwebp7 1.2.4-0.2+deb12u1`.
[`evidence/child-inventory.txt`](evidence/child-inventory.txt).

### 2.3 The dependency edge from `install-php-extensions … gd`

The helper is `install-php-extensions` (mlocati/docker-php-extension-installer),
**shipped inside the upstream base**, not authored by Foundry. Its `gd@debian`
branch, read out of the pinned 8.4 base:

```sh
gd@debian)
    …
    if test $PHP_MAJMIN_VERSION -ge 801; then
        if test $DISTRO_VERSION_NUMBER -ge 12; then
            buildRequiredPackageLists_persistent="… ^libavif[0-9]+$ ^libaom[0-9]+$ ^libdav1d[0-9]+$"
            buildRequiredPackageLists_volatile="…  libavif-dev libaom-dev libdav1d-dev"
        elif ! isLibaomInstalled || … ; then
            case "${IPE_GD_WITHOUTAVIF:-}" in …
```

and the configure line it then runs:

```sh
docker-php-ext-configure gd --enable-gd --with-webp --with-jpeg --with-xpm --with-freetype --with-avif
```

Two facts follow, and the second is the one that matters:

1. On Debian 12 the helper **apt-installs** `libaom3`; it does not compile it.
2. `IPE_GD_WITHOUTAVIF` — the installer's only AVIF opt-out — sits in the
   `elif` arm and is therefore **unreachable on Debian ≥ 12**. There is no
   supported way to ask this helper for a non-AVIF `gd` on this base.

Confirmed by apt's own view inside the child:

```console
$ apt-cache rdepends --installed libaom3
libaom3
Reverse Depends:
  libavif15
$ dpkg -s libavif15 | grep ^Depends
Depends: libaom3 (>= 3.2.0), libc6 …, libdav1d6 …, libgav1-1 …, librav1e0 …, libsvtav1enc1 …, libyuv0 …
$ apt-get -s purge libaom3
The following packages will be REMOVED:  libaom3* libavif15*
```

[`evidence/installer-gd-branch.txt`](evidence/installer-gd-branch.txt),
[`evidence/installer-gd-configure.txt`](evidence/installer-gd-configure.txt),
[`evidence/apt-policy-rdepends.txt`](evidence/apt-policy-rdepends.txt).

### 2.4 GD is compiled with AVIF, and the linkage is real

```console
$ php -r 'print_r(gd_info());'
… [WebP Support] => 1   [AVIF Support] => 1   [JPEG Support] => 1   [PNG Support] => 1 …
$ ldd …/gd.so | grep -E 'avif|aom'
libavif.so.15 => /lib/x86_64-linux-gnu/libavif.so.15
libaom.so.3   => /lib/x86_64-linux-gnu/libaom.so.3
```

`gd.so` carries a **direct** `DT_NEEDED` on `libavif.so.15`, and
`libavif.so.15` a direct `DT_NEEDED` on `libaom.so.3`. `imagecreatefromavif()`,
`imageavif()` and `imagewebp()` all exist. Same on 8.3 and 8.4.
[`evidence/child-gd-linkage.txt`](evidence/child-gd-linkage.txt).

### 2.5 Removal breaks extension loading — measured, not argued

Purging `libaom3` from the built child (which takes `libavif15` with it):

```text
PHP Warning:  PHP Startup: Unable to load dynamic library 'gd'
  (… gd.so (libavif.so.15: cannot open shared object file: No such file or directory))
php -r 'var_dump(extension_loaded("gd"));'      => bool(false)
php -r 'imagecreatefromtruecolor…'              => Fatal error: Call to undefined function imagecreatetruecolor()
php -m | wc -l                                   47 -> 46
```

Identical on 8.3 and 8.4. **A PNG-only consumer that never touches AVIF loses
all image processing.** [`evidence/removal-test.txt`](evidence/removal-test.txt).

### 2.6 A patched Debian package does not exist

Debian security tracker, source package `aom`, retrieved **2026-08-26**:

| CVE | bookworm status |
|---|---|
| `CVE-2026-56208` | vulnerable |
| `CVE-2026-56209` | vulnerable |
| `CVE-2026-56210` | vulnerable |
| `CVE-2026-56211` | vulnerable |
| `CVE-2023-39616` | vulnerable (no DSA, ignored) |
| `CVE-2023-6879` | vulnerable (no DSA) |

Versions on that page: bookworm `3.6.0-1+deb12u2`, bookworm-security
`3.6.0-1+deb12u1`, **trixie `3.12.1-1`**, sid `3.14.1-1`. All six are recorded
**fixed** in trixie.

apt inside the child agrees that nothing newer is offered on this base line:

```console
$ apt-cache policy libaom3
  Installed: 3.6.0-1+deb12u2
  Candidate: 3.6.0-1+deb12u2
 *** 3.6.0-1+deb12u2 500  http://deb.debian.org/debian bookworm/main amd64 Packages
     3.6.0-1+deb12u1 500  http://deb.debian.org/debian-security bookworm-security/main amd64 Packages
```

The security suite carries an **older** revision than bookworm/main; the
installed version is already the newest available. The scanner concurs — all six
findings report an empty fixed version on the child
([`evidence/child-scans.txt`](evidence/child-scans.txt)).

### 2.7 A newer official base

The pinned tag lines have moved again since the 2026-08-25 refresh
(`1-php8.3-bookworm` head `sha256:55dc84d1…`, `1-php8.4-bookworm` head
`sha256:4484f5fc…`), but they are still Debian 12, so the candidate package apt
resolves is unchanged and no head on that line can carry a fixed `aom`.

An official **Debian 13 line does exist**: `dunglas/frankenphp:1-php8.4-trixie`,
head `sha256:9a5a469b…` on 2026-08-26. It is the only measured configuration
that carries a fixed `libaom` (§4, C2b).

## 3. Classification

Using `docs/ownership-boundary.md` and `policies/component-ownership.yaml`
vocabulary. The model proposed for this review is **confirmed on the first two
axes and refuted on the third as commonly read**:

```text
inclusion selection        foundry-selected-extension   CONFIRMED
                           Foundry chooses `gd`. The AVIF codec set is chosen by
                           the upstream helper, not by Foundry, and cannot be
                           declined on Debian 12.
binary/package ownership   upstream-base                CONFIRMED
                           libaom3 is a Debian bookworm binary package,
                           component `distro-packages`, foundry_may_compile:false
remediation                NOT Foundry-controlled today
                           No supported dependency or configuration change, and
                           no patched official package, removes the risk from a
                           Debian 12 child without removing shipped capability.
```

The repository's own classifier returns exactly this, and its answer is right:

```console
$ scripts/classify-remediation-owner.sh --image php-frankenphp/8.4 \
    --package libaom3 --installed 3.6.0-1+deb12u2 --newer-base-available no
owner=upstream-base
rebuild_can_remediate=no
ticket_warranted=no
remediation=no fix is available upstream; govern as accepted risk or not-affected
root_cause_key=upstream-base:libaom3:3.6.0-1+deb12u2
```

The expiry refresh said of this output: *"the inventory evidence overrides
that."* It does not. The classifier is answering question 2 (who owns and patches
the binary) and it answers it correctly. The inventory evidence answers question
1 (what put it in the image). Both are true at once, which is precisely why they
had to be separated.

## 4. Remediation candidates tested

`linux/amd64` only. Nothing upstream-owned was compiled: `gd` is a PHP extension
built with the official `docker-php-ext-*` toolchain, which
`policies/component-ownership.yaml` classifies as approved
(`foundry-selected-extension`, `foundry_may_compile: true`).

| id | Candidate | Outcome |
|---|---|---|
| C1 | Current official **patched Debian package** | **DOES NOT EXIST.** All six CVEs vulnerable in bookworm on 2026-08-26; installed version is already the candidate; security suite offers an older revision. |
| C2a | Current official **base digest** on the pinned line | **CANNOT HELP.** Heads have moved but remain Debian 12; the base never ships `libaom` at all, and apt on a Debian 12 child resolves the same unpatched candidate. |
| C2b | Newer official **base line** — `1-php8.4-trixie` | **WORKS, AND PRESERVES CAPABILITY.** Only candidate that does. Costs a distro major-version migration. |
| C3a | Supported installer knob `IPE_GD_WITHOUTAVIF=1` | **REFUTED.** No effect on Debian 12. |
| C3b | Official toolchain, `gd` configured without `--with-avif` | **REMOVES THE PACKAGE BY REMOVING A SHIPPED API.** Not remediation on its own terms. |
| C4 | Package removal (`apt-get purge libaom3`) | **REFUTED — destroys `gd` entirely.** |

### C3a — `IPE_GD_WITHOUTAVIF=1` (build input: `ENV IPE_GD_WITHOUTAVIF=1` before `install-php-extensions gd`)

```text
libaom3:amd64   3.6.0-1+deb12u2
libavif15:amd64 0.11.1-1+deb12u1
[AVIF Support] => 1
libavif.so.15 => …   libaom.so.3 => …
```

Image `sha256:cbb9d939…`. The knob is accepted without error and changes
nothing, because the Debian ≥ 12 arm of the helper never reads it. **The only
configuration switch the supported installer offers for this is inert on the
base these images are built from.**
[`evidence/candidate-c3a.Dockerfile`](evidence/candidate-c3a.Dockerfile),
[`evidence/candidate-c3a-result.txt`](evidence/candidate-c3a-result.txt).

### C3b — `docker-php-ext-configure gd --enable-gd --with-webp --with-jpeg --with-xpm --with-freetype` (no `--with-avif`)

```text
dpkg-query: no packages found matching libaom*
dpkg-query: no packages found matching libavif*
[JPEG Support] => 1  [PNG Support] => 1  [WebP Support] => 1  [FreeType Support] => 1
[AVIF Support] =>            <- empty
gd.so links: libpng16, libwebp7, libjpeg62, libfreetype6   (no libavif, no libaom)
extension_loaded("gd") => true   function_exists("imagewebp") => true
function_exists("imageavif")     => false
```

Image `sha256:51c5d840…`; SBOM 390 components, zero `aom`/`avif`; scanner reports
zero `aom`/`avif` findings.

**State this plainly: C3b is a package removal that removes a GD capability.**
`imageavif()` and `imagecreatefromavif()` are present in every published
`php-frankenphp` image today and are documented to consumers in
`docs/consuming-images.md` and `docs/vulnerability-exceptions.md`. Deleting them
is a consumer-visible API removal, which this repository has already classified
as needing a deprecation path
(`docs/security/triage-2026-07-28-ungoverned-findings.md`). It is a viable
*decision*; it is not a bug fix, and it must not be merged as one.

It does **not** violate a declared runtime contract, because there is none to
violate: `contracts/images/php-frankenphp-8.{3,4}.yaml` declare no
`extensions_contract` at all — only the `php-cli` and `php-fpm` families do — and
`docs/php-extension-matrix.md` lists `gd`'s Debian runtime libraries as
`libpng16-16, libjpeg62-turbo, libfreetype6`, which already understates what the
FrankenPHP children actually link. **The absence of a declared contract is not
evidence that the capability is unused.** It is a gap in the contract.

[`evidence/candidate-c3b.Dockerfile`](evidence/candidate-c3b.Dockerfile),
[`evidence/candidate-c3b-result.txt`](evidence/candidate-c3b-result.txt).

### C2b — official Debian 13 base line

```text
os=Debian GNU/Linux 13 (trixie)
libaom3:amd64   3.12.1-1+deb13u1        <- all six CVEs fixed per the tracker
libavif16:amd64 1.2.1-1.2
[AVIF Support] => 1
gd.so links libavif.so.16 -> libaom.so.3
```

Image `sha256:b769fde0…`; SBOM 379 components; scanner reports zero `aom`/`avif`
findings. This is the **only** candidate that clears all six records while
keeping every capability the children ship today.

It is `pin-digest-bump` under `distro-packages` — a permitted remediation — but
it is a **distro major-version migration** of an entire image family, already
tracked in this repository as the Debian 13 migration. It replaces every package
in the image, not one. It is out of scope for a finding-level fix and belongs to
that migration's own planning and acceptance.

Note the comparison honestly: the C2b and C3b probe images are built directly on
their bases and **do not** run the production Dockerfile's build-tooling purge,
so their raw scanner totals (134 and 266 OS CRITICAL/HIGH) are not comparable to
the hardened child's 79. Only the `aom`/`avif` rows are being compared.

[`evidence/candidate-c2b.Dockerfile`](evidence/candidate-c2b.Dockerfile),
[`evidence/candidate-c2b-result.txt`](evidence/candidate-c2b-result.txt).

### C4 — naive package removal

Image `sha256:7cbb6d84…`. `gd` fails to load (§2.5); `php -m` drops from 47 to
46; SBOM drops to 364 components with zero `aom`/`avif`. A scanner-only view of
this image looks like a clean win. It is a broken image.

### A verification gap this exposed

The production runtime smoke was run against C4 — the image whose `gd` extension
cannot load:

```console
$ scripts/smoke/smoke-php-frankenphp.sh <C4>
SMOKE SUMMARY: 8 passed, 0 failed, 8 checks
```

**The runtime smoke passes on an image with a broken PHP extension**, because it
asserts identity, ports, document root, readiness and capabilities, and never
loads a module. A `purge-package` remediation of this shape would therefore reach
production green. This is reported as a finding, not fixed here: adding an
extension-load assertion is its own change with its own acceptance consequences
and is deliberately left to the maintainer.

## 5. Attribution corrections proposed

`policies/vulnerability-exceptions.yaml` is **not** edited by this review. The
corrections below are proposed for the security owner to apply.

1. **The source narrative is wrong.** Entry 5's text — *"libaom3 AV1 decoder in
   frankenphp base"* — is factually incorrect; the base ships no `libaom`
   (§2.1). Correct wording: *installed into the child by the base's own
   `install-php-extensions` helper when Foundry selects the `gd` extension.*
2. **The compensating control is wrong.** *"dropping AVIF support from the
   frankenphp base would remove this entirely"* names an action nobody can take
   — there is nothing in the base to drop. Correct wording: *AVIF can only be
   dropped by changing how Foundry builds `gd`, which removes `imageavif()` and
   `imagecreatefromavif()` from the published images and requires a deprecation
   decision.*
3. **`remediation_owner: upstream-base` should stand.** The expiry refresh
   flagged this as the error; it is not one (§3). What should change is the
   `classification` field: `ownership-boundary-changed` overstates the finding.
   The *inclusion* boundary is Foundry's; the *package and patch* boundary is
   upstream's, and that is where remediation lives.
4. **`rebuild_can_remediate: no` should stand** for the Debian 12 line, and the
   exit condition should name the two real exits: a fixed `aom` reaching Debian
   12, or adoption of the Debian 13 base line.
5. **`docs/audits/expiry-refresh-2026-08-25/README.md` row G03** should retract
   *"a Foundry-side removal path exists today and is not blocked on upstream."*
   The measured position is: no Foundry-side path exists that does not remove a
   shipped capability, and the capability-preserving path **is** an upstream base
   change.

**Disposition: this is an upstream-base risk requiring governance, not a
Dockerfile bug.** The six records should continue as time-boxed accepted risk
with the corrected attribution, the existing consumer advisory (do not process
untrusted AVIF on `php-frankenphp`), and an exit condition bound to Debian 12
gaining a fixed `aom` or the family moving to Debian 13.

## 6. Acceptance consequences

**Nothing in this review changes a production Dockerfile, package inventory or
image byte.** This directory adds documentation only. No production child's
acceptance evidence is invalidated by merging it, and no re-acceptance is
required. Unaffected children are explicitly **not** invalidated.

If either surviving candidate were later adopted — and neither is dispatched
here — the consequences would be:

**If C3b (drop AVIF from `gd`) were adopted:**

- Affected production children: `php-frankenphp` **8.3 and 8.4**, on
  `linux/amd64` **and** `linux/arm64` — four children. Both Dockerfiles change;
  the package inventory changes (`libaom3`, `libavif15`, `libdav1d6`, `librav1e0`
  and the AV1 codec set leave); every image byte changes.
- Prior acceptance evidence for those four children becomes **stale** on
  adoption: package inventory, SBOM, scan results and the GD feature inventory
  all move.
- Minimum future acceptance scope: **build, SBOM, scan, reconcile, runtime smoke
  and contract verification for `php-frankenphp` 8.3 and 8.4 on both
  architectures — four children.** Plus a consumer-facing deprecation notice,
  because an API disappears. `php-cli`, `php-fpm`, `php-worker`, `nginx` and
  `caddy` are untouched and must not be re-accepted.

**If C2b (Debian 13 base line) were adopted:**

- Affected production children: the same four, and in practice the whole
  Debian-based matrix once the migration generalises.
- Minimum future acceptance scope **for the FrankenPHP family alone**: the same
  four children, full acceptance — but every package in the image changes, so the
  honest scope is the Debian 13 migration's own acceptance plan, not a
  finding-level rebuild. It is named here as the capability-preserving exit
  condition, not proposed as a change.

## 7. Retrieval dates and identities

| Item | Value | Date |
|---|---|---|
| Debian security tracker, source package `aom` | six CVEs vulnerable in bookworm; fixed in trixie `3.12.1-1` | 2026-08-26 |
| `1-php8.3-bookworm` head | `sha256:55dc84d1…` | 2026-08-26 |
| `1-php8.4-bookworm` head | `sha256:4484f5fc…` | 2026-08-26 |
| `1-php8.4-trixie` head | `sha256:9a5a469b…` | 2026-08-26 |
| 8.3 child (pinned base `ae143d38…`) | `sha256:1cf1a470…` | 2026-08-26 |
| 8.4 child (pinned base `cef99f10…`) | `sha256:2a69270c…` | 2026-08-26 |
| C3a / C3b / C2b / C4 probe images | `cbb9d939…` / `51c5d840…` / `b769fde0…` / `7cbb6d84…` | 2026-08-26 |

Probe images are local `--load` builds and were never pushed, signed, promoted or
published. Ownership is stated by role throughout, per this repository's
disclosure practice.
