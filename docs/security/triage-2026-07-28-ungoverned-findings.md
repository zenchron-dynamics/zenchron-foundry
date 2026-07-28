# Triage — 24 ungoverned CRITICAL/HIGH findings (2026-07-28)

**Status:** complete for the 6 images scanned; 4 images pending (see
[Unresolved](#unresolved-questions)).
**Owner:** Zenchron Dynamics / Platform Security
**Approver:** Bogdan Olteanu — *sole-maintainer risk acceptance*
**Trigger for this work:** #102 / #103. The enforcing gate ran
`--ignore-unfixed`, so every finding below was dropped *before* the exception
ledger was consulted. None is a regression introduced by that change; all are
pre-existing exposure that the new reconciliation gate is the first thing to
surface.

> **Independent approval is unavailable.** The project has one maintainer, so no
> second party reviewed these classifications. Every acceptance below is a
> sole-maintainer risk acceptance and must be re-reviewed by an external party
> **before the first enterprise customer or any enterprise-readiness claim.**

## How this was produced

All evidence comes from the images actually built from this branch, not from
metadata alone.

| Image | Local image ID (amd64) |
|---|---|
| `php-cli:8.3-prod` | `sha256:b4549a7a52d4b6c682ba2733ca73ec8b9f1eefb084d60f32c187c83c787b5038` |
| `php-cli:8.4-prod` | `sha256:5795e0f2f8fa8fcd2275720326377a7f097eef64d28d0c74e11a5d86008ec9d6` |
| `php-fpm:8.3-prod` | `sha256:b48c455ee2ea9cfcda3e79c5b8985182e20ea5d2a3141ef319e9f81b51fcfa22` |
| `php-worker:8.3-prod` | `sha256:cf260a5db316323bca206bda961e79de135677e83cb9e896409e5c1e7d1a5057` |
| `php-frankenphp:8.3-prod` | `sha256:873e660abe99e9f6e0b7e0bfa6ab79e22d752f859300884da86a1649f500cc71` |
| `php-frankenphp:8.4` (probe build) | `sha256:62b91f0283c8ba2cd145c64434e5b3f75382e27cd7679d0d4ae13c784f2b263d` |

Scanner: Trivy 0.71.0 (`@sha256:016eae51…`), `--severity CRITICAL,HIGH`, no
ignore file, nothing suppressed. Architecture scanned: **linux/amd64 only**.

### Runtime model (governs every reachability call below)

```console
$ docker image inspect … --format '{{json .Config.Entrypoint}}'
php-cli        ENTRYPOINT ["php"]            CMD ["-v"]
php-fpm        ENTRYPOINT ["php-fpm","--nodaemonize",…]
php-frankenphp ENTRYPOINT ["frankenphp"]     CMD ["run","--config",…]
```

No image runs a shell, cron, MTA or perl as a service. Repository-wide grep over
`images/*/Dockerfile`, worker entrypoints, healthchecks, smoke scripts and
compose profiles found **no perl invocation** at runtime.

### Key linkage evidence

```console
$ ldd "$(command -v php)" | grep -iE 'curl|ssh2|ldap|xml2|tinfo'
  libxml2.so.2      => /lib/x86_64-linux-gnu/libxml2.so.2
  libcurl.so.4      => /lib/x86_64-linux-gnu/libcurl.so.4
  libtinfo.so.6     => /lib/x86_64-linux-gnu/libtinfo.so.6
  libssh2.so.1      => /lib/x86_64-linux-gnu/libssh2.so.1
  libldap-2.5.so.0  => /lib/x86_64-linux-gnu/libldap-2.5.so.0

$ php -m | tr '\n' ' '
… curl … dom … gd … libxml … SimpleXML … xml xmlreader xmlwriter …

$ ldd …/extensions/…/gd.so | grep -i aom      # frankenphp only
  libaom.so.3 => /lib/x86_64-linux-gnu/libaom.so.3
$ php -r 'var_dump(gd_info()["AVIF Support"]);'   # frankenphp
  bool(true)   # imagecreatefromavif() and imageavif() both exist
```

**These are not dormant base packages.** libxml2, libcurl, libssh2, libldap and
libtinfo are linked into the PHP binary itself; libaom is linked into `gd.so`.

### Perl module inventory — the decisive split

```console
$ perl -MStorable -e1        # php-cli / php-fpm / php-worker
  Can't locate Storable.pm in @INC …
$ perl -MStorable -e1        # php-frankenphp
  (loads)
```

| Module | php-cli / php-fpm / php-worker | php-frankenphp |
|---|---|---|
| `Storable` | **ABSENT** | present |
| `Archive::Tar` | **ABSENT** | present |
| `IO::Compress::Gzip` | **ABSENT** | present |
| `IO::Uncompress::Gunzip` | **ABSENT** | present |

`php-*` images install **`perl-base` only**; `php-frankenphp` inherits the full
`perl` + `perl-modules-5.36` + `libperl5.36` set from its upstream base. Trivy
attributes these advisories to the **source** package `perl`, so it reports them
against `perl-base` even when the vulnerable *module* is not installed.

---

## Classification summary

| # | Advisory | Sev | CVSS | Package(s) | Classification | Treatment |
|---|---|---|---|---|---|---|
| 1 | CVE-2026-13221 | CRITICAL | 9.1 | perl | **not affected** (disputed range) | no exception |
| 2 | CVE-2026-57433 | CRITICAL | — | Storable | **not affected** (cli/fpm/worker) · not reachable (frankenphp) | scoped exception, frankenphp only |
| 3 | CVE-2026-6653 | CRITICAL | 9.8 | libxml2 | **conditionally reachable** | time-limited exception + consumer advisory |
| 4 | CVE-2026-42497 | HIGH | 7.5 | Archive::Tar | not affected · not reachable | scoped exception, frankenphp only |
| 5 | CVE-2026-9538 | HIGH | 7.5 | Archive::Tar | not affected · not reachable | scoped exception, frankenphp only |
| 6 | CVE-2026-48962 | HIGH | 7.8 | IO::Compress | not affected · not reachable | scoped exception, frankenphp only |
| 7 | CVE-2026-57432 | HIGH | 8.4 | perl core | not reachable under intended use | scoped exception |
| 8 | CVE-2026-8286 | HIGH | 8.1 | curl/libcurl4 | **conditionally reachable** | time-limited exception + advisory |
| 9 | CVE-2026-8932 | HIGH | 7.5 | curl/libcurl4 | **conditionally reachable** | time-limited exception + advisory |
| 10 | CVE-2026-8927 | HIGH | 7.5 | curl/libcurl4 | **conditionally reachable** | time-limited exception + advisory |
| 11 | CVE-2026-12064 | HIGH | 7.5 | curl/libcurl4 | conditionally reachable (SCP/SFTP only) | time-limited exception |
| 12 | CVE-2026-55200 | HIGH | 8.3 | libssh2-1 | conditionally reachable (SCP/SFTP only) | time-limited exception |
| 13 | CVE-2026-55199 | HIGH | 7.5 | libssh2-1 | conditionally reachable (SCP/SFTP only) | time-limited exception |
| 14 | CVE-2026-7598 | HIGH | 7.3 | libssh2-1 | conditionally reachable (SCP/SFTP only) | time-limited exception |
| 15 | CVE-2023-2953 | HIGH | 7.5 | libldap-2.5-0 | conditionally reachable (ldap:// only) | time-limited exception |
| 16 | CVE-2025-69720 | HIGH | 7.8 | ncurses/libtinfo6 | not reachable under intended use | time-limited exception |
| 17 | CVE-2026-53615 | HIGH | — | util-linux/libblkid1 | not reachable under intended use | time-limited exception |
| 18 | CVE-2026-54369 | HIGH | 7.1 | libacl1 | not reachable under intended use | time-limited exception |
| 19 | CVE-2026-41992 | HIGH | 7.5 | gzip | not reachable under intended use | time-limited exception |
| 20 | CVE-2026-56211 | HIGH | 7.1 | libaom3 | **conditionally reachable** (frankenphp/gd) | time-limited exception + advisory |
| 21 | CVE-2026-56208 | HIGH | 7.6 | libaom3 | conditionally reachable (frankenphp/gd) | time-limited exception |
| 22 | CVE-2026-56209 | HIGH | 7.1 | libaom3 | conditionally reachable (frankenphp/gd) | time-limited exception |
| 23 | CVE-2026-56210 | HIGH | 7.1 | libaom3 | conditionally reachable (frankenphp/gd) | time-limited exception |
| 24 | CVE-2023-39616 | HIGH | 7.5 | libaom3 | conditionally reachable (frankenphp/gd) | time-limited exception |

**Totals:** 1 proven not affected outright · 4 not affected on 4 of 6 images ·
9 conditionally reachable · 10 not reachable under intended use · **0 currently
release-blocking**.

---

## Per-advisory triage

### 1. CVE-2026-13221 — perl regex trie (CRITICAL, CVSS 9.1) — NOT AFFECTED

* **Package/version:** `perl-base` (+ `perl`, `libperl5.36`, `perl-modules-5.36`
  on frankenphp) `5.36.0-7+deb12u3`.
* **Images:** all 6, linux/amd64.
* **Genuinely affected?** **No.** The Debian tracker's own notes state:
  *"Introduced with: `…/Perl/perl5/commit/acababb42be12ff2986b73c1bfa963b70bb5d54e` (v5.37.10)"* and
  *"Fixed by: …03f74bbb… (v5.43.10)"*. Bookworm ships **5.36.0**, which
  **predates the commit that introduced the flaw**. The Debian row nonetheless
  reads `bookworm 5.36.0-7+deb12u3 vulnerable`, and NVD lists the range as
  *"versions up to (including) 5.43.9"* — a range that ignores the introduction
  point. This is the internal inconsistency the issue flagged; the "affected"
  status is an artefact of a range that starts at zero.
* **Vulnerable code present?** No evidence of it, and behaviourally absent.
  Source-level probe against the installed build:

  ```console
  $ docker run --rm --entrypoint perl php-cli:8.3-prod -e '<trie probe>'
    perl version: v5.36.0
    RESULT: all probes correct — no trie mismatch observable in this build
  ```

  The probe compiles a 70 000-branch fixed-string alternation into a trie and
  checks matching either side of the 65 535 boundary (branches 1, 100, 65534,
  65535, 65536, 65537, 69999, 70000) plus three negative probes. Silently
  incorrect matching — the entire symptom of this CVE — does not occur.
* **Reachable?** Moot. No perl runs at runtime in any image.
* **Removable?** `perl-base` is `Priority: required`; dpkg depends on it.
* **Patched base?** None needed.
* **Classification:** **not affected — false positive / disputed range.**
* **Treatment:** **no ledger entry.** Recording an exception would assert we
  accept a risk that the evidence says does not exist, and would then expire and
  demand re-review forever. Instead: suppress nothing, and let the reconciler
  keep failing until the scanner data is corrected — see *Action* below.
* **Action:** report the range inconsistency to the Debian security tracker and
  the Trivy DB. Until either corrects it, this finding has no valid treatment
  other than a **`not_affected` record** (see [Ledger shape](#ledger-shape)).

### 2. CVE-2026-57433 — Storable SX_HOOK integer overflow (CRITICAL)

* **Package/version:** source `perl` `5.36.0-7+deb12u3`; vulnerable component is
  the **`Storable`** module (`< 3.41`).
* **Upstream description (verbatim):** *"retrieve_hook_common reads a signed
  32-bit item count from an SX_HOOK record and calls av_extend with that count
  plus one. … A crafted blob passed to thaw or retrieve triggers the overflow;
  av_extend receives the negative count and dies with a panic, terminating the
  deserialization."*
* **Vulnerable code present?** **php-cli / php-fpm / php-worker: NO** —
  `perl -MStorable -e1` → `Can't locate Storable.pm in @INC`. The module is not
  installed; these images are **not affected**.
  **php-frankenphp: YES** — `Storable.pm` and `auto/Storable/Storable.so` are
  present and load.
* **Reachable (frankenphp)?** No path found. Reaching it requires a perl process
  calling `thaw`/`retrieve` on attacker-supplied bytes. `frankenphp` is the
  entrypoint; nothing in the image's entrypoints, healthchecks or scripts
  invokes perl.
  **Explicit distinction, as required:** an attacker who already has code
  execution inside the container can of course run `/usr/bin/perl`. That is a
  **post-compromise capability, not a pre-authentication remotely reachable
  path**, and it is not treated as reachability here. It does mean this
  advisory would become relevant in a chained-exploit scenario.
* **Impact:** the described outcome is a **panic terminating deserialization** —
  denial of service of that perl process, not RCE.
* **Removable?** Possibly — `perl-modules-5.36` is pulled in by the upstream
  FrankenPHP/php base. Removal is a candidate remediation but risks breaking
  base-image tooling; see [Remediation backlog](#remediation-backlog).
* **Classification:** **not affected** (php-cli/fpm/worker) · **not reachable
  under intended use** (php-frankenphp).
* **Treatment:** one scoped exception, `php-frankenphp` **only**. Expiry
  2026-08-31.

### 3. CVE-2026-6653 — libxml2 use-after-free in `xmlParseInternalSubset` (CRITICAL, CVSS 9.8)

* **Package/version:** `libxml2` `2.9.14+dfsg-1.3~deb12u6`. Affected range
  2.9.11 → 2.11.0.
* **Images:** all 6.
* **Debian status (verbatim):** *"[bookworm] - libxml2 <postponed> (Minor issue;
  UAF present via CVE-2021-3541 backport, fix only in 2.11.0)"*. Fixed in
  sid at `2.14.5+dfsg-0.1`; **no bookworm fix**.
* **Vulnerable code present?** Yes — installed version is inside the affected
  range and Debian confirms the UAF is present via the CVE-2021-3541 backport.
* **Reachable?** **Yes, conditionally.** `ldd php` shows `libxml2.so.2` linked
  directly into the PHP binary, and `dom`, `libxml`, `SimpleXML`, `xml`,
  `xmlreader`, `xmlwriter` are all enabled (`php --ri libxml` → *libXML support
  => active, Compiled Version => 2.9.14*). Any consumer calling
  `simplexml_load_string()`, `DOMDocument::loadXML()`, `XMLReader::XML()`, or
  SOAP/WSDL handling on attacker-supplied XML reaches
  `xmlParseInternalSubset` through DTD/internal-subset parsing.
* **Attacker-controlled data?** Yes, by construction — XML input is the data.
* **Preconditions/privileges:** none beyond supplying XML to an endpoint that
  parses it. Pre-authentication where the consumer exposes such an endpoint.
* **Impact:** denial of service (use-after-free → crash). CVSS 9.8 reflects the
  generic vector; the Debian assessment is "minor issue", and the upstream
  description is explicitly *"allows a remote attacker to cause a
  denial-of-service"*. Under Foundry's model — one process per container,
  orchestrator restart, no shared state — the blast radius is a restarted
  worker, not host compromise.
* **Removable?** **No.** libxml2 is a hard dependency of PHP core XML support;
  removing it removes `dom`/`SimpleXML`/`xml` and breaks essentially every
  framework.
* **Patched base?** None available for bookworm. Debian 13 (trixie) carries a
  fixed libxml2 — this is a concrete argument for #105.
* **Classification:** **conditionally reachable through a consuming
  application.** *Foundry is a reusable base and cannot know whether a consumer
  parses XML; non-reachability must NOT be claimed just because the repository's
  own examples do not parse XML.*
* **Treatment:** time-limited exception, expiry **2026-08-31**, with a
  **consumer-facing advisory** stating plainly that applications parsing
  untrusted XML on these images are exposed to a DoS until the base is updated.
  Not release-blocking: impact is DoS, not RCE, and no fixed bookworm package
  exists to move to.

### 4–6. CVE-2026-42497, CVE-2026-9538 (Archive::Tar), CVE-2026-48962 (IO::Compress)

* **Packages:** source `perl` `5.36.0-7+deb12u3`; vulnerable components are the
  **`Archive::Tar`** and **`IO::Compress`** modules.
* **Vulnerable code present?** **php-cli / php-fpm / php-worker: NO** — both
  modules absent (`perl -MArchive::Tar -e1`, `perl -MIO::Compress::Gzip -e1`
  both fail). **php-frankenphp: yes.**
* **Reachable?** No — same analysis as CVE-2026-57433: no perl process runs.
  CVE-2026-48962 is *"arbitrary code execution via attacker-controlled output
  glob"*, which requires a perl program passing attacker data to IO::Compress;
  none exists.
* **Impact if reached:** arbitrary file modification (42497), ACE (48962), DoS
  (9538) — all within a non-root, read-only-rootfs, `cap_drop: ALL` container.
* **Classification:** **not affected** (php-cli/fpm/worker) · **not reachable
  under intended use** (php-frankenphp).
* **Treatment:** scoped exceptions, `php-frankenphp` only, expiry 2026-08-31.

### 7. CVE-2026-57432 — perl core integer overflow in `S_measure_struct` (HIGH, CVSS 8.4)

* **Package/version:** `perl-base` `5.36.0-7+deb12u3`. Range: *"Perl versions
  through 5.43.10"* — unlike #1, this range has no stated introduction point, so
  5.36.0 is presumed in range.
* **Vulnerable code present?** Presumed yes (core `pack`/`unpack` machinery).
* **Reachable?** No — no perl runs at runtime. Same post-compromise distinction
  as #2 applies.
* **Classification:** **not reachable under intended use.**
* **Treatment:** scoped exception across the php family, expiry 2026-08-31.

### 8–11. curl / libcurl4 — CVE-2026-8286, CVE-2026-8932, CVE-2026-8927, CVE-2026-12064

* **Package/version:** `curl`, `libcurl4` `7.88.1-10+deb12u15`. Debian status
  `fix_deferred` for all four.
* **Images:** all 6.
* **Reachable?** **Yes, conditionally — this is the important group.** `libcurl.so.4`
  is linked into the PHP binary and the **`curl` extension is enabled**, so any
  consumer calling `curl_exec()` exercises this code. Specifically:
  * **CVE-2026-8286** (CVSS 8.1) *"insecure connection establishment due to TLS
    configuration mismatch"* — reachable on ordinary HTTPS requests.
  * **CVE-2026-8932** *"security feature bypass due to improper mTLS connection
    reuse"* — reachable where a consumer uses client certificates.
  * **CVE-2026-8927** *"information disclosure due to uncleared proxy
    authentication state"* — reachable where a consumer uses an authenticated
    proxy.
  * **CVE-2026-12064** *"SSH host verification bypass when using schemeless URLs
    with SFTP/SCP"* — reachable **only** if a consumer uses curl for SCP/SFTP,
    which is unusual in a PHP web workload.
* **Attacker-controlled data?** Partly. 8286/8932/8927 depend on the consumer's
  TLS/proxy configuration rather than on request content; 12064 requires
  attacker influence over the URL *and* SCP/SFTP use.
* **Impact:** downgraded transport security, credential leakage to a proxy,
  bypassed mTLS peer checks. Not container escape; a confidentiality/integrity
  problem for outbound calls made by the consuming application.
* **Removable?** The `curl` **binary** could be dropped, but the exposure is in
  `libcurl4`, which PHP's curl extension requires. Removing the extension would
  break most consumers.
* **Patched base?** No bookworm fix (`fix_deferred`). Watch the weekly rebuild.
* **Classification:** **conditionally reachable** (8286, 8932, 8927);
  conditionally reachable, narrow precondition (12064).
* **Treatment:** time-limited exceptions, expiry **2026-08-31**, plus a
  consumer-facing advisory for the three TLS/proxy items. Not release-blocking:
  no fixed package exists and the failure modes require specific consumer
  configurations.

### 12–14. libssh2-1 — CVE-2026-55200, CVE-2026-55199, CVE-2026-7598

* **Package/version:** `libssh2-1` `1.10.0-3+b1`.
* **Reachable?** Conditionally, and **only through curl's SCP/SFTP support** —
  `libssh2.so.1` is linked by both `php` and `libcurl.so.4`. A PHP web workload
  reaches this only if it makes `scp://`/`sftp://` curl requests.
* **Impact:** DoS (55199), out-of-bounds write (55200, CVSS 8.3), integer
  overflow on oversized credentials (7598).
* **Classification:** **conditionally reachable**, narrow precondition.
* **Treatment:** time-limited exceptions, expiry 2026-08-31. Candidate for
  removal — see backlog.

### 15. CVE-2023-2953 — openldap null-pointer dereference in `ber_memalloc_x` (HIGH)

* **Package/version:** `libldap-2.5-0` `2.5.13+dfsg-5`.
* **Reachable?** Conditionally — `libldap-2.5.so.0` is linked by `php` and
  `libcurl`, reachable only via `ldap://` curl requests or the LDAP extension
  (which is **not** enabled: absent from `php -m`).
* **Impact:** null-pointer dereference → DoS.
* **Classification:** **conditionally reachable**, narrow precondition.
* **Treatment:** time-limited exception, expiry 2026-08-31.

### 16. CVE-2025-69720 — ncurses buffer overflow (HIGH, CVSS 7.8)

* **Packages:** `ncurses-base`, `ncurses-bin`, `libtinfo6` `6.4-4`.
* **Reachable?** `libtinfo.so.6` is linked into `php` (via `readline`), but the
  advisory concerns terminal/terminfo handling driven by `TERM` and terminfo
  data. No Foundry image runs an interactive terminal; `php-cli`'s entrypoint is
  `php`, not a shell, and `TERM` is not attacker-controlled in an orchestrated
  container.
* **Classification:** **not reachable under intended use.**
* **Treatment:** time-limited exception, expiry 2026-08-31.

### 17. CVE-2026-53615 — util-linux integer overflow in `libblkid/partitions/dos.c` (HIGH)

* **Packages:** `util-linux`, `libblkid1`, `libmount1`, `libuuid1`,
  `libsmartcols1`, `bsdutils`, `mount`, `util-linux-extra` `2.38.1-5+deb12u3`.
* **Reachable?** No. The vulnerable path parses **DOS partition tables**;
  reaching it requires `blkid`/`libblkid` probing a block device or disk image.
  Containers run non-root with `cap_drop: ALL` and no block-device access, and
  nothing in the runtime invokes these tools.
* **Classification:** **not reachable under intended use.**
* **Treatment:** time-limited exception, expiry 2026-08-31.

### 18. CVE-2026-54369 — libacl symlink traversal privilege escalation (HIGH)

* **Package:** `libacl1` `2.3.1-3`, Debian `fix_deferred`.
* **Reachable?** No. Requires a process calling libacl functions
  (`setfacl`/`getfacl` paths) across a symlink boundary, typically as root. All
  images run as UID 10001 with a read-only rootfs and `no-new-privileges`; PHP
  does not link libacl.
* **Classification:** **not reachable under intended use.**
* **Treatment:** time-limited exception, expiry 2026-08-31.

### 19. CVE-2026-41992 — gzip global buffer overflow in the LZH decoder (HIGH)

* **Package:** `gzip` `1.12-1`, Debian `fix_deferred`.
* **Reachable?** No. The flaw is in `gzip`'s LZH (`.lzh`) decompression path,
  reached only by running the `gzip`/`zcat` **binary** on an attacker-supplied
  archive. PHP's zlib support does not use it, and nothing at runtime invokes
  gzip.
* **Classification:** **not reachable under intended use.**
* **Treatment:** time-limited exception, expiry 2026-08-31. Candidate for
  removal — see backlog.

### 20–24. libaom3 — CVE-2026-56211, 56208, 56209, 56210, CVE-2023-39616 (HIGH)

* **Package/version:** `libaom3` `3.6.0-1+deb12u2`. **`php-frankenphp` only** —
  not installed on php-cli/fpm/worker.
* **Reachable?** **Yes, conditionally, and this must not be dismissed.**
  `gd.so` links `libaom.so.3`, and gd reports `AVIF Support => true` with both
  `imagecreatefromavif()` and `imageavif()` available. A consumer that accepts
  user-uploaded images and calls `imagecreatefromavif()` — or converts to AVIF
  with `imageavif()` — reaches libaom with attacker-controlled data.
* **Nuance:** CVE-2026-56208/56209/56210/56211 are described as **encoder**
  issues (first-pass stats buffer in LAP mode, SVC layer context,
  `ctrl_set_layer_id`), reached via `imageavif()` *encoding*, where the
  attacker typically controls the *image content* but not the encoder
  parameters. CVE-2026-56211 is nonetheless described as *"remote code
  execution via SVC layer context handling with attacker-controlled …"*, so it
  is treated as the most serious of the group. CVE-2023-39616 is an invalid
  memory read (`will_not_fix` in Debian).
* **Impact:** heap overflow / arbitrary address write / potential RCE inside a
  non-root, read-only, `cap_drop: ALL`, `no-new-privileges` container.
* **Removable?** Possibly — libaom arrives via gd's AVIF support in the upstream
  base. Dropping AVIF would remove the exposure entirely; see backlog.
* **Classification:** **conditionally reachable** (frankenphp only).
* **Treatment:** time-limited exceptions, expiry **2026-08-31**, plus a
  consumer-facing advisory: *do not process untrusted AVIF on
  `php-frankenphp` until the base ships libaom ≥ the fixed version.*

---

## Ledger shape

Per the review constraint, entries are **one record per
`advisory + package/component + reachability classification`**, listing the
affected families explicitly — not one row per image. Where reachability differs
by family (the perl-module advisories), the advisory gets **two** records: a
`not_affected` record for the families where the module is absent, and an
accepted record for `php-frankenphp`.

Every accepted record carries: `owner`, `approver`, `approval_mode:
sole-maintainer risk acceptance`, `independent_approval: unavailable — single
maintainer`, `external_review_trigger`, `reachability`, `reachability_evidence`,
`compensating_controls`, `release_blocking`, `references`, `created_at`,
`expires_at`, `affected_images`, `affected_arches`, `scanned_digests`.

---

## Remediation backlog

| Option | Removes | Risk | Status |
|---|---|---|---|
| Drop `perl-modules-5.36` + `libperl5.36` from `php-frankenphp` | 4 advisories outright (57433, 42497, 48962, 9538) | may break upstream base tooling; needs a build+smoke cycle | **recommended, not yet attempted** |
| Drop the `gzip` binary | 1 advisory (41992) | low; nothing invokes it | candidate |
| Drop AVIF support / `libaom3` from `php-frankenphp` | 5 advisories (56208–56211, 39616) | removes `imageavif()`/`imagecreatefromavif()` — a **consumer-visible API change**, needs a deprecation path | candidate, needs decision |
| Drop SCP/SFTP + LDAP curl protocols | 4 advisories (12064, 55199, 55200, 7598, 2953) | requires rebuilding curl — not possible with the official PHP base | not feasible |
| Move to Debian 13 (trixie) | libxml2 (6653) and others | major migration | **tracked as #105** |

None of these were applied in this change; each needs its own build, smoke and
scan cycle, and the AVIF one needs a compatibility decision.

---

## Round 2 — nginx is NOT yet triaged

The php family and caddy are complete. **`nginx` is not**, and its entries were
deliberately not extended to cover it: nginx serves HTTP and never runs PHP, so
its reachability profile is a different analysis, and reusing php-scoped
reasoning would be exactly the unscoped acceptance #102 exists to prevent.

The built nginx image could not be produced locally — `apt-get update` wedged on
`Ign: …bookworm/main amd64 Packages` for 80+ minutes (the same network flakiness
that killed the overnight `make build-test`). As a conservative stand-in, the
**pinned base** `nginxinc/nginx-unprivileged:1.27-bookworm@sha256:f9dfa9c2…` was
scanned: **87 CRITICAL/HIGH advisories**.

`images/nginx/Dockerfile` upgrades 19 packages (`libssl3`, `openssl`,
`libgnutls30`, `libxml2`, `libxslt1.1`, `libpng16-16`, `libtiff6`, `libpam*`,
`libsystemd0`, `libudev1`, `gpgv`, `libcap2`, `libexpat1`, `libnghttp2-14`,
`perl-base`, `zlib1g`), which clears **58** of them. The estimate for the built
image is therefore **≈29 surviving advisories, 1 CRITICAL** (`CVE-2023-6879`,
libaom3):

| Package | Advisories |
|---|---|
| `curl` / `libcurl4` | 6 + 6 |
| `libaom3` | 6 |
| `libheif1` | 6 |
| `libssh2-1` | 3 |
| `libgssapi-krb5-2` / `libk5crypto3` / `libkrb5-3` / `libkrb5support0` | 2 each |
| `gzip`, `libacl1`, `bsdutils` | 1 each |

This is an **estimate from the base**, not evidence from the artifact we ship.
Round 2 must scan the built image and answer, for nginx specifically:

* is `libcurl` linked into `nginx` at all, or merely present as a base binary?
* can `libaom3`/`libheif1` be reached — nginx serves image bytes, it does not
  decode them;
* are the krb5 libraries reachable without an auth module configured?

Until that is done the gate will fail on nginx, which is the correct behaviour.

## Unresolved questions

1. **3 images unscanned:** `php-fpm:8.4`, `php-worker:8.4` (builds failed on the
   same network fault) and `nginx:prod` (see Round 2). The php 8.4 pair shares
   its Dockerfile and base line with the 8.3 sibling, and `php-cli:8.4` was
   scanned and produced a finding set identical to `php-cli:8.3` — so the risk
   is low, but it is an inference, not evidence.
2. **arm64 not scanned at all.** Every classification above is from linux/amd64.
   Package versions should be identical, but this is unverified.
3. **CVE-2026-13221 needs an upstream correction.** Until the Debian tracker or
   the Trivy DB reflects the v5.37.10 introduction point, the scanner will keep
   reporting it. A `not_affected` record is the honest representation; an
   "exception" would misstate it as accepted risk.
4. **CVE-2026-57432** was classified on a presumed-in-range basis; the upstream
   range gives no introduction point. If it too was introduced after 5.36.0 it
   is *not affected* rather than *not reachable*.
5. **libaom encoder-vs-decoder split** is taken from advisory titles, not from
   source review. If any of 56208–56211 is reachable on the **decode** path,
   `imagecreatefromavif()` on untrusted uploads becomes materially more serious
   and the expiry should shorten.
