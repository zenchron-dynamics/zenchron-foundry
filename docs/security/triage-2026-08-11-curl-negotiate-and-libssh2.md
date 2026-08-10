# Triage — 2026-08-11: curl CVE-2026-8458, and the stale libssh2 pair

**Trigger.** The weekly `scan-images` run [31355306464](https://github.com/zenchron-dynamics/zenchron-foundry/actions/runs/31355306464)
(`event=schedule`, head `b68f2800`, 2026-08-10T04:23Z) failed. It was the first
red scheduled scan since [30789384004](https://github.com/zenchron-dynamics/zenchron-foundry/actions/runs/30789384004)
(2026-08-03, success). Nine jobs failed for **two** distinct reasons:

| jobs | verdict |
| --- | --- |
| `scan php-cli 8.3/8.4`, `scan php-fpm 8.3/8.4`, `scan php-worker 8.3/8.4`, `scan php-frankenphp 8.3/8.4` | `REFUSE: 2 ungoverned CRITICAL/HIGH finding(s)` — `CVE-2026-8458` on `curl` and on `libcurl4`, both `7.88.1-10+deb12u15` |
| `no stale vulnerability exceptions` | `FAIL: 2 active exception(s) matched no finding` — `CVE-2026-55199\|php-all\|libssh2-1\|*` and `CVE-2026-55200\|php-all\|libssh2-1\|*` |
| `scan nginx prod`, `scan caddy prod` | success — neither edge image carries `libcurl4` (purged in `images/nginx/Dockerfile`) |

Both gates behaved correctly. Neither is a false alarm, and neither was fixed by
weakening a check.

---

## 1. CVE-2026-8458 — libcurl connection reuse under Negotiate auth

**Disposition: accepted, scoped exception on `php-all` / `[curl, libcurl4]`.**

### What it is

> libcurl might in some circumstances reuse the wrong connection when asked to do
> Negotiate-authenticated ones, even when they are set to use different
> 'services'.

Introduced in curl 7.43.0, fixed upstream in curl 8.21.0.

### Why a base bump cannot close it

Debian's tracker records **bookworm as unfixed, urgency `postponed`**: there is
no `7.88.1-10+deb12u16` carrying the fix, and none is planned for this release.
The php family already runs the newest published bookworm build,
`7.88.1-10+deb12u15`. There is nothing to bump to. Remediation by base digest —
the platform's normal patch model — is unavailable, which is precisely the
condition an exception exists for.

### Reachability — the code path exists, and was measured

The nginx image is unaffected because it purges `curl` and `libcurl4` outright.
The php images cannot: `libcurl.so.4` is linked into the php binary and the
`curl` extension is enabled.

Probed on `ghcr.io/zenchron-dynamics/php-cli:8.4-prod`:

```text
dpkg-query -W curl libcurl4 libgssapi-krb5-2
  curl              7.88.1-10+deb12u15
  libcurl4          7.88.1-10+deb12u15
  libgssapi-krb5-2  1.20.1-2+deb12u5

php -r 'print_r(curl_version());'
  version  7.88.1   ssl OpenSSL/3.0.20
  features 0x55bfc79d
    CURL_VERSION_GSSNEGOTIATE  YES
    CURL_VERSION_SPNEGO        YES
    CURL_VERSION_KERBEROS5     YES

ldd /usr/lib/x86_64-linux-gnu/libcurl.so.4 | grep -E 'gssapi|krb5'
  libgssapi_krb5.so.2 ...
  libkrb5.so.3 ...
```

So the Negotiate code path is **compiled in and linked** — this is not a
"feature not built" dismissal. Reaching the defect additionally requires the
consuming application to drive `CURLAUTH_NEGOTIATE` requests against **more than
one Kerberos service name** over a reusable connection pool. That is what makes
libcurl select the wrong pooled connection. A PHP web workload does not normally
use Negotiate authentication at all.

Classification `conditionally-reachable-via-consuming-application` — the same
class, same package build and same reasoning already recorded for
`CVE-2026-6276` (cookie leak on connection reuse with a custom `Host` header).

### Consumer advisory

An application that *does* use Negotiate/SPNEGO against more than one service
should set `CURLOPT_FORBID_REUSE` on those handles until a fixed curl reaches
bookworm, or route them through a separate handle pool per service.

### Expiry

`2026-08-31`, matching the rest of the current ledger cohort. Re-review then; do
not extend by default. Watch for a `deb12u16` carrying a backport, or for
Debian to move the CVE off `postponed`.

---

## 2. CVE-2026-55199 / CVE-2026-55200 — libssh2, wrongly held as accepted risk

**Disposition: moved from `exceptions:` to `not_affected:`.**

These two were recorded on 2026-07-28 as accepted risk, with the reachability
argument "libssh2.so.1 is linked by php and by libcurl, so it is reachable ONLY
through curl SCP/SFTP requests". That argument is about *reachability*. It is
the wrong axis: the flaws are **not present in the build we ship**.

| | CVE-2026-55199 | CVE-2026-55200 |
| --- | --- | --- |
| flaw | CPU-exhaustion loop on a crafted `SSH_MSG_EXT_INFO` extension count | out-of-bounds write in `ssh2_transport_read()`, unbounded `packet_length` |
| upstream range | through 1.11.1 | through 1.11.1, fixed in commit `7acf3df` |
| Debian bookworm | **not affected** — "vulnerable code not present", 1.10.0-3 | **not affected** — "vulnerable code not present", 1.10.0-3 |

Confirmed on the shipped image rather than taken on Debian's word.
`php-cli:8.4-prod` carries `libssh2-1 1.10.0-3+b1`, and a literal scan of the
actual shared object finds no trace of the RFC 8308 extension-negotiation code
that CVE-2026-55199 requires:

```text
grep -a -o -E 'ext-info-[cs]|server-sig-algs' /usr/lib/x86_64-linux-gnu/libssh2.so.1.0.1
  (no matches)

# controls in the SAME binary, proving the scan itself works:
grep -a -c 'SSH-2.0'                          -> 2
grep -a -o 'diffie-hellman-group14-sha256'    -> diffie-hellman-group14-sha256
```

Trivy has since stopped reporting both CVEs on all ten images, which is what
made the pair surface as stale exceptions.

### Why record them at all rather than delete

A deleted record is indistinguishable from one that was never considered. If a
future Trivy DB revision re-reports either CVE against 1.10.0 — advisory ranges
of this shape have been wrong before, which is the whole reason
`CVE-2026-13221` and `CVE-2026-57433` sit in `not_affected:` — the finding meets
a written determination instead of silently becoming accepted risk again. The
`installed_version: 1.10.0-3+b1` binding makes each record self-invalidate the
moment the package moves, so this cannot become a permanent blanket suppression.

**`CVE-2026-7598` on the same package is NOT affected by this change.** It is
still reported, still an exception, and still correctly classified — Debian's
determination differs per CVE, and only these two were "vulnerable code not
present".

---

## What was NOT done

- No base digest was bumped. There is no fixed curl to bump to.
- No gate was relaxed, no `--ignore-unfixed`, no `.trivyignore` entry.
- No exception expiry was extended. The new record carries the cohort expiry.
- `CVE-2026-7598` (libssh2, integer overflow via oversized username/password)
  remains an exception, unchanged.

---

## 3. Two open range questions, resolved (#137, #138)

Both were opened on 2026-07-28 as follow-ups to the #102/#103 triage, both with a
2026-08-31 deadline, and both asked the same shape of question: *is the record's
assumed reachability actually right?* Answering them now, before the expiry,
avoids a re-review that only re-states the assumption.

### #137 — CVE-2026-57432 (perl `S_measure_struct`): 5.36.0 IS affected

The record was written on a **presumed-in-range** basis: the upstream range gives
no introduction point, so 5.36.0 was assumed affected. Its sibling
`CVE-2026-13221` turned out *not* affected on exactly that point, which is what
made the presumption worth testing.

It does not go the same way.

Debian's tracker lists only fixes, both landing in v5.43.11:
[`5f7eb6bb`](https://github.com/Perl/perl5/commit/5f7eb6bbbe0510964e3fb1d6bb691e5445913e55)
and `40754edc`. The first one **adds** a guard:

```c
if ((size > 0) &&
    ((len > SSize_t_MAX / size) ||          /* overflow of len * size   */
     (len * size > SSize_t_MAX - total)))   /* overflow of total + ...  */
    croak("Pack template structure size is too large");
```

immediately before the pre-existing `total += len * size;`. It guards
long-standing code rather than fixing code introduced after 5.36.0 — so unlike
CVE-2026-13221 there is no post-5.36.0 introduction point to appeal to.

Confirmed on the shipped build (`php-cli:8.4-prod`, `perl-base
5.36.0-7+deb12u3`): the fix's diagnostic does not exist. A pack template with an
overflowing repeat count runs into `Out of memory!` / the unguarded arithmetic,
never `Pack template structure size is too large`.

**Disposition: the exception stands as an exception.** It does not move to
`not_affected:`. Its `reachability` classification —
`not-reachable-under-intended-use`, because no perl process runs at runtime in
any image — is unchanged and independent of the range question. The record's
evidence and its `note:` are updated to say the range was resolved rather than
presumed.

### #138 — CVE-2026-56208..56211 (libaom): encoder-only, decode is not reachable

The severity assessment rested on advisory **titles** describing encoder paths.
That is now confirmed from vendor analysis rather than inferred.

Red Hat's analysis of CVE-2026-56209 — the most serious of the four, an arbitrary
address write — places it "in the encoder's SVC layer context handling via
`ctrl_set_layer_id()`, **not in decoding functionality**", and states that
"decoding an AV1 file alone cannot trigger this vulnerability". It is reachable
only from an application that exposes **SVC encoder configuration** to untrusted
input. The pointer is injected through crafted Y-plane pixel values, but only
once an out-of-range layer id has already been set through `aom_codec_control`.

The same axis holds for the other three: 56208 is untrusted encoder
configuration, 56210 is a `layer_id` bounds check, 56211 is out-of-range
spatial/temporal layer selection.

php-gd never calls `aom_codec_control` to set a layer id. `imageavif()` encodes
with libaom's defaults, and `imagecreatefromavif()` is a **decode** path that
none of the four reaches.

**Disposition: no change to severity, no change to expiry.** The question in the
issue — "if any is decode-reachable, `imagecreatefromavif()` on untrusted uploads
becomes materially more serious, shorten the expiry" — is answered **no**. The
compensating-control text on all five libaom records (the four plus
`CVE-2023-39616`) is updated from "the flaws are described as ENCODER paths" to
the confirmed finding, and the pointer to "triage unresolved Q5" is removed
because it is no longer unresolved.

The standing consumer advisory is unchanged and still correct: do not process
untrusted AVIF on php-frankenphp until the base ships a fixed libaom. Removing
AVIF support from the base remains the way to delete this class outright, and
remains a consumer-visible change on the backlog.
