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

```
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

```
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
