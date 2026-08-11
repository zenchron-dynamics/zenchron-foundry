# Re-affirmation — 2026-08-12: CVE-2026-56852 (Caddy, `golang.org/x/text`)

**Record:** `policies/vulnerability-exceptions.yaml` → `CVE-2026-56852` / `caddy` /
`golang.org/x/text` / `v0.37.0`
**Original expiry:** 2026-08-14 — the shortest in the ledger
**New expiry:** 2026-08-31, aligned to the current review cohort
**Approver:** Bogdan Olteanu — sole-maintainer risk acceptance
**Issue:** #140

[#140](https://github.com/zenchron-dynamics/zenchron-foundry/issues/140) said
explicitly: *"If it has not shipped by 2026-08-14, re-review rather than extend by
default."* This is that re-review, performed two days early, and its outcome is a
**short bounded re-affirmation** — not a default extension.

---

## 1. Upstream is not lagging a rebuild. Upstream itself is unfixed

This is the finding that changed the shape of the answer. The original record and
the issue both framed the wait as *"watch for an official `caddy:2-alpine`
rebuild"* — implying we were pinned behind a moving tag that would eventually
absorb a fix.

Measured 2026-08-12:

```text
caddy:2-alpine        sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648
caddy:2.11-alpine     sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648
caddy:2.11.4-alpine   sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648

images/caddy/Dockerfile pins
CADDY_BASE            sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648
```

All three tags — including the **explicit current release tag `2.11.4-alpine`** —
resolve to the digest already pinned. The image is not behind. It **is** Caddy
2.11.4, which is the newest official release.

Scanning that exact digest:

```text
usr/bin/caddy  CVE-2026-56852  golang.org/x/text  v0.37.0  ->  fixed in 0.39.0  HIGH
```

So there is no newer base to bump to, and bumping would absorb nothing. The
remediation the record prefers is not available — not because we have not looked,
but because the current upstream release still vendors the vulnerable version.

## 2. The acceptance basis was re-verified on current master, and holds

The exception rests entirely on the certified topology removing the remote path:

```text
attacker-controlled TLS SNI -> tls.ClientHelloInfo.ServerName
  -> certmagic.Config.getNameFromClientHello -> idna.Lookup.ToASCII
  -> norm.NFC.String / QuickSpan / Bytes
```

| control | source of truth | state 2026-08-12 |
| --- | --- | --- |
| `auto_https off` | `images/caddy/Caddyfile` | present, with the CERTIFIED TOPOLOGY note above it |
| TLS termination forbidden | `contracts/images/caddy-prod.yaml` | `tls_termination: forbidden` |
| `:443` / `:8443` listener | shipped Caddyfile | absent |
| 8443 exposure | `images/caddy/Dockerfile` | not `EXPOSE`d |

Nothing in #152–#156, and nothing in this sprint's merged work
(#159, #160, #161, #162), altered Caddy's TLS posture. #160 changed the **nginx** healthcheck and
port surface; Caddy was untouched.

## 3. What was NOT done, and why

- **The expiry was not extended open-endedly.** 2026-08-31 aligns this record with
  the rest of the review cohort so it is examined alongside them, rather than
  drifting on its own short clock.
- **No base digest was bumped.** There is nothing newer to bump to.
- **No gate was relaxed**, no severity downgraded, no compensating control removed.
- **No in-house rebuild of Caddy on `x/text >= 0.39.0` was attempted.** That needs
  an ADR: it makes Foundry the owner of a build input it does not own today, and
  it is a divergence from the official image that consumers would inherit.

## 4. What invalidates this immediately

Any change permitting this image to terminate TLS. The finding becomes directly
remotely reachable and the Caddy image is blocked until one of:

1. an official Caddy build carrying `x/text >= 0.39.0`;
2. an ADR approving a reproducible in-house rebuild on a fixed `x/text`;
3. another concrete mitigation preventing invalid SNI from reaching Caddy.

The consumer advisory is unchanged and still binding: **TLS must terminate at the
upstream load balancer.** It is documented in `docs/consuming-images.md`,
`docs/image-taxonomy.md`, `docs/runtime-hardening.md`, and enforced as a contract
value in `contracts/images/caddy-prod.yaml`.

## 5. The 2026-08-31 re-check

One command decides whether this can be closed rather than renewed:

```bash
docker buildx imagetools inspect caddy:2-alpine --format '{{.Manifest.Digest}}'
```

A digest differing from `sha256:5f5c8640…` means a new upstream build exists. Scan
it before renewing: if it carries `x/text >= 0.39.0`, bump the pin, rescan, and
**delete** this record rather than renewing it again.

If it is still the same digest, that is a second consecutive cohort with no
upstream fix, and the ADR in (2) above should be opened rather than re-affirming a
third time.
