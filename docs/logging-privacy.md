# Access logging and privacy

**Issue:** #107 · **Contract:** [`policies/runtime-contract.yaml`](../policies/runtime-contract.yaml) → `logging_privacy`

## The problem this fixes

The nginx image logged `$request_uri` — the path **including the query string** —
plus the full client address, `Referer` and `User-Agent`. A single request to
`/reset?token=…` put that token in the container log, in the log shipper, in the
SIEM, and in every backup of them. An access log is not somewhere a credential
can be retracted from, and under GDPR the client address and the URL history are
personal data with no stated purpose or retention period attached.

Measured against the previously published image:

```json
{"time":"…","remote_addr":"192.168.215.1","method":"GET",
 "uri":"/pay?token=ZENCHRON_QUERY_CANARY","status":200,
 "referer":"http://evil.example/ZENCHRON_QUERY_CANARY","ua":"ZENCHRON_UA_CANARY"}
```

Same request against the current image:

```json
{"time":"…","client_net":"192.168.215.0/24","method":"GET",
 "path":"/pay","status":200,"bytes":3,"rt":0.000}
```

## The privacy profile is the DEFAULT

`privacy-eu` is what an image logs out of the box. It is not an opt-in, because a
field that is only redacted when someone remembers to select a profile is a field
that gets logged.

| field | `privacy-eu` (default) | `full` (opt-in) |
| --- | --- | --- |
| path | `$uri` — decoded, normalised, **no query string** | `$request_uri` — raw, with query |
| client address | `/24` (IPv4) or `/48` (IPv6) network | full address |
| `Referer` | not logged | logged |
| `User-Agent` | not logged | logged |
| `Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key` | **never logged** | **never logged** |
| method, status, bytes, duration | logged | logged |

Credentials are absent from **both** profiles. They are not diagnostics, and
there is no operational case for writing them to disk that outweighs having them
there.

### Choosing the full profile

```nginx
# In your site config. You are asserting a lawful basis, a stated purpose and a
# retention period for the personal data this produces.
access_log /dev/stdout full;
```

### The `json` name still works

An existing consumer config saying `access_log /dev/stdout json;` keeps working
and now produces the **minimised** output — `json` is an alias of the privacy
format. Silently becoming more private is the right failure mode; breaking the
consumer's config, or silently staying verbose, are both worse.

## Client address truncation

nginx's own `map` directive, and Caddy's own `ip_mask` filter. **No hand-rolled
hashing and no invented cryptography** — a bespoke pseudonymisation scheme is a
cryptographic claim, and this platform is not the place to make one.

IPv4 keeps the `/24`, IPv6 keeps the `/48`. That is enough to see traffic shape,
per-network rate-limit patterns and abuse clustering, and not enough to single
out a subscriber.

### Behind a load balancer

The certified topology terminates TLS upstream, so `$remote_addr` is the load
balancer, not the client. If you need the originating network you must configure
trusted proxies explicitly:

```nginx
# nginx: only then does $remote_addr become the client's address —
# and it is still truncated by the map before it is logged.
set_real_ip_from 10.0.0.0/8;   # YOUR load balancer's range, never 0.0.0.0/0
real_ip_header   X-Forwarded-For;
real_ip_recursive on;
```

`set_real_ip_from 0.0.0.0/0` lets any client forge its own address. It is not a
shortcut; it is a spoofing primitive.

## Caddy

Caddy writes no access log unless a site asks for one — opt-in by Caddy's design,
not ours. What the image controls is what that opt-in produces:

```caddyfile
:8080 {
    import privacy_log      # shipped in the base Caddyfile
    # ... your site
}
```

`privacy_log` uses Caddy's built-in `format filter`: `regexp` strips the query
string name-independently (the `query` filter only acts on parameters you name in
advance, which means maintaining a list of every credential name an application
might invent), `delete` drops the credential headers and `Referer`, and `ip_mask`
truncates **both** `remote_ip` and `client_ip`.

> Masking only `remote_ip` left the full address in `client_ip`. That was found by
> the canary run, not by reading the configuration — which is the argument for
> testing this the way it is tested.

## How this is verified

`scripts/runtime-contract.sh` sends **real requests carrying canary secrets** to
each logging image and greps that container's own log stream:

```text
?token=ZENCHRON_QUERY_CANARY
Authorization: Bearer ZENCHRON_AUTH_CANARY
Cookie: session=ZENCHRON_COOKIE_CANARY
X-Api-Key: ZENCHRON_APIKEY_CANARY
```

Any canary appearing in the log fails the build. Asserting on configuration text
would prove a directive is present; it would not prove the field never reaches
the log.

## What is still the operator's responsibility

This platform controls what the image **emits**. It cannot control what happens
next, and does not claim to:

- **Retention.** Container logs go to your runtime's logging driver. Purpose
  limitation and retention periods are set there, not here.
- **Downstream processors.** A log shipper, SIEM or object store is a processor
  under GDPR and needs its own agreement.
- **Application logs.** PHP's own output is written by your application. Nothing
  in this image filters it.
- **Request bodies.** Never logged by either image, and not something either
  image can filter if an application chooses to log them itself.
