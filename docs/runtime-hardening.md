# Runtime Hardening

Defaults baked into images + enforced by `profiles/compose.security.yml`.

**The contract is declared once and executed once** (#110):
[`policies/runtime-contract.yaml`](../policies/runtime-contract.yaml) holds the
invariants and the profile; `scripts/runtime-contract.sh` runs **every** image
under that profile and reads `/proc/1` — the real entrypoint process — to verify
identity, capabilities, `NoNewPrivs`, seccomp mode, mount flags, listeners, the
PID limit, healthcheck behaviour and graceful shutdown.

Before it existed, each family's smoke test applied a *different subset* of the
advertised hardening: the FrankenPHP smoke started with `--read-only --tmpfs /tmp`
and omitted `cap_drop ALL`, no-new-privileges, PID limits and the
noexec/nosuid/nodev flags entirely. An image could pass its smoke test and still
fail under the profile this document tells you to deploy with.

Latest full-matrix result: **10/10 images executed, 164 checks, 0 failures** —
[`docs/audits/runtime-contract-2026-08-12.json`](audits/runtime-contract-2026-08-12.json).

Syscall and mandatory-access-control confinement: [`security/`](../security)
(#129). Access-log privacy: [logging-privacy.md](logging-privacy.md) (#107).

## Identity & filesystem

- **Non-root**, per image. Nine of the ten images run as the platform identity
  `UID:GID = 10001:10001` with shell `/sbin/nologin`. **nginx runs as `101:101`**
  — it is built on the upstream `nginx-unprivileged` base, which owns
  `/etc/nginx` and its temp paths as 101, so forcing 10001 makes mounted configs
  and assets behave differently from the image's own expectations (#118).
  The identity of each image is declared in
  [`contracts/images/<image>.yaml`](../contracts/images) (`user:`), asserted
  against the built image by `scripts/verify-image-contract.sh`, and matched
  service-by-service in `profiles/compose.security.yml` — which no longer sets a
  single global `user:` for everything.
- **Read-only root filesystem** (`read_only: true`). Writable paths are
  externalized as tmpfs or volumes — never a writable rootfs.
- **tmpfs** for scratch: `/tmp`, `/run` mounted `noexec,nosuid,nodev`.

## Kernel / capabilities

```yaml
cap_drop: [ALL]
security_opt: ["no-new-privileges:true"]
pids_limit: 256
# privileged: NEVER. docker.sock: NEVER mounted.
```

The runtime images need **zero** Linux capabilities: PHP-FPM/CLI/worker, nginx
(unprivileged), and Caddy/FrankenPHP all run with `cap_drop: ALL`. The Caddy and
FrankenPHP binaries ship a `cap_net_bind_service` file capability that the
platform images **strip at build** — otherwise the binary fails to exec under
`cap_drop: ALL` + `no-new-privileges` (`operation not permitted`). Consequence:
these images cannot bind :80/:443 directly; terminate TLS at an upstream
LB/ingress and forward to the high ports (8080) — the documented topology.

### How the strip is enforced (#100)

The removal used to be `setcap -r … 2>/dev/null || true`, so a missing binary, an
absent `setcap`, or a failed removal produced a **green build shipping an image
that cannot start** under the profile above. It is now fail-closed and proven at
three levels:

1. **In the build** — the binary must exist, `setcap`/`getcap` must be present,
   the removal must succeed, the binary must afterwards carry no capability, and
   `getcap -r /` must find **none anywhere** in the image. Any of these REFUSEs
   the build. (Caddy runs no `apk` commands per ADR-0001, so a missing `setcap`
   cannot be installed there — it must fail the build, not be skipped. For
   FrankenPHP the whole-image scan runs *before* `libcap2-bin` is purged, or the
   verifier would be gone before there was anything final to verify.)
2. **On the assembled image** — `scripts/ci/capability-inventory.sh` reads file
   capabilities from `docker export`'s PAX `SCHILY.xattr.security.capability`
   records, needing **no tools inside the image**. That is what makes it work for
   FrankenPHP (which purges `libcap2-bin`) and for any future distroless image
   with no shell. It runs for **all 10 images** from `scripts/smoke/lib.sh`, and
   `trusted-validation.yml` publishes its JSON as part of the
   `trusted-validation-<sha>-*` artifact — on failure too, since that is when the
   offending paths are worth having. (It is no longer `ci.yml`: #96 moved the
   build+smoke matrix out of the pull-request path.)
3. **At runtime** — the Caddy and FrankenPHP smoke tests start the container
   with `--cap-drop ALL --security-opt no-new-privileges`, so a surviving
   capability shows up as a container that cannot serve, not as a passing test.

The same `|| true` shape was removed from the FrankenPHP static-archive deletion
and the user/group creation: a failed `useradd` would otherwise yield an image
whose `USER` does not exist.

### Two-architecture verification

| Image | Arch | File capabilities | Execs under `cap_drop: ALL` + `no-new-privileges` | Date |
|---|---|---|---|---|
| `caddy` | amd64, arm64 | 0 | yes | 2026-07-28 |
| `php-frankenphp:8.4` | amd64, arm64 | 0 | yes | 2026-07-28 |
| `php-frankenphp:8.3` | amd64 | 0 | yes | 2026-07-28 |
| `php-frankenphp:8.3` | **arm64** | **0** | **yes** | **2026-08-01** |

The 8.3/arm64 run closes the last untested combination (#100). Built natively on
an arm64 host from
`dunglas/frankenphp:1-php8.3-bookworm@sha256:6383ab28a5f5dff524085a58fa9a3073150680abf7173a744dd847e7bdd2b7d2`
at repository revision `4fc83eed3e670ed289efc9256c4a785f1eb5c309`; image id
`sha256:326f8f73a778ac2aac4497b5c637c29564e0e1011f45d73e8824b964ada69d4a`.
Inventory verdict `PASS`, `count: 0`; the full smoke suite passed 8/8, and the
container served `/healthz` with `--cap-drop ALL --security-opt
no-new-privileges --read-only`.

**Negative control, same host and profile.** The unmodified upstream base still
ships `/usr/local/bin/frankenphp` with `net_bind_service` (effective), inventory
verdict `FAIL`, and cannot be exec'd at all:

```console
$ docker run --rm --cap-drop ALL --security-opt no-new-privileges \
    dunglas/frankenphp:1-php8.3-bookworm@sha256:6383ab... frankenphp version
/usr/local/bin/docker-php-entrypoint: 9: exec: frankenphp: Operation not permitted
rc=126
```

The same command against the hardened image runs the binary. That contrast is
the regression this guards against: a file capability does not merely add
privilege, it makes the binary unexecutable under the profile these images are
certified for.

## Writable-path exceptions (read-only rootfs)

| Workload | Must be writable | Provided via |
|----------|------------------|--------------|
| PHP-FPM | `/tmp` only (foreground PID 1, no pid file) | tmpfs |
| Laravel | `storage/`, `bootstrap/cache/` | named volume |
| Symfony | `var/cache/`, `var/log/`, `var/sessions/` | named volume (`/app/var`) |
| Uploads | app upload dir | volume (or object storage — preferred) |
| Cache warmup | framework cache dir | volume; warm at build time when possible |
| Sessions | session save path | Redis/DB (preferred) or tmpfs |
| nginx | temp paths (`/tmp/*_temp`) | tmpfs (`nginx.conf` points there) |
| Caddy | `/data`, `/config` (certs/state) | volume |

`profiles/compose.readonly.yml` wires these up; adjust per framework.

## Ports & privilege

Non-root cannot bind ports < 1024. Therefore:

- nginx listens on **8080**, Caddy on **8080** (**no TLS** — see below),
  FrankenPHP on **8080/8443** (+8081 healthz).
- Binding :80/:443 directly is **not supported** by the hardened images (Caddy/
  FrankenPHP have their `cap_net_bind_service` file cap stripped so they run with
  zero caps). Terminate TLS at an upstream LB/ingress and forward to high ports.

## Workers: signals & graceful shutdown

- One process per container. **No supervisor** unless strictly justified
  (supervisor masks crashes, complicates signals, and runs as a long-lived
  parent — prefer the orchestrator's restart policy).
- `tini` is PID 1 to reap zombies and forward `SIGTERM`.
- Workers self-recycle to bound memory:
  - Laravel: `queue:work --max-time=3600 --max-jobs=1000 --memory=200`
  - Symfony: `messenger:consume --time-limit=3600 --memory-limit=256M --limit=1000`
- Compose: `stop_grace_period: 35s`, `stop_signal: SIGTERM`,
  `restart: unless-stopped`. Allow in-flight jobs to finish before SIGKILL.
- Memory: container `mem_limit` should sit **above** the worker `--memory`
  self-restart threshold so the app recycles before the OOM killer fires.

## Healthchecks

- **FPM**: the bundled `php` binary probes the FPM TCP listener
  (`fsockopen 127.0.0.1:9000`) — a successful connect means FPM accepts work.
  No curl/wget/cgi-fcgi needed.
- **worker**: heartbeat freshness — `worker-healthcheck` checks the epoch in
  `/tmp/worker-heartbeat` (see [worker-runtime.md](worker-runtime.md)).
- **caddy / frankenphp**: **real HTTP readiness** — an always-on `:8081/healthz`
  site answers `200`, probed with the alpine base's `wget`. This proves the
  server is actually serving HTTP, not merely that the binary exists.
- **nginx**: **real HTTP readiness** — the image ships its own always-on
  `:8081/healthz` listener (`conf.d/00-readiness.conf`) and the healthcheck
  performs a request against it, requiring `200` with body `ok`. The probe is
  `/usr/local/bin/nginx-healthcheck`, using `IO::Socket::INET` from `perl-base`
  so no HTTP client has to be re-added to an image that deliberately purged
  `curl` (#102/#103).
  This replaced `nginx -t -q`, which parsed the config and exited: it reported a
  hung, unforked or non-listening nginx as healthy (#127). Verified
  behaviourally in `scripts/smoke/smoke-nginx.sh`, which SIGSTOPs every nginx
  process and asserts the config test still passes while the probe fails.
  APPLICATION readiness — is the site config mounted, is php-fpm reachable —
  remains the orchestrator's/LB's business, on the consumer's own `:8080` site.
- Distroless-pure services: rely on orchestrator TCP/HTTP probes.

## Secrets

Never in images, build args, or ENV defaults. Inject at runtime via the
orchestrator's secret mechanism (Docker/Swarm secrets, k8s Secrets, mounted
files). BuildKit `--secret` mounts for build-time credentials — never `ARG`.
