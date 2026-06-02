# Runtime Hardening

Defaults baked into images + enforced by `profiles/compose.security.yml`.

## Identity & filesystem

- **Non-root**: deterministic `UID:GID = 10001:10001`, shell `/sbin/nologin`.
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
LB/ingress and forward to the high ports (8080/8443) — the documented topology.

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

- nginx listens on **8080**, Caddy/FrankenPHP on **8080/8443** (+8081 healthz).
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
- **nginx**: `nginx -t -q` (config validity); the hardened base serves no site
  until an app config is mounted, so readiness is at the orchestrator/LB layer.
- Distroless-pure services: rely on orchestrator TCP/HTTP probes.

## Secrets

Never in images, build args, or ENV defaults. Inject at runtime via the
orchestrator's secret mechanism (Docker/Swarm secrets, k8s Secrets, mounted
files). BuildKit `--secret` mounts for build-time credentials — never `ARG`.
