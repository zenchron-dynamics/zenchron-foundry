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

Add back **only** what a service provably needs, e.g. `NET_BIND_SERVICE` for
nginx/Caddy binding :80/:443 (preferred: terminate TLS at an LB and keep high
ports 8080/8443, dropping the capability entirely).

## Writable-path exceptions (read-only rootfs)

| Workload | Must be writable | Provided via |
|----------|------------------|--------------|
| PHP-FPM | `/tmp`, `/var/run/php` (pid/socket) | tmpfs |
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

- nginx listens on **8080**, Caddy/FrankenPHP on **8080/8443**.
- Bind :80/:443 only by adding `NET_BIND_SERVICE`, or (preferred) let an
  upstream LB/ingress terminate TLS and forward to high ports.

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

## Healthchecks without curl/wget

- FPM: `cgi-fcgi` queries `ping.path` (`/-/fpm-ping` → `pong`).
- nginx: `nginx -t -q`.
- caddy / frankenphp: `caddy version` / `frankenphp version`.
- Distroless-pure services: rely on orchestrator TCP/HTTP probes.

## Secrets

Never in images, build args, or ENV defaults. Inject at runtime via the
orchestrator's secret mechanism (Docker/Swarm secrets, k8s Secrets, mounted
files). BuildKit `--secret` mounts for build-time credentials — never `ARG`.
