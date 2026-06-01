# Worker Runtime & Liveness

`php-worker` runs one long-running process per container (Laravel `queue:work`,
Symfony `messenger:consume`, cron-like loops). This documents the liveness
strategy shipped in the image and how to use it honestly.

## Design decision

We implemented **Option B — a generic heartbeat wrapper** (`worker-entrypoint`)
plus a freshness healthcheck (`worker-healthcheck`), because a naive "the process
exists" check hides deadlocks. The wrapper is honest about what it proves:

- `WORKER_HEARTBEAT_AUTO=1` (default): the wrapper refreshes the heartbeat while
  the worker **process** is alive → **process-liveness**. It does *not* detect a
  deadlocked-but-alive worker. Good enough to catch a crashed/exited worker that
  Docker's restart policy will then recycle.
- `WORKER_HEARTBEAT_AUTO=0`: the wrapper writes only the initial beat; the
  **application** must write `date +%s` (epoch) into the heartbeat file each
  successful job loop → **work-liveness**. A frozen app stops writing → the
  healthcheck goes stale → the container is marked unhealthy.

> The healthcheck reads the **epoch stored in the file** (not the file mtime), so
> a stuck worker genuinely ages out even if some unrelated process touches it.

The scripts live in each worker version's build context
(`images/php-worker/<ver>/worker-entrypoint` and `worker-healthcheck`); they are
byte-identical across versions. A single `shared/` directory was considered but
each image uses its own build context, and restructuring the CI/Makefile build
contexts was out of scope for this pass — the duplication is two small POSIX
scripts kept in sync.

## How it behaves

- `tini` is PID 1 (reaps zombies, forwards signals); it execs `worker-entrypoint`,
  which execs your worker command.
- On `SIGTERM`/`SIGINT`/`SIGQUIT`/`SIGHUP`, the wrapper forwards the signal to the
  worker so it finishes the current job and exits; the container then exits with
  the **worker's** exit code.
- Heartbeat file: `/tmp/worker-heartbeat` (tmpfs) → works under read-only rootfs.
- No `curl`/`wget` needed.
- Custom commands are unaffected — the wrapper just runs `"$@"`.

## Environment variables

| Var | Default | Meaning |
|-----|---------|---------|
| `WORKER_HEARTBEAT_FILE` | `/tmp/worker-heartbeat` | heartbeat path (keep in tmpfs) |
| `WORKER_HEARTBEAT_AUTO` | `1` | `1`=process-liveness; `0`=app writes heartbeat (work-liveness) |
| `WORKER_HEARTBEAT_INTERVAL` | `15` | seconds between auto beats (when AUTO=1) |
| `WORKER_HEARTBEAT_MAX_AGE` | `90` | healthcheck staleness threshold (seconds) |

## Recommended: app-level heartbeat (work-liveness)

For real work-liveness, set `WORKER_HEARTBEAT_AUTO=0` and have the worker touch
the heartbeat after each job.

**Laravel** — in a queue event listener or job middleware:

```php
Queue::after(function () {
    @file_put_contents('/tmp/worker-heartbeat', (string) time());
});
```

**Symfony Messenger** — subscribe to `WorkerRunningEvent` / `WorkerMessageHandledEvent`:

```php
public function onHandled(WorkerMessageHandledEvent $e): void
{
    @file_put_contents('/tmp/worker-heartbeat', (string) time());
}
```

Set `WORKER_HEARTBEAT_MAX_AGE` comfortably above your slowest expected job.

## Restart & memory guidance

- Prefer self-recycling worker flags over relying on the healthcheck:
  Laravel `--max-time=3600 --max-jobs=1000 --memory=200`; Symfony
  `--time-limit=3600 --memory-limit=256M --limit=1000`.
- Compose: `restart: unless-stopped`, `stop_grace_period: 35s`,
  `stop_signal: SIGTERM`. Container `mem_limit` should sit **above** the worker
  `--memory` threshold so the app recycles before the OOM killer.
- One process per container; scale with replicas, not a supervisor.

## Validation

```bash
docker build images/php-worker/8.3
IMG=$(docker build -q images/php-worker/8.3)

# process-liveness (default): healthy while running, under read-only rootfs
docker run -d --read-only --tmpfs /tmp:size=16m --name w "$IMG" sleep 60
docker exec w /usr/local/bin/worker-healthcheck && echo healthy
docker stop w        # fast, graceful (SIGTERM forwarded)

# work-liveness: stale content -> unhealthy
docker run -d --tmpfs /tmp:size=16m -e WORKER_HEARTBEAT_AUTO=0 --name w2 "$IMG" sleep 60
docker exec w2 sh -c 'echo 100 > /tmp/worker-heartbeat'
docker exec -e WORKER_HEARTBEAT_MAX_AGE=5 w2 /usr/local/bin/worker-healthcheck; echo "exit=$? (1=stale)"
docker stop w2
```
