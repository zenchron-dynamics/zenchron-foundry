# SELinux and the Foundry images

**Issue:** #129

**Foundry ships no custom SELinux policy module, on purpose.**

On RHEL-family hosts the `container-selinux` policy already confines containers
as `container_t` with per-container MCS categories, which is the confinement a
custom module would be reimplementing. Shipping a module that a customer must
`semodule -i` onto their hosts is a support burden — it has to be rebuilt for
each policy version, it needs root on every node, and it is one more thing that
can drift from the images it constrains — for no gain over enabling what the
platform already provides.

What matters is that the images are *compatible* with that confinement, which is
what the runtime contract harness establishes: they run non-root, read-only, with
no capabilities and no writes outside their declared tmpfs, which is exactly the
shape `container_t` permits.

## Verifying confinement on an SELinux host

```bash
# Is SELinux enforcing?
getenforce                       # -> Enforcing

# What type is the container process running as?
docker run -d --name zc ghcr.io/zenchron-dynamics/nginx:prod
ps -eZ | grep "$(docker inspect -f '{{.State.Pid}}' zc)"
# -> system_u:system_r:container_t:s0:c123,c456   <- container_t, with MCS
```

## Relabelling mounted volumes

A bind-mounted host directory is not automatically accessible to `container_t`.
Use the standard suffixes rather than disabling SELinux for the container:

| suffix | meaning |
| --- | --- |
| `:z` | relabel shared — the content may be used by **multiple** containers |
| `:Z` | relabel private — the content is for **this** container only |

```bash
docker run -v ./deploy/nginx/app.conf:/etc/nginx/conf.d/app.conf:ro,Z ...
```

**Do not** use `--security-opt label=disable` to make a mount work. That removes
the confinement for the whole container, which is the outcome this document
exists to prevent; `assert-runtime-profiles.sh` fails on it appearing in any
shipped profile or example.

## Pod Security / Kubernetes

The equivalent expectations for a Kubernetes deployment — `runAsNonRoot`,
`readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`,
`capabilities.drop: [ALL]`, `seccompProfile.type: RuntimeDefault` — belong with
the admission policies in **#124** and are not duplicated here.
