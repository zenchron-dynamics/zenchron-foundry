# Runtime confinement reference profiles

**Issue:** #129 · **Contract:** [`policies/runtime-contract.yaml`](../policies/runtime-contract.yaml)

The Compose security profile drops every capability and sets `no-new-privileges`,
then relies on the container runtime's defaults for syscall filtering and
mandatory access control. This directory makes those two layers explicit,
testable and portable — without pretending to more coverage than the environment
actually provides.

## What is here, and what each is worth

| layer | file | enforced by | verified how |
| --- | --- | --- | --- |
| seccomp | [`seccomp/zenchron-default.json`](seccomp/zenchron-default.json) — moby v27.3.1 default, pinned | the container runtime, everywhere | **executed** — every image runs under it in `scripts/runtime-contract.sh` |
| AppArmor | [`apparmor/zenchron-container`](apparmor/zenchron-container) | the host kernel, Debian/Ubuntu hosts | **syntax-validated** always; **executed** only where the host enforces AppArmor |
| SELinux | [`selinux/README.md`](selinux/README.md) | the host kernel, RHEL-family hosts | **documented**; the platform ships no custom policy module |

That table is the honest summary and it is deliberately uneven. Seccomp is
portable and is therefore held to an executable standard. AppArmor and SELinux
are host-kernel features that a CI runner may not have, and evidence that cannot
be produced must not be manufactured — see "What we do not claim" below.

## The seccomp profile is the runtime default, deliberately

`seccomp/zenchron-default.json` is a pinned copy of the container runtime's
default profile, not a hand-written per-image allowlist.

Writing a bespoke syscall allowlist for ten images would have produced a document
that looks stronger and behaves worse. The measured requirement — from the
runtime contract harness, across all ten images — is that every image runs
correctly under the default filter, with `Seccomp: 2` (`SECCOMP_MODE_FILTER`) on
PID 1. A narrower profile has to be re-derived whenever PHP, nginx, Caddy or glibc
changes which syscalls they use, and the failure mode of a stale allowlist is a
container that dies in production on a syscall nobody predicted. The default profile is maintained upstream, tracks those changes, and is itself
**default-deny**: `defaultAction: SCMP_ACT_ERRNO` with an allowlist of 355
unconditionally-permitted syscalls plus 22 capability-conditional groups. Anything
outside that list returns `EPERM`. Measured against the pinned copy:

```text
mount            denied (not in allowlist)
umount2          denied
pivot_root       denied
setns / unshare  denied
init_module      denied
finit_module     denied
kexec_load       denied
bpf              denied
perf_event_open  denied
ptrace           denied
reboot           denied
swapon           denied
```

Every capability-conditional group is unreachable here anyway, because the
contract runs every image with `cap_drop: ALL`.

Pinning it in-repo gives what the default alone does not: a **fixed artefact** the
harness can run against, so "we use the runtime default" becomes a checkable claim
rather than an assumption about whoever's daemon is running.

If a future image genuinely needs a narrower profile, derive it from a measured
syscall trace of that image and give it its own file. Do not narrow this one.

## What we do not claim

- **AppArmor is not enforced on every host.** macOS and Windows Docker hosts, and
  many Kubernetes nodes, do not load AppArmor at all. The profile here is
  validated for syntax on every run and executed only where
  `/sys/kernel/security/apparmor` exists. `scripts/assert-runtime-profiles.sh`
  reports which of the two happened; it never reports the second when only the
  first ran.
- **SELinux ships no policy module.** The container-selinux policy on RHEL-family
  hosts already confines containers with `container_t`, and shipping a custom
  module that must be `semodule -i`-installed on a customer's host is a support
  burden with no security gain over enabling what the platform already has.
  `selinux/README.md` documents the labels and the `--security-opt label=` usage
  instead.
- **None of this substitutes for the capability and privilege controls.** These
  profiles are defence in depth behind `cap_drop: ALL` and `no-new-privileges`,
  which the runtime contract harness verifies on PID 1 of every image.
