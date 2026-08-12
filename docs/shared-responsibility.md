# Shared responsibility

**Issue:** #125

This platform controls what an image **contains and emits**. It cannot control
what happens once you run it, and does not claim to.

## Zenchron Foundry is responsible for

- **Image contents** — base digest pinning, upstream lifecycle tracking
  (`policies/lifecycle.yaml`), and every external build input being pinned and
  checksummed (`policies/supply-chain-inputs.yaml`).
- **Vulnerability posture at build time** — every CRITICAL/HIGH reconciled
  against a scoped, dated, owner-attributed record, or the build fails.
- **The hardened runtime contract** — non-root, read-only rootfs, zero
  capabilities, no-new-privileges, bounded PIDs, hardened tmpfs, no unexpected
  listeners. Executed against all ten images
  (`docs/audits/runtime-contract-2026-08-12.json`).
- **What the image logs** — no query strings, no credential headers, truncated
  client addresses by default (`docs/logging-privacy.md`).
- **Provenance and integrity** — SBOMs, digest-bound release evidence, and
  signing identities scoped per role.
- **Telling you when something changes** — deprecation, withdrawal and security
  advisories, per `docs/product-support-policy.md`.

## You are responsible for

- **Running it under the documented profile.** The controls above are proven
  *under* `profiles/compose.security.yml`. Running with `--privileged`,
  `seccomp=unconfined`, host namespaces or a mounted Docker socket removes them,
  and `scripts/assert-runtime-profiles.sh` demonstrates exactly what each of
  those undoes.
- **Pinning by digest.** Tags move. Every guarantee here is about a digest.
- **Log retention and downstream processors.** The image emits minimised logs;
  where they go, how long they live, and who can read them are yours. Under
  GDPR your log shipper and SIEM are processors and need their own agreement.
- **Secrets.** Never in images, build args or ENV. Mount at runtime.
- **Network exposure and TLS.** The certified Caddy topology **forbids TLS
  termination**; TLS terminates at your load balancer. Enabling it in a derived
  config leaves the certified topology and re-opens a known remote path
  (`CVE-2026-56852`).
- **Your application code, its dependencies and what it logs.** Nothing in these
  images filters application output.
- **Acting on advisories.** A withdrawal notice is only effective if someone
  reads it and re-pins.

## Where the boundary is genuinely unclear

- **Consumer notification reach.** We publish advisories; we cannot confirm you
  received one. There is no authenticated push channel today — recorded as a
  limitation, not solved.
- **Multi-architecture.** All runtime and vulnerability evidence is currently
  `linux/amd64` (#139). arm64 manifests exist and are label-verified, but are
  not execution-verified.
