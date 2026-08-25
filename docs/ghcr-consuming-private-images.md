# Consuming Private GHCR Images

How a production server (Hetzner / any Docker host) securely pulls the **private**
`ghcr.io/zenchron-dynamics/*` images. Pair this with
[production-server-bootstrap.md](production-server-bootstrap.md).

> No real secrets appear in this repo. Every token/value below is a placeholder.

## 1. Package visibility

Packages published by this repo are **private** by default (org policy). Private
is the correct posture: only authorized deploy identities pull them. Do **not**
make them public to "make pulling easier" — that exposes the platform.

Check visibility (org admin / `read:packages`):

```bash
gh api orgs/zenchron-dynamics/packages/container/php-fpm --jq '.visibility'
# -> "private"
```

## 2. Link the package to this repository

Each container package should be linked to `zenchron-dynamics/zenchron-foundry`
so it inherits repo access and shows provenance.

- GitHub UI: Org → Packages → `<package>` → **Package settings** → *Manage
  repository access* / *Inherit access from repository* → add `zenchron-foundry`.
- This is a **UI/admin action** — it cannot be done from this repo's code.

## 3. Grant pull access to a deploy identity

Production must authenticate as a **machine user** or a **fine-grained token**,
never a human admin. Options, most-preferred first:

1. **Dedicated machine user** (e.g. `zenchron-deploy`) added to the org with
   read-only package access, holding a fine-grained PAT scoped to `read:packages`.
2. **Fine-grained PAT** from a service account limited to the org's packages,
   `Packages: Read-only`.
3. (CI only, not servers) the ephemeral `GITHUB_TOKEN`.

## 4. Create a read-only deploy token

Create a token with **only** `read:packages` (classic) or **Packages:
Read-only** (fine-grained). Nothing else.

- Classic PAT: scopes → check **`read:packages`** only. Do **not** check
  `write:packages`, `repo`, `delete:packages`, or `admin:*`.
- Fine-grained PAT: Resource owner `zenchron-dynamics`, Repository access =
  the consuming app repos (or none), **Permissions → Packages: Read-only**.

### Why only `read:packages`

- A server only needs to **pull**. Pull requires read, nothing more.
- If the host is compromised, a read-only token **cannot push** a poisoned image,
  cannot delete packages, cannot touch source. Blast radius = read of images the
  identity could already pull.

### Why not a personal admin token on servers

- A personal admin/`repo`/`write:packages` token on a box means host compromise =
  registry compromise (attacker pushes a backdoored `:8.3-prod`) and possibly
  source/repo compromise. That breaks the whole supply chain. **Never** put an
  admin or push-capable token on a production host.

## 5. Log in from production

```bash
# GHCR_READ_USER  = the machine user, e.g. "zenchron-deploy"
# GHCR_READ_TOKEN = the read:packages token (placeholder)
echo "$GHCR_READ_TOKEN" | docker login ghcr.io -u "$GHCR_READ_USER" --password-stdin
```

`--password-stdin` keeps the token out of shell history and the process list.

## 6. Pull images

```bash
docker pull ghcr.io/zenchron-dynamics/php-fpm:8.3-prod
docker pull ghcr.io/zenchron-dynamics/nginx:prod

# Production should pin by digest (immutable, tamper-evident):
docker pull ghcr.io/zenchron-dynamics/php-fpm@sha256:<digest>
```

Resolve a digest:

```bash
docker buildx imagetools inspect ghcr.io/zenchron-dynamics/php-fpm:8.3-prod \
  --format '{{json .Manifest.Digest}}'
```

## 7. Use the images in Compose

```yaml
services:
  php-fpm:
    image: ghcr.io/zenchron-dynamics/php-fpm@sha256:<digest>   # pin in prod
    pull_policy: always
```

Compose uses the host's `docker login` credentials automatically. Combine with
the shared hardening profiles (see `profiles/`).

## 8. Store the token safely on the server

- Docker writes credentials to `~/.docker/config.json` after `docker login`. On a
  shared host, restrict it: `chmod 600 ~/.docker/config.json`.
- Prefer a **credential helper** (`docker-credential-pass` / `secretservice`) so
  the token is encrypted at rest rather than base64 in plain `config.json`.
- Better: keep the token in your secret manager (Vault, SOPS, systemd
  `LoadCredential`, Hetzner Cloud secrets) and inject at deploy time; run
  `docker login` from a deploy script, not by hand.
- Never bake the token into an image, Compose file, env file committed to git, or
  a `Dockerfile` ARG.

## 9. Rotate the token

1. Create a **new** `read:packages` token for the same identity.
2. Re-run `docker login` on each host with the new token.
3. Verify pulls still work (section 11).
4. **Revoke the old token** (section 10).
5. Rotate on a schedule (e.g. every 90 days) and immediately on suspected leak.

## 10. Revoke the token

- GitHub → Settings → Developer settings → Tokens → **Revoke** (or
  Org → People → machine user → revoke its tokens).
- Revocation is immediate; in-flight `docker pull` using it will start failing.
- After revoke, `docker logout ghcr.io` on hosts that used it and re-login with a
  current token.

## 11. Validation — production CAN pull

```bash
docker logout ghcr.io
echo "$GHCR_READ_TOKEN" | docker login ghcr.io -u "$GHCR_READ_USER" --password-stdin
docker pull ghcr.io/zenchron-dynamics/php-fpm:8.3-prod   # -> Pull complete
docker pull ghcr.io/zenchron-dynamics/nginx:prod         # -> Pull complete
```

## 12. Validation — the token CANNOT push

A read-only token must be rejected on push:

```bash
docker tag ghcr.io/zenchron-dynamics/nginx:prod \
           ghcr.io/zenchron-dynamics/php-fpm:test-denied
docker push ghcr.io/zenchron-dynamics/php-fpm:test-denied
# EXPECTED:
#   denied: permission_denied   (or: denied: installation not allowed ...)
```

If this push **succeeds**, the token is over-scoped — revoke it immediately and
re-issue with only `read:packages`.

> Caveat: do not run the negative push test against the real production namespace
> with a token that might actually have write — it could publish a junk tag. Run
> it only with the read-only token you are validating, where failure is expected.

## 13. Optional but recommended — verify the signature before running

```bash
cosign verify \
  --certificate-identity-regexp \
  '^https://github\.com/zenchron-dynamics/zenchron-foundry/\.github/workflows/publish-(ghcr|rc)\.yml@refs/heads/master$' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ghcr.io/zenchron-dynamics/php-fpm:8.3-prod
```

See [sbom-and-signing.md](sbom-and-signing.md) and `scripts/verify-signatures.sh`.

## 14. Free-tier notes (GitHub Free, public repo, private packages)

Private GHCR consumption works fine on the **Free plan** — package access is
independent of branch-protection limits. What changes on Free is cost/limits
awareness, not capability.

> Scope note: everything in this section covers *consumption* only. It is not a
> governance control and it never was. The older wording here said "private repo"
> and that "repo governance stays advisory" — both were false from 2026-07-28.
> The repository is **public**, so branch and tag rulesets are available on Free
> and are **enforced**: see [repository-security.md](repository-security.md),
> declared in
> [`../policies/repository-governance.yaml`](../policies/repository-governance.yaml)
> and verified in
> [`audits/governance-verification-2026-08-24.json`](audits/governance-verification-2026-08-24.json).
> The accepted-risk record this section used to cite is
> [superseded](audits/free-tier-governance-accepted-risk.md) — do not cite it as
> current.

- **Create the deploy identity manually** in the GitHub UI: a machine/deploy user
  added to the org, then a classic PAT with **`read:packages` only** (no
  `repo`, no `write:packages`, no `delete:packages`, no `admin:*`). PATs cannot
  be minted via API, so this is a one-time UI action.
- **Use the token only on servers** (never in CI — CI uses the ephemeral
  `GITHUB_TOKEN`; never in an image or committed file).
- **Watch storage / data-transfer limits.** GHCR has account storage and monthly
  transfer allowances; private images count against them. Keep images minimal
  (already done via Wolfi), prune old dated tags you no longer need, and avoid
  re-pulling unnecessarily.
- **Avoid repeated unnecessary pulls.** Pin by digest and rely on the local image
  cache; use `pull_policy: missing` (or omit `always`) for stable digests so
  hosts don't re-download every deploy. Pull `always` only when tracking a moving
  `*-prod` tag in lower environments.
- **Pin digests in production** (`@sha256:`) — immutable, tamper-evident, and it
  also makes caching deterministic so you transfer bytes once.

### Exact commands (free-tier consumption)

```bash
docker logout ghcr.io || true

echo "$GHCR_READ_TOKEN" | docker login ghcr.io \
  -u "$GHCR_READ_USER" \
  --password-stdin

docker pull ghcr.io/zenchron-dynamics/php-fpm:8.3-prod
docker pull ghcr.io/zenchron-dynamics/nginx:prod
```

### Negative push test (read-only token must be denied)

```bash
docker tag ghcr.io/zenchron-dynamics/php-fpm:8.3-prod \
           ghcr.io/zenchron-dynamics/php-fpm:test-denied
docker push ghcr.io/zenchron-dynamics/php-fpm:test-denied
# EXPECTED:
#   denied: permission_denied
```

Run the negative test **only** with the read-only token you are validating, where
failure is the expected outcome — never with a write-capable token against the
real namespace.
