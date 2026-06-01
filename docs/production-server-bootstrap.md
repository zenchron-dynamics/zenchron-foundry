# Production Server Bootstrap (Docker Compose)

Bring a fresh Hetzner/Ubuntu (or any Linux) host to the point where it can
securely pull and run `ghcr.io/zenchron-dynamics/*` images. Companion to
[ghcr-consuming-private-images.md](ghcr-consuming-private-images.md).

> Placeholders only. Replace `<…>` with your real values at deploy time.

## 0. Assumptions

- A non-root sudo user (e.g. `deploy`) exists; you do **not** run containers as
  the host root user where avoidable.
- TLS terminates at a load balancer / reverse proxy in front of the host (images
  listen on high ports 8080/8443, not 80/443).

## 1. Install Docker Engine + Compose plugin

```bash
curl -fsSL https://get.docker.com | sh           # or distro packages
sudo usermod -aG docker deploy                    # so 'deploy' can run docker
# log out/in for the group to take effect
docker version && docker compose version
```

## 2. Create the read-only GHCR login

Use a **machine user** + `read:packages` token (never a personal/admin token —
see the consuming doc, §4). Inject the token from your secret store, do not paste
it into history:

```bash
export GHCR_READ_USER="<machine-user>"
GHCR_READ_TOKEN="$(cat /run/secrets/ghcr_read_token)"   # from your secret store
echo "$GHCR_READ_TOKEN" | docker login ghcr.io -u "$GHCR_READ_USER" --password-stdin
unset GHCR_READ_TOKEN
chmod 600 ~/.docker/config.json
```

Recommended: a **credential helper** so the token is encrypted at rest:

```bash
sudo apt-get install -y pass docker-credential-pass   # example
# configure ~/.docker/config.json: { "credsStore": "pass" }
```

## 3. Lay down the deploy directory

```text
/opt/<app>/
├── compose.yml                  # your app stack
├── compose.prod.yml             # prod overrides (digests, replicas)
├── profiles/                    # copied from zenchron-foundry/profiles
│   ├── compose.security.yml
│   ├── compose.readonly.yml
│   └── compose.laravel.yml      # or compose.symfony.yml
└── deploy/
    ├── nginx/app.conf            # from images/nginx/conf.d/app.conf.example
    └── env/                      # secrets injected at runtime, NOT committed
```

## 4. Pull (pin by digest)

```bash
docker pull ghcr.io/zenchron-dynamics/php-fpm@sha256:<digest>
docker pull ghcr.io/zenchron-dynamics/nginx:prod
```

## 5. (Recommended) verify signatures before first run

```bash
# install cosign once
curl -sSfL https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64 \
  -o /usr/local/bin/cosign && chmod +x /usr/local/bin/cosign
cosign verify \
  --certificate-identity-regexp 'https://github.com/zenchron-dynamics/zenchron-foundry/.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ghcr.io/zenchron-dynamics/php-fpm:8.3-prod
```

## 6. Bring the stack up with hardening profiles

```bash
cd /opt/<app>
docker compose \
  -f compose.yml \
  -f compose.prod.yml \
  -f profiles/compose.security.yml \
  -f profiles/compose.readonly.yml \
  -f profiles/compose.laravel.yml \
  up -d
docker compose ps
```

## 7. Secrets injection (never in images)

- Use Docker/Compose secrets, systemd `LoadCredential`, or your secret manager to
  mount app secrets at runtime.
- App `.env` lives on the host (mode `600`, owner `deploy`) or is rendered from
  the secret store at deploy — **never** committed and **never** baked into an
  image (the example `.dockerignore` enforces this for image builds).

## 8. Token hygiene on the host

- `chmod 600 ~/.docker/config.json`; prefer a credential helper.
- Rotate the GHCR token on schedule and on suspected leak (consuming doc, §9).
- `docker logout ghcr.io` when decommissioning a host.

## 9. Validation

```bash
# Login works and can pull:
docker logout ghcr.io
echo "$GHCR_READ_TOKEN" | docker login ghcr.io -u "$GHCR_READ_USER" --password-stdin
docker pull ghcr.io/zenchron-dynamics/php-fpm:8.3-prod
docker pull ghcr.io/zenchron-dynamics/nginx:prod

# Token cannot push (expected: denied):
docker tag ghcr.io/zenchron-dynamics/nginx:prod ghcr.io/zenchron-dynamics/php-fpm:test-denied
docker push ghcr.io/zenchron-dynamics/php-fpm:test-denied   # -> denied: permission_denied

# Stack is healthy:
docker compose ps        # php-fpm/nginx/worker -> healthy
```

## 10. What requires the GitHub UI / org admin (cannot be scripted from this repo)

- Creating the machine user and its `read:packages` token.
- Linking each GHCR package to the repository.
- Setting/confirming package visibility.

These are noted explicitly so they are not mistaken for code-enforceable steps.
