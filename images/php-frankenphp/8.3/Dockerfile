# syntax=docker/dockerfile:1.7
# =============================================================================
# Zenchron Dynamics — php-frankenphp 8.3 (production, Debian-first)
# Modern PHP app server with embedded Caddy. Single binary replaces
# php-fpm + nginx/caddy. FrankenPHP requires PHP >= 8.2, so 7.4/8.0 do NOT and
# CANNOT exist for this family — by design.
# Base: official dunglas/frankenphp:1-php8.3-bookworm (Debian 12), pinned by
# digest. Extensions are installed with the image's official helper, which
# compiles them and removes its own build tooling.
# Non-root, listens on high ports (8080 HTTP, 8081 healthz); bind :80/:443 only via
# cap_add NET_BIND_SERVICE or an upstream LB. See docs/runtime-hardening.md.
# Patch model: bump the pinned base digest to absorb CVEs — do NOT apt-get
# upgrade inside the image (see docs/security/base-image-patching.md).
# =============================================================================
ARG FRANKENPHP_BASE="dunglas/frankenphp:1-php8.3-bookworm@sha256:6383ab28a5f5dff524085a58fa9a3073150680abf7173a744dd847e7bdd2b7d2"

FROM ${FRANKENPHP_BASE} AS runtime

ARG BUILD_DATE
ARG VCS_REF

LABEL org.opencontainers.image.title="zenchron-php-frankenphp" \
      org.opencontainers.image.description="Hardened FrankenPHP 8.3 app server (embedded Caddy), Debian-based" \
      org.opencontainers.image.vendor="Zenchron Dynamics" \
      org.opencontainers.image.source="https://github.com/zenchron-dynamics/zenchron-foundry" \
      org.opencontainers.image.base.name="docker.io/dunglas/frankenphp:1-php8.3-bookworm" \
      org.opencontainers.image.version="8.3-prod" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.licenses="LicenseRef-Zenchron-Internal" \
      com.zenchron.runtime="php-frankenphp" \
      com.zenchron.php="8.3" \
      com.zenchron.base="debian-bookworm" \
      com.zenchron.support="supported" \
      com.zenchron.support_state="security-only"

# Install production PHP extensions via the official helper bundled in the image
# (compiles with the official toolchain, then removes its build deps). Adjust the
# set per docs/php-extension-policy.md.
RUN set -eux; \
    install-php-extensions \
        opcache \
        intl \
        pdo_pgsql \
        pgsql \
        pdo_mysql \
        zip \
        gd \
        bcmath \
        pcntl \
        sockets \
        redis

# Deterministic non-root identity + writable runtime dirs under /tmp so a single
# tmpfs satisfies a read-only rootfs. Strip cap_net_bind_service from the
# frankenphp binary so it execs under cap_drop: ALL + no-new-privileges (we use
# high ports + upstream TLS). libcap2-bin provides setcap on Debian.
# Also strip the compiler toolchain the FrankenPHP/php base inherits from
# buildpack-deps (gcc + /usr/lib/gcc, ~100MB) + the PHP source tarball + static
# archives: install-php-extensions already compiled everything, so no build tools
# are needed at runtime (validation gate: "no build tools in final image").
COPY healthcheck /usr/local/bin/frankenphp-healthcheck
# hadolint ignore=DL3008
# Capability removal and toolchain deletion are FAIL-CLOSED (#100). This block
# used to hide three failures behind `|| true`: `setcap -r ... 2>/dev/null ||
# true` (a missing binary or failed removal shipped the capability anyway),
# `find ... -delete 2>/dev/null || true` (static archives could survive), and
# `groupadd/useradd ... || true` (a failed identity yields an image whose USER
# does not exist). Each step is now load-bearing and each removal is PROVEN.
#
# Ordering is deliberate: getcap lives in libcap2-bin, so the whole-image scan
# runs AFTER every purge/delete but BEFORE libcap2-bin itself is removed —
# otherwise the verifier would be gone before there was anything final to verify.
# scripts/ci/capability-inventory.sh re-checks the assembled image from outside,
# which also covers every layer added after this one.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends libcap2-bin; \
    test -x /usr/local/bin/frankenphp; \
    setcap -r /usr/local/bin/frankenphp; \
    if [ -n "$(getcap /usr/local/bin/frankenphp)" ]; then \
        echo "REFUSE: frankenphp still carries: $(getcap /usr/local/bin/frankenphp)" >&2; \
        exit 1; \
    fi; \
    apt-get purge -y --auto-remove \
        gcc g++ cpp make autoconf binutils dpkg-dev libc6-dev linux-libc-dev m4 patch re2c; \
    rm -f /usr/local/bin/phpize /usr/local/bin/docker-php-source; \
    rm -rf /usr/src/*; \
    find / -xdev -name '*.a' -delete; \
    if [ -n "$(find / -xdev -name '*.a' -print -quit)" ]; then \
        echo "REFUSE: static archives survived deletion:" >&2; \
        find / -xdev -name '*.a' >&2; \
        exit 1; \
    fi; \
    remaining="$(getcap -r / 2>/dev/null)"; \
    if [ -n "${remaining}" ]; then \
        echo "REFUSE: file capabilities remain in the final image:" >&2; \
        echo "${remaining}" >&2; \
        exit 1; \
    fi; \
    apt-get purge -y --auto-remove libcap2-bin; \
    rm -rf /var/lib/apt/lists/*; \
    # #101: build RESIDUE, not image content. apt/dpkg logs record WHEN the
    # build ran and ldconfig's aux-cache embeds timestamps, so two builds of the
    # same commit differed in exactly these 8 files out of 3505 — enough to
    # change a layer digest while the served content was identical. Removing
    # them makes the layer reproducible, and also stops shipping a record of the
    # build host's clock to consumers.
    rm -rf /var/log/apt /var/log/dpkg.log /var/log/alternatives.log \
           /var/cache/ldconfig/aux-cache; \
    groupadd -g 10001 app; \
    useradd  -u 10001 -g app -d /app -s /usr/sbin/nologin -M app; \
    mkdir -p /app /tmp/caddy-data /tmp/caddy-config; \
    chown -R 10001:10001 /app /tmp/caddy-data /tmp/caddy-config; \
    chmod 0555 /usr/local/bin/frankenphp-healthcheck

# Hardened production config.
COPY Caddyfile        /etc/frankenphp/Caddyfile
COPY php.ini          /usr/local/etc/php/conf.d/zz-zenchron.ini

ENV SERVER_NAME=":8080" \
    FRANKENPHP_CONFIG="" \
    XDG_DATA_HOME=/tmp/caddy-data \
    XDG_CONFIG_HOME=/tmp/caddy-config

USER 10001:10001
WORKDIR /app
EXPOSE 8080 8081

# Readiness probe: hit the always-on /healthz site (proves the embedded server is
# serving HTTP, not just that the binary runs). Uses the bundled php binary —
# no curl/wget in the hardened Debian image.
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/frankenphp-healthcheck"]

ENTRYPOINT ["frankenphp"]
CMD ["run", "--config", "/etc/frankenphp/Caddyfile"]
