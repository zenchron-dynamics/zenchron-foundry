# syntax=docker/dockerfile:1.7
# =============================================================================
# Zenchron Dynamics — nginx (production, PHP-FPM front / static server)
# Based on the upstream UNPRIVILEGED nginx image, DEBIAN (bookworm) variant:
# already non-root and listens on :8080 by default. Bind :80/:443 only via
# NET_BIND_SERVICE or upstream LB.
# Read-only-rootfs compatible (nginx temp paths point to tmpfs; see nginx.conf).
# No default "Welcome to nginx" page is shipped.
# Patch model: bump the pinned base digest to absorb CVEs — do NOT apt-get
# upgrade inside the image (see docs/security/base-image-patching.md).
# =============================================================================
ARG NGINX_BASE="nginxinc/nginx-unprivileged:1.27-bookworm@sha256:f9dfa9c20b2b0b7c5cc830374f22f23dee3f750b6c5291ca7e0330b5c88e6403"

FROM ${NGINX_BASE} AS runtime

ARG BUILD_DATE
ARG VCS_REF

LABEL org.opencontainers.image.title="zenchron-nginx" \
      org.opencontainers.image.description="Hardened nginx for PHP-FPM upstream / static assets, Debian-based" \
      org.opencontainers.image.vendor="Zenchron Dynamics" \
      org.opencontainers.image.source="https://github.com/zenchron-dynamics/zenchron-foundry" \
      org.opencontainers.image.base.name="docker.io/nginxinc/nginx-unprivileged:1.27-bookworm" \
      org.opencontainers.image.version="prod" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.licenses="LicenseRef-Zenchron-Internal" \
      com.zenchron.runtime="nginx" \
      com.zenchron.base="debian-bookworm" \
      com.zenchron.support="supported"

# Already runs as uid 101 (nginx) in the upstream unprivileged image. Switch to
# root only to install our hardened config / fix ownership, then drop back.
USER root

# Targeted Debian SECURITY remediation for the edge proxy. The official nginx
# image lags Debian's published point releases (no fresher upstream tag exists),
# so without this the image ships stale openssl/gnutls/xml/etc. This is NOT a
# blanket `apt-get upgrade`: it upgrades ONLY the named, CVE-bearing runtime
# libraries of a TLS-handling edge component to their Debian security versions,
# so the image passes the enforcing fixable-CRITICAL/HIGH gate. Reviewed weekly;
# see docs/security/base-image-patching.md and docs/vulnerability-management.md.
# hadolint ignore=DL3008
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends --only-upgrade \
        libssl3 openssl libgnutls30 \
        libpam0g libpam-modules libpam-modules-bin libpam-runtime libsystemd0 \
        libudev1 gpgv libcap2 libnghttp2-14 perl-base zlib1g; \
    apt-get purge -y --auto-remove \
        curl \
        nginx-module-image-filter nginx-module-xslt nginx-module-njs nginx-module-geoip \
        libtiff6 libexpat1; \
    rm -rf /var/lib/apt/lists/*; \
    if command -v curl >/dev/null 2>&1; then \
        echo "REFUSE: curl survived removal" >&2; exit 1; \
    fi; \
    for pkg in curl libcurl4 libssh2-1 libaom3 libheif1 libgssapi-krb5-2 \
               libxml2 libxslt1.1 libtiff6 libexpat1 libgd3; do \
        st="$(dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null || true)"; \
        case "$st" in *"install ok installed"*) \
            echo "REFUSE: $pkg survived removal" >&2; exit 1 ;; \
        esac; \
    done; \
    test -x /usr/sbin/nginx; \
    nginx -v

# Remove the default site / welcome page, install our hardened config.
# Attack-surface removal (#102/#103) is folded into the upgrade layer above —
# a purge in a LATER layer only adds whiteouts and cannot reclaim the bytes.
#
# `curl` is installed by the upstream base and has ZERO reverse dependencies
# here (`apt-cache rdepends --installed curl` -> none); the healthcheck is
# `nginx -t -q` and no shipped config or script invokes it. Purging it lets
# autoremove take libcurl4 and transitively libssh2-1 and the krb5 stack — none
# of which is linked into the nginx binary (`ldd $(command -v nginx)` shows only
# libcrypt, libpcre2-8, libssl, libcrypto, libz, libc).
#
# The four dynamic modules the upstream base ships are ALL unloaded here — no
# `load_module` directive exists in any shipped config — and each drags a
# decoder/parser stack in with it:
#   image-filter -> libgd3 -> libheif1 -> libaom3/libavif15  (AVIF/HEIF decoders)
#   xslt         -> libxslt1.1 -> libxml2                    (XML parser)
#   njs          -> libxml2
#   geoip        -> libgeoip
# Purging them removes those stacks outright, including libxml2 and its
# CVE-2026-6653 use-after-free. libtiff6/libexpat1 are then orphaned (no reverse
# dependencies) and go too.
#
# CONSUMER-VISIBLE: a consumer that needs image_filter, xslt, njs or geoip must
# load it from a derived image or use the upstream nginx image — see
# docs/security/triage-2026-07-28-ungoverned-findings.md.
#
# Deliberately KEPT: libacl1 (required by coreutils/tar/sed) and gzip
# (Priority: required) — removing either breaks the base.
RUN rm -f /etc/nginx/conf.d/default.conf /usr/share/nginx/html/index.html 2>/dev/null || true
COPY nginx.conf       /etc/nginx/nginx.conf
COPY conf.d/          /etc/nginx/conf.d/
RUN chown -R 101:101 /etc/nginx

USER 101:101
EXPOSE 8080

# nginx -t style liveness; on read-only rootfs ensure tmpfs for temp paths.
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD ["nginx", "-t", "-q"]

STOPSIGNAL SIGQUIT
ENTRYPOINT ["nginx", "-g", "daemon off;"]
