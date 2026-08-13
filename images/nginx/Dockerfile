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
# Upstream LINE POLICY: track the nginx STABLE line, not mainline (#104).
# 1.27 was a mainline line and is no longer listed on nginx.org at all — it was
# superseded by the 1.28 stable branch. `stable-bookworm` and `1.28-bookworm`
# resolve to the same digest. Lifecycle state and the maximum permitted lag are
# declared in policies/lifecycle.yaml and gated by scripts/assert-lifecycle.sh.
ARG NGINX_BASE="nginxinc/nginx-unprivileged:1.28-bookworm@sha256:cd33960e98e93d4d63385790ff7f8f5bf2ca95184c581b7f42ae8aea1139fbfc"

FROM ${NGINX_BASE} AS runtime

ARG BUILD_DATE
ARG VCS_REF

LABEL org.opencontainers.image.title="zenchron-nginx" \
      org.opencontainers.image.description="Hardened nginx for PHP-FPM upstream / static assets, Debian-based" \
      org.opencontainers.image.vendor="Zenchron Dynamics" \
      org.opencontainers.image.source="https://github.com/zenchron-dynamics/zenchron-foundry" \
      org.opencontainers.image.base.name="docker.io/nginxinc/nginx-unprivileged:1.28-bookworm" \
      org.opencontainers.image.version="prod" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.licenses="LicenseRef-Zenchron-Internal" \
      com.zenchron.runtime="nginx" \
      com.zenchron.base="debian-bookworm" \
      com.zenchron.support="supported" \
      com.zenchron.support_state="supported"

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
    # #101: build RESIDUE, not image content. apt/dpkg logs record WHEN the
    # build ran and ldconfig's aux-cache embeds timestamps, so two builds of the
    # same commit differed in exactly these 8 files out of 3505 — enough to
    # change a layer digest while the served content was identical. Removing
    # them makes the layer reproducible, and also stops shipping a record of the
    # build host's clock to consumers.
    rm -rf /var/log/apt /var/log/dpkg.log /var/log/alternatives.log \
           /var/cache/ldconfig/aux-cache; \
    # gettext-base ships optional Java bindings for libintl:
    #   /usr/share/java/libintl{,-0.21}.jar plus two under /usr/share/maven-repo.
    # The package stays for envsubst (config templating), which is a C binary and
    # does not use them. There is no JVM in this image, so nothing can execute a
    # jar — they are pure dead weight.
    #
    # They are also the sole reason a scan of this image demanded a Java
    # vulnerability database. Trivy's jar analyzer finds them and initialises the
    # java-db: 905 MiB compressed, 1.5 GB on disk. That database is what broke
    # run 31701249058 (scan FATAL, no report) and then run 31749810234 (the
    # mirror 404'd on download). Even with a working mirror, freezing it would
    # mean pushing a ~1 GB artifact into all ten stage jobs on a 2 vCPU / 4 GB
    # runner with a history of disk exhaustion. Deleting four unusable files is
    # cheaper and more honest than scanning them.
    rm -rf /usr/share/java /usr/share/maven-repo; \
    jars="$(find / -xdev \( -name '*.jar' -o -name '*.war' -o -name '*.ear' \
                          -o -name '*.par' -o -name '*.jmod' \) -print 2>/dev/null)"; \
    if [ -n "$jars" ]; then \
        echo "REFUSE: Java artifacts survived removal:" >&2; \
        echo "$jars" >&2; exit 1; \
    fi; \
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
COPY healthcheck      /usr/local/bin/nginx-healthcheck
RUN set -eux; \
    chown -R 101:101 /etc/nginx; \
    chmod 0555 /usr/local/bin/nginx-healthcheck; \
    # The probe uses IO::Socket::INET from perl-base. If a future layer drops
    # perl, the healthcheck would fail on every interval and the image would
    # look permanently unhealthy — catch that at build time, not in production.
    perl -MIO::Socket::INET -e 'exit 0'; \
    # 00-readiness.conf must really be included: nginx.conf globs *.conf, so a
    # file renamed to .example or .disabled silently stops being served and the
    # healthcheck below would have nothing to talk to.
    # Written to a file rather than piped: the default RUN shell is /bin/sh with
    # no `pipefail`, so `nginx -T | grep -q` would report success on grep alone
    # even if nginx -T itself failed.
    nginx -T > /tmp/nginx-conf.dump 2>/dev/null; \
    grep -q 'listen 8081' /tmp/nginx-conf.dump; \
    rm -f /tmp/nginx-conf.dump; \
    # `nginx -T` runs as root and writes /tmp/nginx.pid plus the *_temp dirs from
    # nginx.conf. Left behind, they are ROOT-OWNED files baked into the image, and
    # nginx at runtime (uid 101) then cannot open its own pid file:
    #   [emerg] open() "/tmp/nginx.pid" failed (13: Permission denied)
    # Verified: without this cleanup the image starts under a tmpfs /tmp (which
    # shadows them) but `nginx -t` fails on a plain run.
    rm -rf /tmp/nginx.pid /tmp/client_temp /tmp/proxy_temp /tmp/fastcgi_temp \
           /tmp/uwsgi_temp /tmp/scgi_temp

# 8080 serves the consumer's site. 8081 is the internal readiness listener
# (conf.d/00-readiness.conf) — give it to an orchestrator probe, never to the
# internet.
USER 101:101
EXPOSE 8080 8081

# A REAL request/response cycle against the always-on readiness listener, not a
# config parse. `nginx -t -q` reported a hung or unforked nginx as healthy: it
# proves the files parse, never that anything is being served (#127).
# On a read-only rootfs ensure tmpfs for the temp paths in nginx.conf.
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/nginx-healthcheck"]

STOPSIGNAL SIGQUIT
ENTRYPOINT ["nginx", "-g", "daemon off;"]
