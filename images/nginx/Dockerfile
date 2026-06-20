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
# Remove the default site / welcome page, install our hardened config.
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
