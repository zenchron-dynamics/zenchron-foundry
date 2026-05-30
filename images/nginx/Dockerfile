# syntax=docker/dockerfile:1.7
# =============================================================================
# Zenchron Dynamics — nginx (production, PHP-FPM front / static server)
# Based on the upstream UNPRIVILEGED nginx image: already non-root and listens
# on :8080 by default. Bind :80/:443 only via NET_BIND_SERVICE or upstream LB.
# Read-only-rootfs compatible (nginx temp paths point to tmpfs; see nginx.conf).
# No default "Welcome to nginx" page is shipped.
# =============================================================================
ARG NGINX_BASE="nginxinc/nginx-unprivileged:1.27-alpine@sha256:65e3e85dbaed8ba248841d9d58a899b6197106c23cb0ff1a132b7bfe0547e4c0"

FROM ${NGINX_BASE} AS runtime

ARG BUILD_DATE
ARG VCS_REF

LABEL org.opencontainers.image.title="zenchron-nginx" \
      org.opencontainers.image.description="Hardened nginx for PHP-FPM upstream / static assets" \
      org.opencontainers.image.vendor="Zenchron Dynamics" \
      org.opencontainers.image.source="https://github.com/zenchron-dynamics/zenchron-foundry" \
      org.opencontainers.image.version="prod" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.licenses="LicenseRef-Zenchron-Internal" \
      com.zenchron.runtime="nginx" \
      com.zenchron.support="supported"

# Already runs as uid 101 (nginx) in the upstream unprivileged image.
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
