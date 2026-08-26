# Candidate C4 — naive package removal: purge libaom3 from the built child.
# Built ONLY to measure what the existing gates would and would not catch.
FROM laneL/php-frankenphp:8.4-baseline
USER 0:0
RUN set -eux; \
    apt-get update; \
    apt-get purge -y --auto-remove libaom3; \
    rm -rf /var/lib/apt/lists/*
USER 10001:10001
