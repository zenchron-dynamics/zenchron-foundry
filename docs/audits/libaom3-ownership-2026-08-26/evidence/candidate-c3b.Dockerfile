# Candidate C3b — official toolchain, explicit gd configure without --with-avif
FROM dunglas/frankenphp:1-php8.4-bookworm@sha256:cef99f108009ed60c6d60261c8edc17104fce06aafaf24c21119cd4b4c704aa7
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        libfreetype6-dev libjpeg62-turbo-dev libpng-dev libwebp-dev libxpm-dev; \
    docker-php-ext-configure gd --enable-gd --with-webp --with-jpeg --with-xpm --with-freetype; \
    docker-php-ext-install -j"$(nproc)" gd; \
    rm -rf /var/lib/apt/lists/*
RUN set -eux; \
    echo "== dpkg libaom/libavif =="; dpkg-query -W "libaom*" "libavif*" || true; \
    echo "== gd_info =="; php -r 'print_r(gd_info());'; \
    echo "== ldd gd.so =="; ldd "$(php -r 'echo ini_get("extension_dir");')/gd.so" | grep -E "avif|aom|webp|png|jpeg|freetype" || true
