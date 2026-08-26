# Candidate C2b — newer OFFICIAL upstream base LINE: Debian 13 (trixie) variant
FROM dunglas/frankenphp:1-php8.4-trixie@sha256:9a5a469b5b49252ca8fd2cc67d2c90df34ba35e40097fd675c5735a4850bed0e
RUN set -eux; \
    echo "== base before =="; dpkg-query -W "libaom*" "libavif*" 2>&1 || true; \
    . /etc/os-release; echo "os=$PRETTY_NAME"
RUN set -eux; install-php-extensions gd
RUN set -eux; \
    echo "== after gd =="; dpkg-query -W "libaom*" "libavif*" 2>&1 || true; \
    php -r 'print_r(gd_info());'; \
    ldd "$(php -r 'echo ini_get("extension_dir");')/gd.so" | grep -E "avif|aom|webp|png|jpeg|freetype" || true
