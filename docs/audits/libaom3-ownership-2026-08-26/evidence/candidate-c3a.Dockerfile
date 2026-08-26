# Candidate C3a — supported installer configuration knob IPE_GD_WITHOUTAVIF=1
FROM dunglas/frankenphp:1-php8.4-bookworm@sha256:cef99f108009ed60c6d60261c8edc17104fce06aafaf24c21119cd4b4c704aa7
ENV IPE_GD_WITHOUTAVIF=1
RUN set -eux; install-php-extensions gd
RUN set -eux; \
    echo "== dpkg libaom/libavif =="; dpkg-query -W "libaom*" "libavif*" || true; \
    echo "== gd_info =="; php -r 'print_r(gd_info());'; \
    echo "== ldd gd.so =="; ldd "$(php -r 'echo ini_get("extension_dir");')/gd.so" | grep -E "avif|aom|webp|png|jpeg|freetype" || true
