#!/usr/bin/env bash
# =============================================================================
# Zenchron Dynamics — php-cli runtime smoke test.
# Usage: smoke-php-cli.sh <image-ref>   (image must already be built)
#
# Ground truth (images/php-cli/8.{3,4}/Dockerfile):
#   ENTRYPOINT ["php"], CMD ["-v"]; USER 10001:10001; build tools stripped.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" >/dev/null 2>&1 && pwd)"
# shellcheck source=lib.sh
. "$SCRIPT_DIR/lib.sh"

require_image "${1:-}"
IMG="$1"

# Required extensions for the CLI runtime (compiled set + official-base set).
REQUIRED_EXTS="bcmath ctype curl dom fileinfo gd intl mbstring opcache openssl \
pcntl pdo pdo_mysql pdo_pgsql pgsql redis simplexml sockets sodium sqlite3 \
tokenizer xml zip"

printf '== smoke: php-cli (%s) ==\n' "$IMG"

# php works (default ENTRYPOINT is php; CMD -v).
check "php -v reports a version" \
    sh -c "docker run --rm '$IMG' -v | grep -q '^PHP '"

# All required extensions are loaded.
check "required extensions present" \
    php_extensions_present "$IMG" "$REQUIRED_EXTS"

# Runtime identity is non-root.
check "runs as non-root (uid != 0)" assert_nonroot "$IMG"
check "runs as the pinned uid 10001" assert_uid "$IMG" "10001"

# Works under a read-only rootfs with a tmpfs /tmp, and /tmp is writable.
check "read-only rootfs + tmpfs /tmp is writable" \
    docker run --rm --read-only --tmpfs /tmp --entrypoint sh "$IMG" \
        -c 'printf ok > /tmp/probe && grep -q ok /tmp/probe'

# Hardening: the documented gate is "no build toolchain in the final image".
# (NOTE: these are Debian-first images by design, so apt/dpkg intentionally
# remain — see report. There is no alpine apk, which we still assert.)
check "no apk package manager (not an alpine image)" tool_absent "$IMG" "apk"
check "no gcc build tool" tool_absent "$IMG" "gcc"
check "no make build tool" tool_absent "$IMG" "make"
check "no phpize (extension build helper removed)" tool_absent "$IMG" "phpize"

# --- component-absence guard (#102/#103) ------------------------------------
# The ledger records CVE-2026-57433 (Storable), CVE-2026-42497 / CVE-2026-9538
# (Archive::Tar) and CVE-2026-48962 (IO::Compress) as NOT AFFECTED on this image
# family, on the evidence that the vulnerable MODULES are not installed — the
# family carries perl-base only. A base change that pulls in perl-modules-5.36
# would silently falsify that evidence and those advisories would start applying.
# Fail here rather than let a not_affected record outlive its justification.
check "perl module Storable absent (not_affected evidence)" \
    module_absent "$IMG" Storable
check "perl module Archive::Tar absent (not_affected evidence)" \
    module_absent "$IMG" Archive::Tar
check "perl module IO::Compress::Gzip absent (not_affected evidence)" \
    module_absent "$IMG" IO::Compress::Gzip

finish
