#!/usr/bin/env bash
# =============================================================================
# Zenchron Dynamics — runtime smoke-test shared library.
#
# Sourced by the per-family smoke scripts (smoke-php-cli.sh, smoke-nginx.sh, ...).
# Provides a tiny assertion framework plus a handful of Docker helpers used to
# probe an ALREADY-BUILT image reference.
#
# Design notes:
#   * `check "desc" cmd...` runs a command, NEVER aborts the calling script, and
#     records a pass or a fail. The command's combined output is shown on FAIL.
#   * `finish` prints the canonical summary line and EXITS nonzero when either no
#     checks ran at all (zero checks == failure) or any check failed.
#   * Callers run with `set -euo pipefail`; because `check` evaluates its command
#     inside an `if` condition, errexit is suppressed for the assertion itself, so
#     a failing probe is recorded rather than killing the run.
#   * `require_image` records the ref in SMOKE_IMAGE so `finish` can run the
#     UNIVERSAL final-image assertions once, here, instead of in six scripts.
# =============================================================================

# Directory of this library — used to reach sibling scripts regardless of the
# caller's cwd (CI invokes the family scripts from the repo root).
_SMOKE_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

# Assertion counters (global, per-process).
PASS=0
FAIL=0

# check <description> <command> [args...]
# Runs the command; records PASS on exit 0, FAIL otherwise. Output shown on FAIL.
check() {
    _desc="$1"
    shift
    if _out="$("$@" 2>&1)"; then
        PASS=$((PASS + 1))
        printf 'PASS  %s\n' "$_desc"
    else
        FAIL=$((FAIL + 1))
        printf 'FAIL  %s\n' "$_desc" >&2
        if [ -n "${_out:-}" ]; then
            printf '%s\n' "$_out" | while IFS= read -r _line; do
                printf '        %s\n' "$_line" >&2
            done
        fi
    fi
}

# pass_count / fail_count — emit the current counters (in-process helpers).
pass_count() { printf '%d\n' "$PASS"; }
fail_count() { printf '%d\n' "$FAIL"; }

# finish — print the summary and exit with the right status.
#
# Runs the UNIVERSAL final-image assertions first, so every smoke script gets
# them without repetition and on both call paths (scripts/smoke-test.sh, and
# trusted-validation.yml, which invokes the family scripts directly — #96 moved
# the build+smoke matrix out of ci.yml, because a pull_request workflow runs the
# PR's own copy of itself and cannot be trusted on a privileged runner).
# Today that is the
# zero-file-capabilities contract (#100): under `cap_drop: ALL` +
# `no-new-privileges`, a binary carrying a file capability cannot even be
# exec'd, so a surviving capability is a broken image, not a nuance.
finish() {
    if [ -n "${SMOKE_IMAGE:-}" ]; then
        # CAPABILITY_INVENTORY_DIR (set by CI) also captures the machine-readable
        # inventory here, so the evidence artifact costs no extra image export.
        if [ -n "${CAPABILITY_INVENTORY_DIR:-}" ]; then
            mkdir -p "$CAPABILITY_INVENTORY_DIR"
            _cap_json="${CAPABILITY_INVENTORY_DIR}/$(printf '%s' "$SMOKE_IMAGE" | tr '/:' '--').json"
            check "no file capabilities in the final image (cap_drop: ALL contract)" \
                bash "${_SMOKE_LIB_DIR}/../ci/capability-inventory.sh" "$SMOKE_IMAGE" --json "$_cap_json"
        else
            check "no file capabilities in the final image (cap_drop: ALL contract)" \
                bash "${_SMOKE_LIB_DIR}/../ci/capability-inventory.sh" "$SMOKE_IMAGE"
        fi
    fi

    _total=$((PASS + FAIL))
    printf 'SMOKE SUMMARY: %d passed, %d failed, %d checks\n' "$PASS" "$FAIL" "$_total"
    if [ "$_total" -eq 0 ]; then
        printf 'SMOKE ERROR: zero checks executed (treated as failure)\n' >&2
        exit 3
    fi
    if [ "$FAIL" -gt 0 ]; then
        exit 1
    fi
    exit 0
}

# require_image <image-ref> — abort early (before any checks) when no ref given.
# Also records the ref for the universal assertions in `finish`.
require_image() {
    if [ -z "${1:-}" ]; then
        printf 'usage: %s <image-ref>\n' "$(basename "$0")" >&2
        exit 2
    fi
    SMOKE_IMAGE="$1"
}

# -----------------------------------------------------------------------------
# Docker probe helpers. All take the image ref explicitly.
# -----------------------------------------------------------------------------

# runtime_uid <image-ref> — print the numeric uid the image runs as.
runtime_uid() {
    docker run --rm --entrypoint id "$1" -u
}

# assert_nonroot <image-ref> — succeed when the runtime uid is not 0.
assert_nonroot() {
    _uid="$(runtime_uid "$1")"
    [ -n "$_uid" ] && [ "$_uid" != "0" ]
}

# assert_uid <image-ref> <expected-uid> — succeed when the runtime uid matches.
assert_uid() {
    _uid="$(runtime_uid "$1")"
    [ "$_uid" = "$2" ]
}

# tool_absent <image-ref> <tool> — succeed when <tool> is NOT on PATH in the image.
tool_absent() {
    ! docker run --rm --entrypoint sh "$1" -c "command -v $2 >/dev/null 2>&1"
}

# exposes_port <image-ref> <port> — succeed when <port>/tcp is an EXPOSEd port.
exposes_port() {
    docker image inspect --format '{{json .Config.ExposedPorts}}' "$1" \
        | grep -q "\"$2/tcp\""
}

# php_extensions_present <image-ref> <space-separated-list>
# Succeeds only when every listed extension is loaded. Names are matched against
# the normalized set of loaded PHP + Zend extensions, so the "Zend OPcache" alias
# for `opcache` and the upper-case "PDO" name are handled correctly. Reports misses.
php_extensions_present() {
    docker run --rm --entrypoint php "$1" -r "
        \$req = preg_split('/\\s+/', trim('$2'));
        \$loaded = array_map('strtolower',
            array_merge(get_loaded_extensions(false), get_loaded_extensions(true)));
        \$norm = array();
        foreach (\$loaded as \$l) {
            \$norm[\$l] = true;
            if (strpos(\$l, 'zend ') === 0) { \$norm[substr(\$l, 5)] = true; }
        }
        \$missing = array();
        foreach (\$req as \$e) {
            if (\$e !== '' && !isset(\$norm[strtolower(\$e)])) { \$missing[] = \$e; }
        }
        if (\$missing) {
            fwrite(STDERR, 'missing extensions: ' . implode(', ', \$missing) . PHP_EOL);
            exit(1);
        }
        exit(0);
    "
}

# container_stays_up <timeout-secs> <docker-run-args...>
# Starts a detached container, waits, asserts it is still running, then removes it.
container_stays_up() {
    _wait="$1"
    shift
    _name="smoke-up-$$-$RANDOM"
    if ! docker run -d --name "$_name" "$@" >/dev/null 2>&1; then
        docker rm -f "$_name" >/dev/null 2>&1 || true
        return 1
    fi
    sleep "$_wait"
    _running="$(docker inspect -f '{{.State.Running}}' "$_name" 2>/dev/null || echo false)"
    docker rm -f "$_name" >/dev/null 2>&1 || true
    [ "$_running" = "true" ]
}

# poll_http_body <url> <want-substring> <timeout-secs>
# Polls until the body contains <want-substring> (uses curl, falls back to wget).
poll_http_body() {
    _url="$1"
    _want="$2"
    _deadline=$(( $(date +%s) + ${3:-15} ))
    while [ "$(date +%s)" -le "$_deadline" ]; do
        if _body="$(_http_get "$_url")"; then
            case "$_body" in
                *"$_want"*) return 0 ;;
            esac
        fi
        sleep 1
    done
    return 1
}

# poll_http_up <url> <timeout-secs> — polls until the URL returns any HTTP status.
poll_http_up() {
    _url="$1"
    _deadline=$(( $(date +%s) + ${2:-15} ))
    while [ "$(date +%s)" -le "$_deadline" ]; do
        _code="$(_http_status "$_url")"
        if [ -n "$_code" ] && [ "$_code" != "000" ]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# _http_get <url> — fetch a body (curl or wget). Internal.
_http_get() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsS --max-time 3 "$1" 2>/dev/null
    else
        wget -q -O - --timeout=3 "$1" 2>/dev/null
    fi
}

# _http_status <url> — print the HTTP status code (000 on connection failure).
_http_status() {
    if command -v curl >/dev/null 2>&1; then
        curl -s -o /dev/null --max-time 3 -w '%{http_code}' "$1" 2>/dev/null
    elif wget -q -O /dev/null --timeout=3 "$1" 2>/dev/null; then
        printf '200\n'
    else
        printf '000\n'
    fi
}
