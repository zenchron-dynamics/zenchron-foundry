#!/usr/bin/env bash
# =============================================================================
# Zenchron Dynamics — local runtime smoke for the platform images.
# Reproduces (as far as a laptop can) the runtime checks GitHub CI / consumer
# validation perform, against LOCALLY BUILT images. Pairs with `make build-test`.
#
# Covers: non-root (uid 10001 / nginx 101), read-only rootfs + tmpfs /tmp,
# cap_drop ALL + no-new-privileges, php -v/-m, FPM config + :9000 listener,
# worker heartbeat + healthcheck + clean SIGTERM, FrankenPHP HTTP :8080 +
# readiness :8081, nginx config test, caddy /healthz.
#
# Usage: scripts/smoke-local.sh [PHP_VERSION]   (default 8.4)
# Image refs default to the local build tags (REGISTRY/NAMESPACE overridable).
# This NEVER pushes, deletes, or touches anything outside the containers it
# creates (all named zsmoke-*), and removes only those.
# =============================================================================
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$ROOT"
PHP="${1:-8.4}"
REG="${REGISTRY:-ghcr.io}"; NS="${NAMESPACE:-zenchron-dynamics}"; SFX="${TAG_SUFFIX:-prod}"
CLI="$REG/$NS/php-cli:${PHP}-$SFX"; FPM="$REG/$NS/php-fpm:${PHP}-$SFX"
WRK="$REG/$NS/php-worker:${PHP}-$SFX"; FRK="$REG/$NS/php-frankenphp:${PHP}-$SFX"
NGX="$REG/$NS/nginx:$SFX"; CAD="$REG/$NS/caddy:$SFX"
RO=(--read-only --tmpfs /tmp:size=64m,nosuid,nodev --cap-drop ALL --security-opt no-new-privileges)
pass=0; fail=0
ok(){ printf '  ✓ %s\n' "$1"; pass=$((pass+1)); }
no(){ printf '  ✗ %s\n' "$1"; fail=$((fail+1)); }
have(){ docker image inspect "$1" >/dev/null 2>&1; }

echo "== CLI ($CLI) =="
if have "$CLI"; then
  docker run --rm "$CLI" -v 2>/dev/null | grep -qi "PHP $PHP" && ok "php -v" || no "php -v"
  docker run --rm "${RO[@]}" --user 10001:10001 "$CLI" -m 2>/dev/null | grep -qi '^redis$' && ok "php -m + read-only/non-root run" || no "php -m read-only"
else echo "  (skip: $CLI not built)"; fi

echo "== FPM ($FPM) =="
if have "$FPM"; then
  docker run --rm --entrypoint php-fpm "$FPM" -t -y /usr/local/etc/php-fpm.conf >/dev/null 2>&1 && ok "fpm config test" || no "fpm config test"
  cid=$(docker run -d --name zsmoke-fpm "${RO[@]}" --user 10001:10001 "$FPM" 2>/dev/null); sleep 3
  docker exec zsmoke-fpm /usr/local/bin/docker-healthcheck >/dev/null 2>&1 && ok "fpm :9000 listener (readonly/nonroot/capdrop)" || no "fpm listener"
  docker exec zsmoke-fpm id 2>/dev/null | grep -q 'uid=10001' && ok "fpm non-root 10001" || no "fpm uid"
  docker rm -f zsmoke-fpm >/dev/null 2>&1
else echo "  (skip: $FPM not built)"; fi

echo "== WORKER ($WRK) =="
if have "$WRK"; then
  cid=$(docker run -d --name zsmoke-wrk "${RO[@]}" --user 10001:10001 "$WRK" php -r 'while(true)sleep(1);' 2>/dev/null); sleep 4
  docker exec zsmoke-wrk sh -c 'test -f /tmp/worker-heartbeat' 2>/dev/null && ok "worker heartbeat written" || no "worker heartbeat"
  docker exec zsmoke-wrk /usr/local/bin/worker-healthcheck >/dev/null 2>&1 && ok "worker healthcheck exit0" || no "worker healthcheck"
  t0=$(date +%s); docker stop -t 10 zsmoke-wrk >/dev/null 2>&1; t1=$(date +%s)
  [ $((t1-t0)) -lt 10 ] && ok "worker clean SIGTERM (${t0:+$((t1-t0))}s, signal forwarded)" || no "worker SIGTERM slow"
  docker rm -f zsmoke-wrk >/dev/null 2>&1
else echo "  (skip: $WRK not built)"; fi

echo "== FRANKENPHP ($FRK) =="
if have "$FRK"; then
  cid=$(docker run -d --name zsmoke-frk "${RO[@]}" --user 10001:10001 -p 18080:8080 -p 18081:8081 "$FRK" 2>/dev/null); sleep 6
  [ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18081/healthz)" = 200 ] && ok "frankenphp readiness :8081 -> 200" || no "frankenphp readiness"
  code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18080/); [ -n "$code" ] && [ "$code" != 000 ] && ok "frankenphp HTTP :8080 responds ($code)" || no "frankenphp :8080"
  docker exec zsmoke-frk id 2>/dev/null | grep -q 'uid=10001' && ok "frankenphp non-root 10001" || no "frankenphp uid"
  docker logs zsmoke-frk 2>&1 | grep -qiE 'operation not permitted' && no "frankenphp cap error" || ok "frankenphp runs under cap_drop ALL"
  docker rm -f zsmoke-frk >/dev/null 2>&1
else echo "  (skip: $FRK not built)"; fi

echo "== NGINX ($NGX) =="
if have "$NGX"; then
  cid=$(docker run -d --name zsmoke-ngx --read-only --tmpfs /tmp --tmpfs /var/cache/nginx --tmpfs /var/run --cap-drop ALL --security-opt no-new-privileges "$NGX" 2>/dev/null); sleep 2
  docker exec zsmoke-ngx nginx -t -q >/dev/null 2>&1 && ok "nginx config test (read-only)" || no "nginx config"
  docker exec zsmoke-ngx id 2>/dev/null | grep -q 'uid=101' && ok "nginx non-root 101" || no "nginx uid"
  docker rm -f zsmoke-ngx >/dev/null 2>&1
else echo "  (skip: $NGX not built)"; fi

echo "== CADDY ($CAD) =="
if have "$CAD"; then
  cid=$(docker run -d --name zsmoke-cad --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges --user 10001:10001 -e XDG_DATA_HOME=/tmp -e XDG_CONFIG_HOME=/tmp -p 18082:8081 "$CAD" 2>/dev/null); sleep 3
  [ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18082/healthz)" = 200 ] && ok "caddy /healthz :8081 -> 200 (readonly/nonroot)" || no "caddy healthz"
  docker rm -f zsmoke-cad >/dev/null 2>&1
else echo "  (skip: $CAD not built)"; fi

echo "== smoke summary: $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
