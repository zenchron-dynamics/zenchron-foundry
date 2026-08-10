#!/usr/bin/env bash
# =============================================================================
# tests/runtime/test_uid_contract.sh — one UID/GID story per image (#118).
#
# The defect: profiles/compose.security.yml spread `user: "10001:10001"` into
# every service through a shared anchor, including nginx. The nginx image runs as
# UID 101 — it is built on the upstream nginx-unprivileged base and /etc/nginx
# and its temp paths are chowned 101:101. So the image and the platform's own
# recommended overlay disagreed about who the process is, and the documented
# "deterministic UID 10001" claim was not true of all ten images.
#
# The rule this enforces: contracts/images/<image>.yaml `user:` is THE source of
# truth, and every other place that names an identity must agree with it —
# the Dockerfile's USER line, the Compose security profile, and the docs.
#
# This resolves the values with yq and compares them; it does not restate the
# expected UIDs as literals, so adding an image or changing a base's identity
# cannot leave a stale expectation passing.
#
# Runs offline. No docker, no network.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

PROFILE=profiles/compose.security.yml

ck "every image contract declares a user" \
   '[ "$(for f in contracts/images/*.yaml; do yq -r ".user // \"\"" "$f" 2>/dev/null; done | grep -c .)" \
     = "$(ls contracts/images/*.yaml | wc -l | tr -d " ")" ]'
ck "every declared identity is non-root" \
   '! for f in contracts/images/*.yaml; do yq -r ".user" "$f" 2>/dev/null; done | grep -qE "^(0|root)(:|$)"'

# --- the Dockerfile must run as the identity its contract declares -----------
# Maps contract file -> Dockerfile. The edge images live at images/<fam>/, the
# PHP families at images/<fam>/<selector>/.
for c in contracts/images/*.yaml; do
  fam="$(yq -r '.image' "$c")"; sel="$(yq -r '.selector' "$c")"; want="$(yq -r '.user' "$c")"
  df="images/$fam/Dockerfile"; [ -f "$df" ] || df="images/$fam/$sel/Dockerfile"
  ck "$fam/$sel: Dockerfile has a USER line" "grep -qE '^USER ' '$df'"
  got="$(grep -E '^USER ' "$df" | tail -1 | awk '{print $2}')"
  ck "$fam/$sel: Dockerfile USER '$got' == contract '$want'" "[ '$got' = '$want' ]"
done

# --- the security profile must not contradict any contract ------------------
# THE regression: a single global `user:` on the shared anchor. If it comes back,
# nginx silently inherits 10001 again.
ck "the shared hardening anchor declares no global user" \
   '! yq -e ".\"x-zenchron-hardening\".user" '"$PROFILE"' >/dev/null 2>&1'
ck "every hardened service declares its own user" \
   '[ "$(yq -r ".services | to_entries | map(select(.value.user == null)) | length" '"$PROFILE"')" = 0 ]'

# nginx is the whole point: its profile identity must be the contract's, not the
# platform default.
NGINX_WANT="$(yq -r '.user' contracts/images/nginx-prod.yaml)"
ck "profile nginx user == nginx contract ($NGINX_WANT)" \
   '[ "$(yq -r ".services.nginx.user" '"$PROFILE"')" = "'"$NGINX_WANT"'" ]'
ck "profile nginx is NOT forced to the php identity" \
   '[ "$(yq -r ".services.nginx.user" '"$PROFILE"')" != "10001:10001" ]'

# ...and the php-family services must still be 10001, or this "fix" would have
# traded one wrong identity for another.
PHP_WANT="$(yq -r '.user' contracts/images/php-fpm-8.4.yaml)"
for svc in php-fpm php-cli worker frankenphp; do
  ck "profile $svc user == php contract ($PHP_WANT)" \
     '[ "$(yq -r ".services.'"$svc"'.user" '"$PROFILE"')" = "'"$PHP_WANT"'" ]'
done
CADDY_WANT="$(yq -r '.user' contracts/images/caddy-prod.yaml)"
ck "profile caddy user == caddy contract ($CADDY_WANT)" \
   '[ "$(yq -r ".services.caddy.user" '"$PROFILE"')" = "'"$CADDY_WANT"'" ]'

# The hardening the anchor DOES carry must survive: removing `user:` from it
# must not have removed anything else.
for k in read_only cap_drop security_opt pids_limit tmpfs; do
  ck "the hardening anchor still carries $k" \
     'yq -e ".\"x-zenchron-hardening\".'"$k"'" '"$PROFILE"' >/dev/null'
done
ck "every hardened service still gets read_only" \
   '[ "$(yq -r ".services | to_entries | map(select(.value.read_only != true)) | length" '"$PROFILE"')" = 0 ]'
ck "every hardened service still drops ALL capabilities" \
   '[ "$(yq -r ".services[] | .cap_drop[]" '"$PROFILE"' 2>/dev/null | grep -cx ALL)" \
     = "$(yq -r ".services | length" '"$PROFILE"' 2>/dev/null)" ]'

# --- the documentation must not restate a UID that no longer holds ----------
ck "runtime-hardening.md names nginx's real UID" \
   'grep -q "101" docs/runtime-hardening.md'

echo "----"; [ "$fail" -eq 0 ] && echo "test_uid_contract: PASS" || echo "test_uid_contract: FAIL"
exit $fail
