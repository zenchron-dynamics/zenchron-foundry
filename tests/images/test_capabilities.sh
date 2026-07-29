#!/usr/bin/env bash
# =============================================================================
# tests/images/test_capabilities.sh — fail-closed capability removal (#100).
#
# The regression: `setcap -r ... 2>/dev/null || true` let a missing binary, an
# absent setcap, or a failed removal ship a capability while the build stayed
# green. Under `cap_drop: ALL` + `no-new-privileges` the kernel then refuses to
# exec that binary at all, so the image is simply broken — silently.
#
# Offline by design (no docker): asserts the Dockerfiles cannot regress to a
# suppressed failure, and that the verifier is wired into every path. The
# image-level proof needs a built image and runs in `make smoke-all` / CI, where
# scripts/smoke/lib.sh applies the check to all 10 images.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

CAP_DOCKERFILES="images/caddy/Dockerfile images/php-frankenphp/8.3/Dockerfile images/php-frankenphp/8.4/Dockerfile"

# Instructions only. The blocks below DESCRIBE the retired `|| true` pattern in
# their comments, and a bare grep would match that prose and report a
# regression that is not there. Dockerfile comments are whole-line, so dropping
# lines that start with `#` is exact, not a heuristic.
code() { grep -vE '^[[:space:]]*#' "$1"; }

# --- the exact regression, per Dockerfile ----------------------------------
for df in $CAP_DOCKERFILES; do
  ck "$df: setcap failures are NOT suppressed" \
     "! code '$df' | grep -qE 'setcap[^;]*(\|\| *true|2>/dev/null)'"
  ck "$df: removal is proven with getcap afterwards" \
     "grep -q 'getcap' '$df'"
  ck "$df: whole-image scan, not just the one binary" \
     "grep -q 'getcap -r /' '$df'"
  ck "$df: a remaining capability REFUSEs the build" \
     "grep -q 'REFUSE: file capabilities remain' '$df'"
done

# The identity commands were suppressed too: a failed adduser yields an image
# whose USER does not exist.
for df in $CAP_DOCKERFILES; do
  ck "$df: user/group creation is not suppressed" \
     "! code '$df' | grep -qE '(addgroup|adduser|groupadd|useradd)[^;]*\|\| *true'"
done

# Static-archive deletion had the same fail-open shape.
for df in images/php-frankenphp/8.3/Dockerfile images/php-frankenphp/8.4/Dockerfile; do
  ck "$df: static-archive deletion is not suppressed" \
     "! code '$df' | grep -qE \"find .*'\\*\\.a'.*(\\|\\| *true|2>/dev/null)\""
  ck "$df: surviving archives REFUSE the build" \
     "grep -q 'REFUSE: static archives survived deletion' '$df'"
done

# Ordering: getcap comes from libcap2-bin, so the whole-image scan must run
# BEFORE that package is purged, or it would verify nothing.
for df in images/php-frankenphp/8.3/Dockerfile images/php-frankenphp/8.4/Dockerfile; do
  ck "$df: image scan precedes the libcap2-bin purge" \
     "[ \"\$(grep -n 'getcap -r /' '$df' | cut -d: -f1)\" -lt \"\$(grep -n 'purge -y --auto-remove libcap2-bin' '$df' | cut -d: -f1)\" ]"
done

# 8.3 and 8.4 must not drift apart.
ck "frankenphp 8.3 and 8.4 hardening blocks stay identical" \
   "diff <(sed -n '/FAIL-CLOSED/,/chmod 0555/p' images/php-frankenphp/8.3/Dockerfile) \
         <(sed -n '/FAIL-CLOSED/,/chmod 0555/p' images/php-frankenphp/8.4/Dockerfile) >/dev/null"

# --- the verifier -----------------------------------------------------------
ck "capability-inventory self-test passes" \
   "bash scripts/ci/capability-inventory.sh --self-test >/dev/null"
ck "capability-inventory is executable" \
   "test -x scripts/ci/capability-inventory.sh"

# --- wiring: an unwired gate is not a gate ---------------------------------
ck "every smoke run asserts zero capabilities (shared lib)" \
   "grep -q 'capability-inventory.sh' scripts/smoke/lib.sh"
ck "the assertion runs from finish(), so all 10 images get it" \
   "sed -n '/^finish()/,/^}/p' scripts/smoke/lib.sh | grep -q 'capability-inventory.sh'"
ck "require_image records the ref the assertion needs" \
   "sed -n '/^require_image()/,/^}/p' scripts/smoke/lib.sh | grep -q 'SMOKE_IMAGE='"
# The build+smoke matrix moved out of ci.yml in #96: a pull_request workflow
# runs the PR's own copy of itself, so it cannot be trusted to build on the
# self-hosted pool. It lives in trusted-validation.yml, which is dispatch-only
# and therefore always defined by master. Assert against the workflow that
# actually builds, and assert the STRUCTURE rather than grepping for a string
# that could sit in a comment.
CAPWF=.github/workflows/trusted-validation.yml
ck "the trusted build workflow exists" "test -f $CAPWF"
ck "CI captures the inventory during the smoke step" \
   "python3 -c \"
import yaml
d=yaml.safe_load(open('$CAPWF'))
steps=d['jobs']['validate']['steps']
smoke=[s for s in steps if s.get('id')=='smoke']
assert smoke, 'no smoke step'
assert smoke[0].get('env',{}).get('CAPABILITY_INVENTORY_DIR')=='capability-inventory', smoke[0].get('env')\""
ck "CI publishes the machine-readable inventory" \
   "python3 -c \"
import yaml
d=yaml.safe_load(open('$CAPWF'))
ups=[s for s in d['jobs']['validate']['steps']
     if 'upload-artifact' in str(s.get('uses',''))]
assert ups, 'no upload step'
w=ups[0]['with']
assert 'capability-inventory/' in w['path'], w['path']
# Evidence must survive a FAILING run: a regression is exactly when the
# offending paths are worth keeping.
assert ups[0].get('if')=='always()', ups[0].get('if')
assert w.get('if-no-files-found')=='error', w.get('if-no-files-found')\""
ck "the inventory is NOT expected from the pull-request workflow" \
   "! grep -q 'CAPABILITY_INVENTORY_DIR' .github/workflows/ci.yml"

# --- the hardened runtime profile is actually exercised --------------------
for s in scripts/smoke/smoke-caddy.sh scripts/smoke/smoke-php-frankenphp.sh; do
  ck "$s: runtime container drops ALL capabilities" \
     "grep -q -- '--cap-drop ALL' '$s'"
  ck "$s: runtime container sets no-new-privileges" \
     "grep -q -- '--security-opt no-new-privileges' '$s'"
done

echo "----"; [ "$fail" -eq 0 ] && echo "test_capabilities: PASS" || echo "test_capabilities: FAIL"
exit $fail
