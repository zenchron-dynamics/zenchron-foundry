#!/usr/bin/env bash
# =============================================================================
# tests/governance/test_package_acl_probe.sh
# -----------------------------------------------------------------------------
# The package ACL boundary cannot be READ — the documented public GitHub API
# exposes neither the organization's package-inheritance default nor a package's
# "Manage Actions access" role. `.github/workflows/package-acl-probe.yml`
# therefore measures the boundary behaviourally.
#
# Two things must hold for that evidence to mean anything:
#
#   1. The probe cannot become a way to run untrusted code with `packages:
#      write`. It is dispatch-only, default-branch-only, and never checks out.
#   2. A registry error must not be mistaken for a denial. If a timeout counted
#      as "denied", a network failure would manufacture a passing boundary —
#      the exact fail-open shape this repository keeps removing.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

WF=.github/workflows/package-acl-probe.yml

ck "the probe workflow exists" "test -f $WF"

# --- it cannot be turned into an execution path ----------------------------
ck "dispatch-only: no pull_request or push trigger" \
   "python3 -c \"
import yaml
d=yaml.safe_load(open('$WF'))
t=list(d[True])
assert t==['workflow_dispatch'], t\""
ck "it never checks out repository or PR code" \
   "python3 -c \"
import yaml
d=yaml.safe_load(open('$WF'))
for j in d['jobs'].values():
    for s in j['steps']:
        assert 'checkout' not in str(s.get('uses','')), s.get('uses')\""
ck "it refuses to run from anything but the default branch" \
   "grep -q 'refs/heads/master' $WF && grep -q 'REFUSE: dispatch from master only' $WF"
ck "no id-token, no environment, no production credential" \
   "python3 -c \"
import yaml
d=yaml.safe_load(open('$WF'))
assert 'id-token' not in (d.get('permissions') or {})
for name,j in d['jobs'].items():
    assert 'environment' not in j, name
    assert 'id-token' not in (j.get('permissions') or {}), name\""
ck "permissions are exactly contents:read + packages:write" \
   "python3 -c \"
import yaml
d=yaml.safe_load(open('$WF'))
want={'contents':'read','packages':'write'}
assert d['permissions']==want, d['permissions']
assert d['jobs']['probe']['permissions']==want\""
ck "every action is SHA-pinned" \
   "python3 -c \"
import re,yaml
d=yaml.safe_load(open('$WF'))
for j in d['jobs'].values():
    for s in j['steps']:
        u=s.get('uses')
        if u: assert re.search(r'@[0-9a-f]{40}\$', u.split(' ')[0]), u\""

# --- package names are literals, never expressions -------------------------
ck "production package names are fixed literals" \
   "grep -q 'for pkg in php-fpm php-cli php-worker php-frankenphp caddy nginx' $WF"
ck "no dynamic registry or package expression" \
   "! grep -qE 'ghcr\\.io/\\\$\\{\\{' $WF"

# --- the classifier: a network failure is NOT a denial ---------------------
# Extracted and driven directly, because this is the judgement that decides
# whether the boundary is reported as holding.
classify() {
  local o; o="$(tr '[:upper:]' '[:lower:]' <<<"$1")"
  case "$o" in
    *denied*|*unauthorized*|*"insufficient_scope"*|*forbidden*|*"403"*|*"permission"*)
      echo denied ;;
    *timeout*|*"timed out"*|*"5"[0-9][0-9]*|*"connection"*|*"no such host"*|*"i/o"*|*eof*)
      echo indeterminate ;;
    *) echo indeterminate ;;
  esac
}
c() { ck "classify: $1 -> $3" "[ \"\$(classify '$2')\" = '$3' ]"; }

c "denied"              "denied: requested access to the resource is denied" denied
c "unauthorized"        "unauthorized: authentication required"              denied
c "insufficient_scope"  "insufficient_scope: authorization failed"           denied
c "403"                 "unexpected status from POST request: 403 Forbidden" denied
c "permission"          "permission_denied: write_package"                   denied
c "timeout"             "net/http: request canceled (Client.Timeout)"        indeterminate
c "502"                 "received unexpected HTTP status: 502 Bad Gateway"   indeterminate
c "connection refused"  "dial tcp: connection refused"                       indeterminate
c "no such host"        "dial tcp: lookup ghcr.io: no such host"             indeterminate
c "EOF"                 "unexpected EOF"                                     indeterminate
c "unknown text"        "something nobody predicted"                         indeterminate
c "empty output"        ""                                                   indeterminate

# --- the verdict is fail-closed -------------------------------------------
ck "an indeterminate result fails the verdict" \
   "grep -q 'select(.result==\"indeterminate\")] | length) > 0 then \"FAIL\"' $WF"
ck "a non-private package fails the verdict" \
   "grep -q 'select(.visibility != \"private\")] | length) > 0 then \"FAIL\"' $WF"
ck "exactly 6 production denials are required" \
   "grep -q 'select(.expected_access==\"read-only\" and .result==\"denied\")] | length) != 6' $WF"
ck "exactly 1 staging write must be allowed" \
   "grep -q 'select(.expected_access==\"write\" and .result==\"allowed\")] | length) != 1' $WF"
ck "an unreadable package visibility is 'unreadable', never assumed private" \
   "grep -q 'echo unreadable' $WF"

# --- an unexpected write is recorded, not cleaned up -----------------------
ck "an unexpected production write fails the run" \
   "grep -q 'BOUNDARY FAILURE' $WF"
ck "...and the canary is deliberately left in place" \
   "grep -q 'left in place deliberately' $WF"
ck "...and the workflow never deletes a package version" \
   "! grep -qiE 'gh api -X DELETE|docker.*rmi.*ghcr|DELETE /orgs' $WF"

# --- evidence --------------------------------------------------------------
ck "evidence is uploaded even when the run fails" \
   "python3 -c \"
import yaml
d=yaml.safe_load(open('$WF'))
up=[s for s in d['jobs']['probe']['steps'] if 'upload-artifact' in str(s.get('uses',''))]
assert up, 'no upload step'
assert up[0].get('if')=='always()', up[0].get('if')
assert up[0]['with']['if-no-files-found']=='error'\""
ck "evidence binds run id, attempt and source revision" \
   "python3 -c \"
h=open('$WF').read()
for k in ('workflow_run_id','workflow_run_attempt','source_revision','schema_version'):
    assert k in h, k\""

echo "----"; [ "$fail" -eq 0 ] && echo "test_package_acl_probe: PASS" || echo "test_package_acl_probe: FAIL"
exit $fail
