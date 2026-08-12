#!/usr/bin/env bash
# =============================================================================
# tests/runtime/test_runtime_contract.sh — the runtime assurance subsystem, from
# the outside (#110, #107, #129).
#
# The executable half needs docker and runs in trusted-validation.yml and
# `make runtime-contract`. This is the OFFLINE half: it proves the subsystem is
# complete, internally consistent, and actually wired into the paths that gate a
# release — the ways a harness stops being run without anyone noticing.
#
# The defect that motivated the harness: each family's smoke test applied a
# DIFFERENT subset of the advertised hardening. FrankenPHP's started with
# `--read-only --tmpfs /tmp` and omitted cap_drop, no-new-privileges, PID limits
# and the tmpfs flags entirely, so an image could pass smoke and fail under the
# profile the documentation tells consumers to use.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

POL=policies/runtime-contract.yaml

# --- the subsystem exists and self-checks -----------------------------------
ck "the runtime contract harness self-test passes" \
   "bash scripts/runtime-contract.sh --self-test >/dev/null"
ck "the confinement profiles gate self-test passes" \
   "bash scripts/assert-runtime-profiles.sh --self-test >/dev/null"

# --- one contract, not per-family improvisation -----------------------------
ck "every shipping image has a runtime block in its contract" \
   'python3 -c "
import glob, yaml
missing = [f for f in glob.glob(\"contracts/images/*.yaml\")
           if not ((yaml.safe_load(open(f)) or {}).get(\"runtime\") or {}).get(\"mode\")]
assert not missing, missing
"'
ck "every runtime block declares a stop signal and a grace period" \
   'python3 -c "
import glob, yaml
bad = []
for f in glob.glob(\"contracts/images/*.yaml\"):
    r = (yaml.safe_load(open(f)) or {}).get(\"runtime\") or {}
    if not r.get(\"stop_signal\") or not isinstance(r.get(\"graceful_stop_seconds\"), int):
        bad.append(f)
assert not bad, bad
"'
ck "the harness matrix is exactly the shipping matrix" \
   "[ \"\$(bash -c 'source /dev/null; ZC_REGISTRY=x bash scripts/runtime-contract.sh --self-test >/dev/null 2>&1; echo ok')\" = ok ]"

# --- the profile is not editable by editing an example ----------------------
# policies/runtime-contract.yaml is the contract; profiles/compose.security.yml
# is an example a consumer edits. They must agree, and the CONTRACT is the one
# the harness runs.
ck "the contract profile and the compose profile agree" \
   'python3 -c "
import yaml
p = yaml.safe_load(open(\"policies/runtime-contract.yaml\"))[\"profile\"]
c = yaml.safe_load(open(\"profiles/compose.security.yml\"))[\"x-zenchron-hardening\"]
assert c[\"read_only\"] is p[\"read_only\"]
assert c[\"cap_drop\"] == p[\"cap_drop\"]
assert c[\"security_opt\"] == p[\"security_opt\"]
assert c[\"pids_limit\"] == p[\"pids_limit\"]
for m in c[\"tmpfs\"]:
    for f in p[\"tmpfs_flags\"]:
        assert f in m, (m, f)
"'
# The mode=1777 fix. Docker mounts every tmpfs except /tmp as 755 root-owned, so
# a non-root image cannot write a path its own contract declares writable —
# caddy failed with `open /data/caddy/instance.uuid: read-only file system` on
# every start, and the read-only rootfs took the blame for a mount-mode problem.
ck "every tmpfs in the compose profile sets an explicit mode" \
   'python3 -c "
import yaml
c = yaml.safe_load(open(\"profiles/compose.security.yml\"))[\"x-zenchron-hardening\"]
missing = [m for m in c[\"tmpfs\"] if \"mode=\" not in m]
assert not missing, missing
"'
ck "the contract declares the tmpfs mode the harness applies" \
   "[ -n \"\$(python3 -c \"
import yaml; print(yaml.safe_load(open('$POL'))['profile'].get('tmpfs_mode',''))\")\" ]"

# --- wired into the paths that gate a release -------------------------------
# A harness nobody runs is documentation. These are the ways it stops running.
ck "trusted-validation executes the runtime contract" \
   "grep -q 'scripts/runtime-contract.sh' .github/workflows/trusted-validation.yml"
ck "trusted-validation executes the confinement profiles gate" \
   "grep -q 'assert-runtime-profiles.sh --executed' .github/workflows/trusted-validation.yml"
ck "macro-validate runs the offline half of the profiles gate" \
   "grep -q 'assert-runtime-profiles.sh' scripts/macro-validate.sh"
ck "the Makefile exposes a whole-matrix run" \
   "grep -q 'runtime-contract.sh --all' Makefile"

# --- #107: the privacy contract is declared AND implemented -----------------
ck "the policy declares which images the logging contract applies to" \
   'python3 -c "
import yaml
lp = yaml.safe_load(open(\"policies/runtime-contract.yaml\"))[\"logging_privacy\"]
assert lp[\"applies_to\"], lp
assert lp[\"canaries\"], lp
assert lp[\"default_profile\"] == \"privacy-eu\", lp[\"default_profile\"]
"'
# nginx: the ACTIVE access_log must be the minimised format. A `log_format` that
# exists but is not selected logs nothing.
ck "nginx's active access_log uses the privacy format" \
   "grep -qE '^[[:space:]]*access_log[[:space:]]+/dev/stdout[[:space:]]+privacy_eu;' images/nginx/nginx.conf"
ck "the privacy format logs \$uri, never \$request_uri or \$request" \
   'python3 -c "
import re
t = open(\"images/nginx/nginx.conf\").read()
m = re.search(r\"log_format privacy_eu.*?;\", t, re.S).group(0)
assert \"\$uri\" in m, m
for bad in (\"\$request_uri\", \"\$args\", \"\$query_string\", \"\$http_cookie\", \"\$http_authorization\"):
    assert bad not in m, bad
"'
ck "the privacy format logs a truncated client network, not \$remote_addr" \
   'python3 -c "
import re
t = open(\"images/nginx/nginx.conf\").read()
m = re.search(r\"log_format privacy_eu.*?;\", t, re.S).group(0)
assert \"\$client_net\" in m and \"\$remote_addr\" not in m, m
assert \"map \$remote_addr \$client_net\" in t
"'
# The `json` alias must NOT quietly remain the verbose format: consumer site
# configs say `access_log /dev/stdout json;` and would keep leaking.
ck "the legacy 'json' format name is now an alias of the privacy format" \
   'python3 -c "
import re
t = open(\"images/nginx/nginx.conf\").read()
m = re.search(r\"log_format json .*?;\", t, re.S).group(0)
assert \"\$request_uri\" not in m and \"\$remote_addr\" not in m, m
"'
ck "caddy ships an importable privacy_log snippet" \
   "grep -q '^(privacy_log)' images/caddy/Caddyfile"
ck "caddy masks BOTH remote_ip and client_ip" \
   "grep -q 'request>remote_ip ip_mask' images/caddy/Caddyfile && grep -q 'request>client_ip ip_mask' images/caddy/Caddyfile"
ck "caddy strips the query string name-independently" \
   "grep -q 'request>uri regexp' images/caddy/Caddyfile"
ck "caddy deletes the credential headers" \
   'for h in Authorization Cookie X-Api-Key; do grep -q "request>headers>$h delete" images/caddy/Caddyfile || exit 1; done'

# --- #129: the profiles exist and are referenced ----------------------------
ck "the pinned seccomp profile exists and is default-deny" \
   "python3 -c \"
import json; d=json.load(open('security/seccomp/zenchron-default.json'))
assert d['defaultAction']=='SCMP_ACT_ERRNO'\""
ck "the AppArmor reference profile exists" "test -s security/apparmor/zenchron-container"
ck "SELinux is documented, and no policy module is shipped" \
   "test -f security/selinux/README.md && ! find security/selinux -name '*.pp' -o -name '*.te' | grep -q ."
ck "the README does not claim AppArmor enforcement is universal" \
   "grep -qi 'not enforced on every host' security/README.md"

echo "----"; [ "$fail" -eq 0 ] && echo "test_runtime_contract: PASS" || echo "test_runtime_contract: FAIL"
exit $fail
