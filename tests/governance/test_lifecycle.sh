#!/usr/bin/env bash
# =============================================================================
# tests/governance/test_lifecycle.sh — the lifecycle inventory must describe the
# images that actually exist, and the images must advertise what it says
# (#104, #105, #106).
#
# The defect: images/nginx/Dockerfile pinned nginx 1.27 — a mainline line that
# upstream had superseded and which nginx.org no longer lists at all — while
# docs/base-image-strategy.md called it "nginx 1.27 stable". Nothing could see
# it. The vulnerability gate only reports CVEs already published against the
# version we ship, and an unmaintained line's defining property is that new CVEs
# stop being FIXED, not that they stop being found.
#
# Everything below derives its expectation from policies/lifecycle.yaml or from
# the Dockerfiles, and compares the two. Restating a version number here would
# only add a third place to drift.
#
# Runs offline. No docker, no network.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

ck "the lifecycle gate's own self-test passes" \
   "bash scripts/assert-lifecycle.sh --self-test >/dev/null"
ck "the real inventory passes the gate today" \
   "bash scripts/assert-lifecycle.sh >/dev/null"
ck "the gate is wired into macro-validate" \
   "grep -q 'assert-lifecycle.sh' scripts/macro-validate.sh"

# --- the pin and the inventory must agree ----------------------------------
# The nginx Dockerfile must be on a line the inventory calls in-use, and that
# line must not be one it calls unsupported. Reading BOTH sides is the point:
# asserting "the Dockerfile says 1.28" would pass even if the inventory still
# claimed 1.27 was what we ship.
ck "the nginx pin matches the in-use nginx line in the inventory" \
   'python3 -c "
import yaml
df = open(\"images/nginx/Dockerfile\").read()
# split, not a regex: the regex needed more layers of shell quoting than the
# assertion is worth, and an earlier attempt silently passed a stray literal
# through ck(), which only ever sees two arguments.
tag = df.split(\"ARG NGINX_BASE=\" + chr(34))[1].split(\"@\")[0]
inv = yaml.safe_load(open(\"policies/lifecycle.yaml\"))
inuse = [e for e in inv[\"lines\"] if e[\"kind\"] == \"server\" and \"nginx\" in (e.get(\"used_by\") or [])]
assert len(inuse) == 1, [e[\"id\"] for e in inuse]
line = inuse[0]
tags = [line.get(\"upstream_tag\")] + (line.get(\"equivalent_tags\") or [])
assert tag in tags, (tag, line[\"id\"], tags)
assert line[\"upstream_state\"] not in (\"unsupported\", \"eol\"), line[\"upstream_state\"]
"'

ck "the retired nginx line is still recorded, and used by nothing" \
   'python3 -c "
import yaml
inv = yaml.safe_load(open(\"policies/lifecycle.yaml\"))
old = [e for e in inv[\"lines\"] if e[\"id\"] == \"nginx-1.27\"]
assert old, \"the retired line was deleted — the gate can no longer detect a regression onto it\"
assert old[0][\"upstream_state\"] == \"unsupported\", old[0][\"upstream_state\"]
assert not (old[0].get(\"used_by\") or []), old[0][\"used_by\"]
"'

ck "no Dockerfile still pins the retired nginx line" \
   "! grep -rn 'nginx-unprivileged:1.27' images/ | grep -vE '^[^:]+:[0-9]+:[[:space:]]*#'"

# --- every image advertises the state the inventory assigns it --------------
# com.zenchron.support says Foundry supports the image. com.zenchron.support_state
# says what UPSTREAM state its primary runtime line is in. Before this, all ten
# images said "supported" and nothing distinguished PHP 8.3 (security-fixes-only
# since 2025-12-31) from PHP 8.4 (active) — the same overstatement class as #121.
ck "every image declares com.zenchron.support_state" \
   '[ "$(grep -rl "com.zenchron.support_state=" images/*/Dockerfile images/*/*/Dockerfile | wc -l | tr -d " ")" \
      = "$(bash -c ". scripts/lib/common.sh; matrix_image_labels" | grep -c .)" ]'

ck "each PHP image advertises the state its PHP line is actually in" \
   'python3 -c "
import yaml, re, glob, os
inv = yaml.safe_load(open(\"policies/lifecycle.yaml\"))
by_ver = {e[\"tracks\"].split()[-1]: e for e in inv[\"lines\"]
          if e[\"kind\"] == \"runtime\" and e[\"tracks\"].startswith(\"PHP\")}
bad = []
for df in glob.glob(\"images/php-*/*/Dockerfile\"):
    ver = os.path.basename(os.path.dirname(df))
    want = by_ver[ver].get(\"support_state\")
    got = re.search(r\"com\\.zenchron\\.support_state=\\\"([^\\\"]+)\\\"\", open(df).read())
    got = got.group(1) if got else None
    if got != want:
        bad.append((df, got, want))
assert not bad, bad
"'

ck "PHP 8.3 is advertised as security-only, not as active" \
   'python3 -c "
import re
for fam in (\"php-cli\", \"php-fpm\", \"php-worker\", \"php-frankenphp\"):
    t = open(\"images/%s/8.3/Dockerfile\" % fam).read()
    assert re.search(r\"support_state=\\\"security-only\\\"\", t), fam
"'

# --- documentation must not contradict the inventory ------------------------
ck "no doc still calls the retired nginx line stable" \
   "! grep -rn 'nginx 1.27 stable' docs/ --include='*.md' | grep -q ."
ck "no doc still calls Debian 12 the current stable" \
   '[ -z "$(grep -rn "current Debian stable" docs --include=*.md 2>/dev/null | grep -viE "trixie|debian 13|used to|no longer" || true)" ]'
ck "the Debian 13 migration plan the inventory points at exists" \
   'test -f "$(python3 -c "
import yaml
inv = yaml.safe_load(open(\"policies/lifecycle.yaml\"))
print([e for e in inv[\"lines\"] if e[\"id\"] == \"debian-bookworm\"][0][\"migration_plan\"])")"'
ck "the PHP version policy exists and names the retirement trigger" \
   "test -f docs/php-version-policy.md && grep -qi 'security-only' docs/php-version-policy.md"

# --- PHP 8.5 is a known gap, recorded as such -------------------------------
# #106 cannot close while publication is disabled, so the honest state is a
# tracked gap in the inventory rather than silence.
ck "PHP 8.5 is in the inventory, offered, and flagged governance-pending" \
   'python3 -c "
import yaml
inv = yaml.safe_load(open(\"policies/lifecycle.yaml\"))
e = [x for x in inv[\"lines\"] if x[\"id\"] == \"php-8.5\"][0]
assert e[\"support_state\"] == \"active\", e[\"support_state\"]
assert sorted(e[\"used_by\"]) == [\"php-cli\", \"php-fpm\", \"php-frankenphp\", \"php-worker\"], e[\"used_by\"]
assert e[\"foundry_release_state\"] == \"governance-pending\", e.get(\"foundry_release_state\")
"'

echo "----"; [ "$fail" -eq 0 ] && echo "test_lifecycle: PASS" || echo "test_lifecycle: FAIL"
exit $fail
