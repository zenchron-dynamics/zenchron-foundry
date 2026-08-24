#!/usr/bin/env bash
# shellcheck disable=SC2034
# ^ ck() evals its second argument; uses inside those strings are invisible here.
# =============================================================================
# tests/matrix/test_php_lifecycle_and_selectors.sh
# -----------------------------------------------------------------------------
# THE DEFECT THIS EXISTS FOR. `php-all` matched on FAMILY ONLY:
#
#     if entry_image == "php-all": return fam in PHP_FAMILIES
#
# The moment PHP 8.5 entered MATRIX_IMAGES, all 23 historical `php-all` risk
# decisions would have silently started governing it — decisions made from
# evidence that never contained 8.5. Bare family selectors (`php-frankenphp`,
# 12 more) had the identical defect.
#
# Selectors touching a PHP family are now bound to an immutable cohort name.
# Adding a PHP version cannot widen `php-8.3-8.4`, so 8.5 begins UNGOVERNED.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
REC=scripts/reconcile-vulnerabilities.sh
LEDGER=policies/vulnerability-exceptions.yaml
LIFE=policies/lifecycle.yaml
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
# common.sh sets -e for its own callers. Sourcing it here imports that, and this
# suite deliberately runs commands that exit non-zero (an ungoverned finding must
# refuse). Without restoring +e the first intentional refusal kills the run and
# every later assertion silently never executes — which looks like a pass.
. scripts/lib/common.sh
set +e

# --- matrix shape -----------------------------------------------------------
ck "the matrix holds the shipping image definitions" \
   "[ \"\$(matrix_images | wc -l | tr -d ' ')\" -eq \"\$MATRIX_COUNT\" ]"

# PHP 8.5 IS WITHDRAWN FROM THE LIVE MATRIX. It was added in an earlier batch
# without ever building a child, and the build then turned out to be broken
# (opcache, php-redis). Both root causes are fixed and four amd64 children have
# been built and scanned — so the reason it stays out is no longer "it does not
# build" but "production is MATRIX_COUNT images and 8.5 has not earned that".
# It lives as an enumerated EXPERIMENTAL cohort instead:
# policies/experimental-cohorts.yaml + scripts/experimental/experimental-plan.sh,
# proved reachable AND isolated by tests/experimental/test_experimental_plan.sh.
ck "PHP 8.5 is NOT in the live matrix" \
   "[ \"\$(matrix_images | grep -c ':8.5\$')\" -eq 0 ]"
# The 8.5 image definitions EXIST and BUILD as of 2026-08-23 (opcache + php-redis
# fixes). They are deliberately not in the PRODUCTION matrix: production stays at
# MATRIX_COUNT images, and 8.5 is an experimental cohort with its own governance.
ck "the 8.5 image definitions exist and are digest-pinned to official bases" \
   "for f in php-cli php-fpm php-worker php-frankenphp; do
      test -s \"images/\$f/8.5/Dockerfile\" || exit 1
      grep -qE '(php|dunglas/frankenphp):[^ ]*8\.5[^ ]*@sha256:[a-f0-9]{64}' \"images/\$f/8.5/Dockerfile\" || exit 1
    done"
ck "...but PRODUCTION contracts exist only for matrix images" \
   "! ls contracts/images/*-8.5.yaml >/dev/null 2>&1"
ck "...and the cli/fpm/worker 8.5 Dockerfiles do NOT compile opcache" \
   "for f in php-cli php-fpm php-worker; do
      grep -A16 'docker-php-ext-install' \"images/\$f/8.5/Dockerfile\" | grep -qE '^\s+opcache' && exit 1
      grep -q 'OPCACHE IS NOT COMPILED ON PHP 8.5' \"images/\$f/8.5/Dockerfile\" || exit 1
    done; true"
ck "...while 8.3 and 8.4 still DO compile opcache (unchanged)" \
   "for v in 8.3 8.4; do
      grep -A16 'docker-php-ext-install' \"images/php-cli/\$v/Dockerfile\" | grep -qE '^\s+opcache' || exit 1
    done"
ck "...and 8.5 pins php-redis 6.3.0 (6.1.0 fails: php_smart_string.h removed in 8.5)" \
   "for f in php-cli php-fpm php-worker; do
      grep -q 'PHPREDIS_VERSION=\"6.3.0\"' \"images/\$f/8.5/Dockerfile\" || exit 1
    done"
ck "...with the build blocker recorded as evidence, not folklore" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$LIFE'))
e=[x for x in d['lines'] if x['id']=='php-8.5'][0]
assert e['foundry_release_state']=='experimental-amd64-only', e.get('foundry_release_state')
b=e['blocker']
assert 'opcache' in b['summary']
assert 'redis' in b['ruled_out']
assert b['next_action'] and b['why_not_in_matrix']
assert e['used_by']==[], e['used_by']\""
ck "the planner yields exactly MATRIX_COUNT x 2 children" \
   "[ \"\$(bash scripts/release/build-acceptance-matrix.sh 'linux/amd64,linux/arm64' | jq '(.include // .) | length')\" -eq \$(( MATRIX_COUNT * 2 )) ]"

# --- a finding fixture ------------------------------------------------------
scan() { jq -n --arg c "$2" --arg p "$3" --arg v "$4" '{
  SchemaVersion:2, ArtifactName:"t", Metadata:{OS:{Family:"debian",Name:"12.15"}},
  Results:[{Target:"t",Class:"os-pkgs",Type:"debian",
    Vulnerabilities:[{VulnerabilityID:$c,PkgName:$p,InstalledVersion:$v,Severity:"HIGH",DataSource:{ID:"debian"}}]}]}' > "$1"; }
run() { TODAY=2026-08-21 bash "$REC" "$1" "$2" "$3" --arch "$4" --policy "${5:-$LEDGER}" --today 2026-08-21 2>&1; }

# CVE-2026-14456 is governed for the 8.3-8.4 cohort at this exact version.
scan "$TMP/ssl.json" CVE-2026-14456 libssl3 "3.0.20-1~deb12u2"

# --- the cohort covers what it was evidenced on -----------------------------
# rc is captured into a variable: `[ $? -eq 0 ]` inside ck()'s eval string reads
# ck's OWN status, not the reconciler's, and would pass no matter what happened.
for v in 8.3 8.4; do
  for f in php-cli php-fpm php-worker php-frankenphp; do
    run "$TMP/ssl.json" "$f" "$v" linux/amd64 >/dev/null 2>&1; rc=$?
    ck "$f/$v is covered by the php-8.3-8.4 cohort" "[ '$rc' -eq 0 ]"
  done
done

# --- THE POINT: 8.5 is ungoverned ------------------------------------------
for f in php-cli php-fpm php-worker php-frankenphp; do
  run "$TMP/ssl.json" "$f" 8.5 linux/amd64 > "$TMP/o-$f.txt" 2>&1
  ck "$f/8.5 would be UNGOVERNED if re-added — the cohort cannot widen" \
     "grep -q 'no in-scope exception' '$TMP/o-$f.txt'"
  ck "...and the refusal names $f/8.5, not a neighbour" \
     "grep -q '$f/8.5' '$TMP/o-$f.txt'"
done

# --- the moving selectors are refused outright ------------------------------
python3 - "$TMP/phpall.yaml" <<'PY'
import yaml,sys
d=yaml.safe_load(open("policies/vulnerability-exceptions.yaml"))
for e in d["exceptions"]:
    if e["image"]=="php-8.3-8.4": e["image"]="php-all"
yaml.safe_dump(d,open(sys.argv[1],"w"),sort_keys=False,allow_unicode=True)
PY
run "$TMP/ssl.json" php-cli 8.4 linux/amd64 "$TMP/phpall.yaml" > "$TMP/o-phpall.txt" 2>&1
ck "SABOTAGE: a restored 'php-all' selector is REFUSED, not honoured" \
   "grep -q 'no longer accepted' '$TMP/o-phpall.txt'"
ck "...naming the version-bounded replacement" \
   "grep -q 'php-8.3-8.4' '$TMP/o-phpall.txt'"

python3 - "$TMP/bare.yaml" <<'PY'
import yaml,sys
d=yaml.safe_load(open("policies/vulnerability-exceptions.yaml"))
for e in d["exceptions"]:
    if e["image"]=="php-frankenphp-8.3-8.4": e["image"]="php-frankenphp"
yaml.safe_dump(d,open(sys.argv[1],"w"),sort_keys=False,allow_unicode=True)
PY
# libaom3 / CVE-2023-6879 is governed ONLY by the php-frankenphp entry. Using a
# cohort-covered CVE here would let the cohort satisfy the finding and the
# sabotage would pass while proving nothing.
scan "$TMP/aom.json" CVE-2023-6879 libaom3 "3.6.0-1+deb12u2"
run "$TMP/aom.json" php-frankenphp 8.4 linux/amd64 "$TMP/bare.yaml" > "$TMP/o-bare.txt" 2>&1
run "$TMP/aom.json" php-frankenphp 8.4 linux/amd64 > "$TMP/o-aom-ok.txt" 2>&1; rc_aom=$?
ck "the frankenphp-only finding IS governed by its cohort entry (fixture sanity)" \
   "[ '$rc_aom' -eq 0 ]"
ck "SABOTAGE: a bare PHP family selector is REFUSED" \
   "grep -q 'bare PHP family selector' '$TMP/o-bare.txt'"
ck "...naming the cohort form to use instead" \
   "grep -q 'php-frankenphp-8.3-8.4' '$TMP/o-bare.txt'"

# `all` must not absorb a new PHP version either.
python3 - "$TMP/all.yaml" <<'PY'
import yaml,sys
d=yaml.safe_load(open("policies/vulnerability-exceptions.yaml"))
for e in d["exceptions"]:
    if e["cve"]=="CVE-2026-14456" and e["image"]=="php-8.3-8.4": e["image"]="all"
yaml.safe_dump(d,open(sys.argv[1],"w"),sort_keys=False,allow_unicode=True)
PY
run "$TMP/ssl.json" php-cli 8.5 linux/amd64 "$TMP/all.yaml" > "$TMP/o-all.txt" 2>&1
ck "SABOTAGE: even the 'all' selector does not reach PHP 8.5" \
   "grep -q 'no in-scope exception' '$TMP/o-all.txt'"

# --- no moving selector survives in the committed ledger -------------------
ck "the ledger contains no 'php-all' selector" \
   "! python3 -c \"
import yaml;d=yaml.safe_load(open('$LEDGER'))
rows=d['exceptions']+(d.get('not_affected') or [])
assert not [e for e in rows if e.get('image')=='php-all']
\" 2>&1 | grep -q Assertion"
# The not_affected list uses the SAME selector grammar as exceptions and was
# missed by the first migration, so twelve records kept bare family selectors and
# began refusing. It was caught by reconciling ACCEPTED evidence, not by any
# unit test — so both lists are now asserted explicitly.
ck "the ledger contains no bare PHP family selector (BOTH lists)" \
   "! python3 -c \"
import yaml;d=yaml.safe_load(open('$LEDGER'))
bare={'php-cli','php-fpm','php-worker','php-frankenphp'}
rows=d['exceptions']+(d.get('not_affected') or [])
assert not [e for e in rows if e.get('image') in bare]
# non-vacuity: both lists must actually be populated, or this proves nothing
assert d['exceptions'] and d.get('not_affected')
\" 2>&1 | grep -q Assertion"

# --- lifecycle metadata (the CANONICAL inventory, not a parallel file) -----
# An earlier draft of this change added policies/php-lifecycle.yaml alongside the
# existing policies/lifecycle.yaml. Two inventories is exactly the writer/reader
# drift this project keeps hitting, so the duplicate was deleted and 8.5 folded
# into the canonical one.
ck "there is exactly ONE lifecycle inventory" \
   "test -f policies/lifecycle.yaml && ! test -f policies/php-lifecycle.yaml"
ck "the inventory declares PHP 8.3, 8.4 and 8.5" \
   "[ \"\$(python3 -c \"
import yaml;d=yaml.safe_load(open('$LIFE'))
print(len([x for x in d['lines'] if x['id'].startswith('php-8.')]))\")\" -eq 3 ]"
ck "8.5 tracks upstream 'active' but Foundry 'experimental-amd64-only'" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$LIFE'))
e=[x for x in d['lines'] if x['id']=='php-8.5'][0]
assert e['support_state']=='active', e['support_state']
assert e['foundry_release_state']=='experimental-amd64-only', e.get('foundry_release_state')\""
ck "8.3 is security-only — deprecation is advertised, not implied" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$LIFE'))
e=[x for x in d['lines'] if x['id']=='php-8.3'][0]
assert e['support_state']=='security-only', e['support_state']\""
ck "every matrix PHP version has an inventory line claiming its images" \
   "python3 -c \"
import yaml,subprocess
d=yaml.safe_load(open('$LIFE'))
by={x['id'].split('-')[1]:x for x in d['lines'] if x['id'].startswith('php-8.')}
out=subprocess.run(['bash','-c','. scripts/lib/common.sh; matrix_images'],capture_output=True,text=True).stdout
for tok in out.split():
    fam,ver=tok.split(':')
    if not fam.startswith('php-'): continue
    e=by[ver]
    assert fam in e['used_by'], (tok, e['used_by'])\""
ck "no inventory line claims an image that does not exist in the matrix" \
   "python3 -c \"
import yaml,subprocess
d=yaml.safe_load(open('$LIFE'))
out=subprocess.run(['bash','-c','. scripts/lib/common.sh; matrix_images'],capture_output=True,text=True).stdout
have={(t.split(':')[0],t.split(':')[1]) for t in out.split()}
for x in d['lines']:
    if not x['id'].startswith('php-8.'): continue
    ver=x['id'].split('-')[1]
    for fam in (x.get('used_by') or []):
        assert (fam,ver) in have, (fam,ver)\""
ck "a passed upstream support deadline is detectable" \
   "python3 -c \"
import yaml,datetime
d=yaml.safe_load(open('$LIFE'))
today=datetime.date.today()
bad=[x['id'] for x in d['lines']
     if x.get('support_ends') and datetime.date.fromisoformat(str(x['support_ends']))<today
     and x.get('support_state') not in ('unsupported','retired','not-yet-offered')
     and x.get('upstream_state') not in ('unsupported','retired')]
assert not bad, 'past support_ends but still offered: %r' % bad\""

# --- no hardcoded 10-image / 20-child assumption anywhere ------------------
# Comments are stripped: build-acceptance-matrix.sh documents the OLD 10x2=20
# arithmetic in prose, and a check that matches its own explanatory comment is
# not a check.
#
# THIS PATTERN LIST IS THE PRODUCT OF A FAILURE. Its first version matched three
# shapes and missed ELEVEN real hardcoded assumptions that PHP 8.5 then broke in
# CI one at a time: the release-manifest schema, the manifest generator, the
# promotion fixtures, MATRIX_COUNT, assert-image-matrix, per-image runtime
# contract counts, extension contract counts, and five test suites. Every miss
# was a literal shaped slightly differently from the ones I had imagined.
#
# So it now matches the SHAPES, not the specific numbers: any comparison of a
# counted thing against a bare integer in matrix-adjacent code.
offenders="$(grep -rnE 'expected_children.*=.*[0-9]+|wc -l[^|]*\)\" = [0-9]+|-eq (10|14|20|28)\b|keys \| length\" \) = [0-9]+' \
             scripts/ .github/workflows/ contracts/ 2>/dev/null \
           | grep -vE 'test_|\.md:' \
           | grep -vE ':[0-9]+: *#' \
           | grep -vE 'MATRIX_COUNT|NIMG|NCHILD' || true)"
ck "no script or workflow compares a matrix-derived count to a bare literal" \
   "[ -z \"\$offenders\" ] || { printf 'offenders:\n%s\n' \"\$offenders\"; false; }"

# The two INTENTIONAL tripwires are exempt and named, so nobody deletes them
# thinking they are the drift this check hunts.
# A hardcoded PHP version list in a fixture is only WRONG when it disagrees with
# the live matrix. The previous form matched ("8.3","8.4") unconditionally: right
# while PHP 8.5 was in the matrix, a false positive the moment 8.5 was withdrawn.
# Compare against MATRIX_IMAGES instead of a constant.
python3 scripts/ci/check-php-version-fixtures.py > "$TMP/vfix.out" 2>&1; _vfix=$?
ck "hardcoded PHP version lists agree with the live matrix" "[ $_vfix -eq 0 ]"
[ $_vfix -eq 0 ] || sed 's/^/      /' "$TMP/vfix.out"

ck "the two deliberate drift tripwires still exist and agree with the matrix" \
   "grep -q '^MATRIX_COUNT=' scripts/lib/common.sh &&
    grep -q 'INTENTIONAL independent count assertion' scripts/assert-image-matrix.sh &&
    [ \"\$(bash -c '. scripts/lib/common.sh; echo \$MATRIX_COUNT')\" -eq \"\$(bash -c '. scripts/lib/common.sh; matrix_image_labels' | grep -c .)\" ]"

ck "every matrix image has a runtime contract and every PHP one an extension contract" \
   "[ \"\$(ls contracts/images/*.yaml | wc -l | tr -d ' ')\" -eq \"\$(bash -c '. scripts/lib/common.sh; echo \$MATRIX_COUNT')\" ] &&
    [ \"\$(ls contracts/php-extensions/*.txt | wc -l | tr -d ' ')\" -eq \"\$(grep -h '^extensions_contract:' contracts/images/*.yaml | sort -u | wc -l | tr -d ' ')\" ]"

ck "the authorizer derives its expected count from the matrix, not a literal" \
   "grep -q 'n_images=\"\$(matrix_image_labels | wc -l' scripts/release/authorize-staged-candidates.sh"

# --- REGRESSION: the accepted evidence must still reconcile clean ----------
# This is the check that caught the not_affected miss. A selector change can look
# perfect in unit fixtures and still break real, previously-passing evidence.
ACC=docs/audits/acceptance-multiarch-2026-08-20/acceptance-evidence.json
ck "the accepted run's 20 children are all recorded as reconciliation PASS" \
   "[ \"\$(jq -r '[.children[]|select(.reconciliation==\"PASS\")]|length' $ACC)\" -eq 20 ]"
ck "every governed CVE in that evidence still resolves to a live ledger entry" \
   "python3 -c \"
import json,yaml
acc=json.load(open('$ACC'))
led=yaml.safe_load(open('$LEDGER'))
have={e['cve'] for e in led['exceptions']} | {e['cve'] for e in (led.get('not_affected') or [])}
seen=set()
for c in acc['children']:
    seen |= set(c.get('governed_findings') or {})
assert seen, 'no governed findings in the accepted evidence — check is vacuous'
missing = sorted(seen - have)
assert not missing, 'accepted evidence cites CVEs no ledger entry covers: %r' % missing\""

echo "----"; [ "$fail" -eq 0 ] && echo "test_php_lifecycle_and_selectors: PASS" || echo "test_php_lifecycle_and_selectors: FAIL"
exit $fail
