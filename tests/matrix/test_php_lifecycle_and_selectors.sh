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
LIFE=policies/php-lifecycle.yaml
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
ck "the matrix holds 14 image definitions" "[ \"\$(matrix_images | wc -l | tr -d ' ')\" -eq 14 ]"
ck "PHP 8.5 is present for all four families" \
   "[ \"\$(matrix_images | grep -c ':8.5$')\" -eq 4 ]"
ck "the planner yields exactly 28 children on two platforms" \
   "[ \"\$(bash scripts/release/build-acceptance-matrix.sh 'linux/amd64,linux/arm64' | jq '(.include // .) | length')\" -eq 28 ]"
ck "...14 per platform" \
   "[ \"\$(bash scripts/release/build-acceptance-matrix.sh 'linux/amd64,linux/arm64' | jq '[(.include // .)[]|select(.platform==\"linux/arm64\")]|length')\" -eq 14 ]"
ck "every 8.5 family has a real image directory with a Dockerfile" \
   "for f in php-cli php-fpm php-worker php-frankenphp; do test -s \"images/\$f/8.5/Dockerfile\" || exit 1; done"
ck "every 8.5 base is digest-pinned to an OFFICIAL upstream image" \
   "[ \"\$(grep -hoE '(php|dunglas/frankenphp):[^ ]*8\.5[^ ]*@sha256:[a-f0-9]{64}' images/php-*/8.5/Dockerfile | wc -l | tr -d ' ')\" -ge 4 ]"

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
  ck "$f/8.5 is UNGOVERNED — the cohort did not silently widen" \
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
ck "the ledger contains no bare PHP family selector" \
   "! python3 -c \"
import yaml;d=yaml.safe_load(open('$LEDGER'))
bare={'php-cli','php-fpm','php-worker','php-frankenphp'}
rows=d['exceptions']+(d.get('not_affected') or [])
assert not [e for e in rows if e.get('image') in bare]
\" 2>&1 | grep -q Assertion"

# --- lifecycle metadata -----------------------------------------------------
ck "lifecycle policy declares 8.3, 8.4 and 8.5" \
   "[ \"\$(python3 -c \"import yaml;print(len(yaml.safe_load(open('$LIFE'))['versions']))\")\" -eq 3 ]"
ck "8.5 is marked governance-pending, NOT supported" \
   "[ \"\$(python3 -c \"
import yaml;d=yaml.safe_load(open('$LIFE'))
print([v['support_state'] for v in d['versions'] if v['version']=='8.5'][0])\")\" = governance-pending ]"
ck "8.3 is marked deprecated and carries a migration target" \
   "python3 -c \"
import yaml;d=yaml.safe_load(open('$LIFE'))
v=[x for x in d['versions'] if x['version']=='8.3'][0]
assert v['support_state']=='deprecated' and v['migration_target'] and v['retire_after']\""
ck "every matrix PHP version is declared in the lifecycle policy" \
   "python3 -c \"
import yaml,subprocess
d=yaml.safe_load(open('$LIFE'))
declared={v['version'] for v in d['versions']}
out=subprocess.run(['bash','-c','. scripts/lib/common.sh; matrix_images'],capture_output=True,text=True).stdout
inmatrix={t.split(':')[1] for t in out.split() if t.startswith('php-')}
assert inmatrix <= declared, (inmatrix - declared)\""
ck "every lifecycle version that is not retired is present in the matrix" \
   "python3 -c \"
import yaml,subprocess
d=yaml.safe_load(open('$LIFE'))
live={v['version'] for v in d['versions'] if v['support_state']!='retired'}
out=subprocess.run(['bash','-c','. scripts/lib/common.sh; matrix_images'],capture_output=True,text=True).stdout
inmatrix={t.split(':')[1] for t in out.split() if t.startswith('php-')}
assert live <= inmatrix, (live - inmatrix)\""
ck "a lifecycle deadline that has passed is detectable" \
   "python3 -c \"
import yaml,datetime
d=yaml.safe_load(open('$LIFE'))
today=datetime.date.today()
overdue=[v['version'] for v in d['versions']
         if v.get('retire_after') and datetime.date.fromisoformat(str(v['retire_after']))<today
         and v['support_state']!='retired']
assert not overdue, 'past retire_after but still live: %r' % overdue\""

# --- no hardcoded 10-image / 20-child assumption anywhere ------------------
# Comments are stripped: build-acceptance-matrix.sh documents the OLD 10x2=20
# arithmetic in prose, and a check that matches its own explanatory comment is
# not a check.
offenders="$(grep -rnE 'expected_children.*=.*20|images.*==.*10|-eq 20\b|grep -c \.\)\" = (10|20)\b' \
             scripts/ .github/workflows/ 2>/dev/null \
           | grep -vE 'test_|\.md:' \
           | grep -vE ':[0-9]+: *#' || true)"
ck "no script or workflow hardcodes a 10-image / 20-child matrix" \
   "[ -z \"\$offenders\" ] || { printf 'offenders:\n%s\n' \"\$offenders\"; false; }"
ck "the authorizer derives its expected count from the matrix, not a literal" \
   "grep -q 'n_images=\"\$(matrix_image_labels | wc -l' scripts/release/authorize-staged-candidates.sh"

echo "----"; [ "$fail" -eq 0 ] && echo "test_php_lifecycle_and_selectors: PASS" || echo "test_php_lifecycle_and_selectors: FAIL"
exit $fail
