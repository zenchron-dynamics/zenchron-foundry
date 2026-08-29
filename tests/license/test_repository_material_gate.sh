#!/usr/bin/env bash
# =============================================================================
# tests/license/test_repository_material_gate.sh
# -----------------------------------------------------------------------------
# The repository-material half of the licence gate, exercised against the REAL
# TREE — not only against fixtures.
#
# WHY BOTH. scripts/license/assert-repository-material.sh --self-test proves the
# script refuses fixtures. That is necessary and it is not sufficient: it proves
# nothing about whether THIS repository's material is accounted for. The
# repository has been bitten by exactly that gap before — a grep that matched
# only a `--self-test` line "proved" a workflow invoked the licence gate. So
# this file runs the gate over the checkout, sabotages a COPY of the checkout,
# and asserts on what comes back.
#
# TWO KINDS OF ASSERTION, following tests/integration/test_evidence_path_e2e.sh:
#
#   ck()   proven. The shipped code observably does this.
#   gap()  a shortfall that is TRUE TODAY, pinned so it cannot be
#          re-discovered by accident. Every gap names what would close it. When
#          somebody closes one, this test FAILS and says to promote the line.
#
# THE HONESTY THIS FILE IS ACCOUNTABLE FOR. Discovery of copied material is
# HEURISTIC and cannot be otherwise: deciding that an arbitrary file was copied
# from somewhere is undecidable in general. Nothing here asserts universal
# discovery, and the test names below say HEURISTIC where the mechanism is
# heuristic. The limits are pinned as gaps, not narrated away.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1

fail=0 nck=0 ngap=0
ck()  { nck=$((nck+1));  if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }
gap() { ngap=$((ngap+1)); if eval "$2"; then echo "GAP  - $1"; else
          echo "FAIL - GAP ASSERTION NO LONGER HOLDS (promote to ck): $1"; fail=1; fi; }

GATE=scripts/license/assert-repository-material.sh
INV=policies/repository-material.yaml
BASE=docs/licensing/repository-material-baseline.txt
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# `gate | grep -q` inherits the gate's status under pipefail, so a MATCHING grep
# on a refusal would read as a failure — backwards. Capture, then assert.
run() { bash "$GATE" "$@" >"$TMP/out" 2>&1; }
says() { grep -q "$1" "$TMP/out"; }

echo "== the artifacts exist and are well formed ================================"

ck "the gate exists and is executable" "[ -x '$GATE' ]"
ck "the canonical inventory exists" "[ -f '$INV' ]"
ck "the reviewed baseline path list exists" "[ -f '$BASE' ]"
ck "the inventory schema exists" "[ -f schemas/repository-material-v1.schema.json ]"
ck "the inventory validates against its own schema" \
   "python3 - <<'PY'
import json, sys, yaml
try:
    import jsonschema
except ImportError:
    sys.exit(0)   # reported, not silently passed: see the NOTE assertion below
schema = json.load(open('schemas/repository-material-v1.schema.json'))
doc = json.loads(json.dumps(yaml.safe_load(open('policies/repository-material.yaml')), default=str))
jsonschema.validate(instance=doc, schema=schema)
PY"
ck "jsonschema IS available here, so the line above was not a silent skip" \
   "python3 -c 'import jsonschema'"

echo
echo "== the gate's own fixtures ================================================"

ck "the gate's self-test passes" "bash '$GATE' --self-test >'$TMP/st' 2>&1"
ck "...and it exercised all seven required fail-closed cases" \
   "for c in RM-LICENCE-TEXT-MISSING RM-NOTICE-MISSING RM-HASH-DRIFT \
             RM-LICENCE-UNRECOGNISED RM-UNINVENTORIED-MATERIAL \
             RM-OUTBOUND-TERMS-PLACEHOLDER RM-REPOSITORY-EVIDENCE-ABSENT; do
      grep -q \"\$c\" '$TMP/st' || exit 1
    done"

echo
echo "== the REAL tree, which is the assertion the fixtures cannot make ========="

ck "the gate PASSES against the committed tree" "run"
ck "...having composed all four sources, each named in the output" \
   "says 'SOURCE 1  image SBOM' && says 'SOURCE 2  repository-material inventory' \
    && says 'SOURCE 3  licence texts and notices' && says 'SOURCE 4  project outbound licence'"
ck "...over the whole tracked tree, not a subset" \
   "n=\$(git ls-files | wc -l | tr -d ' '); says \"HEURISTIC over \$n tracked files\""
ck "...reporting the outbound licence as NOT FINAL, which is the true state" \
   "says 'NOT FINAL'"
ck "...and saying in the output that discovery cannot prove a file is first-party" \
   "says 'CANNOT prove a file is first-party'"

ck "every material the inventory names is a tracked file that exists" \
   "python3 - <<'PY'
import os, sys, yaml
d = yaml.safe_load(open('policies/repository-material.yaml'))
missing = [m['path'] for m in d['materials'] if not os.path.isfile(m['path'])]
sys.exit(1 if missing else 0)
PY"
ck "the five known copied files are all inventoried" \
   "python3 - <<'PY'
import sys, yaml
want = {
 'security/seccomp/zenchron-default.json',
 'security/apparmor/zenchron-container',
 'docs/audits/libaom3-ownership-2026-08-26/evidence/installer-helper.txt',
 'docs/audits/libaom3-ownership-2026-08-26/evidence/installer-gd-branch.txt',
 'docs/audits/libaom3-ownership-2026-08-26/evidence/installer-gd-configure.txt',
}
have = {m['path'] for m in yaml.safe_load(open('policies/repository-material.yaml'))['materials']}
sys.exit(0 if want <= have else 1)
PY"
ck "the reviewed baseline covers the tracked tree exactly" \
   "diff <(git ls-files | LC_ALL=C sort) '$BASE' >/dev/null"

echo
echo "== SABOTAGE, on a COPY of the real tree ==================================="
# A faithful copy: the tracked files, in a real git repository, so the gate's
# own `git ls-files` discovery runs exactly as it does here.
SB="$TMP/sabotage"
mkdir -p "$SB"
git ls-files -z | tar -cf - --null -T - 2>/dev/null | (cd "$SB" && tar -xf -)
( cd "$SB" && git init -q . && git config user.email t@t && git config user.name t \
  && git add -A && git commit -qm copy ) >/dev/null 2>&1
sb() { bash "$GATE" --root "$SB" --inventory "$SB/$INV" \
        --policy "$SB/policies/license-policy.yaml" --license-file "$SB/LICENSE" \
        "$@" >"$TMP/out" 2>&1; }

ck "NON-VACUOUS: the untouched copy passes, so every refusal below is the sabotage" "sb"

ck "S1 an inventoried copy whose licence text is deleted is REFUSED" \
   "mv '$SB/third-party/moby-v27.3.1/LICENSE' '$TMP/keep-lt'; ! sb"
ck "S1 ...with RM-LICENCE-TEXT-MISSING naming the file and the obligation" \
   "says 'RM-LICENCE-TEXT-MISSING' && says 'third-party/moby-v27.3.1/LICENSE' \
    && says 'retain-license-text'"
ck "S1 NON-VACUOUS: restoring it clears exactly that refusal" \
   "mv '$TMP/keep-lt' '$SB/third-party/moby-v27.3.1/LICENSE'; sb"

ck "S2 a required upstream NOTICE that is deleted is REFUSED" \
   "mv '$SB/third-party/moby-v27.3.1/NOTICE' '$TMP/keep-nt'; ! sb"
ck "S2 ...with RM-NOTICE-MISSING, distinct from the licence-text refusal" \
   "says 'RM-NOTICE-MISSING' && ! says 'RM-LICENCE-TEXT-MISSING'"
ck "S2 NON-VACUOUS: restoring it clears exactly that refusal" \
   "mv '$TMP/keep-nt' '$SB/third-party/moby-v27.3.1/NOTICE'; sb"

ck "S3 editing inventoried material without re-reviewing it is REFUSED" \
   "printf '\n' >> '$SB/security/apparmor/zenchron-container'; ! sb"
ck "S3 ...with RM-HASH-DRIFT naming both the new and the reviewed hash" \
   "says 'RM-HASH-DRIFT' && says 'was reviewed at'"
ck "S3 NON-VACUOUS: recording the new hash as reviewed clears it" \
   "h=\$(shasum -a 256 '$SB/security/apparmor/zenchron-container' | cut -d' ' -f1)
    sed -i.bak \"s|9c4fc9fb22492a7217e2bdff37e8cd7ac6f270681d7560abceb632596f1b639b|\$h|\" '$SB/$INV'
    rm -f '$SB/$INV.bak'; sb"
ck "S3 (reset) the copy is restored to a passing state" \
   "( cd '$SB' && git checkout -q -- security/apparmor/zenchron-container '$INV' ); sb"

ck "S4 a declared licence the policy does not allow is REFUSED" \
   "sed -i.bak 's|declared_spdx: MIT|declared_spdx: GPL-3.0-only|' '$SB/$INV'
    rm -f '$SB/$INV.bak'; ! sb"
ck "S4 ...with RM-LICENCE-UNRECOGNISED naming the policy state it resolved to" \
   "says 'RM-LICENCE-UNRECOGNISED' && says 'legal-review-required'"
ck "S4 a declared licence nobody has classified is REFUSED the same way" \
   "( cd '$SB' && git show HEAD:'$INV' ) | sed 's|declared_spdx: MIT|declared_spdx: NOT-A-REAL-LICENCE-9.9|' > '$SB/$INV'
    ! sb && says 'RM-LICENCE-UNRECOGNISED'"
ck "S4 NON-VACUOUS: the committed inventory passes the same check" \
   "( cd '$SB' && git checkout -q -- '$INV' ); sb"

ck "S5 HEURISTIC DISCOVERY: a newly added copied file absent from the inventory is REFUSED" \
   "mkdir -p '$SB/vendor/acme'
    printf 'Copyright (c) 2019 Acme Corp\nPermission is hereby granted, free of charge, to any person\n' \
      > '$SB/vendor/acme/copied.c'
    ( cd '$SB' && git add -A && git commit -qm sab ) >/dev/null 2>&1
    ! sb"
ck "S5 ...with RM-UNINVENTORIED-MATERIAL naming the file and which signals fired" \
   "says 'RM-UNINVENTORIED-MATERIAL' && says 'vendor/acme/copied.c' \
    && says 'path-third-party' && says 'embedded-licence-grant' && says 'foreign-copyright-header'"
ck "S5 ...and it does NOT tell the author to silence the signal" "says 'Do not silence the signal'"
ck "S5 NON-VACUOUS: removing it clears exactly that refusal" \
   "rm -rf '$SB/vendor'; ( cd '$SB' && git add -A && git commit -qm unsab ) >/dev/null 2>&1; sb"

ck "S6 placeholder outbound terms presented as FINAL are REFUSED" \
   "! sb --require-final-outbound-terms"
ck "S6 ...with RM-OUTBOUND-TERMS-PLACEHOLDER naming both facts, LICENSE and the policy" \
   "says 'RM-OUTBOUND-TERMS-PLACEHOLDER' && says 'declares itself a placeholder' \
    && says 'publication.decision'"
ck "S6 ...and it refuses to be cleared by editing the gate" "says 'not cleared by editing this script'"
ck "S6 NON-VACUOUS: the identical tree passes when finality is not asserted" "sb"

ck "S7 image SBOM evidence beside an empty repository verdict is REFUSED" \
   "printf '{\"schema\":\"foundry.license-inventory/v1\",\"components\":[{\"name\":\"libfoo\",\"version\":\"1\",\"licenses\":[\"MIT\"],\"unknown\":false,\"conflict\":false,\"sources\":[]}]}\n' > '$TMP/img.json'
    python3 - '$SB/$INV' <<'PY'
import sys, re
p = sys.argv[1]
s = open(p).read().replace('status: reviewed', 'status: unreviewed')
open(p, 'w').write(s)
PY
    ! sb --image-inventory '$TMP/img.json'"
ck "S7 ...with RM-REPOSITORY-EVIDENCE-ABSENT, which is the blind spot itself" \
   "says 'RM-REPOSITORY-EVIDENCE-ABSENT' && says 'cannot see repository material'"
ck "S7 NON-VACUOUS: the same image evidence passes beside reviewed repository evidence" \
   "( cd '$SB' && git checkout -q -- '$INV' ); sb --image-inventory '$TMP/img.json'"

ck "S8 a tracked file outside the reviewed baseline is REFUSED at release scope" \
   "printf 'nothing here trips any signal at all\n' > '$SB/quiet-new-file.txt'
    ( cd '$SB' && git add -A && git commit -qm quiet ) >/dev/null 2>&1
    ! sb --require-reviewed-baseline"
ck "S8 ...with RM-BASELINE-STALE naming the file and how to regenerate the baseline" \
   "says 'RM-BASELINE-STALE' && says 'quiet-new-file.txt' && says 'git ls-files'"
ck "S8 ...and at PR scope the same file is REPORTED as drift, never passed in silence" \
   "sb && says 'BASELINE DRIFT' && says 'quiet-new-file.txt'"
# The refresh that added 37 paths to the list left reviewed_at_revision alone and
# reasoned that the field is not machine-checked. It is not, and it was still a
# CLAIM about the list. The list now carries three cohorts and the gate validates
# the split, so "in the list" can no longer read as "somebody looked at it".
#
# The cohort rewriter is a FILE, not an inline heredoc: `ck` runs its argument
# through eval, and a heredoc body inside an eval'd double-quoted string is one
# stray quote away from being reinterpreted.
COH="$TMP/cohorts.py"
cat >"$COH" <<'COHPY'
import hashlib, re, sys
inv, mode = sys.argv[1], sys.argv[2]
s = open(inv).read()
def setf(src, key, val):
    return re.sub(r'^  %s: .*$' % key, '  %s: %s' % (key, val), src, count=1, flags=re.M)
def emptylist(src, key):
    return re.sub(r'^  %s:\n(    - .*\n)*' % key, '  %s: []\n' % key, src, flags=re.M)
def setlist(src, key, items):
    body = ''.join('    - %s\n' % i for i in items)
    src = emptylist(src, key)
    return re.sub(r'^  %s: \[\]\n' % key, '  %s:\n%s' % (key, body), src, count=1, flags=re.M)
if mode == 'review-all':
    # Reviewing the delta MOVES paths between cohorts. It never deletes the model.
    lst = sys.argv[3]
    paths = [l.strip() for l in open(lst) if l.strip()]
    s = emptylist(s, 'unreviewed_paths')
    s = emptylist(s, 'generated_audit_paths')
    s = setf(s, 'path_list_sha256', hashlib.sha256(open(lst, 'rb').read()).hexdigest())
    s = setf(s, 'path_count', len(paths))
    s = setf(s, 'reviewed_count', len(paths))
    s = setf(s, 'unreviewed_count', 0)
    s = setf(s, 'generated_audit_count', 0)
elif mode == 'rehash':
    lst = sys.argv[3]
    paths = [l.strip() for l in open(lst) if l.strip()]
    s = setf(s, 'path_list_sha256', hashlib.sha256(open(lst, 'rb').read()).hexdigest())
    s = setf(s, 'path_count', len(paths))
    s = setf(s, 'reviewed_count', len(paths))
elif mode == 'undercount':
    n = int(re.search(r'^  reviewed_count: (\d+)$', s, re.M).group(1))
    s = setf(s, 'reviewed_count', n - 1)
elif mode == 'advance-review-revision':
    rev = re.search(r'^  observed_at_revision: ([0-9a-f]{40})$', s, re.M).group(1)
    n = int(re.search(r'^  reviewed_count: (\d+)$', s, re.M).group(1))
    s = setf(s, 'reviewed_count', n - 1)
    s = setf(s, 'unreviewed_count', 1)
    s = setlist(s, 'unreviewed_paths', ['LICENSE'])
    s = setf(s, 'reviewed_at_revision', rev)
elif mode == 'phantom-path':
    n = int(re.search(r'^  reviewed_count: (\d+)$', s, re.M).group(1))
    s = setf(s, 'reviewed_count', n - 1)
    s = setf(s, 'unreviewed_count', 1)
    s = setlist(s, 'unreviewed_paths', ['no/such/path.txt'])
else:
    raise SystemExit('unknown mode %r' % mode)
open(inv, 'w').write(s)
COHPY

ck "S8b release scope REFUSES while any path is recorded unreviewed or generated-audit" \
   "! sb --require-reviewed-baseline && says 'RM-BASELINE-UNREVIEWED'"
ck "S8b ...saying that listing a path is not reviewing it" \
   "says 'does not become reviewed by being listed'"
ck "S8b ...and at PR scope the cohorts are REPORTED, never silent" \
   "sb; says 'BASELINE COHORTS' && says 'UNREVIEWED' && says 'not an exemption'"
ck "S8 NON-VACUOUS: reviewing it and regenerating the baseline clears the refusal" \
   "( cd '$SB' && git ls-files | LC_ALL=C sort ) > '$SB/$BASE'
    python3 '$COH' '$SB/$INV' review-all '$SB/$BASE'
    ( cd '$SB' && git add -A && git commit -qm rebase ) >/dev/null 2>&1
    ( cd '$SB' && git ls-files | LC_ALL=C sort ) > '$SB/$BASE'
    python3 '$COH' '$SB/$INV' rehash '$SB/$BASE'
    sb --require-reviewed-baseline"
cp "$SB/$INV" "$TMP/inv-cohort-keep.yaml"
ck "S8c SABOTAGE: cohorts that do not account for every listed path are REFUSED" \
   "python3 '$COH' '$SB/$INV' undercount
    ! sb && says 'RM-BASELINE-COHORT-INVALID' && says 'in exactly one cohort'"
ck "S8c SABOTAGE: advancing the review revision to cover unreviewed paths is REFUSED" \
   "cp '$TMP/inv-cohort-keep.yaml' '$SB/$INV'
    python3 '$COH' '$SB/$INV' advance-review-revision
    ! sb && says 'RM-BASELINE-COHORT-INVALID' && says 'Generating the list is not reviewing it'"
ck "S8c SABOTAGE: a cohort naming a path the list does not hold is REFUSED" \
   "cp '$TMP/inv-cohort-keep.yaml' '$SB/$INV'
    python3 '$COH' '$SB/$INV' phantom-path
    ! sb && says 'RM-BASELINE-COHORT-INVALID' && says 'not in the path list at all'"
ck "S8c NON-VACUOUS: restoring the accounted cohorts passes again" \
   "cp '$TMP/inv-cohort-keep.yaml' '$SB/$INV'; sb --require-reviewed-baseline"
ck "S9 an edited baseline whose hash no longer matches the inventory is REFUSED" \
   "printf 'zzz-not-a-real-path\n' >> '$SB/$BASE'; ! sb && says 'RM-BASELINE-UNVERIFIABLE'"

# --- S10 THE CARRIED LICENCE-TEXT STORE -------------------------------------
# A redistributor owes the recipient the TEXT of each licence it ships under.
# Recording that a text is carried is not carrying it, and carrying different
# bytes than the record names is worse than carrying none: the first person to
# find out would be the recipient checking the hash. Each of the three ways that
# can go wrong has its own code.
STORE=third-party/licence-texts/PROVENANCE.yaml
ck "S10 NON-VACUOUS: the untouched store passes, so every refusal below is sabotage" \
   "( cd '$SB' && git checkout -q -- . ); sb"
ck "S10 the store really is non-empty, so the assertions below are not about nothing" \
   "python3 -c \"
import yaml,sys
d=yaml.safe_load(open('$STORE'))
assert d['record_type']=='carried-licence-texts', d.get('record_type')
assert len(d['files'])>=50, len(d['files'])
sys.exit(0)\""
ck "S10 SABOTAGE: a carried text whose bytes differ from the record is REFUSED" \
   "printf 'tampered\n' >> '$SB/third-party/licence-texts/MIT.txt'
    ! sb && says 'RM-LICENCE-TEXT-STORE-DRIFT' && says 'third-party/licence-texts/MIT.txt'"
ck "S10 ...saying why a text that is not its recorded bytes discharges nothing" \
   "says 'discharges' && says 'recipient checking it'"
ck "S10 SABOTAGE: a carried text that is DELETED is REFUSED, not skipped" \
   "( cd '$SB' && git checkout -q -- . )
    rm -f '$SB/third-party/licence-texts/GPL-2.0-only.txt'
    ! sb && says 'RM-LICENCE-TEXT-STORE-MISSING' && says 'GPL-2.0-only.txt'"
ck "S10 SABOTAGE: an EMPTY carried text is refused exactly like an absent one" \
   "( cd '$SB' && git checkout -q -- . )
    : > '$SB/third-party/licence-texts/Apache-2.0.txt'
    ! sb && says 'RM-LICENCE-TEXT-STORE-MISSING'"
ck "S10 SABOTAGE: a declared store with no provenance record is REFUSED" \
   "( cd '$SB' && git checkout -q -- . )
    rm -f '$SB/$STORE'
    ! sb && says 'RM-LICENCE-TEXT-STORE-UNREADABLE'"
ck "S10 SABOTAGE: a provenance record listing an UNTRACKED text is REFUSED" \
   "( cd '$SB' && git checkout -q -- . )
    python3 - '$SB/$STORE' <<'PY10'
import sys
p = sys.argv[1]
s = open(p).read()
s += (\"  - spdx_id: NOT-TRACKED\n\"
      \"    path: third-party/licence-texts/NOT-TRACKED.txt\n\"
      \"    upstream_path: text/NOT-TRACKED.txt\n\"
      \"    source_url: https://example.invalid/NOT-TRACKED.txt\n\"
      \"    bytes: 1\n\"
      \"    sha256: \" + \"0\" * 64 + \"\\n\"
      \"    verbatim: true\n\"
      \"    local_modifications: none\n\"
      \"    policy_state: legal-review-required\n\"
      \"    policy_obligations: []\n\"
      \"    measured_occurrences_in_cohort: null\n\")
open(p, 'w').write(s)
PY10
    ! sb && says 'RM-LICENCE-TEXT-STORE-UNTRACKED' && says 'NOT-TRACKED.txt'"
ck "S10 the store's paths are COVERED, so they do not also refuse as uninventoried" \
   "( cd '$SB' && git checkout -q -- . ); sb && ! says 'RM-UNINVENTORIED-MATERIAL'"
ck "S10 NON-VACUOUS: removing the declaration makes all 56 texts refuse as uninventoried" \
   "python3 - '$SB/$INV' <<'PY11'
import re, sys
p = sys.argv[1]
s = open(p).read()
s = re.sub(r'^carried_licence_texts:\n(  .*\n|\n(?=  ))*', '', s, count=1, flags=re.M)
open(p, 'w').write(s)
PY11
    ! sb && says 'RM-UNINVENTORIED-MATERIAL' && says 'third-party/licence-texts/'"
ck "S10 ...and restoring it clears them again" \
   "( cd '$SB' && git checkout -q -- . ); sb"

echo
echo "== the composition is WIRED, not merely available ========================="
# The precedent this repository paid for: `grep -rq 'scripts/license/'` matched
# exactly one `--self-test` line and "proved" the gate was wired. A self-test is
# the script testing itself; it gates no artifact. So the search here excludes
# self-tests, and a probe proves the search discriminates.
_real_calls() {
  grep -rn 'scripts/license/assert-repository-material.sh' .github/workflows/ 2>/dev/null \
    | grep -v -- '--self-test'
}
ck "a workflow invokes the gate against the REAL inventory, not only --self-test" \
   "[ -n \"\$(_real_calls)\" ]"
ck "NON-VACUOUS: the same search does NOT count a --self-test-only invocation" \
   "printf 'run: bash scripts/license/assert-repository-material.sh --self-test\n' > '$TMP/probe'
    [ -z \"\$(grep -n 'scripts/license/' '$TMP/probe' | grep -v -- '--self-test')\" ]"
ck "the invoking workflow is the REQUIRED 'repo structure' job" \
   "python3 - <<'PY'
import re, sys
s = open('.github/workflows/ci.yml').read()
i = s.find('assert-repository-material.sh')
sys.exit(0 if i > 0 and 'repo structure' in s[:i] else 1)
PY"
ck "run-all discovers this test, so losing it is a red check" \
   "find tests -name 'test_*.sh' | grep -qx 'tests/license/test_repository_material_gate.sh'"

echo
echo "== WHAT DISCOVERY CANNOT PROVE — pinned, not narrated ====================="

gap "HEURISTIC DISCOVERY has unknown recall: inventoried material exists that trips NO signal" \
    "python3 - <<'PY'
import re, sys, yaml, os
# Two of the five inventoried materials carry no copyright line, no licence
# reference, no upstream URL and no third-party path. Nothing in them says
# 'third party'. They were found by a human reading the directory.
GRANT = re.compile(r'Permission is hereby granted|Licensed under the Apache Licen[sc]e'
                   r'|Redistribution and use in source and binary forms'
                   r'|GNU GENERAL PUBLIC LICEN[SC]E|SPDX-Licen[sc]e-Identifier:')
COPY  = re.compile(r'copyright[^\n]{0,40}?(?:\(c\)|©|\d{4})', re.I)
PATH  = re.compile(r'^(third[-_]party|vendor|external|contrib|patches|upstream)/')
silent = []
for m in yaml.safe_load(open('policies/repository-material.yaml'))['materials']:
    p = m['path']
    body = open(p, encoding='utf-8', errors='replace').read()
    head = '\n'.join(body.splitlines()[:40])
    if PATH.match(p) or GRANT.search(body) or COPY.search(head):
        continue
    silent.append(p)
sys.exit(0 if silent else 1)
PY"
echo "       WHAT WOULD CLOSE IT: a provenance record required for every file at"
echo "       the moment it is added (a commit-time control, not a scan), or"
echo "       content-matching every tracked file against upstream corpora."
echo "       Neither is implemented and neither is claimed. Absence of a signal"
echo "       is not evidence that a file is first-party."

gap "the reviewed baseline is enforced only where a caller asks for it" \
    "! grep -rq -- '--require-reviewed-baseline' .github/workflows/ 2>/dev/null"
echo "       WHAT WOULD CLOSE IT: a required check passing"
echo "       --require-reviewed-baseline. It is deliberately not wired to every"
echo "       PR today: every added file would turn every open PR red until its"
echo "       author regenerated the baseline. At PR scope drift is REPORTED"
echo "       (see the S8 assertions), never silently passed."

gap "two inventoried materials name no upstream revision, so their licence cannot be re-verified" \
    "python3 -c \"
import sys, yaml
ms = yaml.safe_load(open('policies/repository-material.yaml'))['materials']
sys.exit(0 if any(m['upstream']['revision'].startswith('unpinned') for m in ms) else 1)\""
echo "       WHAT WOULD CLOSE IT: capturing the install-php-extensions version"
echo "       out of the pinned FrankenPHP base-image digest into"
echo "       policies/supply-chain-inputs.yaml, which today records it as"
echo "       'version: inherited'. The MIT determination stands on the header"
echo "       reproduced in the excerpt; what cannot be re-derived is WHICH"
echo "       upstream revision that header came from."

gap "the outbound licence question (#98) is untouched by any of this" \
    "python3 -c \"
import sys, yaml
p = yaml.safe_load(open('policies/license-policy.yaml'))['publication']
sys.exit(0 if p['decision'] == 'undetermined' else 1)\""
echo "       WHAT WOULD CLOSE IT: the owner and counsel recording a decision."
echo "       Not an engineering act. This gate accounts for INBOUND obligations"
echo "       that attach today and establishes no right to distribute anything."

echo
# --- BASELINE REFRESH INTEGRITY (2026-08-28) --------------------------------
# The list and its hash must move together. A half-applied refresh leaves the
# tree passing a check that is no longer about the tree.
_REC=docs/licensing/repository-material-baseline-refresh-2026-08-28.md
ck "the refresh is recorded, with both hashes" \
   "[ -f '$_REC' ] &&
    grep -q '8ed5728b5df9f4b080659d8473990daa1cc418dbb51cd42aab76b5b558812b07' '$_REC' &&
    grep -q '93b1721573c936d8f3e9947f2c1ab43f8f219c90134dac4c00b2fa452d6a7a84' '$_REC'"
ck "...enumerating every addition, with zero removals" \
   "grep -qE '\| additions \| 37 \|' '$_REC' && grep -qE '\| removals \| \*\*0\*\* \|' '$_REC'"
ck "...stating that inclusion is NOT legal review" \
   "grep -qi 'NOT equivalent to legal review' '$_REC'"
ck "...and that reviewed_at_revision is deliberately unchanged" \
   "grep -qi 'reviewed_at_revision' '$_REC' && grep -qi 'unchanged' '$_REC'"
# The enumeration lists one path per line. Rather than parse the code fence
# (whose backticks fight the shell), assert directly on the path lines: every
# enumerated path must sit under the intended directory, and there must be 37.
_enum_paths() { grep -E '^docs/audits/real-image-inventories-2026-08-28/' "$_REC"; }
_enum_stray() { grep -E '^docs/' "$_REC" | grep -vE '^docs/audits/real-image-inventories-2026-08-28/'; }

ck "every enumerated addition is under the intended audit directory" \
   "[ -z \"\$(_enum_stray)\" ]"
ck "NON-VACUOUS: the enumeration is not empty and matches the stated count" \
   "[ \"\$(_enum_paths | wc -l | tr -d ' ')\" = 37 ]"

# --- BASELINE REFRESH INTEGRITY, notice/source-obligation delta -------------
# A second refresh, recorded the same way: the list and its hash move together,
# and the record enumerates every addition so a half-applied refresh is visible.
_REC2=docs/licensing/repository-material-baseline-refresh-2026-08-28-notices.md
ck "the notice refresh is recorded, with both hashes" \
   "[ -f '$_REC2' ] &&
    grep -q 'ad9ffdd7996ff31256a46a1589da483ed0a2c17a0b8b5a3e0747e8432f114717' '$_REC2' &&
    grep -q 'e9f488f263a5c6f35556e05517ddf7d36b22002bf9f3ce0ca227dc0d744c85ac' '$_REC2'"
# The invariant is not "THIS record carries the current hash" — that goes stale
# the next time the baseline moves, and a stale assertion teaches people to edit
# the assertion. It is "SOME committed refresh record carries the hash the
# inventory is pinned to", so every refresh must leave a record behind and a
# half-applied one is still a red check.
_cur_hash() { shasum -a 256 "$BASE" | cut -d' ' -f1; }
ck "the shipped baseline's hash is recorded in SOME refresh record, and in the inventory" \
   "h=\"\$(_cur_hash)\"
    grep -q \"\$h\" '$INV' &&
    grep -rlq \"\$h\" docs/licensing/repository-material-baseline-refresh-*.md"
ck "NON-VACUOUS: a hash that is NOT the baseline's is in no refresh record" \
   "! grep -rlq '0000000000000000000000000000000000000000000000000000000000000000' \
        docs/licensing/repository-material-baseline-refresh-*.md"
ck "every refresh record states that inclusion is not legal review" \
   "n=0
    for f in docs/licensing/repository-material-baseline-refresh-*.md; do
      grep -qi 'NOT equivalent to legal review' \"\$f\" || exit 1
      n=\$((n+1))
    done
    [ \"\$n\" -ge 3 ]"
ck "...enumerating every addition, with zero removals" \
   "grep -qE '\| additions \| 66 \|' '$_REC2' && grep -qE '\| removals \| \*\*0\*\* \|' '$_REC2'"
ck "...stating that inclusion is NOT legal review" \
   "grep -qi 'NOT equivalent to legal review' '$_REC2'"
ck "...and saying exactly what the review of a carried licence text consisted of" \
   "grep -qi 'No claim is made that a human read' '$_REC2' &&
    grep -qi 'accounted for' '$_REC2'"
ck "...and that reviewed_at_revision is deliberately unchanged" \
   "grep -qi 'reviewed_at_revision' '$_REC2' && grep -qi 'unchanged' '$_REC2'"
ck "NON-VACUOUS: every enumerated addition is a path the tree really tracks" \
   "n=0
    while IFS= read -r pth; do
      case \"\$pth\" in
        policies/*|third-party/*|scripts/*|tests/*|docs/*|schemas/*) ;;
        *) continue ;;
      esac
      git ls-files --error-unmatch \"\$pth\" >/dev/null 2>&1 || exit 1
      n=\$((n+1))
    done < <(sed -n '/^\`\`\`text\$/,/^\`\`\`\$/p' '$_REC2' | sed '1d;\$d')
    [ \"\$n\" = 66 ]"

echo "----"
printf 'assertions: %d proven, %d pinned gaps\n' "$nck" "$ngap"
[ "$fail" -eq 0 ] && echo "test_repository_material_gate: PASS" || echo "test_repository_material_gate: FAIL"
exit "$fail"
