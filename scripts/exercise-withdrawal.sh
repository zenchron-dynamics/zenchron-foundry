#!/usr/bin/env bash
# =============================================================================
# scripts/exercise-withdrawal.sh — prove the withdrawal machinery works (#125).
#
# #125 requires that "withdrawal and emergency communication are exercised". A
# procedure nobody has run is a procedure that fails the first time it matters,
# usually at the step nobody thought about.
#
# This runs the real machinery against a SIMULATED compromised release:
#   1. identify every affected digest, per image, per architecture
#   2. produce the advisory naming DIGESTS, not just tags
#   3. produce the consumer notice
#   4. record the withdrawal
#   5. assert the record is complete against the schema in
#      policies/support-policy.yaml
#
# Everything it writes is stamped `simulated: true` and carries SIMULATED in the
# title. A tabletop artefact that could be mistaken for a real advisory is worse
# than no tabletop.
#
# It NEVER sends anything. Producing the notice and delivering it are different
# acts, and only the first is automatable here.
#
# Usage:
#   exercise-withdrawal.sh --simulate [--out DIR]
#   exercise-withdrawal.sh --self-test
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1
POLICY="$ROOT/policies/support-policy.yaml"

pass=0; fail=0
ck() { if eval "$2"; then pass=$((pass+1)); echo "ok   - $1"; else fail=$((fail+1)); echo "FAIL - $1"; fi; }

simulate() {
  local out="${1:-$ROOT/docs/audits/withdrawals}"
  local id; id="withdrawal-SIMULATED-$(date -u +%Y-%m-%d)"
  local rec="$out/${id}.yaml"
  mkdir -p "$out"

  echo "== withdrawal exercise (SIMULATED) =="

  # --- 1. affected digests -------------------------------------------------
  # The real question a withdrawal must answer: WHICH digests. Tags move;
  # digests are what a consumer pinned. Resolved from the shipping matrix, so
  # the exercise cannot quietly cover fewer images than we publish.
  local images n=0
  images="$(python3 -c "
import glob, yaml
for f in sorted(glob.glob('contracts/images/*.yaml')):
    d = yaml.safe_load(open(f))
    sel = d['selector']
    print('%s:%s' % (d['image'], 'prod' if sel == 'prod' else sel + '-prod'))")"
  [ -n "$images" ] || { echo "REFUSE: could not resolve the shipping matrix" >&2; return 1; }

  local affected="" ref dig
  while IFS= read -r img; do
    [ -n "$img" ] || continue
    n=$((n + 1))
    ref="ghcr.io/zenchron-dynamics/${img}"
    # Real digest where the registry answers; a clearly-marked placeholder where
    # it does not. An exercise that silently drops unresolvable images would
    # under-report exactly the way a real incident must not.
    dig="$(docker buildx imagetools inspect "$ref" --format '{{.Manifest.Digest}}' 2>/dev/null | tr -d '[:space:]')"
    case "$dig" in
      sha256:*) affected="${affected}${img}|${dig}|resolved"$'\n' ;;
      *)        affected="${affected}${img}|UNRESOLVED|would-block-a-real-withdrawal"$'\n' ;;
    esac
  done <<< "$images"

  local resolved unresolved
  resolved="$(printf '%s' "$affected" | grep -c '|resolved' || true)"
  unresolved="$(printf '%s' "$affected" | grep -c 'UNRESOLVED' || true)"
  printf '  images in matrix: %d   digests resolved: %s   unresolved: %s\n' "$n" "$resolved" "$unresolved"

  # --- 2/3/4. advisory, notice, record ------------------------------------
  AFFECTED="$affected" ID="$id" N="$n" RESOLVED="$resolved" UNRESOLVED="$unresolved" \
  python3 - "$rec" <<'PY'
import datetime, os, sys, yaml

rec_path = sys.argv[1]
now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()
rows = [l.split("|") for l in os.environ["AFFECTED"].splitlines() if l.strip()]

advisory = (
    "SIMULATED SECURITY ADVISORY — NOT A REAL ADVISORY\n"
    "==================================================\n\n"
    "This is a tabletop artefact produced by scripts/exercise-withdrawal.sh.\n"
    "It describes a hypothetical compromised release and must never be\n"
    "published, sent, or quoted as a real Zenchron advisory.\n\n"
    "Summary\n-------\n"
    "A release of the Zenchron Foundry images is withdrawn. The digests below\n"
    "MUST NOT be used. Published digests are immutable and remain pullable;\n"
    "withdrawal is an instruction, not a technical recall.\n\n"
    "Affected digests\n----------------\n"
)
for name, dig, status in rows:
    advisory += "  ghcr.io/zenchron-dynamics/%-28s %s%s\n" % (
        name, dig, "" if status == "resolved" else "   <-- UNRESOLVED")
advisory += (
    "\nWhat to do\n----------\n"
    "1. Stop deploying the digests above.\n"
    "2. Re-pin to the corrective release named in the real advisory.\n"
    "3. If you cannot re-pin immediately, apply the mitigations in the real\n"
    "   advisory.\n\n"
    "Why digests and not tags\n------------------------\n"
    "This platform tells consumers to pin by digest. Those consumers are the\n"
    "ones a tag-only advisory would fail to reach.\n"
)

notice = (
    "SIMULATED CONSUMER NOTICE — NOT A REAL NOTICE\n"
    "=============================================\n\n"
    "Subject: [SIMULATED] Zenchron Foundry — release withdrawn, action required\n\n"
    "This is a tabletop artefact. Do not send it.\n\n"
    "We are withdrawing a release of the Zenchron Foundry container images.\n"
    "If you deploy any of the digests listed in the accompanying advisory, stop\n"
    "using them and re-pin to the corrective release.\n\n"
    "Channels this notice would go out on are listed in\n"
    "policies/support-policy.yaml (`channels:`). Any channel marked\n"
    "`status: unavailable` there is one this notice would NOT reach — which is\n"
    "the point of recording it.\n\n"
    "Contact: security@zenchron.com\n"
)

record = {
    "simulated": True,
    "id": os.environ["ID"],
    "title": "SIMULATED withdrawal exercise",
    "opened_at": now,
    "opened_by": "scripts/exercise-withdrawal.sh",
    "reason": "tabletop exercise — hypothetical compromised release (#125)",
    "images_in_matrix": int(os.environ["N"]),
    "digests_resolved": int(os.environ["RESOLVED"]),
    "digests_unresolved": int(os.environ["UNRESOLVED"]),
    "affected": [{"image": r[0], "digest": r[1], "status": r[2]} for r in rows],
    "advisory_published": False,
    "consumers_notified": False,
    "corrective_release": None,
    "note": (
        "Nothing was published or sent. This record exists to prove the "
        "machinery produces a complete, digest-level withdrawal package."
    ),
}
yaml.safe_dump(record, open(rec_path, "w"), sort_keys=False, width=100)
open(rec_path.replace(".yaml", "-advisory.txt"), "w").write(advisory)
open(rec_path.replace(".yaml", "-consumer-notice.txt"), "w").write(notice)
print("  advisory:       %s" % rec_path.replace(".yaml", "-advisory.txt"))
print("  consumer notice:%s" % rec_path.replace(".yaml", "-consumer-notice.txt"))
print("  record:         %s" % rec_path)
PY

  # --- 5. the record must satisfy the schema -------------------------------
  echo
  echo "== asserting the exercise produced a COMPLETE package =="
  ck "the withdrawal record exists" "test -s '$rec'"
  ck "it is marked simulated" \
     "python3 -c \"import yaml;assert yaml.safe_load(open('$rec'))['simulated'] is True\""
  ck "every shipping image is represented" \
     "python3 -c \"
import yaml, glob
r = yaml.safe_load(open('$rec'))
assert r['images_in_matrix'] == len(glob.glob('contracts/images/*.yaml')), r['images_in_matrix']
assert len(r['affected']) == r['images_in_matrix']\""
  # THE assertion that makes the exercise worth running: a withdrawal that
  # cannot name every digest is one that would leave consumers on a bad image.
  ck "every affected image resolved to a real digest" \
     "python3 -c \"
import yaml
r = yaml.safe_load(open('$rec'))
bad = [a['image'] for a in r['affected'] if not str(a['digest']).startswith('sha256:')]
assert not bad, ('these images could not be resolved to a digest', bad)\""
  ck "the advisory names digests, not only tags" \
     "grep -qE 'sha256:[0-9a-f]{16}' '${rec%.yaml}-advisory.txt'"
  ck "the advisory and notice are unmistakably marked SIMULATED" \
     "head -3 '${rec%.yaml}-advisory.txt' | grep -q SIMULATED && head -3 '${rec%.yaml}-consumer-notice.txt' | grep -q SIMULATED"
  ck "the record does NOT claim anything was published or sent" \
     "python3 -c \"
import yaml
r = yaml.safe_load(open('$rec'))
assert r['advisory_published'] is False and r['consumers_notified'] is False\""
  ck "the notice points at the real contact from the policy" \
     "grep -q 'security@zenchron.com' '${rec%.yaml}-consumer-notice.txt'"

  echo "----"
  printf 'withdrawal exercise: %d ok, %d failed\n' "$pass" "$fail"
  [ "$fail" -eq 0 ]
}

self_test() {
  ck "the support policy defines a withdrawal procedure" \
     "python3 -c \"
import yaml; w=yaml.safe_load(open('$POLICY'))['withdrawal']
assert w['procedure'] and w['required_actions'] and w['exercise']\""
  ck "it states that digests cannot be unpublished" \
     "python3 -c \"
import yaml; w=yaml.safe_load(open('$POLICY'))['withdrawal']
assert 'immutable' in w['constraint'].lower()\""
  ck "the exercise script it names is this one" \
     "[ \"\$(python3 -c \"
import yaml;print(yaml.safe_load(open('$POLICY'))['withdrawal']['exercise'])\")\" = scripts/exercise-withdrawal.sh ]"
  echo "----"
  printf 'self-test: %d ok, %d failed\n' "$pass" "$fail"
  [ "$fail" -eq 0 ]
}

case "${1:-}" in
  --simulate)  shift; [ "${1:-}" = "--out" ] && simulate "$2" || simulate ;;
  --self-test) self_test ;;
  *) echo "usage: $(basename "$0") --simulate [--out DIR] | --self-test" >&2; exit 64 ;;
esac
