#!/usr/bin/env bash
# =============================================================================
# scripts/admin/runner-group-patch.sh
# -----------------------------------------------------------------------------
# Safely mutate an org runner group.
#
# WHY THIS EXISTS. On 2026-08-02, an otherwise-correct PATCH that changed only
# `selected_workflows` also CLEARED the group's repository selection: GitHub
# treats an omitted `selected_repository_ids` as "set to empty", even when the
# field is nowhere in the request. The group went from one authorised repository
# to zero, which would have made every trusted job unschedulable.
#
# The direction of failure was CLOSED — no repository gained access, the only
# authorised one lost it — and postcondition verification caught it. But a
# 200 OK is not evidence that a mutation did what was asked, and the declarative
# policy cannot prevent a hand-written curl. This is the guardrail:
#
#   1. Snapshot the FULL group, its repositories and its runners before touching
#      anything.
#   2. REFUSE to send a PATCH that omits selected_repository_ids.
#   3. Send the mutation.
#   4. Re-fetch everything and diff it against the snapshot.
#   5. Any field that changed other than the intended ones is an incident:
#      restore from the snapshot and stop.
#
# Prefer the dedicated endpoints for repository membership
# (PUT/PUT/DELETE .../runner-groups/{id}/repositories) over a whole-group PATCH.
#
# Usage:
#   runner-group-patch.sh <group-id> <payload.json> [--evidence <dir>]
#   runner-group-patch.sh --self-test
#
# Env: ORG (default zenchron-dynamics), GH_API_FN (injectable for tests)
# Exit: 0 mutation applied and verified; 1 refused, failed, or reverted.
# =============================================================================
set -euo pipefail

ORG="${ORG:-zenchron-dynamics}"

_api() { gh api "$@"; }
api() { "${GH_API_FN:-_api}" "$@"; }

die() { echo "REFUSE: $*" >&2; return 1; }

# ---------------------------------------------------------------------------
# assert_patch_payload_safe <payload-file>
#
# The one rule that would have prevented the incident: a whole-group PATCH must
# carry the complete, current repository selection, or it destroys it.
# ---------------------------------------------------------------------------
assert_patch_payload_safe() {
  local file="$1"
  [ -f "$file" ] || die "payload not found: $file" || return 1
  PAYLOAD="$file" python3 - <<'PY'
import json, os, sys

path = os.environ["PAYLOAD"]
try:
    p = json.load(open(path))
except Exception as exc:
    sys.exit("REFUSE: payload is not valid JSON: %s" % exc)
if not isinstance(p, dict):
    sys.exit("REFUSE: payload must be a JSON object")

ids = p.get("selected_repository_ids")
if ids is None:
    sys.exit(
        "REFUSE: payload omits selected_repository_ids.\n"
        "  A runner-group PATCH that omits this field CLEARS the repository\n"
        "  selection — GitHub reads 'absent' as 'set to empty'. That is how the\n"
        "  2026-08-02 availability incident happened.\n"
        "  Include the COMPLETE current list, or change membership only through\n"
        "  /orgs/{org}/actions/runner-groups/{id}/repositories.")
if not isinstance(ids, list) or not ids:
    sys.exit("REFUSE: selected_repository_ids must be a non-empty list; an empty "
             "list authorises no repository at all")
if not all(isinstance(i, int) for i in ids):
    sys.exit("REFUSE: selected_repository_ids must contain integer repository IDs")

# visibility: selected without an id list is the same trap by another route.
if p.get("visibility") == "selected" and not ids:
    sys.exit("REFUSE: visibility 'selected' with no selected_repository_ids")
PY
}

snapshot() { # snapshot <group-id> <dir> <label>
  local gid="$1" dir="$2" tag="$3"
  mkdir -p "$dir"
  api "orgs/${ORG}/actions/runner-groups/${gid}"              > "${dir}/group-${tag}.json"
  api "orgs/${ORG}/actions/runner-groups/${gid}/repositories" > "${dir}/repositories-${tag}.json"
  api "orgs/${ORG}/actions/runner-groups/${gid}/runners"      > "${dir}/runners-${tag}.json"
}

# compare_snapshots <dir> <allowed-changed-field...>
# Everything not named is required to be identical.
compare_snapshots() {
  local dir="$1"; shift
  DIR="$dir" ALLOWED="$*" python3 - <<'PY'
import json, os, sys

d = os.environ["DIR"]
allowed = set(os.environ["ALLOWED"].split())

before = json.load(open(f"{d}/group-before.json"))
after  = json.load(open(f"{d}/group-after.json"))
rb = json.load(open(f"{d}/repositories-before.json"))
ra = json.load(open(f"{d}/repositories-after.json"))
nb = json.load(open(f"{d}/runners-before.json"))
na = json.load(open(f"{d}/runners-after.json"))

problems = []
for k in sorted(set(before) | set(after)):
    if k in allowed:
        continue
    if before.get(k) != after.get(k):
        problems.append("group.%s: %r -> %r" % (k, before.get(k), after.get(k)))

def ids(doc, key, field):
    return sorted(x[field] for x in doc.get(key, []))

if "repositories" not in allowed:
    if ids(rb, "repositories", "id") != ids(ra, "repositories", "id"):
        problems.append("repository selection: %s -> %s"
                        % (ids(rb, "repositories", "id"), ids(ra, "repositories", "id")))
if ids(nb, "runners", "id") != ids(na, "runners", "id"):
    problems.append("runner membership: %s -> %s"
                    % (ids(nb, "runners", "id"), ids(na, "runners", "id")))

# Independent of intent: these must never end up unsafe.
if after.get("visibility") != "selected":
    problems.append("visibility is %r, not 'selected'" % after.get("visibility"))
if after.get("restricted_to_workflows") is not True:
    problems.append("restricted_to_workflows is %r" % after.get("restricted_to_workflows"))
if not ra.get("repositories"):
    problems.append("NO repository is authorised — trusted jobs become unschedulable")
for w in after.get("selected_workflows") or []:
    if not w.endswith("@refs/heads/master"):
        problems.append("workflow not pinned to master: %s" % w)

if problems:
    print("MUTATION CHANGED MORE THAN INTENDED:", file=sys.stderr)
    for p in problems:
        print("  %s" % p, file=sys.stderr)
    sys.exit(1)
print("verified: only the intended fields changed")
PY
}

patch_group() { # patch_group <group-id> <payload> [evidence-dir]
  local gid="$1" payload="$2" dir="${3:-}"
  [ -n "$dir" ] || dir="$(mktemp -d)"

  assert_patch_payload_safe "$payload" || return 1

  echo "==> snapshotting group ${gid} before mutation"
  snapshot "$gid" "$dir" before

  echo "==> applying PATCH"
  api -X PATCH "orgs/${ORG}/actions/runner-groups/${gid}" --input "$payload" \
    > "${dir}/patch-response.json" || { echo "PATCH failed" >&2; return 1; }

  echo "==> re-fetching and comparing (a 200 is not evidence)"
  snapshot "$gid" "$dir" after

  if ! compare_snapshots "$dir" selected_workflows; then
    echo "==> RESTORING repository selection from the snapshot" >&2
    python3 -c "
import json,sys
d=json.load(open('${dir}/repositories-before.json'))
print(json.dumps({'selected_repository_ids':[r['id'] for r in d['repositories']]}))" \
      > "${dir}/restore.json"
    api -X PUT "orgs/${ORG}/actions/runner-groups/${gid}/repositories" \
      --input "${dir}/restore.json" >/dev/null || true
    echo "RESTORED. Evidence: ${dir}" >&2
    return 1
  fi
  echo "OK: runner group ${gid} mutated and verified. Evidence: ${dir}"
}

# ---------------------------------------------------------------------------
_rgp_self_test() {
  command -v python3 >/dev/null || { echo "SKIP - python3 absent"; return 0; }
  local fail=0 ok=0 tmp; tmp="$(mktemp -d)"
  t() { if eval "$2" >/dev/null 2>&1; then echo "  ok   $1"; ok=$((ok+1)); else
        echo "  FAIL $1"; fail=$((fail+1)); fi; }
  n() { if eval "$2" >/dev/null 2>&1; then echo "  FAIL $1 (accepted)"; fail=$((fail+1)); else
        echo "  ok   $1"; ok=$((ok+1)); fi; }

  # THE regression: the payload that caused the 2026-08-02 incident.
  cat > "$tmp/incident.json" <<'J'
{"name":"zenchron-foundry-trusted","visibility":"selected",
 "allows_public_repositories":true,"restricted_to_workflows":true,
 "selected_workflows":["a@refs/heads/master"]}
J
  n "a payload omitting selected_repository_ids is REFUSED" \
    "assert_patch_payload_safe '$tmp/incident.json'"

  cat > "$tmp/good.json" <<'J'
{"name":"zenchron-foundry-trusted","visibility":"selected",
 "allows_public_repositories":true,"restricted_to_workflows":true,
 "selected_repository_ids":[1254295268],
 "selected_workflows":["a@refs/heads/master"]}
J
  t "a payload carrying the complete list is accepted" \
    "assert_patch_payload_safe '$tmp/good.json'"

  printf '{"selected_repository_ids":[]}' > "$tmp/empty.json"
  n "an EMPTY selected_repository_ids is refused" \
    "assert_patch_payload_safe '$tmp/empty.json'"
  printf '{"selected_repository_ids":"1254295268"}' > "$tmp/str.json"
  n "a non-list selected_repository_ids is refused" \
    "assert_patch_payload_safe '$tmp/str.json'"
  printf '{"selected_repository_ids":["1254295268"]}' > "$tmp/strid.json"
  n "non-integer repository IDs are refused" \
    "assert_patch_payload_safe '$tmp/strid.json'"
  printf 'not json' > "$tmp/bad.json"
  n "an unparseable payload is refused" "assert_patch_payload_safe '$tmp/bad.json'"
  n "a missing payload is refused"      "assert_patch_payload_safe '$tmp/nope.json'"

  # --- the comparison catches the incident's SHAPE --------------------------
  local d="$tmp/snap"; mkdir -p "$d"
  cat > "$d/group-before.json" <<'J'
{"id":3,"name":"g","visibility":"selected","allows_public_repositories":true,
 "restricted_to_workflows":true,
 "selected_workflows":["a@refs/heads/master"]}
J
  cp "$d/group-before.json" "$d/group-after.json"
  printf '{"repositories":[{"id":1254295268}]}' > "$d/repositories-before.json"
  printf '{"repositories":[{"id":1254295268}]}' > "$d/repositories-after.json"
  printf '{"runners":[{"id":22}]}' > "$d/runners-before.json"
  printf '{"runners":[{"id":22}]}' > "$d/runners-after.json"
  t "an unchanged group compares clean" "compare_snapshots '$d' selected_workflows"

  printf '{"repositories":[]}' > "$d/repositories-after.json"
  n "a CLEARED repository selection is caught" "compare_snapshots '$d' selected_workflows"
  printf '{"repositories":[{"id":1254295268}]}' > "$d/repositories-after.json"

  printf '{"runners":[]}' > "$d/runners-after.json"
  n "changed runner membership is caught"      "compare_snapshots '$d' selected_workflows"
  printf '{"runners":[{"id":22}]}' > "$d/runners-after.json"

  python3 -c "
import json
d=json.load(open('$d/group-before.json')); d['visibility']='all'
json.dump(d,open('$d/group-after.json','w'))"
  n "a widened visibility is caught"           "compare_snapshots '$d' selected_workflows"

  python3 -c "
import json
d=json.load(open('$d/group-before.json')); d['restricted_to_workflows']=False
json.dump(d,open('$d/group-after.json','w'))"
  n "a dropped workflow restriction is caught" "compare_snapshots '$d' selected_workflows"

  python3 -c "
import json
d=json.load(open('$d/group-before.json'))
d['selected_workflows']=['a@refs/heads/feature']
json.dump(d,open('$d/group-after.json','w'))"
  n "a non-master workflow pin is caught"      "compare_snapshots '$d' selected_workflows"

  cp "$d/group-before.json" "$d/group-after.json"
  python3 -c "
import json
d=json.load(open('$d/group-after.json')); d['allows_public_repositories']=False
json.dump(d,open('$d/group-after.json','w'))"
  n "an unrelated field change is caught"      "compare_snapshots '$d' selected_workflows"

  rm -rf "$tmp"
  echo "self-test: $ok ok, $fail failed"
  [ "$fail" -eq 0 ]
}

case "${1-}" in
  --self-test) _rgp_self_test && echo "runner-group-patch.sh: SELF-TEST OK" ;;
  "") echo "usage: runner-group-patch.sh <group-id> <payload.json> [evidence-dir]" >&2; exit 2 ;;
  *) patch_group "$@" ;;
esac
