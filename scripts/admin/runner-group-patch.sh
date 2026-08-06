#!/usr/bin/env bash
# =============================================================================
# scripts/admin/runner-group-patch.sh
# -----------------------------------------------------------------------------
# Mutate an org runner group's PROPERTIES and WORKFLOW allowlist, and leave its
# repository membership exactly as the caller declares it.
#
# WHY THE PREVIOUS VERSION HAD TO BE REPLACED. On 2026-08-02 a PATCH that changed
# only `selected_workflows` also emptied the group's repository selection. The
# fix then was to REQUIRE `selected_repository_ids` in every PATCH payload.
# GitHub now rejects that field outright:
#
#     "selected_repository_ids" is not a permitted key. (HTTP 422)
#
# So the guardrail demanded a field the API forbids, and nothing could pass. The
# safety RATIONALE was right; the MECHANISM became impossible.
#
# The replacement is not a guess. Measured on a throwaway group, 2026-08-06 —
# docs/audits/runner-group-patch-semantics-2026-08-06/:
#
#     PATCH with    selected_repository_ids  -> 422, nothing changes
#     PATCH without selected_repository_ids  -> 200 OK, membership CLEARED
#     PUT .../repositories                   -> membership restored exactly
#
# The 200 OK is the dangerous part: the call reports success while emptying the
# selection, so only a postcondition read can tell the difference.
#
# WHAT THIS GUARANTEES, HONESTLY. Two REST calls cannot be made atomic. A
# workflow PATCH opens a MEASURED FAIL-CLOSED AVAILABILITY WINDOW in which no
# repository is authorised and trusted jobs are unschedulable. This helper closes
# that window immediately, verifies closure, and treats failure to restore
# repository membership as an INCIDENT. It is not transactional and must not be
# described as such.
#
# Usage:
#   runner-group-patch.sh <group-id> <group-patch.json> <desired-repositories.json> \
#                         [--evidence <dir>]
#   runner-group-patch.sh --self-test
#
# The repository list is a SEPARATE MANDATORY INPUT, never part of the PATCH.
#
# Env: ORG (default zenchron-dynamics), API_VERSION (default 2026-03-10, pinned
# across every call), GH_API_FN (injectable transport), EXPECT_* preconditions.
# Exit: 0 applied and verified; 1 refused, failed, or incident.
# =============================================================================
set -uo pipefail

ORG="${ORG:-zenchron-dynamics}"
API_VERSION="${API_VERSION:-2026-03-10}"

_api() { gh api -H "X-GitHub-Api-Version: ${API_VERSION}" "$@"; }
api() { "${GH_API_FN:-_api}" "$@"; }

log()  { printf '%s\n' "$*"; }
warn() { printf '%s\n' "$*" >&2; }
die()  { printf 'REFUSE: %s\n' "$*" >&2; return 1; }

# An ALLOWLIST, not a denylist: an unknown key is refused rather than forwarded,
# because the failure mode here is precisely a field doing something other than
# what it appears to.
PATCH_ALLOWED_KEYS="name visibility allows_public_repositories restricted_to_workflows selected_workflows"
PATCH_FORBIDDEN_KEYS="selected_repository_ids runners repositories"

assert_patch_payload_safe() { # <payload-file>
  local file="$1"
  [ -f "$file" ] || { die "patch payload not found: $file"; return 1; }
  PAYLOAD="$file" ALLOWED="$PATCH_ALLOWED_KEYS" FORBIDDEN="$PATCH_FORBIDDEN_KEYS" python3 - <<'PY'
import json, os, sys
allowed = set(os.environ["ALLOWED"].split())
forbidden = set(os.environ["FORBIDDEN"].split())
try:
    p = json.load(open(os.environ["PAYLOAD"]))
except Exception as exc:
    sys.exit("REFUSE: patch payload is not valid JSON: %s" % exc)
if not isinstance(p, dict):
    sys.exit("REFUSE: patch payload must be a JSON object")
bad = sorted(set(p) & forbidden)
if bad:
    sys.exit("REFUSE: %s belong to dedicated endpoints and must not appear in a "
             "group PATCH. GitHub rejects selected_repository_ids with 422, and a "
             "PATCH that omits it CLEARS repository membership - pass the "
             "repository list as the separate mandatory argument." % ", ".join(bad))
unknown = sorted(set(p) - allowed)
if unknown:
    sys.exit("REFUSE: unsupported PATCH key(s): %s (allowed: %s)"
             % (", ".join(unknown), ", ".join(sorted(allowed))))
for w in p.get("selected_workflows", []):
    if not w.endswith("@refs/heads/master"):
        sys.exit("REFUSE: workflow ref not pinned to the default branch: %s" % w)
PY
}

assert_repo_list_safe() { # <repos-file>
  local file="$1"
  [ -f "$file" ] || { die "desired-repositories file not found: $file"; return 1; }
  REPOS="$file" python3 - <<'PY'
import json, os, sys
try:
    d = json.load(open(os.environ["REPOS"]))
except Exception as exc:
    sys.exit("REFUSE: desired-repositories is not valid JSON: %s" % exc)
ids = d.get("selected_repository_ids") if isinstance(d, dict) else d
if not isinstance(ids, list) or not ids:
    sys.exit("REFUSE: desired repository list is empty or malformed. An empty list "
             "would leave the group with no authorised repository, which is the "
             "outage this helper exists to prevent.")
if not all(isinstance(i, int) for i in ids):
    sys.exit("REFUSE: repository ids must be integers: %r" % ids)
PY
}

repo_ids_of() {
  python3 -c 'import json,sys
d=json.load(open(sys.argv[1]))
print(json.dumps(d.get("selected_repository_ids") if isinstance(d,dict) else d))' "$1"
}

group_json()   { api "orgs/${ORG}/actions/runner-groups/$1"; }
repos_json()   { api "orgs/${ORG}/actions/runner-groups/$1/repositories" --jq '[.repositories[].id]'; }
runners_json() { api "orgs/${ORG}/actions/runner-groups/$1/runners" --jq '[.runners[].id]'; }

snapshot() { # <gid> <dir> <prefix>
  local gid="$1" dir="$2" p="$3"
  mkdir -p "$dir"
  group_json   "$gid" > "$dir/${p}-group.json"   2>/dev/null
  repos_json   "$gid" > "$dir/${p}-repos.json"   2>/dev/null
  runners_json "$gid" > "$dir/${p}-runners.json" 2>/dev/null
  [ -s "$dir/${p}-group.json" ] && [ -s "$dir/${p}-repos.json" ] && [ -s "$dir/${p}-runners.json" ]
}

# UNCONDITIONAL after every successful PATCH. Never skipped because a GET looked
# fine: the measurement says the PATCH clears membership, and a read that
# disagrees is a reason to investigate, not to skip the repair.
put_repositories() { # <gid> <ids-json>
  local gid="$1" ids="$2" tmp rc
  tmp="$(mktemp)"
  python3 -c 'import json,sys; json.dump({"selected_repository_ids": json.loads(sys.argv[1])}, open(sys.argv[2],"w"))' "$ids" "$tmp"
  api --method PUT "orgs/${ORG}/actions/runner-groups/${gid}/repositories" --input "$tmp" >/dev/null 2>&1
  rc=$?
  rm -f "$tmp"
  return $rc
}

restore_repositories() { # <gid> <ids-json> — bounded retries, membership FIRST
  local gid="$1" ids="$2" i
  for i in 1 2 3; do
    if put_repositories "$gid" "$ids"; then
      [ "$(repos_json "$gid" 2>/dev/null)" = "$ids" ] && return 0
    fi
    warn "restore attempt $i did not take; retrying"
  done
  return 1
}

assert_preconditions() { # <gid> <dir>
  local dir="$2" got
  if [ -n "${EXPECT_NAME:-}" ]; then
    got="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("name",""))' "$dir/before-group.json")"
    [ "$got" = "$EXPECT_NAME" ] || { die "group name is '$got', expected '$EXPECT_NAME'"; return 1; }
  fi
  if [ -n "${EXPECT_REPOS:-}" ]; then
    got="$(cat "$dir/before-repos.json")"
    [ "$got" = "$EXPECT_REPOS" ] || { die "repositories are $got, expected $EXPECT_REPOS"; return 1; }
  fi
  if [ -n "${EXPECT_RUNNERS:-}" ]; then
    got="$(cat "$dir/before-runners.json")"
    [ "$got" = "$EXPECT_RUNNERS" ] || { die "runners are $got, expected $EXPECT_RUNNERS"; return 1; }
  fi
  # This helper RESTORES membership; it does not invent it.
  [ "$(cat "$dir/before-repos.json")" = "[]" ] \
    && { die "group already authorises no repositories; refusing to mutate"; return 1; }
  return 0
}

write_evidence() { # <gid> <dir> <verdict> <reason> <want-ids>
  python3 - "$1" "$2" "$3" "$4" "$5" "$ORG" "$API_VERSION" <<'PY'
import json, os, sys, datetime
gid, ev, verdict, reason, want, org, apiv = sys.argv[1:8]
def rd(n):
    try: return json.load(open(os.path.join(ev, n)))
    except Exception: return None
json.dump({
  "schema_version": 1, "organization": org, "runner_group_id": int(gid),
  "api_version": apiv,
  "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
  "verdict": verdict, "reason": reason,
  "desired_repository_ids": json.loads(want),
  "before": {"group": rd("before-group.json"), "repositories": rd("before-repos.json"),
             "runners": rd("before-runners.json")},
  "patch_request": rd("patch-request.json"),
  "after": {"group": rd("after-group.json"), "repositories": rd("after-repos.json"),
            "runners": rd("after-runners.json")},
  "restored": {"group": rd("restored-group.json"), "repositories": rd("restored-repos.json"),
               "runners": rd("restored-runners.json")},
  "guarantee": ("the PATCH opens a measured fail-closed window in which no repository "
                "is authorised; this run closed it and verified closure. Two REST "
                "calls are not atomic."),
}, open(os.path.join(ev, "result.json"), "w"), indent=2)
PY
  log "evidence: $2/result.json ($3)"
}

patch_group() { # <gid> <patch.json> <repos.json> [--evidence <dir>]
  local gid="${1:?usage: runner-group-patch.sh <group-id> <group-patch.json> <desired-repositories.json> [--evidence <dir>]}"
  local patch="${2:?group-patch.json required}"
  local repos="${3:?desired-repositories.json required}"
  shift 3
  local ev="./runner-group-evidence"
  while [ $# -gt 0 ]; do
    case "$1" in
      --evidence) ev="${2:?--evidence needs a path}"; shift 2 ;;
      *) die "unknown option: $1"; return 1 ;;
    esac
  done
  mkdir -p "$ev"

  assert_patch_payload_safe "$patch" || return 1
  assert_repo_list_safe "$repos" || return 1
  local want_ids; want_ids="$(repo_ids_of "$repos")"

  log "==> snapshotting group ${gid}"
  snapshot "$gid" "$ev" before || { die "could not read the group before mutating it"; return 1; }
  assert_preconditions "$gid" "$ev" || return 1

  # A snapshot acted on minutes later cannot see concurrent administration.
  local recheck; recheck="$(repos_json "$gid" 2>/dev/null)"
  [ "$recheck" = "$(cat "$ev/before-repos.json")" ] \
    || { die "repository selection changed between snapshot and PATCH (now $recheck)"; return 1; }

  log "==> PATCH (properties + workflows only)"
  cp "$patch" "$ev/patch-request.json"
  if ! api --method PATCH "orgs/${ORG}/actions/runner-groups/${gid}" \
        --input "$patch" > "$ev/patch-response.json" 2>"$ev/patch-error.txt"; then
    warn "PATCH failed; repository membership was never touched"
    [ -s "$ev/patch-error.txt" ] && cat "$ev/patch-error.txt" >&2
    write_evidence "$gid" "$ev" REFUSED "patch-failed" "$want_ids"
    return 1
  fi

  log "==> PUT repositories (closing the availability window)"
  if ! restore_repositories "$gid" "$want_ids"; then
    warn "INCIDENT: repository membership could not be restored after the PATCH"
    warn "the group may currently authorise NO repositories"
    write_evidence "$gid" "$ev" INCIDENT "repository-restore-failed" "$want_ids"
    return 1
  fi

  log "==> verifying postconditions"
  snapshot "$gid" "$ev" after || { die "could not re-read the group after mutating it"; return 1; }

  local verdict=PASS reason=ok after_repos after_runners mismatch
  after_repos="$(cat "$ev/after-repos.json")"
  after_runners="$(cat "$ev/after-runners.json")"
  [ "$after_repos" = "$want_ids" ] || { verdict=INCIDENT; reason="repositories are $after_repos, expected $want_ids"; }
  [ "$after_runners" = "$(cat "$ev/before-runners.json")" ] \
    || { verdict=INCIDENT; reason="runner membership drifted: $(cat "$ev/before-runners.json") -> $after_runners"; }

  mismatch="$(PATCH="$patch" AFTER="$ev/after-group.json" python3 - <<'PY'
import json, os
p = json.load(open(os.environ["PATCH"])); a = json.load(open(os.environ["AFTER"]))
out = []
for k, v in p.items():
    got = a.get(k)
    if k == "selected_workflows":
        if sorted(got or []) != sorted(v): out.append("%s mismatch" % k)
    elif got != v: out.append("%s: %r != requested %r" % (k, got, v))
print("; ".join(out))
PY
)"
  [ -n "$mismatch" ] && { verdict=INCIDENT; reason="$mismatch"; }

  if [ "$verdict" != PASS ]; then
    warn "INCIDENT: $reason"
    warn "restoring repository membership FIRST, then the previous group state"
    restore_repositories "$gid" "$(cat "$ev/before-repos.json")" \
      || warn "INCIDENT: could not restore the previous repository membership"
    # The rollback is itself a PATCH, which clears membership again...
    PREV="$ev/before-group.json" python3 -c 'import json,os,sys
g=json.load(open(os.environ["PREV"]))
json.dump({k:g[k] for k in ("name","visibility","allows_public_repositories","restricted_to_workflows","selected_workflows") if k in g}, open(sys.argv[1],"w"))' "$ev/rollback-patch.json" 2>/dev/null \
      && api --method PATCH "orgs/${ORG}/actions/runner-groups/${gid}" --input "$ev/rollback-patch.json" >/dev/null 2>&1
    # ...so it goes back a SECOND time.
    restore_repositories "$gid" "$(cat "$ev/before-repos.json")" \
      || warn "INCIDENT: repository membership empty after the rollback PATCH"
    snapshot "$gid" "$ev" restored || true
    write_evidence "$gid" "$ev" "$verdict" "$reason" "$want_ids"
    return 1
  fi

  write_evidence "$gid" "$ev" PASS ok "$want_ids"
  log "OK: group ${gid} updated; repositories $after_repos; runners unchanged"
}

# ---------------------------------------------------------------------------
# self-test — drives patch_group through an injected transport so the REAL
# execution path runs, not a parallel reimplementation. The transport models the
# MEASURED behaviour: a keyless PATCH empties the repository selection.
# ---------------------------------------------------------------------------
_rgp_self_test() {
  local ok=0 nbad=0 tmp rc; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  t() { if eval "$2"; then echo "ok   - $1"; ok=$((ok+1)); else echo "FAIL - $1"; nbad=$((nbad+1)); fi; }

  printf '{"selected_repository_ids":[1254295268]}\n' > "$tmp/repos.json"
  printf '{"name":"g","visibility":"selected","allows_public_repositories":true,"restricted_to_workflows":true,"selected_workflows":["zenchron-dynamics/zenchron-foundry/.github/workflows/stage-and-authorize.yml@refs/heads/master"]}\n' > "$tmp/patch.json"

  printf '{"selected_workflows":[],"selected_repository_ids":[1]}\n' > "$tmp/b1.json"
  t "PATCH payload containing selected_repository_ids refuses locally" "! assert_patch_payload_safe '$tmp/b1.json' 2>/dev/null"
  printf '{"runners":[1]}\n' > "$tmp/b2.json"
  t "PATCH payload containing runners refuses locally" "! assert_patch_payload_safe '$tmp/b2.json' 2>/dev/null"
  printf '{"repositories":[1]}\n' > "$tmp/b3.json"
  t "PATCH payload containing repositories refuses locally" "! assert_patch_payload_safe '$tmp/b3.json' 2>/dev/null"
  printf '{"name":"g","surprise":true}\n' > "$tmp/b4.json"
  t "an unknown PATCH key refuses" "! assert_patch_payload_safe '$tmp/b4.json' 2>/dev/null"
  printf '{"selected_workflows":["o/r/.github/workflows/x.yml@refs/heads/dev"]}\n' > "$tmp/b5.json"
  t "a non-master workflow ref refuses" "! assert_patch_payload_safe '$tmp/b5.json' 2>/dev/null"
  printf '{"selected_repository_ids":[]}\n' > "$tmp/b6.json"
  t "an empty desired repository list refuses" "! assert_repo_list_safe '$tmp/b6.json' 2>/dev/null"
  t "a well-formed payload is accepted" "assert_patch_payload_safe '$tmp/patch.json'"

  FAKE="$tmp/state"; mkdir -p "$FAKE"; export FAKE
  _reset() { printf '[1254295268]\n' > "$FAKE/repos"; printf '[]\n' > "$FAKE/runners"
             printf 'old.yml@refs/heads/master\n' > "$FAKE/wf"; : > "$FAKE/calls"
             printf 'ok\n' > "$FAKE/pmode"; printf 'ok\n' > "$FAKE/umode"; printf 'no\n' > "$FAKE/drift"; }
  fake_api() {
    local method="" path="" input=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --method) method="$2"; shift 2 ;; --input) input="$2"; shift 2 ;;
        --jq) shift 2 ;; -H) shift 2 ;; *) path="$1"; shift ;;
      esac
    done
    echo "${method:-GET} $path" >> "$FAKE/calls"
    case "${method:-GET} $path" in
      "GET "*"/repositories") cat "$FAKE/repos" ;;
      "GET "*"/runners")      cat "$FAKE/runners" ;;
      "GET "*) jq -n --arg w "$(cat "$FAKE/wf")" '{id:9,name:"g",visibility:"selected",allows_public_repositories:true,restricted_to_workflows:true,selected_workflows:[$w]}' ;;
      "PATCH "*)
        [ "$(cat "$FAKE/pmode")" = fail ] && return 1
        python3 -c 'import json,sys
p=json.load(open(sys.argv[1])); open(sys.argv[2],"w").write((p.get("selected_workflows") or ["none"])[0]+"\n")' "$input" "$FAKE/wf"
        printf '[]\n' > "$FAKE/repos"          # MEASURED: PATCH clears membership
        [ "$(cat "$FAKE/drift")" = yes ] && printf '[7]\n' > "$FAKE/runners"
        echo '{}' ;;
      "PUT "*"/repositories")
        [ "$(cat "$FAKE/umode")" = fail ] && return 1
        python3 -c 'import json,sys
json.dump(json.load(open(sys.argv[1]))["selected_repository_ids"], open(sys.argv[2],"w"))' "$input" "$FAKE/repos"
        printf '\n' >> "$FAKE/repos"; echo '{}' ;;
      *) echo '{}' ;;
    esac
  }

  printf '{"name":"g","visibility":"selected","allows_public_repositories":true,"restricted_to_workflows":true,"selected_workflows":["zenchron-dynamics/zenchron-foundry/.github/workflows/new.yml@refs/heads/master"]}\n' > "$tmp/wf.json"

  _reset
  ( GH_API_FN=fake_api EXPECT_REPOS='[1254295268]' patch_group 9 "$tmp/wf.json" "$tmp/repos.json" --evidence "$tmp/e1" ) >/dev/null 2>&1; rc=$?
  t "a successful run exits 0" "[ $rc -eq 0 ]"
  t "the repository PUT always follows a successful PATCH" "grep -q 'PUT .*repositories' '$FAKE/calls'"
  t "repository PUT restores the exact desired set" "[ \"\$(tr -d '\\n' < '$FAKE/repos')\" = '[1254295268]' ]"
  t "evidence is emitted on success" "[ \"\$(jq -r .verdict '$tmp/e1/result.json')\" = PASS ]"
  t "PASS is backed by a postcondition read, not the 200 alone" \
    "jq -e '.after.repositories != null' '$tmp/e1/result.json' >/dev/null"
  # Not "does the word appear" — it appears in the DENIAL. The evidence must
  # state the limitation, and must never assert the opposite.
  t "the evidence states the operation is not atomic" \
    "grep -q 'are not atomic' '$tmp/e1/result.json'"
  t "...and never claims it is transactional or atomic" \
    "! grep -qiE 'is atomic|atomically|transactional\\.' '$tmp/e1/result.json'"
  t "...and names the fail-closed window" \
    "grep -q 'fail-closed window' '$tmp/e1/result.json'"

  _reset; printf 'fail\n' > "$FAKE/umode"
  ( GH_API_FN=fake_api patch_group 9 "$tmp/wf.json" "$tmp/repos.json" --evidence "$tmp/e2" ) >/dev/null 2>&1; rc=$?
  t "repository PUT failure exits non-zero" "[ $rc -ne 0 ]"
  t "...and records an INCIDENT" "[ \"\$(jq -r .verdict '$tmp/e2/result.json')\" = INCIDENT ]"
  t "...and evidence is emitted on failure" "test -s '$tmp/e2/result.json'"

  _reset; printf 'fail\n' > "$FAKE/pmode"
  ( GH_API_FN=fake_api patch_group 9 "$tmp/wf.json" "$tmp/repos.json" --evidence "$tmp/e3" ) >/dev/null 2>&1; rc=$?
  t "a failed PATCH exits non-zero" "[ $rc -ne 0 ]"
  t "...performs no repository PUT" "! grep -q 'PUT .*repositories' '$FAKE/calls'"
  t "...leaves membership untouched" "[ \"\$(tr -d '\\n' < '$FAKE/repos')\" = '[1254295268]' ]"
  t "...and records REFUSED" "[ \"\$(jq -r .verdict '$tmp/e3/result.json')\" = REFUSED ]"

  _reset; printf 'yes\n' > "$FAKE/drift"
  ( GH_API_FN=fake_api patch_group 9 "$tmp/wf.json" "$tmp/repos.json" --evidence "$tmp/e4" ) >/dev/null 2>&1; rc=$?
  t "runner membership drift exits non-zero" "[ $rc -ne 0 ]"
  t "...and is named in the evidence" "grep -q 'runner membership drifted' '$tmp/e4/result.json'"

  _reset
  printf '{"selected_repository_ids":[1254295268,999999]}\n' > "$tmp/wide.json"
  ( GH_API_FN=fake_api EXPECT_REPOS='[1254295268]' patch_group 9 "$tmp/wf.json" "$tmp/wide.json" --evidence "$tmp/e5" ) >/dev/null 2>&1
  t "repository widening is recorded explicitly" "jq -e '.desired_repository_ids|length==2' '$tmp/e5/result.json' >/dev/null"

  _reset
  ( GH_API_FN=fake_api EXPECT_REPOS='[1]' patch_group 9 "$tmp/wf.json" "$tmp/repos.json" --evidence "$tmp/e6" ) >/dev/null 2>&1; rc=$?
  t "a precondition mismatch refuses before mutating" "[ $rc -ne 0 ]"
  t "...and no PATCH was sent" "! grep -q '^PATCH' '$FAKE/calls'"

  echo "self-test: $ok ok, $nbad failed"
  [ "$nbad" -eq 0 ]
}

case "${1-}" in
  --self-test) _rgp_self_test && echo "runner-group-patch.sh: SELF-TEST OK" ;;
  "") echo "usage: runner-group-patch.sh <group-id> <group-patch.json> <desired-repositories.json> [--evidence <dir>]" >&2; exit 2 ;;
  *) patch_group "$@" ;;
esac
