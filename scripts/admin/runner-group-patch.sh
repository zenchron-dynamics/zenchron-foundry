#!/usr/bin/env bash
# =============================================================================
# scripts/admin/runner-group-patch.sh
# -----------------------------------------------------------------------------
# Change an org runner group's WORKFLOW ALLOWLIST (and only that), while
# PRESERVING every other property, its repository membership and its runners.
#
# THIS HELPER DOES NOT CHANGE REPOSITORY MEMBERSHIP. It restores it. GitHub's
# PATCH destroys the selection as a side effect, so the repository list is
# supplied purely so the helper can put back exactly what was there. Widening or
# narrowing membership is a different operation with different review, and any
# attempt to do it here REFUSES before anything is mutated.
#
# WHY IT WORKS THIS WAY. Measured on a throwaway group, 2026-08-06 —
# docs/audits/runner-group-patch-semantics-2026-08-06/:
#
#     PATCH with    selected_repository_ids  -> 422, nothing changes
#     PATCH without selected_repository_ids  -> 200 OK, membership CLEARED
#     PUT .../repositories                   -> restored exactly
#
# A 200 OK is emitted while the selection is emptied. Since the API demonstrably
# changes a resource nobody asked about, NOTHING may be inferred from the status
# code or from the fields that happened to be requested: every stable field is
# compared before and after, and only explicitly intended ones may differ.
#
# WHAT IT DOES NOT GUARANTEE. Two REST calls cannot be made atomic. The PATCH
# opens a measured FAIL-CLOSED AVAILABILITY WINDOW in which no repository is
# authorised and trusted jobs are unschedulable. This closes it immediately and
# verifies closure. It is not transactional.
#
# Usage:
#   runner-group-patch.sh <group-id> <group-patch.json> <expected-state.json> \
#                         [--evidence <dir>]
#   runner-group-patch.sh --self-test
#
# expected-state.json is MANDATORY and must describe the COMPLETE pre-mutation
# state. Optional expectations are fail-open: the binding disappears exactly when
# nobody supplies it.
#
#   {"id":3, "name":"zenchron-foundry-trusted", "visibility":"selected",
#    "allows_public_repositories":true, "restricted_to_workflows":true,
#    "selected_repository_ids":[...], "runner_ids":[...],
#    "selected_workflows":[...]}
#
# Exit: 0 only when the mutation is verified AND its evidence is written and
# re-read. 1 on any refusal, failure or incident.
# =============================================================================
set -uo pipefail

ORG="${ORG:-zenchron-dynamics}"
API_VERSION="${API_VERSION:-2026-03-10}"

_api() { gh api -H "X-GitHub-Api-Version: ${API_VERSION}" "$@"; }
api() { "${GH_API_FN:-_api}" "$@"; }

log()  { printf '%s\n' "$*"; }
warn() { printf '%s\n' "$*" >&2; }
die()  { printf 'REFUSE: %s\n' "$*" >&2; return 1; }

# Only the workflow allowlist may be intentionally changed. The other keys are
# accepted so the caller can restate them, but they are pinned to safe values;
# a request to relax them refuses.
PATCH_ALLOWED_KEYS="name visibility allows_public_repositories restricted_to_workflows selected_workflows"
PATCH_FORBIDDEN_KEYS="selected_repository_ids runners repositories"
INTENDED_MUTABLE_KEYS="selected_workflows"
# Safety invariants required both in the request and in the observed state.
SAFE_VISIBILITY="selected"
SAFE_RESTRICTED="true"
SAFE_PUBLIC="true"

# Sorted, de-duplicated integer list. Every comparison goes through this so
# ordering noise never reads as drift and a duplicated id never hides a change.
canon_ids() { # <json-array>
  python3 -c 'import json,sys
v=json.loads(sys.argv[1])
if not isinstance(v,list) or not all(isinstance(i,int) for i in v):
    sys.exit("REFUSE: not an integer id list: %r" % (v,))
if len(set(v))!=len(v):
    sys.exit("REFUSE: duplicate ids: %r" % (v,))
print(json.dumps(sorted(v)))' "$1"
}
canon_strs() { # <json-array>
  python3 -c 'import json,sys
v=json.loads(sys.argv[1])
if not isinstance(v,list): sys.exit("REFUSE: not a list")
if len(set(v))!=len(v): sys.exit("REFUSE: duplicate entries: %r" % (v,))
print(json.dumps(sorted(v)))' "$1"
}

assert_patch_payload_safe() { # <payload-file>
  local file="$1"
  [ -f "$file" ] || { die "patch payload not found: $file"; return 1; }
  PAYLOAD="$file" ALLOWED="$PATCH_ALLOWED_KEYS" FORBIDDEN="$PATCH_FORBIDDEN_KEYS" \
  SVIS="$SAFE_VISIBILITY" SRES="$SAFE_RESTRICTED" SPUB="$SAFE_PUBLIC" python3 - <<'PY'
import json, os, sys
allowed = set(os.environ["ALLOWED"].split()); forbidden = set(os.environ["FORBIDDEN"].split())
try: p = json.load(open(os.environ["PAYLOAD"]))
except Exception as exc: sys.exit("REFUSE: patch payload is not valid JSON: %s" % exc)
if not isinstance(p, dict): sys.exit("REFUSE: patch payload must be a JSON object")
bad = sorted(set(p) & forbidden)
if bad:
    sys.exit("REFUSE: %s belong to dedicated endpoints and must not appear in a group "
             "PATCH. GitHub rejects selected_repository_ids with 422, and a PATCH that "
             "omits it CLEARS membership." % ", ".join(bad))
unknown = sorted(set(p) - allowed)
if unknown:
    sys.exit("REFUSE: unsupported PATCH key(s): %s" % ", ".join(unknown))
# Permitted is not the same as safe. A caller must not be able to relax the
# boundary while nominally editing a workflow list.
if "visibility" in p and p["visibility"] != os.environ["SVIS"]:
    sys.exit("REFUSE: visibility must remain %r, requested %r" % (os.environ["SVIS"], p["visibility"]))
if "restricted_to_workflows" in p and p["restricted_to_workflows"] is not (os.environ["SRES"] == "true"):
    sys.exit("REFUSE: restricted_to_workflows must remain %s" % os.environ["SRES"])
if "allows_public_repositories" in p and p["allows_public_repositories"] is not (os.environ["SPUB"] == "true"):
    sys.exit("REFUSE: allows_public_repositories must remain %s" % os.environ["SPUB"])
wf = p.get("selected_workflows")
if wf is None or not wf:
    sys.exit("REFUSE: selected_workflows is the only intended change and must be present and non-empty")
for w in wf:
    if not w.endswith("@refs/heads/master"):
        sys.exit("REFUSE: workflow ref not pinned to the default branch: %s" % w)
if len(set(wf)) != len(wf):
    sys.exit("REFUSE: duplicate workflow entries: %r" % wf)
PY
}

assert_expected_state() { # <expected-file> <gid>
  local file="$1" gid="$2"
  [ -f "$file" ] || { die "expected-state document not found: $file"; return 1; }
  EXPECTED="$file" GID="$gid" SVIS="$SAFE_VISIBILITY" SRES="$SAFE_RESTRICTED" SPUB="$SAFE_PUBLIC" python3 - <<'PY'
import json, os, sys
try: e = json.load(open(os.environ["EXPECTED"]))
except Exception as exc: sys.exit("REFUSE: expected-state is not valid JSON: %s" % exc)
need = ["id","name","visibility","allows_public_repositories","restricted_to_workflows",
        "selected_repository_ids","runner_ids","selected_workflows"]
missing = [k for k in need if k not in e]
if missing:
    sys.exit("REFUSE: expected-state is missing %s. Every expectation is mandatory; an "
             "optional one is fail-open." % ", ".join(missing))
if str(e["id"]) != os.environ["GID"]:
    sys.exit("REFUSE: expected-state is for group %s, invoked for %s" % (e["id"], os.environ["GID"]))
if e["visibility"] != os.environ["SVIS"]: sys.exit("REFUSE: expected visibility must be %r" % os.environ["SVIS"])
if e["restricted_to_workflows"] is not (os.environ["SRES"] == "true"): sys.exit("REFUSE: expected restricted_to_workflows must be true")
if e["allows_public_repositories"] is not (os.environ["SPUB"] == "true"): sys.exit("REFUSE: expected allows_public_repositories must be true")
if not e["selected_repository_ids"]:
    sys.exit("REFUSE: expected repository list is empty; this helper restores membership, it does not invent it")
PY
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

# Canonical fingerprint of an observed state, for drift comparison and for the
# postcondition diff. Every stable field, not only the requested ones.
fingerprint() { # <dir> <prefix>
  python3 -c 'import json,sys
g=json.load(open(sys.argv[1])); r=json.load(open(sys.argv[2])); n=json.load(open(sys.argv[3]))
print(json.dumps({
 "name":g.get("name"), "visibility":g.get("visibility"),
 "allows_public_repositories":g.get("allows_public_repositories"),
 "restricted_to_workflows":g.get("restricted_to_workflows"),
 "default":g.get("default"), "inherited":g.get("inherited"),
 "selected_workflows":sorted(g.get("selected_workflows") or []),
 "repositories":sorted(r), "runners":sorted(n)}, sort_keys=True))' \
   "$1/$2-group.json" "$1/$2-repos.json" "$1/$2-runners.json"
}

put_repositories() { # <gid> <ids-json>
  local gid="$1" ids="$2" tmp rc
  tmp="$(mktemp)"
  python3 -c 'import json,sys; json.dump({"selected_repository_ids": json.loads(sys.argv[1])}, open(sys.argv[2],"w"))' "$ids" "$tmp"
  api --method PUT "orgs/${ORG}/actions/runner-groups/${gid}/repositories" --input "$tmp" >/dev/null 2>&1
  rc=$?; rm -f "$tmp"; return $rc
}

# Restores AND verifies. Returns non-zero unless the observed set is exactly the
# requested one and non-empty.
restore_repositories() { # <gid> <ids-json>
  local gid="$1" ids="$2" i got
  for i in 1 2 3; do
    put_repositories "$gid" "$ids"
    got="$(canon_ids "$(repos_json "$gid" 2>/dev/null || echo '[]')" 2>/dev/null)"
    if [ "$got" = "$ids" ] && [ "$got" != "[]" ]; then return 0; fi
    warn "restore attempt $i did not take (observed ${got:-unreadable}); retrying"
  done
  return 1
}

# Recovery outcome, recorded rather than discarded. recover() has several
# materially different catastrophic endings and they must not all read as one
# generic INCIDENT.
RECOVERY_ATTEMPTED=false
RECOVERY_STATUS=NOT_ATTEMPTED
RECOVERY_REASON=""
RECOVERY_MEMBERSHIP_OK=false
RECOVERY_FINGERPRINT_OK=false

finish() { # <gid> <ev> <verdict> <reason> <want>
  write_evidence "$@" || { warn "INCIDENT: evidence could not be written"; return 1; }
  # Re-read it: an unreadable record is the same as no record.
  jq -e '.verdict' "$2/result.json" >/dev/null 2>&1 || { warn "INCIDENT: evidence is unreadable after writing"; return 1; }
  [ "$3" = PASS ]
}

write_evidence() { # <gid> <ev> <verdict> <reason> <want>
  RA="$RECOVERY_ATTEMPTED" RS="$RECOVERY_STATUS" RR="$RECOVERY_REASON" \
  RM="$RECOVERY_MEMBERSHIP_OK" RF="$RECOVERY_FINGERPRINT_OK" \
  python3 - "$1" "$2" "$3" "$4" "$5" "$ORG" "$API_VERSION" <<'PY'
import json, os, sys, datetime
gid, ev, verdict, reason, want, org, apiv = sys.argv[1:8]
def rd(n):
    try: return json.load(open(os.path.join(ev, n)))
    except Exception: return None
json.dump({
  "schema_version": 2, "organization": org, "runner_group_id": int(gid), "api_version": apiv,
  "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
  "verdict": verdict, "reason": reason,
  "preserved_repository_ids": json.loads(want),
  "before": {"group": rd("before-group.json"), "repositories": rd("before-repos.json"), "runners": rd("before-runners.json")},
  "recheck": {"repositories": rd("recheck-repos.json"), "runners": rd("recheck-runners.json")},
  "patch_request": rd("patch-request.json"),
  "after": {"group": rd("after-group.json"), "repositories": rd("after-repos.json"), "runners": rd("after-runners.json")},
  "restored": {"group": rd("restored-group.json"), "repositories": rd("restored-repos.json"), "runners": rd("restored-runners.json")},
  "recovery": {"attempted": os.environ.get("RA") == "true",
               "status": os.environ.get("RS", "NOT_ATTEMPTED"),
               "reason": os.environ.get("RR", ""),
               "repository_membership_verified": os.environ.get("RM") == "true",
               "original_fingerprint_restored": os.environ.get("RF") == "true"},
  "guarantee": ("repository membership is PRESERVED, never modified, by this helper. "
                "The PATCH opens a measured fail-closed window in which no repository is "
                "authorised; it is closed and verified here. Two REST calls are not atomic."),
}, open(os.path.join(ev, "result.json"), "w"), indent=2)
PY
}

patch_group() { # <gid> <patch.json> <expected-state.json> [--evidence <dir>]
  local gid="${1:?usage: runner-group-patch.sh <group-id> <group-patch.json> <expected-state.json> [--evidence <dir>]}"
  local patch="${2:?group-patch.json required}"
  local expected="${3:?expected-state.json required}"
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
  assert_expected_state "$expected" "$gid" || return 1

  # A non-intended field present in the request must already equal the expected
  # state. `name` is an allowed key, so a typo would otherwise reach GitHub and
  # be caught only AFTER execution, as an unrequested change to be recovered from.
  # A guardrail that detects a caller mistake only by performing it is not one.
  local nk
  for nk in name visibility allows_public_repositories restricted_to_workflows; do
    local rv ev_
    rv="$(jq -r --arg k "$nk" 'if has($k) then (.[$k]|tostring) else "\u0000absent" end' "$patch")"
    [ "$rv" = "$(printf '\u0000')absent" ] && continue
    ev_="$(jq -r --arg k "$nk" '.[$k]|tostring' "$expected")"
    [ "$rv" = "$ev_" ] || { die "request sets $nk='$rv' but the expected state says '$ev_'; only selected_workflows may change"; return 1; }
  done

  local exp_repos exp_runners exp_wf
  exp_repos="$(canon_ids "$(jq -c .selected_repository_ids "$expected")")" || return 1
  exp_runners="$(canon_ids "$(jq -c .runner_ids "$expected")")" || return 1
  exp_wf="$(canon_strs "$(jq -c .selected_workflows "$expected")")" || return 1

  # ---- snapshot A -------------------------------------------------------
  log "==> snapshot A"
  snapshot "$gid" "$ev" before || { die "could not read the group"; return 1; }
  local a_repos a_runners a_wf
  a_repos="$(canon_ids "$(cat "$ev/before-repos.json")")" || return 1
  a_runners="$(canon_ids "$(cat "$ev/before-runners.json")")" || return 1
  a_wf="$(canon_strs "$(jq -c '.selected_workflows // []' "$ev/before-group.json")")" || return 1

  # ---- validate A against the mandatory expectations --------------------
  local want got
  for pair in "name:$(jq -r .name "$expected"):$(jq -r .name "$ev/before-group.json")" \
              "visibility:$(jq -r .visibility "$expected"):$(jq -r .visibility "$ev/before-group.json")" \
              "restricted_to_workflows:$(jq -r .restricted_to_workflows "$expected"):$(jq -r .restricted_to_workflows "$ev/before-group.json")" \
              "allows_public_repositories:$(jq -r .allows_public_repositories "$expected"):$(jq -r .allows_public_repositories "$ev/before-group.json")"; do
    local k="${pair%%:*}" rest="${pair#*:}"; want="${rest%%:*}"; got="${rest#*:}"
    [ "$want" = "$got" ] || { die "$k is '$got', expected '$want'"; return 1; }
  done
  [ "$a_repos"   = "$exp_repos" ]   || { die "repositories are $a_repos, expected $exp_repos"; return 1; }
  [ "$a_runners" = "$exp_runners" ] || { die "runners are $a_runners, expected $exp_runners"; return 1; }
  [ "$a_wf"      = "$exp_wf" ]      || { die "current workflow set differs from the expected one"; return 1; }
  [ "$a_repos" = "[]" ] && { die "group authorises no repositories; refusing to mutate"; return 1; }

  # Membership is PRESERVED. Widening or narrowing is a different operation.
  local preserve="$a_repos"

  # ---- snapshot B, immediately before mutating --------------------------
  log "==> snapshot B (drift check)"
  local fa fb
  fa="$(fingerprint "$ev" before)"
  snapshot "$gid" "$ev" recheck || { die "could not re-read the group before mutating"; return 1; }
  fb="$(fingerprint "$ev" recheck)"
  [ "$fa" = "$fb" ] || { die "the group changed between snapshot A and the PATCH (concurrent administration); refusing"; return 1; }

  # ---- mutate -----------------------------------------------------------
  log "==> PATCH (workflow allowlist only)"
  cp "$patch" "$ev/patch-request.json"
  if ! api --method PATCH "orgs/${ORG}/actions/runner-groups/${gid}" \
        --input "$patch" > "$ev/patch-response.json" 2>"$ev/patch-error.txt"; then
    # A non-zero CLIENT result does not prove the SERVER made no change. A lost
    # response, a broken connection or a 5xx after the mutation was applied all
    # look identical here — and in that case the group is already left with the
    # new workflow set and an EMPTY repository selection, which is the outage
    # this helper exists to prevent. Same posture as the rest of Foundry: a
    # generic failure is INDETERMINATE, never proof of a no-op.
    warn "PATCH returned non-zero: INDETERMINATE — the mutation may or may not have been applied"
    [ -s "$ev/patch-error.txt" ] && cat "$ev/patch-error.txt" >&2
    warn "re-asserting repository membership before assuming anything"
    if ! restore_repositories "$gid" "$preserve"; then
      warn "INCIDENT: membership could not be re-asserted after an indeterminate PATCH"
      RECOVERY_STATUS=FAILED RECOVERY_REASON="membership-reassert-failed-after-indeterminate-patch" \
        RECOVERY_ATTEMPTED=true RECOVERY_MEMBERSHIP_OK=false RECOVERY_FINGERPRINT_OK=false
      finish "$gid" "$ev" INCIDENT "patch-indeterminate; membership could not be re-asserted" "$preserve"
      return 1
    fi
    if ! snapshot "$gid" "$ev" after; then
      warn "INCIDENT: state unreadable after an indeterminate PATCH"
      RECOVERY_STATUS=FAILED RECOVERY_REASON="state-unreadable-after-indeterminate-patch" \
        RECOVERY_ATTEMPTED=true RECOVERY_MEMBERSHIP_OK=true RECOVERY_FINGERPRINT_OK=false
      finish "$gid" "$ev" INCIDENT "patch-indeterminate; state unreadable" "$preserve"
      return 1
    fi
    if [ "$(fingerprint "$ev" after)" = "$(fingerprint "$ev" before)" ]; then
      # Nothing was applied. Membership is proven restored. Still never PASS:
      # the requested mutation did not happen.
      RECOVERY_STATUS=RESTORED RECOVERY_REASON="patch-not-applied; original state intact" \
        RECOVERY_ATTEMPTED=true RECOVERY_MEMBERSHIP_OK=true RECOVERY_FINGERPRINT_OK=true
      finish "$gid" "$ev" INDETERMINATE "patch-failed-and-not-applied" "$preserve"
      return 1
    fi
    warn "the group DID change despite the failure; recovering"
    recover "$gid" "$ev" "$preserve"
    finish "$gid" "$ev" INDETERMINATE "patch-failed-but-partially-applied" "$preserve"
    return 1
  fi

  log "==> PUT repositories (closing the availability window)"
  if ! restore_repositories "$gid" "$preserve"; then
    warn "INCIDENT: repository membership could not be restored after the PATCH"
    warn "no further PATCH will be attempted while access may be empty"
    # This branch never reaches recover(), so it records its own outcome —
    # otherwise the artifact would say NOT_ATTEMPTED for the worst case there is.
    RECOVERY_ATTEMPTED=true
    RECOVERY_STATUS=FAILED
    RECOVERY_REASON="membership-restoration-failed-after-patch; no rollback attempted"
    RECOVERY_MEMBERSHIP_OK=false
    RECOVERY_FINGERPRINT_OK=false
    finish "$gid" "$ev" INCIDENT "repository-restore-failed-after-patch" "$preserve"; return 1
  fi

  # ---- verify -----------------------------------------------------------
  log "==> verifying postconditions"
  if ! snapshot "$gid" "$ev" after; then
    warn "INCIDENT: the group could not be re-read after mutation; attempting recovery"
    recover "$gid" "$ev" "$preserve"
    finish "$gid" "$ev" INCIDENT "postcondition-read-failed" "$preserve"; return 1
  fi

  local verdict=PASS reason=ok
  local diff
  diff="$(BEF="$(fingerprint "$ev" before)" AFT="$(fingerprint "$ev" after)" \
          REQ="$patch" INTENDED="$INTENDED_MUTABLE_KEYS" python3 - <<'PY'
import json, os
b = json.loads(os.environ["BEF"]); a = json.loads(os.environ["AFT"])
req = json.load(open(os.environ["REQ"])); intended = set(os.environ["INTENDED"].split())
out = []

# TWO INDEPENDENT ASSERTIONS. A single loop that skips when before == after was
# wrong for the intended field: if the API returns 200, clears membership, and
# does NOT apply the requested workflow change, then before == after and the
# comparison short-circuits before ever checking the REQUESTED value. The helper
# would report PASS while the workflow was never installed — precisely the
# "200 is not proof the mutation happened" failure this exists to catch.

# 1. Intended fields must equal what was REQUESTED, whether or not they changed.
for k in sorted(intended):
    want = sorted(req.get(k, []))
    if a.get(k) != want:
        out.append("%s: %r != requested %r" % (k, a.get(k), want))

# 2. Everything else must equal what was there BEFORE.
for k in sorted(set(b) | set(a)):
    if k in intended:
        continue
    if b.get(k) != a.get(k):
        out.append("UNREQUESTED CHANGE %s: %r -> %r" % (k, b.get(k), a.get(k)))
print("; ".join(out))
PY
)"
  [ -n "$diff" ] && { verdict=INCIDENT; reason="$diff"; }

  # Independent invariants, not merely "unchanged".
  [ "$(jq -r .visibility "$ev/after-group.json")" = "$SAFE_VISIBILITY" ] || { verdict=INCIDENT; reason="visibility is not $SAFE_VISIBILITY"; }
  [ "$(jq -r .restricted_to_workflows "$ev/after-group.json")" = "$SAFE_RESTRICTED" ] || { verdict=INCIDENT; reason="restricted_to_workflows is not $SAFE_RESTRICTED"; }
  [ "$(canon_ids "$(cat "$ev/after-repos.json")" 2>/dev/null)" = "$preserve" ] || { verdict=INCIDENT; reason="repositories are not exactly $preserve"; }
  [ "$(canon_ids "$(cat "$ev/after-runners.json")" 2>/dev/null)" = "$exp_runners" ] || { verdict=INCIDENT; reason="runner membership drifted"; }

  if [ "$verdict" != PASS ]; then
    warn "INCIDENT: $reason"
    recover "$gid" "$ev" "$preserve"
    finish "$gid" "$ev" INCIDENT "$reason" "$preserve"; return 1
  fi

  finish "$gid" "$ev" PASS ok "$preserve" || return 1
  log "OK: group ${gid} workflow allowlist updated; repositories $preserve preserved; runners unchanged"
}

# Recovery, in the one order that is safe. Membership FIRST; a rollback PATCH is
# never sent while access may be empty, because that PATCH would clear it again
# with nothing proven to restore.
recover() { # <gid> <ev> <preserve>
  local gid="$1" ev="$2" preserve="$3"
  RECOVERY_ATTEMPTED=true
  RECOVERY_MEMBERSHIP_OK=false
  RECOVERY_FINGERPRINT_OK=false
  warn "recovery: restoring repository membership first"
  if ! restore_repositories "$gid" "$preserve"; then
    warn "INCIDENT: membership restoration failed; STOPPING. No rollback PATCH will be sent"
    warn "the group may authorise no repositories — manual intervention required"
    RECOVERY_STATUS=FAILED
    RECOVERY_REASON="membership-restoration-failed-before-rollback"
    return 1
  fi
  RECOVERY_MEMBERSHIP_OK=true
  warn "recovery: membership verified; rolling back group fields"
  if ! PREV="$ev/before-group.json" python3 -c 'import json,os,sys
g=json.load(open(os.environ["PREV"]))
json.dump({k:g[k] for k in ("name","visibility","allows_public_repositories","restricted_to_workflows","selected_workflows") if k in g}, open(sys.argv[1],"w"))' "$ev/rollback-patch.json" 2>/dev/null; then
    RECOVERY_STATUS=FAILED; RECOVERY_REASON="could-not-build-rollback-payload"; return 1
  fi
  if ! api --method PATCH "orgs/${ORG}/actions/runner-groups/${gid}" --input "$ev/rollback-patch.json" >/dev/null 2>&1; then
    warn "INCIDENT: rollback PATCH failed"
    # Indeterminate for the same reason as the forward PATCH: it may have applied
    # and cleared membership before failing.
    if restore_repositories "$gid" "$preserve"; then
      RECOVERY_STATUS=FAILED; RECOVERY_REASON="rollback-patch-failed; membership re-asserted"
    else
      RECOVERY_MEMBERSHIP_OK=false
      RECOVERY_STATUS=FAILED; RECOVERY_REASON="rollback-patch-failed; membership also empty"
    fi
    return 1
  fi
  # The rollback PATCH cleared membership again.
  if ! restore_repositories "$gid" "$preserve"; then
    RECOVERY_MEMBERSHIP_OK=false
    RECOVERY_STATUS=FAILED; RECOVERY_REASON="membership-restoration-failed-after-rollback"
    warn "INCIDENT: membership empty after the rollback PATCH"
    return 1
  fi
  if ! snapshot "$gid" "$ev" restored; then
    RECOVERY_STATUS=FAILED; RECOVERY_REASON="restored-state-unreadable"
    warn "INCIDENT: could not read the restored state"
    return 1
  fi
  if [ "$(fingerprint "$ev" restored)" != "$(fingerprint "$ev" before)" ]; then
    RECOVERY_STATUS=FAILED; RECOVERY_REASON="restored-fingerprint-differs-from-original"
    warn "INCIDENT: restored state does not match the original"
    return 1
  fi
  RECOVERY_FINGERPRINT_OK=true
  RECOVERY_STATUS=RESTORED
  RECOVERY_REASON="original state restored and verified"
  warn "recovery: original state restored and verified"
}

# ---------------------------------------------------------------------------
_rgp_self_test() {
  local ok=0 nbad=0 tmp rc; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  t() { if eval "$2"; then echo "ok   - $1"; ok=$((ok+1)); else echo "FAIL - $1"; nbad=$((nbad+1)); fi; }
  local OLD="zenchron-dynamics/zenchron-foundry/.github/workflows/old.yml@refs/heads/master"
  local DRIFT="zenchron-dynamics/zenchron-foundry/.github/workflows/drifted.yml@refs/heads/master"
  local NEW="zenchron-dynamics/zenchron-foundry/.github/workflows/new.yml@refs/heads/master"

  mkexp() { python3 -c 'import json,sys
json.dump({"id":9,"name":"g","visibility":"selected","allows_public_repositories":True,
"restricted_to_workflows":True,"selected_repository_ids":json.loads(sys.argv[1]),
"runner_ids":json.loads(sys.argv[2]),"selected_workflows":[sys.argv[3]]}, open(sys.argv[4],"w"))' "$1" "$2" "$3" "$4"; }
  mkpatch() { python3 -c 'import json,sys
json.dump({"name":"g","visibility":"selected","allows_public_repositories":True,
"restricted_to_workflows":True,"selected_workflows":[sys.argv[1]]}, open(sys.argv[2],"w"))' "$1" "$2"; }

  mkexp '[1254295268]' '[]' "$OLD" "$tmp/exp.json"
  mkpatch "$NEW" "$tmp/patch.json"

  # --- local validation ---------------------------------------------------
  printf '{"selected_workflows":["x@refs/heads/master"],"selected_repository_ids":[1]}\n' > "$tmp/b1.json"
  t "PATCH containing selected_repository_ids refuses" "! assert_patch_payload_safe '$tmp/b1.json' 2>/dev/null"
  printf '{"runners":[1]}\n' > "$tmp/b2.json"
  t "PATCH containing runners refuses" "! assert_patch_payload_safe '$tmp/b2.json' 2>/dev/null"
  printf '{"name":"g","surprise":true}\n' > "$tmp/b3.json"
  t "an unknown PATCH key refuses" "! assert_patch_payload_safe '$tmp/b3.json' 2>/dev/null"
  printf '{"visibility":"all","selected_workflows":["x@refs/heads/master"]}\n' > "$tmp/b4.json"
  t "an unsafe visibility value refuses" "! assert_patch_payload_safe '$tmp/b4.json' 2>/dev/null"
  printf '{"restricted_to_workflows":false,"selected_workflows":["x@refs/heads/master"]}\n' > "$tmp/b5.json"
  t "relaxing restricted_to_workflows refuses" "! assert_patch_payload_safe '$tmp/b5.json' 2>/dev/null"
  printf '{"selected_workflows":["o/r/.github/workflows/x.yml@refs/heads/dev"]}\n' > "$tmp/b6.json"
  t "a non-master workflow ref refuses" "! assert_patch_payload_safe '$tmp/b6.json' 2>/dev/null"
  printf '{"id":9,"name":"g"}\n' > "$tmp/b7.json"
  t "an incomplete expected-state refuses" "! assert_expected_state '$tmp/b7.json' 9 2>/dev/null"
  t "canonicalisation rejects duplicate ids" "! canon_ids '[1,1]' 2>/dev/null"
  t "canonicalisation sorts ids" "[ \"\$(canon_ids '[3,1,2]')\" = '[1, 2, 3]' ] || [ \"\$(canon_ids '[3,1,2]')\" = '[1,2,3]' ]"

  # --- injected transport, modelling the MEASURED behaviour ---------------
  FAKE="$tmp/state"; mkdir -p "$FAKE"; export FAKE
  _reset() { printf '[1254295268]\n' > "$FAKE/repos"; printf '[]\n' > "$FAKE/runners"
             printf '%s\n' "$OLD" > "$FAKE/wf"; printf 'selected\n' > "$FAKE/vis"; : > "$FAKE/calls"
             printf 'ok\n' > "$FAKE/pmode"; printf 'ok\n' > "$FAKE/umode"
             printf 'no\n' > "$FAKE/sideeffect"; printf 'no\n' > "$FAKE/readfail"
             printf 'no\n' > "$FAKE/noop"; printf 'no\n' > "$FAKE/once"
             printf '0\n' > "$FAKE/ggets"; printf '0\n' > "$FAKE/failgget"
             printf '0\n' > "$FAKE/driftafter"; printf 'no\n' > "$FAKE/drifted"; }
  fake_api() {
    local m="" p="" i=""
    while [ $# -gt 0 ]; do
      case "$1" in --method) m="$2"; shift 2 ;; --input) i="$2"; shift 2 ;;
                   --jq) shift 2 ;; -H) shift 2 ;; *) p="$1"; shift ;; esac
    done
    echo "${m:-GET} $p" >> "$FAKE/calls"
    case "${m:-GET} $p" in
      "GET "*"/repositories") [ "$(cat "$FAKE/readfail")" = yes ] && return 1; cat "$FAKE/repos" ;;
      "GET "*"/runners")      [ "$(cat "$FAKE/readfail")" = yes ] && return 1; cat "$FAKE/runners" ;;
      "GET "*)
        [ "$(cat "$FAKE/readfail")" = yes ] && return 1
        n=$(( $(cat "$FAKE/ggets") + 1 )); echo "$n" > "$FAKE/ggets"
        # Fail ONE specific group read, so the postcondition-snapshot branch is
        # reached rather than the earlier restore-verification branch.
        [ "$n" = "$(cat "$FAKE/failgget")" ] && return 1
        # Concurrent administration BETWEEN snapshot A and snapshot B.
        if [ "$(cat "$FAKE/driftafter")" != 0 ] && [ "$n" -ge "$(cat "$FAKE/driftafter")" ] \
           && [ "$(cat "$FAKE/drifted")" = no ]; then
          printf 'yes\n' > "$FAKE/drifted"; printf '%s\n' "$DRIFT" > "$FAKE/wf"
        fi
        jq -n --arg w "$(cat "$FAKE/wf")" --arg v "$(cat "$FAKE/vis")" \
          '{id:9,name:"g",visibility:$v,allows_public_repositories:true,restricted_to_workflows:true,default:false,inherited:false,selected_workflows:[$w]}' ;;
      "PATCH "*)
        # fail        : nothing applied, non-zero          (clean client failure)
        # failafter   : workflow applied + repos cleared, then non-zero
        # failclear   : repos cleared only, then non-zero
        case "$(cat "$FAKE/pmode")" in
          fail) return 1 ;;
          failclear) printf 'ok\n' > "$FAKE/pmode"; printf '[]\n' > "$FAKE/repos"; return 1 ;;
          failafter)
            # one-shot: the recovery rollback must be able to succeed, or the
            # test proves detection instead of repair
            printf 'ok\n' > "$FAKE/pmode"
            python3 -c 'import json,sys
p=json.load(open(sys.argv[1])); open(sys.argv[2],"w").write((p.get("selected_workflows") or ["none"])[0]+"\n")' "$i" "$FAKE/wf"
            printf '[]\n' > "$FAKE/repos"; return 1 ;;
        esac
        # noop: 200 OK, membership cleared, requested change NOT applied.
        if [ "$(cat "$FAKE/noop")" != yes ]; then
          python3 -c 'import json,sys
p=json.load(open(sys.argv[1])); open(sys.argv[2],"w").write((p.get("selected_workflows") or ["none"])[0]+"\n")' "$i" "$FAKE/wf"
        fi
        printf '[]\n' > "$FAKE/repos"                       # MEASURED
        # Apply visibility from the payload, so a rollback PATCH can genuinely
        # restore it; otherwise recovery could never be proved to work.
        python3 -c 'import json,sys
p=json.load(open(sys.argv[1]))
v=p.get("visibility")
if v: open(sys.argv[2],"w").write(v+"\n")' "$i" "$FAKE/vis"
        if [ "$(cat "$FAKE/sideeffect")" = yes ]; then
          printf 'all\n' > "$FAKE/vis"
          # one-shot: the rollback PATCH must be able to succeed
          [ "$(cat "$FAKE/once")" = yes ] && printf 'no\n' > "$FAKE/sideeffect"
        fi
        echo '{}' ;;
      "PUT "*"/repositories")
        [ "$(cat "$FAKE/umode")" = fail ] && return 1
        python3 -c 'import json,sys
json.dump(json.load(open(sys.argv[1]))["selected_repository_ids"], open(sys.argv[2],"w"))' "$i" "$FAKE/repos"
        printf '\n' >> "$FAKE/repos"; echo '{}' ;;
      *) echo '{}' ;;
    esac
  }

  _reset
  ( GH_API_FN=fake_api patch_group 9 "$tmp/patch.json" "$tmp/exp.json" --evidence "$tmp/e1" ) >/dev/null 2>&1; rc=$?
  t "a preserving run exits 0" "[ $rc -eq 0 ]"
  t "membership is preserved exactly" "[ \"\$(tr -d '\\n' < '$FAKE/repos')\" = '[1254295268]' ]"
  t "evidence records PASS" "[ \"\$(jq -r .verdict '$tmp/e1/result.json')\" = PASS ]"
  t "the evidence says membership is preserved, not modified" \
    "grep -q 'PRESERVED, never modified' '$tmp/e1/result.json'"

  # widening / narrowing REFUSE before any PATCH
  _reset; mkexp '[1254295268,999999]' '[]' "$OLD" "$tmp/wide.json"
  ( GH_API_FN=fake_api patch_group 9 "$tmp/patch.json" "$tmp/wide.json" --evidence "$tmp/e2" ) >/dev/null 2>&1; rc=$?
  t "repository widening REFUSES" "[ $rc -ne 0 ]"
  t "...and sends no PATCH" "! grep -q '^PATCH' '$FAKE/calls'"
  _reset; mkexp '[]' '[]' "$OLD" "$tmp/narrow.json"
  ( GH_API_FN=fake_api patch_group 9 "$tmp/patch.json" "$tmp/narrow.json" --evidence "$tmp/e3" ) >/dev/null 2>&1; rc=$?
  t "repository narrowing REFUSES" "[ $rc -ne 0 ]"
  t "...and sends no PATCH" "! grep -q '^PATCH' '$FAKE/calls'"

  # --- THE BLOCKER: 200 OK, membership cleared, requested change NOT applied.
  # before == after for selected_workflows, so a comparison that skips equal
  # fields never checks it against the REQUEST and reports PASS.
  _reset; printf 'yes\n' > "$FAKE/noop"
  ( GH_API_FN=fake_api patch_group 9 "$tmp/patch.json" "$tmp/exp.json" --evidence "$tmp/en" ) >/dev/null 2>&1; rc=$?
  t "a 200 no-op PATCH does NOT yield PASS" "[ $rc -ne 0 ]"
  t "...recorded as an INCIDENT" "[ \"\$(jq -r .verdict '$tmp/en/result.json')\" = INCIDENT ]"
  t "...naming selected_workflows against the request" \
    "grep -q 'selected_workflows.*!= requested' '$tmp/en/result.json'"
  t "...and the original state is restored" \
    "[ \"\$(tr -d '\\n' < '$FAKE/repos')\" = '[1254295268]' ]"

  # --- REAL snapshot A -> snapshot B drift. The control plane changes BETWEEN
  # the two reads; expectations still match A, so this can only be caught by the
  # fingerprint comparison.
  _reset; printf '2\n' > "$FAKE/driftafter"
  ( GH_API_FN=fake_api patch_group 9 "$tmp/patch.json" "$tmp/exp.json" --evidence "$tmp/ed" ) >/dev/null 2>&1; rc=$?
  t "concurrent administration between snapshot A and B REFUSES" "[ $rc -ne 0 ]"
  t "...sending no PATCH" "! grep -q '^PATCH' '$FAKE/calls'"
  t "...and no repository PUT" "! grep -q 'PUT .*repositories' '$FAKE/calls'"

  # expectation mismatch at snapshot A is a DIFFERENT gate; keep both.
  _reset; mkexp '[1254295268]' '[7]' "$OLD" "$tmp/rdrift.json"
  ( GH_API_FN=fake_api patch_group 9 "$tmp/patch.json" "$tmp/rdrift.json" --evidence "$tmp/e4" ) >/dev/null 2>&1; rc=$?
  t "runner set disagreeing with expectations REFUSES" "[ $rc -ne 0 ]"
  t "...and sends no PATCH" "! grep -q '^PATCH' '$FAKE/calls'"
  _reset; mkexp '[1254295268]' '[]' "$NEW" "$tmp/wdrift.json"
  ( GH_API_FN=fake_api patch_group 9 "$tmp/patch.json" "$tmp/wdrift.json" --evidence "$tmp/e5" ) >/dev/null 2>&1; rc=$?
  t "workflow set disagreeing with expectations REFUSES" "[ $rc -ne 0 ]"

  # --- unrequested side effect on the FIRST patch only, so recovery can succeed
  # and the full restore state machine is actually exercised.
  _reset; printf 'yes\n' > "$FAKE/sideeffect"; printf 'yes\n' > "$FAKE/once"
  ( GH_API_FN=fake_api patch_group 9 "$tmp/patch.json" "$tmp/exp.json" --evidence "$tmp/e6" ) >/dev/null 2>&1; rc=$?
  t "an unrequested group-field side effect is an INCIDENT" "[ $rc -ne 0 ]"
  t "...named as an unrequested change" "grep -q 'UNREQUESTED CHANGE\\|visibility is not' '$tmp/e6/result.json'"
  t "...recovery sends a rollback PATCH" "[ \"\$(grep -c '^PATCH' '$FAKE/calls')\" -ge 2 ]"
  t "...restores membership after the rollback too" \
    "[ \"\$(grep -c 'PUT .*repositories' '$FAKE/calls')\" -ge 3 ]"
  t "...and the group is fully restored to its original state" \
    "[ \"\$(tr -d '\\n' < '$FAKE/repos')\" = '[1254295268]' ] && \
     [ \"\$(cat '$FAKE/vis')\" = selected ] && [ \"\$(cat '$FAKE/wf')\" = '$OLD' ]"

  # --- A NON-ZERO PATCH IS INDETERMINATE, NOT PROOF OF A NO-OP.
  # The previous version asserted "a failed PATCH performs no repository PUT" —
  # encoding the defect as a requirement. A lost response or a 5xx AFTER the
  # server applied the change is indistinguishable from a clean failure, and in
  # that case the group is left with the new workflows and NO repositories.
  _reset; printf 'fail\n' > "$FAKE/pmode"
  ( GH_API_FN=fake_api patch_group 9 "$tmp/patch.json" "$tmp/exp.json" --evidence "$tmp/e7" ) >/dev/null 2>&1; rc=$?
  t "a PATCH that fails before applying exits non-zero" "[ $rc -ne 0 ]"
  t "...STILL re-asserts repository membership" "grep -q 'PUT .*repositories' '$FAKE/calls'"
  t "...is recorded INDETERMINATE, never REFUSED/PASS" \
    "[ \"\$(jq -r .verdict '$tmp/e7/result.json')\" = INDETERMINATE ]"
  t "...and states the original survived" \
    "[ \"\$(jq -r .recovery.original_fingerprint_restored '$tmp/e7/result.json')\" = true ]"

  # apply-then-fail: the case that can recreate the outage
  _reset; printf 'failafter\n' > "$FAKE/pmode"
  ( GH_API_FN=fake_api patch_group 9 "$tmp/patch.json" "$tmp/exp.json" --evidence "$tmp/e7b" ) >/dev/null 2>&1; rc=$?
  t "a PATCH that APPLIES then fails exits non-zero" "[ $rc -ne 0 ]"
  t "...restores repository membership" "[ \"\$(tr -d '\\n' < '$FAKE/repos')\" = '[1254295268]' ]"
  t "...detects that the group did change" \
    "[ \"\$(jq -r .reason '$tmp/e7b/result.json')\" = patch-failed-but-partially-applied ]"
  t "...and recovers the original workflow set" "[ \"\$(cat '$FAKE/wf')\" = '$OLD' ]"
  t "...recording recovery as RESTORED" \
    "[ \"\$(jq -r .recovery.status '$tmp/e7b/result.json')\" = RESTORED ]"

  # repos cleared only, then failure
  _reset; printf 'failclear\n' > "$FAKE/pmode"
  ( GH_API_FN=fake_api patch_group 9 "$tmp/patch.json" "$tmp/exp.json" --evidence "$tmp/e7c" ) >/dev/null 2>&1; rc=$?
  t "a PATCH that clears repositories then fails exits non-zero" "[ $rc -ne 0 ]"
  t "...restores membership rather than assuming a no-op" \
    "[ \"\$(tr -d '\\n' < '$FAKE/repos')\" = '[1254295268]' ]"

  # indeterminate AND unreadable afterwards
  _reset; printf 'fail\n' > "$FAKE/pmode"; printf '3\n' > "$FAKE/failgget"
  ( GH_API_FN=fake_api patch_group 9 "$tmp/patch.json" "$tmp/exp.json" --evidence "$tmp/e7d" ) >/dev/null 2>&1; rc=$?
  t "an indeterminate PATCH with unreadable state exits non-zero" "[ $rc -ne 0 ]"
  t "...and says the state was unreadable" \
    "grep -q 'state unreadable' '$tmp/e7d/result.json'"

  # first restoration fails -> no rollback PATCH at all
  _reset; printf 'fail\n' > "$FAKE/umode"
  ( GH_API_FN=fake_api patch_group 9 "$tmp/patch.json" "$tmp/exp.json" --evidence "$tmp/e8" ) >/dev/null 2>&1; rc=$?
  t "a failed first restoration exits non-zero" "[ $rc -ne 0 ]"
  t "...sends exactly one PATCH (no rollback while access may be empty)" \
    "[ \"\$(grep -c '^PATCH' '$FAKE/calls')\" = 1 ]"
  t "...and records an INCIDENT" "[ \"\$(jq -r .verdict '$tmp/e8/result.json')\" = INCIDENT ]"

  # --- post-mutation read failure, targeted at the POSTCONDITION snapshot.
  # Group GETs: 1 = snapshot A, 2 = snapshot B, 3 = postcondition snapshot.
  # Failing #3 reaches the branch defect 6 was written to repair, instead of the
  # earlier restore-verification branch (which reads repositories, not the group).
  _reset; printf '3\n' > "$FAKE/failgget"
  ( GH_API_FN=fake_api patch_group 9 "$tmp/patch.json" "$tmp/exp.json" --evidence "$tmp/e9" ) >/dev/null 2>&1; rc=$?
  t "a postcondition-snapshot failure exits non-zero" "[ $rc -ne 0 ]"
  t "...after the first membership restoration succeeded" \
    "[ \"\$(grep -c 'PUT .*repositories' '$FAKE/calls')\" -ge 1 ]"
  t "...runs recovery, including a rollback PATCH" "[ \"\$(grep -c '^PATCH' '$FAKE/calls')\" -ge 2 ]"
  t "...restores membership again after that rollback" \
    "[ \"\$(tr -d '\\n' < '$FAKE/repos')\" = '[1254295268]' ]"
  t "...still writes evidence" "test -s '$tmp/e9/result.json'"
  t "...recorded as postcondition-read-failed" \
    "[ \"\$(jq -r .reason '$tmp/e9/result.json')\" = postcondition-read-failed ]"

  # --- recovery outcomes must be machine-readable, not one generic INCIDENT.
  _reset; printf 'yes\n' > "$FAKE/sideeffect"; printf 'yes\n' > "$FAKE/once"
  ( GH_API_FN=fake_api patch_group 9 "$tmp/patch.json" "$tmp/exp.json" --evidence "$tmp/r1" ) >/dev/null 2>&1
  t "successful recovery is recorded as RESTORED" \
    "[ \"\$(jq -r .recovery.status '$tmp/r1/result.json')\" = RESTORED ]"
  t "...with membership and fingerprint both verified" \
    "[ \"\$(jq -r .recovery.repository_membership_verified '$tmp/r1/result.json')\" = true ] && \
     [ \"\$(jq -r .recovery.original_fingerprint_restored '$tmp/r1/result.json')\" = true ]"

  # rollback PATCH fails during recovery
  _reset; printf 'yes\n' > "$FAKE/sideeffect"
  _rbfail_api() { local r
    if [ "${1:-}" = --method ] && [ "${2:-}" = PATCH ] && grep -qc '^PATCH' "$FAKE/calls"        && [ "$(grep -c '^PATCH' "$FAKE/calls")" -ge 1 ]; then printf 'fail\n' > "$FAKE/pmode"; fi
    fake_api "$@"; r=$?; return $r; }
  ( GH_API_FN=_rbfail_api patch_group 9 "$tmp/patch.json" "$tmp/exp.json" --evidence "$tmp/r2" ) >/dev/null 2>&1
  t "a failed rollback PATCH is named in the evidence" \
    "jq -r .recovery.reason '$tmp/r2/result.json' | grep -q 'rollback-patch-failed\\|membership-restoration'"
  t "...and recovery status is FAILED" \
    "[ \"\$(jq -r .recovery.status '$tmp/r2/result.json')\" = FAILED ]"

  # membership restoration fails before any rollback
  _reset; printf 'fail\n' > "$FAKE/umode"
  ( GH_API_FN=fake_api patch_group 9 "$tmp/patch.json" "$tmp/exp.json" --evidence "$tmp/r3" ) >/dev/null 2>&1
  t "a failed first restoration is recorded as FAILED" \
    "[ \"\$(jq -r .recovery.status '$tmp/r3/result.json')\" = FAILED ]"
  t "...naming the membership failure explicitly" \
    "jq -r .recovery.reason '$tmp/r3/result.json' | grep -q membership"
  t "...and membership is NOT claimed verified" \
    "[ \"\$(jq -r .recovery.repository_membership_verified '$tmp/r3/result.json')\" = false ]"

  # a clean PASS records no recovery
  _reset
  ( GH_API_FN=fake_api patch_group 9 "$tmp/patch.json" "$tmp/exp.json" --evidence "$tmp/r4" ) >/dev/null 2>&1
  t "a clean run records recovery as not attempted" \
    "[ \"\$(jq -r .recovery.attempted '$tmp/r4/result.json')\" = false ]"

  # --- non-intended request fields are pinned BEFORE mutating -------------
  _reset
  python3 -c 'import json,sys
json.dump({"name":"wrong-name","visibility":"selected","allows_public_repositories":True,
"restricted_to_workflows":True,"selected_workflows":[sys.argv[1]]}, open(sys.argv[2],"w"))' "$NEW" "$tmp/badname.json"
  ( GH_API_FN=fake_api patch_group 9 "$tmp/badname.json" "$tmp/exp.json" --evidence "$tmp/r5" ) >/dev/null 2>&1; rc=$?
  t "a request renaming the group REFUSES" "[ $rc -ne 0 ]"
  t "...before sending any PATCH" "! grep -q '^PATCH' '$FAKE/calls'"

  # --- evidence-write failure AFTER a fully successful mutation. The earlier
  # version pointed --evidence at an uncreatable path, which failed before the
  # first control-plane call and so never exercised the post-mutation timing.
  _reset
  ( write_evidence() { return 1; }
    GH_API_FN=fake_api patch_group 9 "$tmp/patch.json" "$tmp/exp.json" --evidence "$tmp/ew" ) >/dev/null 2>&1; rc=$?
  t "an evidence-write failure after a successful mutation never yields PASS" "[ $rc -ne 0 ]"
  t "...even though the mutation itself succeeded" \
    "[ \"\$(cat '$FAKE/wf')\" = '$NEW' ] && [ \"\$(tr -d '\\n' < '$FAKE/repos')\" = '[1254295268]' ]"
  _reset
  ( GH_API_FN=fake_api patch_group 9 "$tmp/patch.json" "$tmp/exp.json" --evidence /proc/nonexistent/nope ) >/dev/null 2>&1; rc=$?
  t "an uncreatable evidence directory also refuses" "[ $rc -ne 0 ]"

  echo "self-test: $ok ok, $nbad failed"
  [ "$nbad" -eq 0 ]
}

case "${1-}" in
  --self-test) _rgp_self_test && echo "runner-group-patch.sh: SELF-TEST OK" ;;
  "") echo "usage: runner-group-patch.sh <group-id> <group-patch.json> <expected-state.json> [--evidence <dir>]" >&2; exit 2 ;;
  *) patch_group "$@" ;;
esac
