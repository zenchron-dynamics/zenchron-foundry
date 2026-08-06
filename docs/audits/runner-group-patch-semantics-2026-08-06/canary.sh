#!/usr/bin/env bash
# =============================================================================
# Canary: does a keyless runner-group PATCH preserve or clear repository membership?
#
# GitHub rejects selected_repository_ids on PATCH (422), and the existing helper
# REQUIRES it — so the guardrail and the API are mutually exclusive. The 422
# proves the helper must change; it says nothing about whether OMITTING the field
# preserves membership or silently clears it, which is the behaviour that caused
# the 2026-08-02 incident.
#
# Measured on a throwaway group, never on group 3.
# =============================================================================
set -uo pipefail

ORG=zenchron-dynamics
REPO_ID=1254295268
APIV="2026-03-10"
NONCE="$(od -An -N3 -tx1 /dev/urandom | tr -d ' \n')"
NAME="zenchron-foundry-patch-semantics-20260806-${NONCE}"
EV="${EV:-/tmp/rgcanary}"
mkdir -p "$EV"

api() { gh api -H "X-GitHub-Api-Version: ${APIV}" "$@"; }
stamp() { date -u +%Y-%m-%dT%H:%M:%SZ; }
say() { printf '\n== %s ==\n' "$*"; }

ACTOR="$(gh api user --jq .login)"
echo "actor=$ACTOR  api_version=$APIV  group_name=$NAME"

# --- create ---------------------------------------------------------------
say "create"
CREATED_AT="$(stamp)"
jq -n --arg n "$NAME" --argjson r "[$REPO_ID]" '{
  name:$n, visibility:"selected", selected_repository_ids:$r, runners:[],
  allows_public_repositories:true, restricted_to_workflows:true,
  selected_workflows:["zenchron-dynamics/zenchron-foundry/.github/workflows/build-images.yml@refs/heads/master"]
}' > "$EV/00-create-request.json"

api --method POST "orgs/${ORG}/actions/runner-groups" \
    --input "$EV/00-create-request.json" > "$EV/01-create-response.json" 2>"$EV/01-create-error.txt" || {
  echo "REFUSE: could not create the temporary group"; cat "$EV/01-create-error.txt"; exit 1; }
GID="$(jq -r .id "$EV/01-create-response.json")"
case "$GID" in ''|null|3) echo "REFUSE: refusing to continue with group id '$GID'"; exit 1 ;; esac
echo "temporary group id=$GID"

cleanup() {
  if [ -n "${GID:-}" ] && [ "$GID" != 3 ]; then
    say "delete (cleanup)"
    api --method DELETE "orgs/${ORG}/actions/runner-groups/${GID}" >/dev/null 2>&1 \
      && echo "deleted group $GID" || echo "WARNING: could not delete group $GID — REMOVE IT MANUALLY"
  fi
}
trap cleanup EXIT

snap() { # snap <prefix>
  api "orgs/${ORG}/actions/runner-groups/${GID}" > "$EV/${1}-group.json" 2>/dev/null
  api "orgs/${ORG}/actions/runner-groups/${GID}/repositories" --jq '[.repositories[].id]' > "$EV/${1}-repos.json" 2>/dev/null
  api "orgs/${ORG}/actions/runner-groups/${GID}/runners" --jq '[.runners[].id]' > "$EV/${1}-runners.json" 2>/dev/null
}

# --- precondition ----------------------------------------------------------
say "before"
BEFORE_AT="$(stamp)"; snap 10-before
echo "repos:    $(cat "$EV/10-before-repos.json")"
echo "runners:  $(cat "$EV/10-before-runners.json")"
echo "workflows:$(jq -c '.selected_workflows' "$EV/10-before-group.json")"

[ "$(jq -c . "$EV/10-before-repos.json")" = "[$REPO_ID]" ] || { echo "REFUSE: precondition (1 repo) not met"; exit 1; }
[ "$(jq -c . "$EV/10-before-runners.json")" = "[]" ]       || { echo "REFUSE: precondition (0 runners) not met"; exit 1; }
[ "$(jq '.selected_workflows|length' "$EV/10-before-group.json")" = 1 ] || { echo "REFUSE: precondition (1 workflow) not met"; exit 1; }

# --- the measurement: a REAL keyless workflow mutation ---------------------
say "keyless PATCH (build-images -> stage-and-authorize)"
jq -n --arg n "$NAME" '{
  name:$n, visibility:"selected",
  allows_public_repositories:true, restricted_to_workflows:true,
  selected_workflows:["zenchron-dynamics/zenchron-foundry/.github/workflows/stage-and-authorize.yml@refs/heads/master"]
}' > "$EV/20-patch-request.json"

PATCH_AT="$(stamp)"
api --method PATCH "orgs/${ORG}/actions/runner-groups/${GID}" \
    --input "$EV/20-patch-request.json" > "$EV/21-patch-response.json" 2>"$EV/21-patch-error.txt"
PATCH_RC=$?
echo "patch rc=$PATCH_RC"
[ -s "$EV/21-patch-error.txt" ] && cat "$EV/21-patch-error.txt"

say "after"
AFTER_AT="$(stamp)"; snap 30-after
AFTER_REPOS="$(jq -c . "$EV/30-after-repos.json" 2>/dev/null || echo '"unreadable"')"
AFTER_RUNNERS="$(jq -c . "$EV/30-after-runners.json" 2>/dev/null || echo '"unreadable"')"
AFTER_WF="$(jq -r '.selected_workflows[]?' "$EV/30-after-group.json" | sed 's|.*/workflows/||')"
echo "repos:    $AFTER_REPOS"
echo "runners:  $AFTER_RUNNERS"
echo "workflows:$AFTER_WF"

# --- classify --------------------------------------------------------------
VERDICT=UNEXPECTED
if [ "$AFTER_REPOS" = "[$REPO_ID]" ]; then VERDICT=PRESERVED
elif [ "$AFTER_REPOS" = "[]" ];      then VERDICT=CLEARED
fi
for chk in \
  "runners:$AFTER_RUNNERS:[]" \
  "visibility:$(jq -r .visibility "$EV/30-after-group.json"):selected" \
  "restricted:$(jq -r .restricted_to_workflows "$EV/30-after-group.json"):true" \
  "workflow:$AFTER_WF:stage-and-authorize.yml@refs/heads/master"; do
  k="${chk%%:*}"; rest="${chk#*:}"; got="${rest%:*}"; want="${rest##*:}"
  [ "$got" = "$want" ] || { echo "UNEXPECTED: $k is '$got', expected '$want'"; VERDICT=UNEXPECTED; }
done
say "VERDICT: $VERDICT"

# --- restore membership through the documented endpoint --------------------
say "PUT repositories (documented replace)"
jq -n --argjson r "[$REPO_ID]" '{selected_repository_ids:$r}' > "$EV/40-put-request.json"
api --method PUT "orgs/${ORG}/actions/runner-groups/${GID}/repositories" \
    --input "$EV/40-put-request.json" > "$EV/41-put-response.txt" 2>&1
PUT_RC=$?
echo "put rc=$PUT_RC"

say "final"
snap 50-final
FINAL_REPOS="$(jq -c . "$EV/50-final-repos.json" 2>/dev/null || echo '"unreadable"')"
FINAL_RUNNERS="$(jq -c . "$EV/50-final-runners.json" 2>/dev/null || echo '"unreadable"')"
FINAL_WF="$(jq -r '.selected_workflows[]?' "$EV/50-final-group.json" | sed 's|.*/workflows/||')"
echo "repos:    $FINAL_REPOS"
echo "runners:  $FINAL_RUNNERS"
echo "workflows:$FINAL_WF"

RESTORED=no
[ "$FINAL_REPOS" = "[$REPO_ID]" ] && [ "$FINAL_RUNNERS" = "[]" ] \
  && [ "$(jq -r .visibility "$EV/50-final-group.json")" = selected ] \
  && [ "$(jq -r .restricted_to_workflows "$EV/50-final-group.json")" = true ] \
  && [ "$FINAL_WF" = "stage-and-authorize.yml@refs/heads/master" ] && RESTORED=yes
echo "restored=$RESTORED"

jq -n --arg actor "$ACTOR" --arg apiv "$APIV" --arg name "$NAME" --argjson gid "$GID" \
      --arg created "$CREATED_AT" --arg before "$BEFORE_AT" --arg patched "$PATCH_AT" --arg after "$AFTER_AT" \
      --arg verdict "$VERDICT" --arg restored "$RESTORED" \
      --argjson patch_rc "$PATCH_RC" --argjson put_rc "$PUT_RC" \
      --argjson before_repos "$(cat "$EV/10-before-repos.json")" \
      --argjson after_repos "$(jq -c . "$EV/30-after-repos.json" 2>/dev/null || echo null)" \
      --argjson final_repos "$(jq -c . "$EV/50-final-repos.json" 2>/dev/null || echo null)" \
      --argjson patch_req "$(cat "$EV/20-patch-request.json")" \
      '{schema_version:1, experiment:"runner-group PATCH repository-membership semantics",
        question:"does a PATCH that omits selected_repository_ids preserve or clear repository membership?",
        organization:"zenchron-dynamics", temporary_group:{id:$gid, name:$name},
        api_version:$apiv, actor:$actor,
        timestamps:{created:$created, before:$before, patched:$patched, after:$after},
        patch_request:$patch_req, patch_exit:$patch_rc, repositories_put_exit:$put_rc,
        repositories:{before:$before_repos, after_patch:$after_repos, after_put:$final_repos},
        verdict:$verdict, restored:$restored,
        production_group_3_touched:false, workflows_dispatched:0}' > "$EV/99-result.json"

say "result"
jq . "$EV/99-result.json"
