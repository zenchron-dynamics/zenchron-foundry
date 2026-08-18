#!/usr/bin/env bash
# =============================================================================
# The 20-child acceptance shape, proven without running a single builder.
#
# THE DEFECT THIS LOCKS DOWN. The pinned acceptance basis asked for 10 images on
# 2 platforms in one run. That was unreachable: the stage matrix had no platform
# axis and took the platform straight from `inputs.platforms`, so a two-platform
# dispatch handed every child "linux/amd64,linux/arm64" and every child refused
#
#     REFUSE: one platform per child; got 'linux/amd64,linux/arm64'
#
# while the authorizer expected 10 x 2 = 20 and found none. Ten refusals, zero
# children, zero evidence, and a ~15-hour run's worth of authority spent proving
# a typo. These assertions cost milliseconds and would have caught it.
#
# WHAT IS DELIBERATELY *NOT* ASSERTED HERE: that arm64 is authorized. Platform
# authorization lives in the authorizer, after the children, so an unevidenced
# architecture still records evidence before refusal — that is how #139's arm64
# evidence was acquired. Shape early, authority late.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

W=.github/workflows/stage-and-authorize.yml
B=scripts/release/build-acceptance-matrix.sh

# --- the shared enumerator --------------------------------------------------
ck "the matrix enumerator self-tests clean" "bash $B --self-test >/dev/null 2>&1"

# shellcheck disable=SC2034  # both are consumed inside the eval'd ck assertions
M2="$(bash "$B" 'linux/amd64,linux/arm64' 2>/dev/null)"
# shellcheck disable=SC2034
M1="$(bash "$B" 'linux/amd64' 2>/dev/null)"

ck "two platforms x ten images yields exactly 20 children" \
   '[ "$(printf "%s" "$M2" | jq ".include|length")" = 20 ]'
ck "one platform yields exactly 10 children" \
   '[ "$(printf "%s" "$M1" | jq ".include|length")" = 10 ]'
ck "every child carries exactly one platform, never the raw list" \
   '! printf "%s" "$M2" | jq -e ".include[]|select(.platform|contains(\",\"))" >/dev/null'
ck "every child platform is a linux/<arch> value" \
   'printf "%s" "$M2" | jq -e "all(.include[]; .platform|test(\"^linux/[a-z0-9]+$\"))" >/dev/null'

# --- identity uniqueness, including the STAGING TAG ------------------------
# The tag is what the registry sees; two children colliding there would
# overwrite each other's staged image and the record would describe the wrong
# object. Reconstructed exactly as the workflow builds it.
ck "child labels are unique per platform and repeat across platforms" \
   '[ "$(printf "%s" "$M2" | jq -r "[.include[]|\"\(.fam):\(.ver):\(.platform)\"]|unique|length")" = 20 ] &&
    [ "$(printf "%s" "$M2" | jq -r "[.include[]|\"\(.fam):\(.ver)\"]|unique|length")" = 10 ]'
ck "reconstructed staging tags are unique across all 20 children" \
   'n=$(printf "%s" "$M2" | jq -r ".include[]|\"\(.fam)-\(.ver)-r1-a1-sabc1234-\(.platform|sub(\"^linux/\";\"\"))\"" | sort -u | wc -l | tr -d " ");
    [ "$n" = 20 ]'

# --- the workflow actually consumes it -------------------------------------
wf_check() { python3 - "$1" "${2:-$W}" <<'WFPY'
import sys, yaml, json
what, path = sys.argv[1], sys.argv[2]
w = yaml.safe_load(open(path))
J = w["jobs"]
if what == "matrix-from-guard":
    m = J["stage"]["strategy"]["matrix"]
    assert isinstance(m, str) and "needs.guard.outputs.matrix" in m, m
elif what == "guard-outputs":
    o = J["guard"]["outputs"]
    for k in ("matrix", "expected_children", "platform_count"):
        assert k in o, k
elif what == "timeouts":
    missing = [j for j, v in J.items() if "timeout-minutes" not in v]
    assert not missing, missing
elif what == "max-parallel":
    assert J["stage"]["strategy"]["max-parallel"] == 1
elif what == "no-cancel":
    assert w["concurrency"]["cancel-in-progress"] is False
elif what == "schema-timing":
    d = json.load(open("schemas/post-build-authorization-v1.schema.json"))
    props = d["$defs"]["child"]["properties"]
    for k in ("child_wall_seconds", "runner_name"):
        assert k in props, k
else:
    raise SystemExit("unknown check %s" % what)
WFPY
}

ck "the stage matrix comes from the guard's planned matrix" 'wf_check matrix-from-guard'
ck "no hardcoded image list survives in the stage matrix" \
   '! grep -qE "^\s+- \{ fam:" '"$W"
ck "the guard publishes the matrix and the expected child count" 'wf_check guard-outputs'
ck "the plan step runs the shared enumerator, not its own copy" \
   'grep -q "build-acceptance-matrix.sh" '"$W"

# THE regression that matters: the per-child platform must be the matrix value.
# Written as a function with a heredoc — nesting this depth of quoting inside an
# eval'd string is how the first version of this test broke itself.
child_platform_ok() { # child_platform_ok [workflow-file]
  python3 - "${1:-$W}" <<'PY'
import sys
s = open(sys.argv[1]).read()
# Anchor on the STEP DECLARATION, not the bare phrase: another step's comment
# now explains that the clock used to live in "Staging identity", and matching
# that prose put the window on the wrong step entirely. Third time this class of
# bug has appeared here — a check must never match its own explanation.
i = s.index("- name: Staging identity")
# Slice to the step's own `run:` rather than a fixed byte window — the identity
# step grew when the platform-bound slug was added, and a 1400-char window
# silently stopped covering the env block.
seg = s[i:s.index("run: |", i) + 6]
env = seg
# COMMENTS STRIPPED FIRST. The step's own comment explains that this value used
# to be `inputs.platforms`, so a naive substring search matches the explanation
# and reports the defect as still present — exactly how the first version of
# this assertion failed against a correct workflow.
code = "\n".join(l for l in env.split("\n") if not l.lstrip().startswith("#"))
assert "PLATFORMS: ${{ matrix.platform }}" in code, "child does not take matrix.platform"
assert "inputs.platforms" not in code, "the raw dispatch input reached a child"
PY
}
ck "each child receives matrix.platform, NOT inputs.platforms" 'child_platform_ok'

# --- arithmetic agreement between planner and judge ------------------------
# The planner and the authorizer compute expected_children independently. If
# they ever disagree, a run could PASS over the wrong number of children.
ck "planner and authorizer agree on 20 for two platforms" \
   'a=$(printf "%s" "$M2" | jq ".include|length");
    b=$(bash -c ". scripts/lib/common.sh; echo \$(( \$(matrix_images | wc -l) * 2 ))" | tr -d " ");
    [ "$a" = "$b" ]'
ck "planner and authorizer agree on 10 for one platform" \
   'a=$(printf "%s" "$M1" | jq ".include|length");
    b=$(bash -c ". scripts/lib/common.sh; echo \$(matrix_images | wc -l)" | tr -d " ");
    [ "$a" = "$b" ]'

# --- refusals, each for its stated reason ----------------------------------
why() { bash "$B" "$1" 2>&1 || true; }
ck "an unauthorized-SHAPE platform refuses in the cheap planner" \
   'why "darwin/arm64" | grep -q "not a linux/<arch> platform"'
ck "a duplicated platform refuses and names it" \
   'why "linux/amd64,linux/amd64" | grep -q "requested twice"'
ck "an empty platform list refuses" 'why "" | grep -q "no platforms requested"'

# --- cost controls ----------------------------------------------------------
ck "every job has a timeout so a hung child cannot burn the default 6 hours" 'wf_check timeouts'
ck "max-parallel stays 1 (2 vCPU / 4 GB host; no resource model to justify more)" 'wf_check max-parallel'
ck "children record their own wall time and runner" \
   'grep -q "child_wall_seconds" '"$W"' && grep -q "runner_name" '"$W"
ck "the record schema accepts the timing fields" 'wf_check schema-timing'
ck "acceptance evidence is NOT discarded by concurrency cancellation" 'wf_check no-cancel'

# --- sabotage proofs -------------------------------------------------------
# Each mutates a COPY and requires the corresponding assertion to reject it. A
# green line means the guard detected the sabotage, not that it slipped through.
# The checks are the SAME functions used above, pointed at the mutated file, so
# a sabotage proof cannot drift away from the assertion it is proving.
mutate() { # mutate <sed-expr> -> path to mutated workflow
  local tmp; tmp="$(mktemp -d)"
  mkdir -p "$tmp/.github/workflows"
  sed "$1" "$W" > "$tmp/.github/workflows/stage-and-authorize.yml"
  printf '%s' "$tmp/.github/workflows/stage-and-authorize.yml"
}

M="$(mutate 's|PLATFORMS: ${{ matrix.platform }}|PLATFORMS: ${{ inputs.platforms }}|')"
ck "reverting the child platform to inputs.platforms is REJECTED" \
   '! child_platform_ok "$M" >/dev/null 2>&1'
rm -rf "$(dirname "$(dirname "$(dirname "$M")")")"

M="$(mutate '/^      matrix: ${{ steps.plan.outputs.matrix }}$/d')"
ck "removing the guard's matrix output is REJECTED" \
   '! wf_check guard-outputs "$M" >/dev/null 2>&1'
rm -rf "$(dirname "$(dirname "$(dirname "$M")")")"

M="$(mutate 's|^    timeout-minutes: 150$|    # removed|')"
ck "dropping a job timeout is REJECTED" \
   '! wf_check timeouts "$M" >/dev/null 2>&1'
rm -rf "$(dirname "$(dirname "$(dirname "$M")")")"

M="$(mutate 's|^  max-parallel: 1$|  max-parallel: 4|; s|      max-parallel: 1|      max-parallel: 4|')"
ck "raising max-parallel without a resource model is REJECTED" \
   '! wf_check max-parallel "$M" >/dev/null 2>&1'
rm -rf "$(dirname "$(dirname "$(dirname "$M")")")"

M="$(mutate 's|  cancel-in-progress: false|  cancel-in-progress: true|')"
ck "enabling concurrency cancellation on acceptance is REJECTED" \
   '! wf_check no-cancel "$M" >/dev/null 2>&1'
rm -rf "$(dirname "$(dirname "$(dirname "$M")")")"

echo "----"
[ "$fail" -eq 0 ] && echo "test_multiarch_acceptance_shape: PASS" \
                  || echo "test_multiarch_acceptance_shape: FAIL"
exit $fail
