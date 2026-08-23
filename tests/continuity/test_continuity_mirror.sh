#!/usr/bin/env bash
# =============================================================================
# tests/continuity/test_continuity_mirror.sh — mirror manifest, consistency
# verifier and the offline disaster drill (#116).
#
# Three defects this locks down, all of which were live before this test:
#
#   1. policies/continuity.yaml named `restore.verification:
#      scripts/continuity-verify.sh` and THAT FILE DID NOT EXIST. Nothing
#      checked. A policy pointing at an absent verifier reads as though
#      restoration is verified.
#   2. `continuity-export.sh --export` exited 0 having written only digests.txt
#      when every OCI-layout write failed — a "successful" export nothing can be
#      restored from, against a policy promising `format: OCI layout`.
#   3. There was no mirror manifest and no consistency verifier at all, so
#      "digest equality" was only ever asserted inside a docker-and-network
#      exercise that CI never runs.
#
# The drill here is EXECUTED, offline, every run. It is not a transcript.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

TMP="$(mktemp -d)"
# shellcheck disable=SC2064
trap "rm -rf '$TMP'" EXIT

# Fingerprint the checkout up front. A `git status` check would report a dirty
# working tree the test did not cause; comparing before/after hashes measures
# only what this test did. One test in this repository has already destroyed a
# policy file it was asserting about.
fingerprint() { find policies scripts -type f -exec shasum -a 256 {} + | sort | shasum -a 256; }
PRE_FINGERPRINT="$(fingerprint)"

VERIFY=scripts/continuity-verify.sh
EXPORT=scripts/continuity-export.sh
POLICY=policies/continuity.yaml
MIRROR=policies/continuity-mirror.yaml

ck "continuity-verify self-test passes" "bash $VERIFY --self-test >/dev/null"
ck "continuity-export self-test passes" "bash $EXPORT --self-test >/dev/null"

# --- defect 1: the policy must not point at a verifier that does not exist ---
ck "the verifier named by policies/continuity.yaml EXISTS" \
   "python3 -c \"
import yaml, os, sys
p = yaml.safe_load(open('$POLICY'))['restore']['verification']
sys.exit(0 if os.path.isfile(p) else 1)\""
ck "...and it is executable as named, not merely present" \
   "python3 -c \"
import yaml;print(yaml.safe_load(open('$POLICY'))['restore']['verification'])\" >'$TMP/v' &&
    bash \"\$(cat '$TMP/v')\" --self-test >/dev/null"

# --- the drill actually runs, here, offline ---------------------------------
ck "the offline OCI-layout disaster drill EXECUTES and passes" \
   "bash $VERIFY --drill '$TMP/drill' >'$TMP/drill.log' 2>&1"
ck "...and it ran the sabotage cases, not just the happy path" \
   "grep -q 'WRONG BYTES is refused' '$TMP/drill.log' && grep -q 'missing a referenced blob is refused' '$TMP/drill.log'"
ck "...and it states it is not a mirror" \
   "grep -q 'No independent mirror is provisioned' '$TMP/drill.log'"
ck "...and it needed neither docker nor the network" \
   "! grep -qE '(^|[^a-z])docker ' $VERIFY"

# --- the verifier's real discriminating power -------------------------------
# Right digest name over wrong bytes is the failure a digest list cannot catch.
mkdir -p "$TMP/w"
ck "a faithful copy verifies" \
   "bash $VERIFY --drill '$TMP/w' >/dev/null 2>&1"
ck "non-vacuity: the verifier both passes and fails within one drill run" \
   "grep -q 'ok   - every source digest is present in the mirror' '$TMP/drill.log' &&
    grep -q 'ok   - a mirror with the right digest over WRONG BYTES is refused' '$TMP/drill.log'"

# --- defect 2: an export with no layout must REFUSE -------------------------
# Behavioural, not a grep: stub docker so that digest resolution succeeds and
# every OCI-layout write fails, which is exactly the case that used to exit 0.
mkdir -p "$TMP/bin"
cat >"$TMP/bin/docker" <<'STUB'
#!/usr/bin/env bash
for a in "$@"; do
  case "$a" in
    inspect) echo "sha256:1111111111111111111111111111111111111111111111111111111111111111"; exit 0 ;;
    create)  exit 1 ;;
  esac
done
exit 0
STUB
chmod +x "$TMP/bin/docker"

ck "an export that produced NO OCI layout is REFUSED, not reported as exported" \
   "! PATH='$TMP/bin:$PATH' bash $EXPORT --export '$TMP/exp' >'$TMP/exp.log' 2>&1"
ck "...and says a digest list is not a backup" \
   "grep -q 'inventory, not a backup' '$TMP/exp.log'"
ck "...while an inventory-only export must be asked for EXPLICITLY" \
   "PATH='$TMP/bin:$PATH' bash $EXPORT --export --digests-only '$TMP/exp2' >/dev/null 2>&1"
ck "...and the inventory-only run still wrote the digest list" \
   "test -s '$TMP/exp2/digests.txt'"

# --- defect 3: the mirror manifest ------------------------------------------
ck "the mirror manifest is valid YAML" "python3 -c \"import yaml;yaml.safe_load(open('$MIRROR'))\""
ck "it declares NO mirror, in every field that could imply one" \
   "python3 -c \"
import yaml;m=yaml.safe_load(open('$MIRROR'))['mirror']
assert m['status']=='not-provisioned',m['status']
assert m['independent'] is False,m
assert m['provider'] is None and m['endpoint'] is None and m['credential_source'] is None,m\""
ck "it is registry-NEUTRAL: no vendor endpoint is hardcoded" \
   "! grep -qiE '(ghcr\.io/|docker\.io|quay\.io|amazonaws|azurecr|gcr\.io)' $MIRROR"
ck "independence is defined as separate failure domains, not a second package" \
   "python3 -c \"
import yaml;r=yaml.safe_load(open('$MIRROR'))['mirror']['independence_requirements']
ids={x['id'] for x in r}
assert {'separate-provider','separate-account','external-credentials','immutable-retention'} <= ids, ids
assert all(x.get('why') for x in r), r\""

# --- the critical-release inventory -----------------------------------------
ck "every artifact class says whether it is mirrored" \
   "python3 -c \"
import yaml;a=yaml.safe_load(open('$MIRROR'))['critical_release_inventory']['artifact_classes']
assert a, 'empty inventory'
bad=[x['id'] for x in a if 'mirrored' not in x or 'required' not in x]
assert not bad,bad\""
ck "nothing claims to be mirrored while no mirror exists" \
   "python3 -c \"
import yaml;a=yaml.safe_load(open('$MIRROR'))['critical_release_inventory']['artifact_classes']
claimed=[x['id'] for x in a if x['mirrored']]
assert not claimed, claimed\""
ck "classes that cannot be mirrored yet name the issue blocking them" \
   "python3 -c \"
import yaml;a=yaml.safe_load(open('$MIRROR'))['critical_release_inventory']['artifact_classes']
byid={x['id']:x for x in a}
assert byid['cosign-signatures']['blocked_by']==139,byid['cosign-signatures']
assert byid['vex']['blocked_by']==115,byid['vex']\""
ck "the inventory is DERIVED from the matrix, not a hand-copied digest list" \
   "python3 -c \"
import yaml;c=yaml.safe_load(open('$MIRROR'))['critical_release_inventory']
assert 'contracts/images' in c['source_of_truth'],c\""

# --- no drift between the two continuity policies ---------------------------
# A recovery objective declared twice drifts, and the stale copy is the one
# somebody follows during an outage.
ck "RTO/RPO are declared ONCE, in continuity.yaml only" \
   "python3 -c \"
import yaml
m=yaml.safe_load(open('$MIRROR'))
c=yaml.safe_load(open('$POLICY'))
assert 'rto_hours' in c['objectives'] and 'rpo_releases' in c['objectives'], c['objectives']
assert 'objectives' not in m, 'mirror manifest must not restate RTO/RPO'
flat=yaml.safe_dump(m)
assert 'rto_hours' not in flat and 'rpo_releases' not in flat, 'RTO/RPO duplicated'\""
ck "the verification contract requires CONTENT rehashing, not name matching" \
   "python3 -c \"
import yaml;v=yaml.safe_load(open('$MIRROR'))['verification']
assert v['content_rehashed'] is True,v
assert any('rehash' in s for s in v['must_prove']),v['must_prove']\""
ck "the drill is declared offline and non-evidential" \
   "python3 -c \"
import yaml;v=yaml.safe_load(open('$MIRROR'))['verification']
assert v['drill_is_offline'] is True,v
assert 'never evidence' in v['drill_note'],v['drill_note']\""
ck "the human decisions that actually close #116 are recorded with an owner" \
   "python3 -c \"
import yaml;h=yaml.safe_load(open('$MIRROR'))['required_human_decisions']
assert {'choose-mirror-provider','mirror-credentials','enable-immutable-retention'} <= {x['id'] for x in h}
assert all(x['who'] and x['blocks']==116 for x in h),h\""

# --- the checkout must be untouched -----------------------------------------
ck "the test mutated nothing under policies/ or scripts/" \
   "[ \"\$(fingerprint)\" = '$PRE_FINGERPRINT' ]"

echo "----"
[ "$fail" -eq 0 ] && echo "test_continuity_mirror: PASS" || echo "test_continuity_mirror: FAIL"
exit "$fail"
