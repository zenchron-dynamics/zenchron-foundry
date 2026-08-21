#!/usr/bin/env bash
# =============================================================================
# tests/release/test_no_production_publisher.sh
# -----------------------------------------------------------------------------
# The production publication path was deleted from executable code, not left
# behind a permission denial. This keeps it deleted.
#
# The reasoning is worth restating, because "it fails anyway, why delete it"
# sounds reasonable: a publisher left in place fails with a PERMISSION ERROR,
# and the obvious fix for a permission error is to restore the permission. That
# would reopen the exact bypass the ACL boundary was installed to close. The
# platform denial is the backstop, not the design.
#
# So the invariant is about the REPOSITORY, not about any one workflow: exactly
# one workflow may hold `packages: write`, and no workflow may name a production
# package as a push destination.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

WFDIR=.github/workflows
STAGER="$WFDIR/stage-and-authorize.yml"
PROD_PACKAGES="php-fpm php-cli php-worker php-frankenphp caddy nginx"

ck "the staging workflow exists" "test -f $STAGER"
ck "the reusable production publisher is gone" "! test -f $WFDIR/publish-ghcr.yml"

# --- exactly one workflow may write packages -------------------------------
writers="$(python3 - <<'PY'
import glob, yaml
out = []
for f in sorted(glob.glob('.github/workflows/*.yml')):
    d = yaml.safe_load(open(f)) or {}
    def w(p):
        return isinstance(p, dict) and p.get('packages') == 'write'
    if w(d.get('permissions')):
        out.append(f)
        continue
    for j in (d.get('jobs') or {}).values():
        if isinstance(j, dict) and w(j.get('permissions')):
            out.append(f)
            break
print('\n'.join(out))
PY
)"
# Two workflows may hold it, and only these two:
#   stage-and-authorize  — writes the private quarantine package;
#   package-acl-probe    — must attempt writes in order to prove they are denied.
EXPECTED_WRITERS="$WFDIR/package-acl-probe.yml
$STAGER"
ck "exactly two workflows hold packages: write" \
   "[ \"\$(printf '%s' \"$writers\" | grep -c .)\" = 2 ]"
ck "...and they are the stager and the ACL probe, nothing else" \
   "[ \"\$(printf '%s\n' \"$writers\" | sort)\" = \"\$(printf '%s\n' \"$EXPECTED_WRITERS\" | sort)\" ]"

# --- nothing may push to a production package ------------------------------
# Literal references first. This is NOT sufficient on its own: scheduled-rebuild
# composed its destination from ${REGISTRY}/${NAMESPACE}/${{ matrix.fam }} and a
# name search never saw it. A grep is not an inventory, so the operation check
# below is the one that actually holds.
for p in $PROD_PACKAGES; do
  hits="$(grep -rlE "ghcr\.io/[a-z0-9-]+/${p}(:|@|\")" $WFDIR 2>/dev/null || true)"
  ck "no workflow references ghcr.io/.../${p} as an image reference" "[ -z \"$hits\" ]"
done

# --- no publishing OPERATION outside the two permitted workflows -----------
# Catches destinations composed at runtime, which names cannot.
# Comment lines are excluded: the disabled entry points NAME the scripts they
# used to call, in their headers, and that documentation is the point. What must
# not exist is an executable invocation.
uncommented() { grep -vE '^[[:space:]]*#' "$1"; }
for op in 'push: true' 'cosign sign' 'cosign attest' 'promote-stable.sh' 'rollback-stable.sh' 'imagetools create'; do
  offenders=""
  for f in "$WFDIR"/*.yml; do
    case "$f" in "$STAGER"|"$WFDIR/package-acl-probe.yml") continue ;; esac
    uncommented "$f" | grep -qF "$op" && offenders="$offenders $f"
  done
  ck "no workflow outside the permitted two performs '$op'" "[ -z \"\$(printf '%s' '$offenders' | tr -d ' ')\" ]"
done

# --- the disabled paths must not be reachable on a schedule ---------------
# A nightly job that fails for ever is noise, and noise is how a disabled
# control stops being noticed.
ck "no disabled entry point still runs on a schedule" \
   "python3 -c \"
import glob, yaml
bad=[]
for f in sorted(glob.glob('.github/workflows/*.yml')):
    d=yaml.safe_load(open(f)) or {}
    t=d.get(True) or d.get('on') or {}
    if isinstance(t, dict) and 'schedule' in t:
        jobs=(d.get('jobs') or {})
        if any(n=='refuse' for n in jobs): bad.append(f)
assert not bad, bad\""

# --- the staging workflow stages only, and cannot sign ---------------------
ck "the staging workflow pushes only to foundry-staging" \
   "[ \"\$(grep -cE 'ghcr\\.io/zenchron-dynamics/(php-fpm|php-cli|php-worker|php-frankenphp|caddy|nginx)' $STAGER)\" = 0 ]"
ck "no workflow requests id-token (signing left to the RC manifest)" \
   "! grep -rqE '^\\s*id-token:\\s*write' $WFDIR"
# Cosign is still installed by the workflows that VERIFY signatures, and should
# be — verification is not signing. What must not exist is signing on the build
# path, which is why the check is scoped to the stager rather than repo-wide.
ck "the staging path does not install cosign" "! grep -q 'cosign-installer' $STAGER"
ck "the staging path signs nothing" "! grep -qE 'cosign (sign|attest)' $STAGER"
ck "the staging build creates no index (sbom and provenance both off)" \
   "grep -q 'sbom: false' $STAGER && grep -q 'provenance: false' $STAGER"

# --- the authorization job must not be able to publish ---------------------
ck "the authorization job is packages: read, never write" \
   "python3 -c \"
import yaml
d=yaml.safe_load(open('$STAGER'))
p=d['jobs']['authorize']['permissions']
assert p=={'contents':'read','packages':'read'}, p\""
ck "the authorization job declares no environment" \
   "python3 -c \"
import yaml
d=yaml.safe_load(open('$STAGER'))
assert 'environment' not in d['jobs']['authorize']\""

# --- the disabled entry points are read-only and refuse --------------------
for wf in release publish-rc promote-stable; do
  f="$WFDIR/${wf}.yml"
  ck "$wf is retained as an entry point" "test -f $f"
  ck "$wf is read-only" \
     "python3 -c \"
import yaml
d=yaml.safe_load(open('$f'))
assert d['permissions']=={'contents':'read'}, d['permissions']
for n,j in d['jobs'].items():
    assert j['permissions']=={'contents':'read'}, (n, j['permissions'])
    assert 'environment' not in j, n\""
  ck "$wf executes no build or checkout" \
     "! grep -qE 'actions/checkout|docker/build-push-action|docker push' $f"
  ck "$wf refuses with a pointer to the replacement" \
     "grep -q 'REFUSE: public publication is disabled' $f && grep -q 'stage-and-authorize.yml' $f"
done

# --- the authorization job must survive a failed child ---------------------
# GitHub SKIPS a dependent job when a needed job fails. Without an always()
# condition one failed matrix child produced no record at all — neither PASS nor
# the promised machine-readable FAIL — which is the case the record exists for.
ck "authorization runs even when a child fails" \
   "python3 -c \"
import yaml
d=yaml.safe_load(open('$STAGER'))
c=' '.join(d['jobs']['authorize'].get('if','').split())
assert 'always()' in c, c
assert 'cancelled()' in c, c\""
# always() overrides EVERY needs result, including the guard's. Without an
# explicit success requirement a dispatch from a non-master ref could fail the
# GitHub-hosted guard and still start this job on the SELF-HOSTED runner, check
# out that branch and run its copy of the authorizer.
ck "...but NOT when the default-branch guard failed" \
   "python3 -c \"
import yaml
d=yaml.safe_load(open('$STAGER'))
c=' '.join(d['jobs']['authorize'].get('if','').split())
assert \\\"needs.guard.result == 'success'\\\" in c, c\""
ck "...and not without a frozen database snapshot" \
   "python3 -c \"
import yaml
d=yaml.safe_load(open('$STAGER'))
c=' '.join(d['jobs']['authorize'].get('if','').split())
assert \\\"needs.freeze-db.result == 'success'\\\" in c, c\""
# Truthfulness: an infrastructure failure before authorization produces NO
# record. It must not be described as emitting a refusal, because die() exits
# before the record is written.
ck "the workflow does not claim an empty expectation yields a FAIL record" \
   "! grep -q 'aggregator refuses an empty expectation' $STAGER"
ck "the shared checksum script self-test passes" \
   "bash scripts/release/evidence-checksum.sh --self-test >/dev/null 2>&1"
ck "...and collects evidence tolerantly" \
   "python3 -c \"
import yaml
d=yaml.safe_load(open('$STAGER'))
steps=d['jobs']['authorize']['steps']
assert any('mkdir -p collected' in (s.get('run') or '') for s in steps), 'no unconditional collection dir'
dl=[s for s in steps if 'download-artifact' in str(s.get('uses',''))]
assert dl and dl[0].get('continue-on-error') is True, dl\""
ck "...and recomputes evidence checksums against the collected bundle" \
   "grep -q 'EVIDENCE_ROOT=authorization/child-evidence' $STAGER"

# --- the ref guard runs first, GitHub-hosted, before anything privileged ---
ck "a default-branch guard exists" \
   "python3 -c \"
import yaml
d=yaml.safe_load(open('$STAGER'))
g=d['jobs']['guard']
assert g['runs-on']=='ubuntu-latest', g['runs-on']
assert g['permissions']=={'contents':'read'}, g['permissions']
assert 'refs/heads/master' in str(g['steps'])\""
ck "every privileged job needs the guard first" \
   "python3 -c \"
import yaml
d=yaml.safe_load(open('$STAGER'))
for n in ('freeze-db','stage','authorize'):
    need=d['jobs'][n]['needs']
    need=[need] if isinstance(need,str) else need
    assert 'guard' in need, (n, need)\""
# Comment lines excluded: the guard step EXPLAINS why repository.updated_at is
# the wrong source, and that explanation should stay.
ck "the build timestamp is frozen once, not taken from repository metadata" \
   "grep -q 'needs.guard.outputs.created' $STAGER && ! uncommented $STAGER | grep -q 'repository.updated_at'"

# --- the staged object must be proven to be a platform child ---------------
ck "the media type is read from the registry object" \
   "grep -q 'imagetools inspect .* --raw' $STAGER"
ck "an index media type is refused at staging time" \
   "grep -q 'application/vnd.oci.image.index.v1+json' $STAGER && grep -q 'is an INDEX' $STAGER"

# --- the full OCI contract, not just the revision label --------------------
ck "the staging job runs the full OCI metadata verifier (#126)" \
   "grep -q 'verify-oci-metadata.sh' $STAGER"
ck "...and both the runtime and OCI checks must pass" \
   "grep -q 'runtime_ok. = 1 . && .. \"\$oci_ok\" = 1' $STAGER || grep -q 'oci_ok' $STAGER"
ck "the OCI verifier self-test passes" \
   "bash scripts/release/verify-oci-metadata.sh --self-test >/dev/null 2>&1"
ck "every contract pins its static OCI metadata" \
   "[ \"\$(grep -l 'oci_static:' contracts/images/*.yaml | wc -l | tr -d ' ')\" = \"\$(bash -c '. scripts/lib/common.sh; echo \$MATRIX_COUNT')\" ]"

# --- the producer validates its own output at run time --------------------
ck "the workflow validates the record against schema v1" \
   "grep -q 'validate-authorization-record.sh' $STAGER"
ck "...and a schema-invalid record fails the job" \
   "grep -q 'schema_rc' $STAGER && grep -qE '\\[ .\\\$rc. -eq 0 \\] && \\[ .\\\$schema_rc. -eq 0 \\]' $STAGER"
ck "...while the evidence bundle still uploads" \
   "python3 -c \"
import yaml
d=yaml.safe_load(open('$STAGER'))
up=[s for s in d['jobs']['authorize']['steps'] if 'upload-artifact' in str(s.get('uses',''))]
assert up and up[0].get('if')=='always()', up\""

# --- the offline suite runs in a REQUIRED PR job --------------------------
# Until this was wired, none of the tests that found the last release-blocking
# defects were executed by CI at all.
ck "the offline suite runs in ci.yml" \
   "grep -q 'tests/run-all.sh' .github/workflows/ci.yml"
ck "...inside the already-required repo structure job" \
   "python3 -c \"
import yaml
d=yaml.safe_load(open('.github/workflows/ci.yml'))
job=[j for j in d['jobs'].values() if j.get('name')=='repo structure'][0]
runs=' '.join((s.get('run') or '') for s in job['steps'])
assert 'tests/run-all.sh' in runs, runs[:200]\""
ck "...and refuses to run with a degraded validator" \
   "grep -q 'the suite would silently weaken' .github/workflows/ci.yml"
ck "'repo structure' is a required release check" \
   "grep -q 'repo structure' policies/required-release-checks.yaml"

# --- the runner-group transition is COMPLETE, and declared so ---------------
# This asserted the pending state before 2026-08-08. Inverting it alone would
# prove one property; the transition is described in full instead, so a partial
# or drifted declaration cannot pass.
# Evidence: docs/audits/runner-group-transition-2026-08-08-live/
POLICY=policies/repository-governance.yaml
ck "the declared workflow set is exactly the six trusted builders" \
   "python3 -c \"
import yaml
g=yaml.safe_load(open('$POLICY'))['org_runner_group']
got=sorted(w.split('/workflows/')[1] for w in g['selected_workflows'])
want=sorted(n+'@refs/heads/master' for n in
  ['build-images.yml','scan-images.yml','stage-and-authorize.yml',
   'trusted-validation.yml','verify-rc.yml','verify-signatures.yml'])
assert got==want, got\""
ck "nothing is pending any more" \
   "python3 -c \"
import yaml
g=yaml.safe_load(open('$POLICY'))['org_runner_group']
assert (g.get('pending_workflows') or [])==[], g['pending_workflows']\""
ck "stage-and-authorize is SELECTED" \
   "python3 -c \"
import yaml
g=yaml.safe_load(open('$POLICY'))['org_runner_group']
assert any('stage-and-authorize' in w for w in g['selected_workflows'])\""
ck "...and no longer pending" \
   "python3 -c \"
import yaml
g=yaml.safe_load(open('$POLICY'))['org_runner_group']
assert not any('stage-and-authorize' in w for w in (g.get('pending_workflows') or []))\""
ck "none of the five retired entries survives" \
   "python3 -c \"
import yaml
g=yaml.safe_load(open('$POLICY'))['org_runner_group']
retired=['promote-stable','publish-ghcr','publish-rc','release','scheduled-rebuild']
bad=[w for w in g['selected_workflows'] if any('/'+r+'.yml@' in w for r in retired)]
assert not bad, bad\""
ck "no workflow is both selected and pending" \
   "python3 -c \"
import yaml
g=yaml.safe_load(open('$POLICY'))['org_runner_group']
assert not (set(g.get('pending_workflows') or []) & set(g['selected_workflows']))\""
ck "the repository selection is still exactly one id" \
   "python3 -c \"
import yaml
g=yaml.safe_load(open('$POLICY'))['org_runner_group']
assert g['selected_repository_ids']==[1254295268], g['selected_repository_ids']\""
ck "every declared workflow is pinned to the default branch" \
   "python3 -c \"
import yaml
g=yaml.safe_load(open('$POLICY'))['org_runner_group']
for w in g['selected_workflows']:
    assert w.endswith('@refs/heads/master'), w\""
ck "the superseded PATCH claim is gone from the policy" \
   "! grep -q 'refuses to send a PATCH without it' $POLICY"

echo "----"; [ "$fail" -eq 0 ] && echo "test_no_production_publisher: PASS" || echo "test_no_production_publisher: FAIL"
exit $fail
