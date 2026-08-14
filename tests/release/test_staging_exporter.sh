#!/usr/bin/env bash
# =============================================================================
# The staging exporter must never enable rewrite-timestamp without pushing.
#
# `outputs:` REPLACES docker/build-push-action's `push: true` shorthand rather
# than adding to it. So this is a real and silent failure mode:
#
#     outputs: type=image,rewrite-timestamp=true        <-- never pushes
#     outputs: type=docker,rewrite-timestamp=true       <-- never pushes
#
# Either one leaves the job green while nothing reaches the registry. The
# digest-resolution step would then fail, or worse, resolve a stale tag from a
# previous run and evaluate the wrong image.
#
# The inverse is equally wrong and is checked too: a leftover `push: true`
# ALONGSIDE `outputs:` is a contradiction, because the shorthand no longer
# applies and reading it implies a push that the exporter is really performing.
#
# This is a static check on purpose. The behavioural proof —
# scripts/verify-staging-export.sh — needs a registry and two full builds, so it
# cannot run in the offline suite. This one runs on every PR.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

# NOT "every build must push". build-images.yml deliberately builds
# `type=docker,rewrite-timestamp=true` as a local validation tag and pushes
# nothing — rewrite-timestamp is exactly right there. The first version of this
# check flagged it, which was the check being wrong, not the workflow.
#
# The rules that actually hold everywhere:
#   * `push: true` alongside `outputs:` is contradictory — the shorthand is
#     REPLACED, so reading it implies a push it is not performing.
#   * an exporter that pushes must be type=image; type=docker/type=oci cannot
#     push, so `push=true` on them is a build that silently goes nowhere.
# The strict "must push" requirement is asserted separately, against the one
# workflow whose entire purpose is to stage.
exporter_defects() {
  python3 - "$1" <<'PY'
import glob, os, sys, yaml

root = sys.argv[1]
for f in sorted(glob.glob(os.path.join(root, ".github/workflows/*.yml"))):
    try:
        doc = yaml.safe_load(open(f))
    except Exception as e:
        print("%s: unparseable (%s)" % (os.path.basename(f), e))
        continue
    for jid, job in ((doc or {}).get("jobs") or {}).items():
        for i, s in enumerate(job.get("steps") or []):
            if "build-push-action" not in str(s.get("uses", "")):
                continue
            w = s.get("with") or {}
            outputs = str(w.get("outputs") or "").replace(" ", "")
            name = s.get("name") or i
            if not outputs:
                continue                      # shorthand-only step: not our case
            if str(w.get("push", "")).lower() == "true":
                print("%s job=%s step=%r: `push: true` alongside `outputs:` — the "
                      "shorthand is REPLACED, so this is contradictory"
                      % (os.path.basename(f), jid, name))
            if "push=true" in outputs and "type=image" not in outputs:
                print("%s job=%s step=%r: exporter claims push=true but is not "
                      "type=image (outputs=%s)" % (os.path.basename(f), jid, name, outputs))
PY
}

out="$(exporter_defects "$ROOT")"
[ -n "$out" ] && printf '%s\n' "$out" | sed 's/^/     /'
ck "no workflow contradicts itself about pushing" '[ -z "$out" ]'

# THE rule the exporter change exists to protect: the one workflow that stages
# must actually push, with deterministic timestamps, as a single-platform image.
# This is what fails CI if someone edits `outputs:` and drops push semantics.
ck "the staging exporter pushes AND rewrites timestamps" \
   'python3 -c "
import yaml
d=yaml.safe_load(open(\".github/workflows/stage-and-authorize.yml\"))
s=[x for j in d[\"jobs\"].values() for x in (j.get(\"steps\") or [])
   if \"build-push-action\" in str(x.get(\"uses\",\"\"))]
assert len(s)==1, len(s)
o=(s[0][\"with\"].get(\"outputs\") or \"\").replace(\" \",\"\")
missing=[k for k in (\"type=image\",\"push=true\",\"rewrite-timestamp=true\") if k not in o]
assert not missing, (missing, o)"'

ck "the staging build uses the deterministic exporter" \
   'python3 -c "
import yaml
d=yaml.safe_load(open(\".github/workflows/stage-and-authorize.yml\"))
s=[x for j in d[\"jobs\"].values() for x in (j.get(\"steps\") or [])
   if \"build-push-action\" in str(x.get(\"uses\",\"\"))]
assert len(s)==1, len(s)
w=s[0][\"with\"]
o=w[\"outputs\"].replace(\" \",\"\")
assert \"type=image\" in o, o
assert \"push=true\" in o, o
assert \"rewrite-timestamp=true\" in o, o
assert \"push\" not in w, \"push: shorthand must be gone; outputs replaces it\"
assert w[\"sbom\"] is False and w[\"provenance\"] is False"'

ck "the behavioural proof script exists and self-tests" \
   'bash scripts/verify-staging-export.sh --self-test >/dev/null 2>&1'

# --- non-vacuity ------------------------------------------------------------
# The detector must actually fire on each bad shape, or it is decoration.
probe() {
  local tmpd; tmpd="$(mktemp -d)"
  mkdir -p "$tmpd/.github/workflows"
  cat > "$tmpd/.github/workflows/probe.yml" <<YAML
name: probe
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: docker/build-push-action@0000000000000000000000000000000000000000
        with:
          outputs: $1
YAML
  exporter_defects "$tmpd"
  rm -rf "$tmpd"
}

ck "it flags an exporter that claims push=true but cannot push" \
   'printf "%s" "$(probe "type=docker,push=true,rewrite-timestamp=true")" | grep -q "not.*type=image"'
ck "it accepts the shipped form" \
   '[ -z "$(probe "type=image,push=true,rewrite-timestamp=true")" ]'
ck "it accepts a deliberate local-only build (build-images.yml's shape)" \
   '[ -z "$(probe "type=docker,rewrite-timestamp=true")" ]'

# The staging-specific rule must fire when push semantics are dropped — the
# exact edit this test exists to stop. Simulated against a copy so the real
# workflow is never mutated.
# Returns 0 when the rule CORRECTLY rejects the sabotaged workflow, so a green
# line here means the detector fired — not that the sabotage went unnoticed.
staging_probe() {
  local tmpd detected=1; tmpd="$(mktemp -d)"
  mkdir -p "$tmpd/.github/workflows"
  sed 's|outputs: type=image,push=true,rewrite-timestamp=true|outputs: type=image,rewrite-timestamp=true|' \
    .github/workflows/stage-and-authorize.yml > "$tmpd/.github/workflows/stage-and-authorize.yml"
  if ( cd "$tmpd" && python3 -c "
import yaml
d=yaml.safe_load(open('.github/workflows/stage-and-authorize.yml'))
s=[x for j in d['jobs'].values() for x in (j.get('steps') or [])
   if 'build-push-action' in str(x.get('uses',''))]
o=(s[0]['with'].get('outputs') or '').replace(' ','')
missing=[k for k in ('type=image','push=true','rewrite-timestamp=true') if k not in o]
assert not missing, missing" 2>/dev/null ); then
    detected=1     # the rule PASSED on a sabotaged file: it is not working
  else
    detected=0     # the rule refused it, which is the point
  fi
  rm -rf "$tmpd"
  return $detected
}
ck "dropping push=true from the staging exporter FAILS the check" 'staging_probe'

echo "----"
[ "$fail" -eq 0 ] && echo "test_staging_exporter: PASS" || echo "test_staging_exporter: FAIL"
exit $fail
