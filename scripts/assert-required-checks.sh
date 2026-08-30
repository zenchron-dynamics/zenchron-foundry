#!/usr/bin/env bash
# =============================================================================
# scripts/assert-required-checks.sh
# -----------------------------------------------------------------------------
# Every name in policies/required-release-checks.yaml must be a check name a
# workflow can actually produce, and every gating CI job must be required.
#
# Why this exists: the exact-commit gate (scripts/check-exact-commit-ci.sh)
# matches check names EXACTLY, and its self-test builds its fixture *from the
# policy*, so a policy naming drift is invisible to it — it passes offline while
# rejecting every real commit with "missing: <name>". That is exactly what
# happened: all 18 required names were unproducible, so no release could ever be
# sealed. This check compares the policy against the workflow job names
# (matrices expanded) so the drift fails in CI instead of at the release gate.
#
# GitHub names a matrix job "<job name> (<matrix values>)" only when the job has
# no explicit `name:`. Both matrix jobs here DO set `name:` with matrix
# interpolation, so the rendered name is that template with values substituted.
# =============================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
# shellcheck source=lib/common.sh
. "$ROOT/scripts/lib/common.sh"

# Non-gating jobs: real check names that must NOT be required on a release commit.
# `scan` is required (it is the vulnerability gate); nothing else is exempt here.
# WORKFLOWS (space-separated paths) is injectable for the self-test only.
# Commit statuses a workflow publishes via POST /repos/{repo}/statuses/{sha}.
# These are as real as check runs to every consumer — scripts/check-exact-commit-ci.sh
# merges both — but they carry a `context`, not a job name.
published_statuses() {
  WORKFLOWS="${WORKFLOWS:-.github/workflows/ci.yml .github/workflows/scan-images.yml .github/workflows/trusted-validation.yml}" \
  python3 - <<'PY'
import os, re, sys, yaml

out = []
for path in os.environ["WORKFLOWS"].split():
    try:
        doc = yaml.safe_load(open(path)) or {}
    except Exception:
        continue
    for job in (doc.get("jobs") or {}).values():
        for step in (job.get("steps") or []):
            run = step.get("run") or ""
            if "/statuses/" not in run:
                continue
            # Contexts posted as literal `post "<name>" ...` or -f context=<name>
            out += re.findall(r'^\s*post\s+"([^"]+)"', run, re.M)
            out += re.findall(r'-f\s+context="?([^"\s]+)"?', run)
for name in sorted(set(out)):
    # Skip the shell variable form; only literal contexts are verifiable here.
    if name.startswith("$"):
        continue
    print(name)
PY
}

producible_names() {
  WORKFLOWS="${WORKFLOWS:-.github/workflows/ci.yml .github/workflows/scan-images.yml .github/workflows/trusted-validation.yml}" \
  python3 - <<'PY'
import os, re, yaml

def render(tmpl, ctx):
    def sub(m):
        expr = m.group(1).strip()
        cur = ctx
        for part in expr.split("."):
            if not isinstance(cur, dict) or part not in cur:
                return m.group(0)
            cur = cur[part]
        return str(cur)
    return re.sub(r"\$\{\{\s*(.*?)\s*\}\}", sub, tmpl)

def expand(matrix):
    """GitHub matrix -> list of `matrix` contexts (axes product + include)."""
    axes = {k: v for k, v in matrix.items() if k not in ("include", "exclude")}
    combos = [{}] if axes else []
    for key, values in axes.items():
        combos = [dict(c, **{key: v}) for c in combos for v in values]
    combos += matrix.get("include") or []
    return combos or [{}]

for wf in os.environ["WORKFLOWS"].split():
    doc = yaml.safe_load(open(wf))
    for key, job in (doc.get("jobs") or {}).items():
        name = job.get("name", key)
        matrix = ((job.get("strategy") or {}).get("matrix")) or {}
        if not matrix:
            print(name)
            continue
        for entry in expand(matrix):
            # GitHub collapses the whitespace left by an empty matrix value.
            print(" ".join(render(name, {"matrix": entry}).split()))
PY
}

assert_required_checks() {
  command -v python3 >/dev/null || die "python3 required"
  python3 -c 'import yaml' 2>/dev/null || die "PyYAML required"
  local policy="${POLICY:-policies/required-release-checks.yaml}"
  local prod req missing=0
  prod="$(producible_names | sort -u)"
  req="$(yq -r '.required_checks[]' "$policy" | sort -u)"

  # `required_checks` mirrors `release_required_checks` for older consumers.
  # A literal copy (an anchor would make `yq` edits silently no-op), so the two
  # must be asserted equal or they drift and the older consumers gate on a
  # stale set. Only enforced when the policy declares the split.
  if yq -e '.release_required_checks' "$policy" >/dev/null 2>&1; then
    local rel; rel="$(yq -r '.release_required_checks[]' "$policy" | sort -u)"
    [ "$rel" = "$req" ] || die "required_checks and release_required_checks differ:
$(diff <(printf '%s\n' "$rel") <(printf '%s\n' "$req") || true)"
  fi

  # Herestrings, not `printf | grep -q`: grep -q exits at the first match
  # without draining stdin, so printf can take SIGPIPE (141) and, under
  # pipefail, flip a MATCHED name into a spurious mismatch → REFUSE. Hit
  # intermittently on the runner (PR #76); a herestring has no pipe to break.
  # A required name is producible if some workflow JOB is named that, or if a
  # workflow publishes it as a COMMIT STATUS. trusted-validation.yml publishes
  # the release-required results as statuses against the validated SHA, because
  # a check run attaches to the dispatched ref and never to the commit under
  # validation — so those two names are deliberately NOT job names.
  local statuses; statuses="$(published_statuses)"
  while IFS= read -r n; do
    [ -n "$n" ] || continue
    grep -Fxq "$n" <<<"$prod" && continue
    grep -Fxq "$n" <<<"$statuses" && continue
    echo "  unproducible: $n"; missing=1
  done <<EOF
$req
EOF
  # Matrix legs of trusted-validation are NOT individually required: the
  # workflow's own `seal` job ("trusted validation result") refuses unless the
  # entire 10-image matrix succeeded, so requiring the seal covers them. Listing
  # each leg would duplicate that gate and make the policy churn whenever the
  # matrix changes shape.
  # The trusted matrix legs are aggregated by the `trusted validation result`
  # seal, which IS required and refuses unless every leg AND the stale-exception
  # aggregate are green. Requiring each leg by name as well would make the
  # release gate brittle to a matrix rename without adding a guarantee.
  # Every job in trusted-validation.yml is non-gating BY NAME: none of them is a
  # release-required check any more. The release-required results are the commit
  # statuses that workflow publishes, which are required and are verified above.
  # The two restore-drill jobs are aggregated the same way the trusted matrix
  # legs are: `repo structure` — which IS required — `needs` the restore job,
  # runs with `if: always()` so it cannot be skipped past, and refuses unless it
  # can download and consume that job's verdict. Requiring the legs by name as
  # well would add no guarantee and would need a control-plane change to the
  # live ruleset that this repository is not making here.
  local non_gating='^(trusted dispatch |authorize trusted validation$|publish release statuses$|evidence restore drill )'
  while IFS= read -r n; do
    [ -n "$n" ] || continue
    if grep -qE "$non_gating" <<<"$n"; then continue; fi
    grep -Fxq "$n" <<<"$req" || { echo "  not required: $n"; missing=1; }
  done <<EOF
$prod
EOF
  [ "$missing" -eq 0 ] || die "required-release-checks.yaml does not match the workflow job names"
  log "REQUIRED CHECKS OK: $(printf '%s\n' "$req" | wc -l | tr -d ' ') names, all producible and all gating jobs required"
}

# --- self-test ---------------------------------------------------------------
# Fixture pair: a mini workflow (with a matrix) + a policy listing the RENDERED
# names. The check re-uses its own render/expand logic against the FIXTURE
# workflow — the policy-vs-workflow comparison is what makes it non-tautological:
# a drifted policy name must fail against the very same fixture workflow.
_arc_self_test() {
  command -v python3 >/dev/null 2>&1 && python3 -c 'import yaml' 2>/dev/null \
    || { echo "SKIP - python3/pyyaml absent"; return 0; }
  command -v yq >/dev/null 2>&1 || { echo "SKIP - yq absent"; return 0; }
  local fail=0 tmp; tmp="$(mktemp -d)"
  cat > "$tmp/wf.yml" <<'YAML'
name: fixture
on: push
jobs:
  plain:
    name: fixture plain job
    runs-on: ubuntu-latest
    steps: [{run: "true"}]
  matrixed:
    name: fixture build ${{ matrix.img }} ${{ matrix.ver }}
    runs-on: ubuntu-latest
    strategy:
      matrix:
        img: [alpha, beta]
        ver: ["1.0", ""]
    steps: [{run: "true"}]
YAML
  cat > "$tmp/pol.yaml" <<'POL'
schema_version: 1
accept_conclusions: [success]
required_checks:
  - fixture plain job
  - fixture build alpha 1.0
  - fixture build alpha
  - fixture build beta 1.0
  - fixture build beta
POL
  if ( WORKFLOWS="$tmp/wf.yml" POLICY="$tmp/pol.yaml" assert_required_checks ) >/dev/null 2>&1; then
    echo "ok   - fixture policy matches fixture workflow (matrix expanded)"
  else
    echo "FAIL - fixture policy matches fixture workflow (matrix expanded)"; fail=1
  fi
  # drifted policy name -> FAIL (unproducible by the workflow)
  yq '.required_checks += ["fixture build gamma 1.0"]' "$tmp/pol.yaml" > "$tmp/drift.yaml"
  if ( WORKFLOWS="$tmp/wf.yml" POLICY="$tmp/drift.yaml" assert_required_checks ) >/dev/null 2>&1; then
    echo "FAIL - drifted policy name must fail"; fail=1
  else
    echo "ok   - drifted policy name fails"
  fi
  # dropped gating job -> FAIL (workflow job not required)
  yq '.required_checks -= ["fixture plain job"]' "$tmp/pol.yaml" > "$tmp/drop.yaml"
  if ( WORKFLOWS="$tmp/wf.yml" POLICY="$tmp/drop.yaml" assert_required_checks ) >/dev/null 2>&1; then
    echo "FAIL - dropped gating job must fail"; fail=1
  else
    echo "ok   - dropped gating job fails"
  fi
  rm -rf "$tmp"; return $fail
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-}" in
    --list) producible_names | sort -u ;;
    --self-test) _arc_self_test && echo "assert-required-checks.sh: SELF-TEST OK" ;;
    *) assert_required_checks ;;
  esac
fi
