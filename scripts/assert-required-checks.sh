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
producible_names() {
  python3 - <<'PY'
import re, yaml

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

for wf in (".github/workflows/ci.yml", ".github/workflows/scan-images.yml"):
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

  while IFS= read -r n; do
    [ -n "$n" ] || continue
    printf '%s\n' "$prod" | grep -Fxq "$n" || { echo "  unproducible: $n"; missing=1; }
  done <<EOF
$req
EOF
  while IFS= read -r n; do
    [ -n "$n" ] || continue
    printf '%s\n' "$req" | grep -Fxq "$n" || { echo "  not required: $n"; missing=1; }
  done <<EOF
$prod
EOF
  [ "$missing" -eq 0 ] || die "required-release-checks.yaml does not match the workflow job names"
  log "REQUIRED CHECKS OK: $(printf '%s\n' "$req" | wc -l | tr -d ' ') names, all producible and all gating jobs required"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-}" in
    --list) producible_names | sort -u ;;
    *) assert_required_checks ;;
  esac
fi
