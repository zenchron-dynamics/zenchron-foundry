#!/usr/bin/env bash
# =============================================================================
# scripts/assert-dependabot-manifests.sh
# -----------------------------------------------------------------------------
# Every directory configured in .github/dependabot.yml must actually contain the
# manifest its ecosystem updates (#119).
#
# Why: the composer entry pointed at examples/laravel and examples/symfony, which
# ship no composer.json — their READMEs say "Reference only … No app code shipped
# here". Dependabot therefore updated nothing, while the configuration implied
# example dependencies were monitored. A dependency-update control that silently
# matches no files is worse than no control: it produces false assurance.
#
# This gate makes that impossible to reintroduce. Adding a directory to
# dependabot.yml now requires the manifest to exist.
#
# Usage: assert-dependabot-manifests.sh [<config>]   # default .github/dependabot.yml
#        assert-dependabot-manifests.sh --self-test
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${CONFIG:-${ROOT}/.github/dependabot.yml}"

check() {
  CONFIG_PATH="$1" REPO_ROOT="${2:-$ROOT}" python3 - <<'PY'
import os, sys

try:
    import yaml
except ImportError:
    print("FAIL: PyYAML is required", file=sys.stderr); sys.exit(1)

cfg  = os.environ["CONFIG_PATH"]
root = os.environ["REPO_ROOT"]

# One or more filenames that prove the ecosystem has something to update.
# A directory satisfies the ecosystem if ANY of them is present.
MANIFESTS = {
    "composer":       ["composer.json"],
    "docker":         ["Dockerfile"],
    "github-actions": [".github/workflows"],
    "npm":            ["package.json"],
    "pip":            ["requirements.txt", "pyproject.toml", "setup.py"],
    "gomod":          ["go.mod"],
    "bundler":        ["Gemfile"],
    "cargo":          ["Cargo.toml"],
    "terraform":      ["main.tf", "versions.tf"],
}

try:
    doc = yaml.safe_load(open(cfg)) or {}
except Exception as exc:
    print("FAIL: cannot read %s: %s" % (cfg, exc), file=sys.stderr); sys.exit(1)

updates = doc.get("updates")
if not isinstance(updates, list) or not updates:
    print("FAIL: %s has no 'updates' list — a dependabot config that updates "
          "nothing is not a control" % cfg, file=sys.stderr)
    sys.exit(1)

problems, checked = [], 0
for entry in updates:
    eco = entry.get("package-ecosystem")
    if not eco:
        problems.append("an update entry has no package-ecosystem")
        continue
    dirs = entry.get("directories") or ([entry["directory"]] if entry.get("directory") else [])
    if not dirs:
        problems.append("%s: no directory/directories configured" % eco)
        continue
    names = MANIFESTS.get(eco)
    if names is None:
        # Fail closed: an ecosystem this gate does not know how to verify must be
        # taught here, not silently trusted.
        problems.append("%s: unknown ecosystem — teach assert-dependabot-manifests.sh "
                        "how to verify it" % eco)
        continue
    for d in dirs:
        checked += 1
        rel = d.lstrip("/")
        base = os.path.join(root, rel) if rel else root
        if not os.path.isdir(base):
            problems.append("%s: directory '%s' does not exist" % (eco, d))
            continue
        if not any(os.path.exists(os.path.join(base, n)) for n in names):
            problems.append("%s: '%s' contains none of %s — the entry updates nothing"
                            % (eco, d, "/".join(names)))

if problems:
    print("FAIL: %d dependabot configuration problem(s):" % len(problems), file=sys.stderr)
    for p in problems:
        print("  %s" % p, file=sys.stderr)
    sys.exit(1)

print("RESULT: PASS (%d dependabot directory/ies, every one has its manifest)" % checked)
PY
}

self_test() {
  local tmp ok=0 bad=0
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '${tmp}'" RETURN
  t() { if eval "$2"; then ok=$((ok+1)); echo "  ok   $1"; else bad=$((bad+1)); echo "  FAIL $1"; fi; }

  mkdir -p "$tmp/repo/images/nginx" "$tmp/repo/examples/laravel" "$tmp/repo/.github/workflows"
  : > "$tmp/repo/images/nginx/Dockerfile"

  cat > "$tmp/good.yml" <<'YAML'
version: 2
updates:
  - package-ecosystem: "docker"
    directories: ["/images/nginx"]
  - package-ecosystem: "github-actions"
    directory: "/"
YAML
  t "configured dirs with manifests pass"      "check '$tmp/good.yml' '$tmp/repo' >/dev/null"

  # The exact #119 defect: composer pointed at a directory with no composer.json.
  cat > "$tmp/phantom.yml" <<'YAML'
version: 2
updates:
  - package-ecosystem: "composer"
    directories: ["/examples/laravel"]
YAML
  t "composer dir without composer.json fails" "! check '$tmp/phantom.yml' '$tmp/repo' >/dev/null 2>&1"
  t "…and names the directory" \
    "out=\"\$(check '$tmp/phantom.yml' '$tmp/repo' 2>&1 || true)\"; grep -q 'examples/laravel' <<<\"\$out\""

  # …and passes once the manifest really exists.
  : > "$tmp/repo/examples/laravel/composer.json"
  t "composer dir WITH composer.json passes"   "check '$tmp/phantom.yml' '$tmp/repo' >/dev/null"
  rm -f "$tmp/repo/examples/laravel/composer.json"

  cat > "$tmp/missingdir.yml" <<'YAML'
version: 2
updates:
  - package-ecosystem: "docker"
    directories: ["/images/does-not-exist"]
YAML
  t "nonexistent directory fails"              "! check '$tmp/missingdir.yml' '$tmp/repo' >/dev/null 2>&1"

  cat > "$tmp/unknown.yml" <<'YAML'
version: 2
updates:
  - package-ecosystem: "cocoapods"
    directories: ["/images/nginx"]
YAML
  t "unknown ecosystem fails closed"           "! check '$tmp/unknown.yml' '$tmp/repo' >/dev/null 2>&1"

  printf 'version: 2\n' > "$tmp/empty.yml"
  t "config with no updates fails closed"      "! check '$tmp/empty.yml' '$tmp/repo' >/dev/null 2>&1"
  t "unreadable config fails closed"           "! check '$tmp/nope.yml' '$tmp/repo' >/dev/null 2>&1"

  t "the repository's own config passes"       "check '$CONFIG' '$ROOT' >/dev/null"

  echo "self-test: $ok ok, $bad failed"
  [ "$bad" -eq 0 ]
}

case "${1:-}" in
  --self-test) self_test ;;
  "")          check "$CONFIG" "$ROOT" ;;
  *)           check "$1" "${2:-$ROOT}" ;;
esac
