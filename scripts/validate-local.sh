#!/usr/bin/env bash
# =============================================================================
# Zenchron Dynamics — local static validation (CI-equivalent, graceful).
# Mirrors ci.yml's structure + lint + compose-validate jobs. Tools that are not
# installed locally are reported SKIPPED (never silently passed) — GitHub CI
# remains the authoritative gate.
# =============================================================================
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$ROOT"
rc=0
run(){ "$@" || rc=1; }
skip(){ printf '  ⊘ SKIPPED (%s not installed locally — CI runs it)\n' "$1"; }

echo "== structure + supply-chain guards (no external tools) =="
run bash scripts/check-structure.sh
run bash scripts/assert-no-wolfi.sh

echo "== shellcheck =="
if command -v shellcheck >/dev/null 2>&1; then
  run shellcheck -S warning scripts/*.sh scripts/git-hooks/* images/php-worker/*/worker-* 2>/dev/null
else skip shellcheck; fi

echo "== yamllint =="
if command -v yamllint >/dev/null 2>&1; then run yamllint -c .yamllint.yaml --strict profiles policies .github; else skip yamllint; fi

echo "== hadolint =="
if command -v hadolint >/dev/null 2>&1; then
  while IFS= read -r d; do run hadolint --config policies/hadolint.yaml "$d"; done < <(find images examples -name Dockerfile)
else skip hadolint; fi

echo "== markdownlint =="
if command -v markdownlint-cli2 >/dev/null 2>&1; then run markdownlint-cli2 "**/*.md" "#docs/audits"; else skip markdownlint-cli2; fi

echo "== gitleaks (secret scan) =="
if command -v gitleaks >/dev/null 2>&1; then run gitleaks detect --source . --config policies/gitleaks.toml --redact --no-banner; else skip gitleaks; fi

echo "== docker compose config (examples + profile overlays) =="
if docker info >/dev/null 2>&1; then
  for p in examples/*/compose.yml; do echo "  $p"; docker compose -f "$p" config -q || rc=1; done
  for p in profiles/compose.*.yml; do docker compose -f profiles/_ci-base.yml -f "$p" config -q || rc=1; done
else echo "  ⊘ SKIPPED (docker daemon unavailable)"; fi

echo "== validate-local: $([ $rc -eq 0 ] && echo OK || echo 'issues above') =="
exit "$rc"
