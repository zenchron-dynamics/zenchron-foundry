#!/usr/bin/env bash
# =============================================================================
# Zenchron Dynamics — local vulnerability scan (CI-equivalent gate).
# Mirrors scan-images.yml: Trivy is the ENFORCING gate on FIXABLE CRITICAL/HIGH
# (--ignore-unfixed, honoring policies/.trivyignore); Grype is an advisory
# second opinion; Syft generates an SBOM. Tools that are not installed locally
# are reported as SKIPPED — NEVER silently passed (CI remains the source of truth).
#
# Usage: scripts/scan-local.sh [PHP_VERSION]   (default 8.4)
# Scans LOCALLY BUILT php-cli/fpm/worker/frankenphp + nginx + caddy.
# Does NOT weaken thresholds; edge images (nginx/caddy) are scan-and-report
# exactly as in CI.
# =============================================================================
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$ROOT"
PHP="${1:-8.4}"
REG="${REGISTRY:-ghcr.io}"; NS="${NAMESPACE:-zenchron-dynamics}"; SFX="${TAG_SUFFIX:-prod}"
IGN="policies/.trivyignore"
# fam:image:gate(true=enforcing)
GATED="php-cli:${PHP}-$SFX php-fpm:${PHP}-$SFX php-worker:${PHP}-$SFX php-frankenphp:${PHP}-$SFX"
REPORT="nginx:$SFX caddy:$SFX"
rc=0

scan_trivy(){ # $1 ref  $2 gate(1/0)
  local img="$REG/$NS/$1" gate="$2"
  docker image inspect "$img" >/dev/null 2>&1 || { echo "  (skip $1: not built)"; return; }
  local fx; fx=$(trivy image --quiet --scanners vuln --severity CRITICAL,HIGH --ignore-unfixed \
      --ignorefile "$IGN" --no-progress -f json "$img" 2>/dev/null | grep -c '"VulnerabilityID"')
  if [ "$gate" = 1 ]; then
    if trivy image --quiet --scanners vuln --severity CRITICAL,HIGH --exit-code 1 --ignore-unfixed \
         --ignorefile "$IGN" --no-progress "$img" >/dev/null 2>&1; then
      echo "  ✓ GATE PASS $1 (fixable CRIT/HIGH=$fx)"
    else echo "  ✗ GATE FAIL $1 (fixable CRIT/HIGH=$fx)"; rc=1; fi
  else
    echo "  • report-only $1 (fixable CRIT/HIGH=$fx — edge image, upstream cadence)"
  fi
}

echo "== Trivy enforcing gate (PHP images) =="
if command -v trivy >/dev/null 2>&1; then
  for r in $GATED; do scan_trivy "$r" 1; done
  echo "== Trivy report-only (edge images) =="
  for r in $REPORT; do scan_trivy "$r" 0; done
else echo "  SKIPPED: trivy not installed (CI gate still mandatory)"; rc=1; fi

echo "== Grype (advisory second opinion) =="
if command -v grype >/dev/null 2>&1; then
  for r in $GATED $REPORT; do
    img="$REG/$NS/$r"; docker image inspect "$img" >/dev/null 2>&1 || continue
    n=$(grype -q -o json "$img" 2>/dev/null | grep -c '"severity": "\(Critical\|High\)"' || true)
    echo "  • $r: $n CRITICAL/HIGH (advisory)"
  done
else echo "  SKIPPED: grype not installed locally (advisory only — CI runs it)"; fi

echo "== Syft SBOM =="
if command -v syft >/dev/null 2>&1; then
  img="$REG/$NS/php-cli:${PHP}-$SFX"
  docker image inspect "$img" >/dev/null 2>&1 && syft "$img" -o spdx-json="/tmp/sbom-php-cli-${PHP}.spdx.json" -q 2>/dev/null \
    && echo "  ✓ SBOM: /tmp/sbom-php-cli-${PHP}.spdx.json" || echo "  (php-cli not built)"
else echo "  SKIPPED: syft not installed locally (CI generates + attests SBOMs)"; fi

echo "== scan-local: $([ $rc -eq 0 ] && echo OK || echo 'gate failed / trivy missing') =="
exit "$rc"
