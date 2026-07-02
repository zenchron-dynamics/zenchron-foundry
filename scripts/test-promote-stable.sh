#!/usr/bin/env bash
# Offline unit check for promote-stable.sh ref/alias mapping (no registry).
set -euo pipefail
cd "$(dirname "$0")/.."

PROMOTE_LIB_ONLY=1 REGISTRY=ghcr.io NAMESPACE=zenchron-dynamics
export PROMOTE_LIB_ONLY REGISTRY NAMESPACE
# shellcheck source=/dev/null
source scripts/promote-stable.sh v2026.07.02 rc1

eq() { [ "$2" = "$3" ] || { echo "FAIL $1: got '$2' want '$3'"; exit 1; }; }

eq "php rc ref"   "$(rc_ref_for php-cli 8.4)" "ghcr.io/zenchron-dynamics/php-cli:8.4-debian-rc1"
eq "edge rc ref"  "$(rc_ref_for caddy prod)"  "ghcr.io/zenchron-dynamics/caddy:prod-rc1"
eq "php aliases"  "$(aliases_for 8.3)"        "8.3-prod 8.3-prod-2026.07.02 8.3-debian"
eq "edge aliases" "$(aliases_for prod)"       "prod prod-2026.07.02"

# The promotion must cover exactly the 10-image matrix.
eq "image count"  "$(echo "$IMAGES" | wc -w | tr -d ' ')" "10"
echo "PASS: promote-stable mapping"
