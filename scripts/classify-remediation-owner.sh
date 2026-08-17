#!/usr/bin/env bash
# =============================================================================
# scripts/classify-remediation-owner.sh — who can actually fix a finding, and
# can a rebuild change it at all?
# -----------------------------------------------------------------------------
# WHY THIS EXISTS. The scheduled-rebuild automation used to open one issue per
# image saying only
#
#     "reports fixable CRITICAL/HIGH the current stable may not"
#
# with no CVE, no package, no versions, no scanner identity, and no statement of
# whether rebuilding could change anything. #88-#95 were eight such tickets for
# one root cause, and #79 still carries the title "rebuild requested" for a
# finding that NO rebuild can remediate: kin-openapi and grpc are statically
# linked into the upstream FrankenPHP binary. Building the same Dockerfile from
# the same upstream digest cannot change a vendored module.
#
# That automation has since been deleted along with the publication path it fed
# (see .github/workflows/scheduled-rebuild.yml, now a refusal stub). This script
# is the contract it must satisfy if it ever returns: classify the owner, decide
# whether a rebuild is even capable of remediation, and refuse to raise a
# rebuild ticket when it is not.
#
# THE OWNERSHIP MODEL, from docs/ownership-boundary.md:
#
#   foundry-dockerfile     files and packages Foundry installs or removes
#   foundry-extension      PHP extensions Foundry compiles from a pinned version
#   upstream-base          distro packages inherited from the pinned base image
#   upstream-vendor-binary Go modules statically linked into an upstream binary
#                          (FrankenPHP, Caddy) — a rebuild CANNOT change these
#   consumer-application   reachable only through the consuming application
#   not-affected           the component is absent or the range does not apply
#
# Usage:
#   classify-remediation-owner.sh --image <label> --package <name> \
#       [--installed V] [--fixed V] [--newer-base-available yes|no]
#   classify-remediation-owner.sh --self-test
#
# Output: KEY=VALUE lines — owner, rebuild_can_remediate, ticket_warranted,
# remediation, and root_cause_key (the deduplication key: one ticket per root
# cause, not per image).
# =============================================================================
set -uo pipefail

# Go module paths and the pseudo-package Trivy uses for the Go toolchain. These
# are compiled INTO an upstream binary; nothing in a Foundry layer can move them.
_is_vendored_go() {
  case "$1" in
    stdlib|golang.org/*|google.golang.org/*|github.com/*|gopkg.in/*|go.uber.org/*) return 0 ;;
  esac
  return 1
}

# Images whose primary binary is an upstream-built Go program.
_has_vendored_binary() {
  case "$1" in
    caddy*|php-frankenphp*) return 0 ;;
  esac
  return 1
}

# Extensions Foundry compiles itself, from a version pinned in the Dockerfile.
# These ARE Foundry-controlled: bumping the pin and rebuilding is remediation.
_is_foundry_extension() {
  case "$1" in
    redis|phpredis|igbinary|msgpack) return 0 ;;
  esac
  return 1
}

classify() {
  local image="" pkg="" installed="" fixed="" newer_base="unknown"
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --image)   image="${2-}"; shift 2 ;;
      --package) pkg="${2-}"; shift 2 ;;
      --installed) installed="${2-}"; shift 2 ;;
      --fixed)   fixed="${2-}"; shift 2 ;;
      --newer-base-available) newer_base="${2-}"; shift 2 ;;
      *) echo "REFUSE: unknown argument '$1'" >&2; return 1 ;;
    esac
  done
  [ -n "$image" ] || { echo "REFUSE: --image is required" >&2; return 1; }
  [ -n "$pkg" ]   || { echo "REFUSE: --package is required" >&2; return 1; }

  local owner rebuild remediation ticket
  if _is_vendored_go "$pkg" && _has_vendored_binary "$image"; then
    owner=upstream-vendor-binary
    # THE point of this script. A rebuild re-runs the same Dockerfile against the
    # same pinned digest; the vendored module is inside a binary that Foundry
    # does not build. Only a patched upstream image, or an ADR to compile from
    # source, can change it.
    if [ "$newer_base" = yes ]; then
      rebuild=yes
      remediation="bump the pinned upstream base digest, then the normal release process"
    else
      rebuild=no
      remediation="wait for a patched upstream image; no Foundry rebuild can change a statically linked vendor module (source compilation would need an ADR)"
    fi
  elif _is_foundry_extension "$pkg"; then
    owner=foundry-extension
    rebuild=yes
    remediation="bump the pinned extension version in the Dockerfile and rebuild"
  elif [ -n "$fixed" ]; then
    owner=upstream-base
    if [ "$newer_base" = yes ]; then
      rebuild=yes
      remediation="bump the pinned base digest to one carrying the fixed distro package"
    else
      rebuild=no
      remediation="upstream has a fix but no rebased image exists yet; rebuilding the same digest changes nothing"
    fi
  else
    owner=upstream-base
    rebuild=no
    remediation="no fix is available upstream; govern as accepted risk or not-affected"
  fi

  # A rebuild ticket is warranted ONLY when a rebuild can actually change the
  # finding. Anything else belongs in the ledger or in an upstream-tracking
  # issue — not in a ticket telling someone to press rebuild.
  if [ "$rebuild" = yes ]; then ticket=yes; else ticket=no; fi

  # Deduplication by ROOT CAUSE, not by image: one upstream module at one
  # version is one problem however many images embed it.
  local key="${owner}:${pkg}:${installed:-unpinned}"

  printf 'owner=%s\n' "$owner"
  printf 'rebuild_can_remediate=%s\n' "$rebuild"
  printf 'ticket_warranted=%s\n' "$ticket"
  printf 'remediation=%s\n' "$remediation"
  printf 'root_cause_key=%s\n' "$key"
}

self_test() {
  local pass=0 fail=0
  ck() { if eval "$2"; then pass=$((pass+1)); echo "ok   - $1"; else fail=$((fail+1)); echo "FAIL - $1"; fi; }
  # NOTE the shift: the field name must not be passed on to classify, which
  # would reject it as an unknown argument. The first version omitted it and two
  # key-comparison assertions compared two empty strings — which happened to
  # look like agreement in one case and disagreement in another.
  g() { local field="$1"; shift; classify "$@" 2>/dev/null | grep "^${field}=" | cut -d= -f2-; }

  # 1. a fixable newer upstream base
  ck "a distro package with a newer base available IS a rebuild ticket" \
     '[ "$(classify --image php-cli/8.3 --package zlib1g --installed 1:1.2.13 --fixed 1:1.2.14 --newer-base-available yes | grep ^ticket_warranted= | cut -d= -f2)" = yes ]'
  ck "...and names the base bump as the remediation" \
     'classify --image php-cli/8.3 --package zlib1g --fixed 1:1.2.14 --newer-base-available yes | grep -q "bump the pinned base digest"'

  # 2. an upstream patch NOT yet published as an image
  ck "a fixed distro package with no newer base is NOT a rebuild ticket" \
     '[ "$(classify --image php-cli/8.3 --package zlib1g --fixed 1:1.2.14 --newer-base-available no | grep ^ticket_warranted= | cut -d= -f2)" = no ]'
  ck "...and says rebuilding the same digest changes nothing" \
     'classify --image php-cli/8.3 --package zlib1g --fixed 1:1.2.14 --newer-base-available no | grep -q "changes nothing"'

  # 3. a statically linked vendor binary — the #79 case
  ck "a Go module in the frankenphp binary is upstream-vendor-binary" \
     '[ "$(classify --image php-frankenphp/8.4 --package github.com/getkin/kin-openapi --installed v0.140.0 --fixed 0.144.0 --newer-base-available no | grep ^owner= | cut -d= -f2)" = upstream-vendor-binary ]'
  ck "...a rebuild CANNOT remediate it" \
     '[ "$(classify --image php-frankenphp/8.4 --package github.com/getkin/kin-openapi --fixed 0.144.0 --newer-base-available no | grep ^rebuild_can_remediate= | cut -d= -f2)" = no ]'
  ck "...so NO rebuild ticket is warranted" \
     '[ "$(classify --image php-frankenphp/8.4 --package google.golang.org/grpc --fixed 1.82.1 --newer-base-available no | grep ^ticket_warranted= | cut -d= -f2)" = no ]'
  ck "...and source compilation is named as needing an ADR, not done silently" \
     'classify --image php-frankenphp/8.4 --package google.golang.org/grpc --fixed 1.82.1 --newer-base-available no | grep -q "would need an ADR"'
  ck "the Go toolchain (stdlib) in caddy is also vendor-owned" \
     '[ "$(classify --image caddy/prod --package stdlib --installed v1.26.3 --fixed 1.26.6 --newer-base-available no | grep ^owner= | cut -d= -f2)" = upstream-vendor-binary ]'
  ck "a patched upstream image DOES make the vendor case a rebuild ticket" \
     '[ "$(classify --image caddy/prod --package stdlib --fixed 1.26.6 --newer-base-available yes | grep ^ticket_warranted= | cut -d= -f2)" = yes ]'

  # 4. a Foundry-controlled dependency
  ck "a Foundry-compiled PHP extension is foundry-extension and IS actionable" \
     '[ "$(classify --image php-fpm/8.3 --package redis --installed 6.0.2 --fixed 6.0.3 --newer-base-available no | grep ^owner= | cut -d= -f2)" = foundry-extension ]'
  ck "...remediated by bumping the pin, not by waiting on upstream" \
     'classify --image php-fpm/8.3 --package redis --fixed 6.0.3 | grep -q "bump the pinned extension version"'

  # 5. an unchanged rebuild input
  ck "no fix available at all is not a rebuild ticket" \
     '[ "$(classify --image nginx/prod --package libaom3 --installed 3.6.0 | grep ^ticket_warranted= | cut -d= -f2)" = no ]'
  ck "...and is directed to the ledger instead" \
     'classify --image nginx/prod --package libaom3 | grep -q "accepted risk or not-affected"'

  # 6. multiple images sharing one root cause -> ONE key
  ck "two images embedding the same vendored module share one root_cause_key" \
     '[ "$(g root_cause_key --image php-frankenphp/8.3 --package google.golang.org/grpc --installed v1.81.1)" = \
        "$(g root_cause_key --image php-frankenphp/8.4 --package google.golang.org/grpc --installed v1.81.1)" ]'
  ck "a different installed version is a DIFFERENT root cause" \
     '[ "$(g root_cause_key --image php-frankenphp/8.3 --package google.golang.org/grpc --installed v1.81.1)" != \
        "$(g root_cause_key --image php-frankenphp/8.3 --package google.golang.org/grpc --installed v1.82.1)" ]'
  ck "a distro package and a vendored module never share a key" \
     '[ "$(g root_cause_key --image php-cli/8.3 --package zlib1g --installed 1)" != \
        "$(g root_cause_key --image caddy/prod --package stdlib --installed 1)" ]'

  # 7. refusals
  ck "a missing image refuses"   '! classify --package zlib1g >/dev/null 2>&1'
  ck "a missing package refuses" '! classify --image nginx/prod >/dev/null 2>&1'
  ck "an unknown argument refuses" '! classify --image x --package y --bogus 1 >/dev/null 2>&1'

  echo "----"
  printf 'self-test: %d ok, %d failed\n' "$pass" "$fail"
  [ "$fail" -eq 0 ]
}

case "${1:-}" in
  --self-test) self_test ;;
  "")          echo "usage: $(basename "$0") --image L --package P [--installed V] [--fixed V] [--newer-base-available yes|no] | --self-test" >&2; exit 64 ;;
  *)           classify "$@" ;;
esac
