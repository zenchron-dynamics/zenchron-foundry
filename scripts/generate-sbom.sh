#!/usr/bin/env bash
# =============================================================================
# scripts/generate-sbom.sh — per-child SBOMs (SPDX + CycloneDX), named by the
# ONE canonical identity every consumer looks them up by.
# -----------------------------------------------------------------------------
# THE DEFECT THIS EXISTS FOR.
#
# This script used to name its output by blind character substitution on the
# image reference:
#
#     NAME="$(echo "$IMAGE" | tr '/:@' '___')"
#     -> ghcr.io_zenchron-dynamics_php-fpm_8.3-prod.spdx.json
#
# while scripts/release/generate-evidence-bundle.sh looked up
# <child_slug>.spdx.json — php-fpm-8.3-linux-amd64.spdx.json. The producer's
# output set and the consumer's lookup set NEVER intersected. Handing the
# bundle a complete, correct SBOM directory therefore produced
#
#     "sbom": { "present": false, "children_with_sbom": 0 }
#
# with exit 0: a release whose bill of materials was silently absent, reported
# as a clean build. Two derivations of one identity is the exact defect
# child_slug() was introduced to remove; it had simply reappeared one layer out.
#
# A `tr` substitution is not an identity for a second reason: it is not
# injective. `a/b:c`, `a:b/c` and `a_b_c` all normalise onto one filename, so
# two different images could claim one SBOM. And the reference carries no
# platform, so the amd64 and arm64 children of one image collided outright —
# the same collision that cost run 32123758374 (see child_key in
# scripts/lib/common.sh).
#
# The filename now comes from sbom_filename() in scripts/lib/common.sh, built
# from the same validated (family, selector, platform) components as
# child_slug(). Producer and consumer call the SAME function.
#
# FAIL CLOSED. The identity is mandatory. There is no fallback that derives a
# name from $IMAGE, because a fallback is how the two derivations diverged in
# the first place: it disappears exactly when nobody wires it.
#
# Usage:
#   IMAGE=ghcr.io/zenchron-dynamics/php-fpm:8.3-prod \
#   FAMILY=php-fpm VERSION=8.3 PLATFORM=linux/amd64 \
#     bash scripts/generate-sbom.sh
#
#   scripts/generate-sbom.sh --print-names FAMILY VERSION PLATFORM
#       the filenames this script WOULD write — the hook a consumer or a test
#       uses to prove producer and consumer agree without running syft.
#   scripts/generate-sbom.sh --self-test
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/common.sh
. "$ROOT/scripts/lib/common.sh"

# --- the identity hook, usable without syft and without an image -------------
sbom_print_names() { # <family> <version> <platform>
  local fam="${1:?--print-names: family required}"
  local ver="${2:?--print-names: version required (use 'prod' for edge images)}"
  local plat="${3:?--print-names: platform required, linux/<arch>}"
  # Assigned first, THEN printed. Inside printf's argument list the
  # substitution's non-zero status is discarded, so a refused identity printed
  # an empty column and returned 0 — the fail-open shape this script exists to
  # remove.
  local f name
  for f in $SBOM_FORMATS; do
    name="$(sbom_filename "$fam" "$ver" "$plat" "$f")" || return 1
    printf '%s\t%s\n' "$f" "$name"
  done
}

sbom_generate() {
  cd "$ROOT"
  OUT="${OUT:-artifacts/sbom}"

  : "${IMAGE:?Set IMAGE=ghcr.io/.../name:tag}"
  # The identity is REQUIRED. It is never derived from $IMAGE: an image
  # reference does not carry the platform, and two references normalise onto
  # one name.
  : "${FAMILY:?Set FAMILY=<image family>, e.g. php-fpm — the SBOM names a CHILD}"
  : "${VERSION:?Set VERSION=<selector>, e.g. 8.3, or 'prod' for the edge images}"
  : "${PLATFORM:?Set PLATFORM=linux/<arch> — an SBOM without a platform is not a child identity}"

  # child_slug() validates the components and refuses anything that could
  # collide or escape a path, so this is also the input guard.
  local spdx cdx
  spdx="$(sbom_filename "$FAMILY" "$VERSION" "$PLATFORM" spdx-json)"
  cdx="$(sbom_filename "$FAMILY" "$VERSION" "$PLATFORM" cdx-json)"

  command -v syft >/dev/null 2>&1 || die "syft is required to produce an SBOM"
  mkdir -p "$OUT"

  log "==> Syft SBOM (SPDX): $IMAGE -> $spdx"
  syft "$IMAGE" --platform "$PLATFORM" -c policies/syft.yaml \
       -o "spdx-json=${OUT}/${spdx}"
  log "==> Syft SBOM (CycloneDX): $IMAGE -> $cdx"
  syft "$IMAGE" --platform "$PLATFORM" -c policies/syft.yaml \
       -o "cyclonedx-json=${OUT}/${cdx}"

  ( cd "$OUT" && sha256sum "$spdx" "$cdx" >> checksums.txt )
  log "==> SBOMs written to ${OUT}/"
}

# --- self-test ---------------------------------------------------------------
# No syft, no network, no image. What is asserted is the IDENTITY contract,
# which is the half that was broken.
_sbom_self_test() {
  local fail=0
  t() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

  t "the producer emits one filename per declared format" \
    "[ \"\$(sbom_print_names php-fpm 8.3 linux/amd64 | wc -l | tr -d ' ')\" \
     = \"\$(printf '%s\\n' \$SBOM_FORMATS | wc -l | tr -d ' ')\" ]"
  t "the SPDX name the producer emits IS sbom_filename's" \
    "[ \"\$(sbom_print_names php-fpm 8.3 linux/amd64 | awk -F'\\t' '\$1==\"spdx-json\"{print \$2}')\" \
     = \"\$(sbom_filename php-fpm 8.3 linux/amd64 spdx-json)\" ]"
  t "the platform is part of the emitted name" \
    "[ \"\$(sbom_print_names php-fpm 8.3 linux/amd64 | md5sum 2>/dev/null || sbom_print_names php-fpm 8.3 linux/amd64 | md5)\" \
     != \"\$(sbom_print_names php-fpm 8.3 linux/arm64 | md5sum 2>/dev/null || sbom_print_names php-fpm 8.3 linux/arm64 | md5)\" ]"
  t "REFUSED: no platform is not a child identity" \
    "! ( sbom_print_names php-fpm 8.3 ) >/dev/null 2>&1"
  t "REFUSED: a non-linux platform" \
    "! ( sbom_print_names php-fpm 8.3 darwin/arm64 ) >/dev/null 2>&1"
  t "REFUSED: a family that could escape a path" \
    "! ( sbom_print_names ../etc 8.3 linux/amd64 ) >/dev/null 2>&1"
  t "REFUSED: generating with no IMAGE" \
    "! ( FAMILY=php-fpm VERSION=8.3 PLATFORM=linux/amd64 IMAGE= sbom_generate ) >/dev/null 2>&1"
  t "REFUSED: generating with no identity — there is no \$IMAGE fallback" \
    "! ( IMAGE=ghcr.io/x/php-fpm:8.3-prod FAMILY= VERSION= PLATFORM= sbom_generate ) >/dev/null 2>&1"
  # THE REGRESSION ITSELF: the name this script used to write must not be the
  # name it writes now, and the name it writes now must be the one the bundle
  # looks up.
  t "the pre-fix tr-substitution name is NOT what the producer emits" \
    "[ \"\$(printf '%s' 'ghcr.io/zenchron-dynamics/php-fpm:8.3-prod' | tr '/:@' '___').spdx.json\" \
     != \"\$(sbom_filename php-fpm 8.3 linux/amd64 spdx-json)\" ]"
  t "producer and consumer derive one identity: the child slug" \
    "[ \"\$(sbom_filename php-fpm 8.3 linux/amd64 spdx-json)\" \
     = \"\$(child_slug php-fpm 8.3 linux/amd64).spdx.json\" ]"

  echo "----"
  [ "$fail" -eq 0 ] && echo "generate-sbom.sh: SELF-TEST OK"
  return $fail
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-}" in
    --self-test)   _sbom_self_test ;;
    --print-names) shift; sbom_print_names "$@" ;;
    "")            sbom_generate ;;
    *) die "usage: [IMAGE=... FAMILY=... VERSION=... PLATFORM=...] generate-sbom.sh | --print-names F V P | --self-test" ;;
  esac
fi
