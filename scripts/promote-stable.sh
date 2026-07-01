#!/usr/bin/env bash
# =============================================================================
# Exact RC -> stable digest promotion. NO docker build (rule #14 / Sprint 6).
#
#   scripts/promote-stable.sh <version> <rc>
#     version : vYYYY.MM.DD[.N]   (canonical stable version)
#     rc      : rc<N>             (already-published, signed RC to promote)
#
# Two-phase, atomic-at-the-alias:
#   Phase 1  resolve + verify ALL 10 RC digests (signed + attested); record the
#            CURRENT canonical alias digests for rollback. Mutate nothing.
#   Phase 2  only if all 10 passed: retag each exact RC digest onto its stable
#            aliases (registry-side copy — signatures ride the digest).
#   Phase 3  verify every promoted alias resolves to the exact RC digest.
#
# Any failure in Phase 1 aborts before a single alias is touched.
# =============================================================================
set -euo pipefail

VERSION="${1:?usage: promote-stable.sh <version> <rc>}"
RC="${2:?usage: promote-stable.sh <version> <rc>}"

echo "$VERSION" | grep -Eq '^v[0-9]{4}\.[0-9]{2}\.[0-9]{2}(\.[0-9]+)?$' \
  || { echo "REFUSE: version '$VERSION' is not vYYYY.MM.DD[.N]" >&2; exit 1; }
echo "$RC" | grep -Eq '^rc[0-9]+$' \
  || { echo "REFUSE: rc '$RC' must match rc<N>" >&2; exit 1; }

REGISTRY="${REGISTRY:-ghcr.io}"
NAMESPACE="${NAMESPACE:-zenchron-dynamics}"
NS="${REGISTRY}/${NAMESPACE}"
REL="${VERSION#v}"

IDENT_RE='https://github.com/zenchron-dynamics/zenchron-foundry/.*'
OIDC='https://token.actions.githubusercontent.com'

# Authoritative 10-image set. Field 2 is the PHP minor, or "prod" for edges.
IMAGES="php-fpm:8.3 php-fpm:8.4 php-cli:8.3 php-cli:8.4 php-worker:8.3 php-worker:8.4 php-frankenphp:8.3 php-frankenphp:8.4 caddy:prod nginx:prod"

# Resolve the digest a ref currently points at (no pull, no build).
digest_of() { docker buildx imagetools inspect "$1" --format '{{.Manifest.Digest}}'; }

rc_ref_for()  { # <fam> <ver>
  case "$2" in prod) echo "${NS}/$1:prod-${RC}" ;; *) echo "${NS}/$1:$2-debian-${RC}" ;; esac
}
aliases_for() { # <ver>  -> space-separated stable tag suffixes
  case "$1" in
    prod) echo "prod prod-${REL}" ;;
    *)    echo "$1-prod $1-prod-${REL} $1-debian" ;;
  esac
}

# Allow a test to source just the ref/alias mapping without hitting a registry.
[ -n "${PROMOTE_LIB_ONLY:-}" ] && return 0 2>/dev/null || true

mkdir -p release-artifacts
ROLLBACK="release-artifacts/rollback-${VERSION}.txt"
: > "$ROLLBACK"
echo "# rollback metadata for ${VERSION} (promoted from ${RC})" >> "$ROLLBACK"
echo "# <stable-ref> <prior-digest-or-NONE>" >> "$ROLLBACK"

count=0
declare -a RC_DIGEST

echo "== Phase 1: verify all RC digests (signed + attested) =="
for item in $IMAGES; do
  fam="${item%:*}"; ver="${item#*:}"
  rc_ref="$(rc_ref_for "$fam" "$ver")"

  dg="$(digest_of "$rc_ref")" \
    || { echo "REFUSE: RC image missing: $rc_ref" >&2; exit 1; }
  echo "  $rc_ref -> $dg"

  cosign verify \
    --certificate-identity-regexp "$IDENT_RE" --certificate-oidc-issuer "$OIDC" \
    "${NS}/${fam}@${dg}" >/dev/null \
    || { echo "REFUSE: $rc_ref@$dg is not validly signed" >&2; exit 1; }
  cosign verify-attestation --type spdxjson \
    --certificate-identity-regexp "$IDENT_RE" --certificate-oidc-issuer "$OIDC" \
    "${NS}/${fam}@${dg}" >/dev/null \
    || { echo "REFUSE: $rc_ref@$dg has no valid SBOM attestation" >&2; exit 1; }

  RC_DIGEST["$count"]="$dg"

  # Record prior canonical alias digest (first alias) for rollback.
  primary="${NS}/${fam}:$(aliases_for "$ver" | awk '{print $1}')"
  prior="$(digest_of "$primary" 2>/dev/null || echo NONE)"
  echo "$primary $prior" >> "$ROLLBACK"

  count=$((count + 1))
done

test "$count" -eq 10 || { echo "REFUSE: expected 10 images, verified $count" >&2; exit 1; }
echo "Phase 1 OK: 10/10 RC images verified. Prior aliases recorded in $ROLLBACK"

echo "== Phase 2: promote exact digests -> stable aliases (retag, no rebuild) =="
i=0
for item in $IMAGES; do
  fam="${item%:*}"; ver="${item#*:}"
  dg="${RC_DIGEST[$i]}"
  for suf in $(aliases_for "$ver"); do
    echo "  ${NS}/${fam}:${suf} <= @${dg}"
    docker buildx imagetools create -t "${NS}/${fam}:${suf}" "${NS}/${fam}@${dg}"
  done
  i=$((i + 1))
done

echo "== Phase 3: verify every stable alias == exact RC digest =="
i=0
for item in $IMAGES; do
  fam="${item%:*}"; ver="${item#*:}"
  dg="${RC_DIGEST[$i]}"
  for suf in $(aliases_for "$ver"); do
    got="$(digest_of "${NS}/${fam}:${suf}")"
    test "$got" = "$dg" \
      || { echo "REFUSE: ${NS}/${fam}:${suf} is $got, expected $dg" >&2; exit 1; }
  done
  i=$((i + 1))
done

echo "PROMOTION OK: 10/10 stable aliases match their RC digests exactly (${RC} -> ${VERSION})"
