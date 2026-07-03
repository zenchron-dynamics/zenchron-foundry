#!/usr/bin/env bash
# =============================================================================
# scripts/verify-promotion-state.sh <rc-manifest.yaml> <version>
# -----------------------------------------------------------------------------
# Phase 3 of promotion. For every stable alias, asserts it resolves to the exact
# RC digest from the signed manifest; when cosign is present (and not LOCAL),
# also runs the full identity verification per alias. Emits a schema-valid
# promotion manifest (aliases[] ref/digest/verified) to stdout. Nonzero if any
# alias fails.
# =============================================================================
set -uo pipefail
_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/registry-aliases.sh
. "$_d/lib/registry-aliases.sh"
# shellcheck source=lib/registry-ops.sh
. "$_d/lib/registry-ops.sh"
# shellcheck source=lib/release-manifest.sh
. "$_d/lib/release-manifest.sh"

MANIFEST="${1:?usage: verify-promotion-state.sh <rc-manifest> <version>}"
VERSION="${2:?usage: verify-promotion-state.sh <rc-manifest> <version>}"
REL="${VERSION#v}"
RC="$(manifest_field "$MANIFEST" '.candidate')"
REV="$(manifest_field "$MANIFEST" '.revision')"
mkey() { case "$2" in prod) printf '%s' "$1" ;; *) printf '%s-%s' "$1" "$2" ;; esac; }

ROWS="$(mktemp)"; bad=0
for t in $MATRIX_IMAGES; do
  fam="${t%:*}"; sel="${t#*:}"; key="$(mkey "$fam" "$sel")"
  rcdig="$(manifest_image_field "$MANIFEST" "$key" digest)"
  for suf in $(stable_aliases "$sel" "$REL"); do
    ref="$(full_ref "$fam" "$suf")"
    got="$(reg_digest "$ref" 2>/dev/null || echo '')"
    verified=true
    if [ "$got" != "$rcdig" ]; then verified=false; bad=$((bad+1)); warn "MISMATCH $ref: $got != $rcdig"; fi
    if [ "$verified" = true ] && [ "${LOCAL:-0}" != 1 ] && command -v cosign >/dev/null 2>&1; then
      EXPECTED_REVISION="$REV" EXPECTED_ROLE=rc-publisher \
        bash "$_d/verify-image-release-identity.sh" "$NS/$fam@$got" >/dev/null 2>&1 \
        || { verified=false; bad=$((bad+1)); warn "IDENTITY FAIL $ref"; }
    fi
    printf '%s\t%s\t%s\n' "$ref" "${got:-UNRESOLVED}" "$verified" >> "$ROWS"
  done
done

REL="$REL" VERSION="$VERSION" RC="$RC" REV="$REV" ROWS="$ROWS" python3 - <<'PY'
import os, yaml
rows=[l.rstrip("\n").split("\t") for l in open(os.environ["ROWS"]) if l.strip()]
m={"schema_version":1,"release":os.environ["VERSION"],"candidate":os.environ["RC"],
   "revision":os.environ["REV"],"created_at":__import__("datetime").datetime.now(__import__("datetime").timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
   "aliases":[{"ref":r,"digest":d,"verified":(v=="true")} for r,d,v in rows]}
import sys; yaml.safe_dump(m, sys.stdout, sort_keys=True)
PY
rm -f "$ROWS"
[ "$bad" -eq 0 ] || { warn "promotion verification failed ($bad aliases)"; exit 1; }
