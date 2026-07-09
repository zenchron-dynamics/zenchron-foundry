#!/usr/bin/env bash
# =============================================================================
# scripts/build-release-evidence.sh <out-dir>
# -----------------------------------------------------------------------------
# Assembles the immutable release evidence package for the solo-maintainer
# model: one machine-readable evidence.json + a human-readable EVIDENCE.md +
# a checksum, plus a consumer VERIFY.md rendered from templates/VERIFY.md with
# the EXACT rc-publisher cosign identity (no wildcard).
#
# Inputs (env; all optional — absent values are recorded as "absent"):
#   VERSION RC REVISION
#   RC_MANIFEST STABLE_MANIFEST ROLLBACK_MANIFEST PROMOTION_JOURNAL  (file paths)
#   CI_RUN_ID SCAN_RUN_ID PUBLISH_RUN_ID PROMOTION_RUN_ID RELEASE_RUN_ID
#   SIG_RESULT SBOM_RESULT PROV_RESULT OCIREV_RESULT ARCH_RESULT RUNTIME_RESULT
#   VULN_RESULT ROLLBACK_EXERCISE ENV_CONFIG
# =============================================================================
set -euo pipefail
_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/release-manifest.sh
. "$_d/lib/release-manifest.sh"
# shellcheck source=lib/cosign-identity.sh
. "$_d/lib/cosign-identity.sh"

OUT="${1:?usage: build-release-evidence.sh <out-dir>}"
mkdir -p "$OUT"

_ck() { [ -f "$1" ] && checksum_file "$1" || echo "absent"; }

VERSION="${VERSION:-}" ; RC="${RC:-}" ; REVISION="${REVISION:-}"
require_calver "$VERSION"; require_rc "$RC"; require_hex40 "$REVISION"

RC_ID="$(identity_re_for_role rc-publisher 2>/dev/null || echo 'unknown')"
ISSUER="$(issuer_from_policy 2>/dev/null || echo 'unknown')"

VERSION="$VERSION" RC="$RC" REVISION="$REVISION" \
RC_MANIFEST_CK="$(_ck "${RC_MANIFEST:-}")" STABLE_MANIFEST_CK="$(_ck "${STABLE_MANIFEST:-}")" \
ROLLBACK_CK="$(_ck "${ROLLBACK_MANIFEST:-}")" JOURNAL_CK="$(_ck "${PROMOTION_JOURNAL:-}")" \
CI_RUN_ID="${CI_RUN_ID:-absent}" SCAN_RUN_ID="${SCAN_RUN_ID:-absent}" \
PUBLISH_RUN_ID="${PUBLISH_RUN_ID:-absent}" PROMOTION_RUN_ID="${PROMOTION_RUN_ID:-absent}" \
RELEASE_RUN_ID="${RELEASE_RUN_ID:-absent}" \
SIG_RESULT="${SIG_RESULT:-absent}" SBOM_RESULT="${SBOM_RESULT:-absent}" PROV_RESULT="${PROV_RESULT:-absent}" \
OCIREV_RESULT="${OCIREV_RESULT:-absent}" ARCH_RESULT="${ARCH_RESULT:-absent}" RUNTIME_RESULT="${RUNTIME_RESULT:-absent}" \
VULN_RESULT="${VULN_RESULT:-absent}" ROLLBACK_EXERCISE="${ROLLBACK_EXERCISE:-absent}" ENV_CONFIG="${ENV_CONFIG:-absent}" \
RC_ID="$RC_ID" ISSUER="$ISSUER" CREATED_AT="${CREATED_AT:-$(date -u +%FT%TZ)}" \
python3 - "$OUT" <<'PY'
import os, json, sys
o = sys.argv[1]
e = {
  "release": os.environ["VERSION"], "candidate": os.environ["RC"], "revision": os.environ["REVISION"],
  "created_at": os.environ["CREATED_AT"],
  "governance": {"model": "solo-maintainer", "human_reviewers_required": 0},
  "identity": {"rc_publisher_regexp": os.environ["RC_ID"], "issuer": os.environ["ISSUER"]},
  "artifacts": {
    "rc_manifest_sha256": os.environ["RC_MANIFEST_CK"],
    "stable_manifest_sha256": os.environ["STABLE_MANIFEST_CK"],
    "rollback_manifest_sha256": os.environ["ROLLBACK_CK"],
    "promotion_journal_sha256": os.environ["JOURNAL_CK"],
  },
  "runs": {k: os.environ[k] for k in
           ("CI_RUN_ID","SCAN_RUN_ID","PUBLISH_RUN_ID","PROMOTION_RUN_ID","RELEASE_RUN_ID")},
  "verification": {k.lower(): os.environ[k] for k in
           ("SIG_RESULT","SBOM_RESULT","PROV_RESULT","OCIREV_RESULT","ARCH_RESULT","RUNTIME_RESULT","VULN_RESULT")},
  "rollback_exercise": os.environ["ROLLBACK_EXERCISE"],
  "environment_config": os.environ["ENV_CONFIG"],
}
json.dump(e, open(f"{o}/evidence.json","w"), indent=2, sort_keys=True)

md = [f"# Release evidence — {e['release']} ({e['candidate']})", "",
      f"- Revision: `{e['revision']}`", f"- Created: {e['created_at']}",
      f"- Governance: {e['governance']['model']} (human reviewers required: {e['governance']['human_reviewers_required']})",
      f"- Publisher identity: `{e['identity']['rc_publisher_regexp']}`",
      f"- Issuer: `{e['identity']['issuer']}`", "", "## Artifacts (sha256)"]
md += [f"- {k}: `{v}`" for k,v in e["artifacts"].items()]
md += ["", "## Workflow runs"] + [f"- {k}: {v}" for k,v in e["runs"].items()]
md += ["", "## Verification results"] + [f"- {k}: {v}" for k,v in e["verification"].items()]
md += ["", f"- rollback exercise: {e['rollback_exercise']}", f"- environment config: {e['environment_config']}"]
open(f"{o}/EVIDENCE.md","w").write("\n".join(md)+"\n")
PY

# checksum the machine-readable evidence
checksum_file "$OUT/evidence.json" > "$OUT/evidence.json.sha256"

# consumer VERIFY.md from the template, exact identity substituted
if [ -f "$_d/../templates/VERIFY.md" ]; then
  # NB: '#' delimiter, not '|' — the rc-publisher identity regexp contains a '|'
  # (the publish-(ghcr|rc) alternation) which would break an s|…|…| substitution.
  sed -e "s#{{RELEASE}}#$VERSION#g" -e "s#{{REVISION}}#$REVISION#g" \
      -e "s#{{ISSUER}}#$ISSUER#g" -e "s#{{IDENTITY}}#$RC_ID#g" \
      "$_d/../templates/VERIFY.md" > "$OUT/VERIFY.md"
fi
echo "wrote $OUT/{evidence.json,evidence.json.sha256,EVIDENCE.md,VERIFY.md}"
