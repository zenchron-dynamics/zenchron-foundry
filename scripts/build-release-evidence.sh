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
#
# The publisher identity + issuer are resolved from the cosign identity policy
# and are HARD requirements: an unresolvable identity refuses (never recorded
# as "unknown" — evidence with an unknown signer identity is worthless).
# =============================================================================
set -euo pipefail
_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/release-manifest.sh
. "$_d/lib/release-manifest.sh"
# shellcheck source=lib/cosign-identity.sh
. "$_d/lib/cosign-identity.sh"

_ck() { [ -f "$1" ] && checksum_file "$1" || echo "absent"; }

build_evidence() {
  local OUT="${1:?usage: build-release-evidence.sh <out-dir>}"
  mkdir -p "$OUT"

  VERSION="${VERSION:-}" ; RC="${RC:-}" ; REVISION="${REVISION:-}"
  require_calver "$VERSION"; require_rc "$RC"; require_hex40 "$REVISION"

  # Fail closed: no "unknown" fallback — evidence must pin the exact identity.
  local RC_ID ISSUER
  RC_ID="$(identity_re_for_role rc-publisher)" || die "cannot resolve rc-publisher cosign identity"
  [ -n "$RC_ID" ] || die "empty rc-publisher cosign identity"
  ISSUER="$(issuer_from_policy)" || die "cannot resolve cosign OIDC issuer"
  [ -n "$ISSUER" ] || die "empty cosign OIDC issuer"

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
  local wrote_verify=0
  if [ -f "$_d/../templates/VERIFY.md" ]; then
    # NB: '#' delimiter, not '|' — the rc-publisher identity regexp contains a '|'
    # (the publish-(ghcr|rc) alternation) which would break an s|…|…| substitution.
    sed -e "s#{{RELEASE}}#$VERSION#g" -e "s#{{REVISION}}#$REVISION#g" \
        -e "s#{{ISSUER}}#$ISSUER#g" -e "s#{{IDENTITY}}#$RC_ID#g" \
        "$_d/../templates/VERIFY.md" > "$OUT/VERIFY.md"
    wrote_verify=1
  fi
  # Only claim VERIFY.md when it was actually written.
  if [ "$wrote_verify" = 1 ]; then
    echo "wrote $OUT/{evidence.json,evidence.json.sha256,EVIDENCE.md,VERIFY.md}"
  else
    warn "templates/VERIFY.md not found — consumer VERIFY.md NOT written"
    echo "wrote $OUT/{evidence.json,evidence.json.sha256,EVIDENCE.md}"
  fi
}

# --- self-test ---------------------------------------------------------------
_bre_self_test() {
  command -v python3 >/dev/null 2>&1 && command -v yq >/dev/null 2>&1 \
    || { echo "SKIP - python3/yq absent"; return 0; }
  local fail=0 tmp; tmp="$(mktemp -d)"
  local R=7b4985a1234567890abcdef1234567890abcdef1
  _t() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

  printf 'fixture-manifest\n' > "$tmp/rc.yaml"
  ( VERSION=v2026.07.03 RC=rc1 REVISION="$R" RC_MANIFEST="$tmp/rc.yaml" \
    SIG_RESULT=10/10 SBOM_RESULT=10/10 PROV_RESULT=10/10 OCIREV_RESULT=10/10 \
    ARCH_RESULT=10/10 RUNTIME_RESULT=10/10 VULN_RESULT=enforced \
    CREATED_AT=2026-07-03T12:00:00Z build_evidence "$tmp/out" ) >/dev/null 2>&1
  _t "build succeeds"            "[ $? -eq 0 ]"
  _t "evidence.json written"     'test -f "$tmp/out/evidence.json"'
  _t "checksum sidecar written"  'test -f "$tmp/out/evidence.json.sha256"'
  _t "EVIDENCE.md written"       'test -f "$tmp/out/EVIDENCE.md"'
  _t "checksum matches"          '[ "$(checksum_file "$tmp/out/evidence.json")" = "$(awk "{print \$1}" "$tmp/out/evidence.json.sha256")" ]'
  _t "release field recorded"    '[ "$(yq -r ".release" "$tmp/out/evidence.json")" = "v2026.07.03" ]'
  _t "revision field recorded"   '[ "$(yq -r ".revision" "$tmp/out/evidence.json")" = "'"$R"'" ]'
  _t "sig result recorded"       '[ "$(yq -r ".verification.sig_result" "$tmp/out/evidence.json")" = "10/10" ]'
  _t "rc manifest checksummed"   '[ "$(yq -r ".artifacts.rc_manifest_sha256" "$tmp/out/evidence.json")" = "$(checksum_file "$tmp/rc.yaml")" ]'
  _t "identity is never unknown" '! grep -q "\"unknown\"" "$tmp/out/evidence.json"'

  # negative: unreadable identity policy -> REFUSE (no 'unknown' fallback).
  # Runs in a fresh process so COSIGN_IDENTITY_POLICY is read at lib source time.
  if ( COSIGN_IDENTITY_POLICY="$tmp/no-such-policy.yaml" \
       VERSION=v2026.07.03 RC=rc1 REVISION="$R" \
       bash "${BASH_SOURCE[0]}" "$tmp/out2" ) >/dev/null 2>&1; then
    echo "FAIL - unreadable identity policy must refuse"; fail=1
  else
    echo "ok   - unreadable identity policy refuses"
  fi
  _t "no evidence written on refusal" '! test -f "$tmp/out2/evidence.json"'

  rm -rf "$tmp"; return $fail
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-}" in
    --self-test) _bre_self_test && echo "build-release-evidence.sh: SELF-TEST OK" ;;
    "") echo "usage: build-release-evidence.sh <out-dir> | --self-test" >&2; exit 2 ;;
    *) build_evidence "$1" ;;
  esac
fi
