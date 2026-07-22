#!/usr/bin/env bash
# =============================================================================
# scripts/validate-release-evidence.sh <evidence.json>
# -----------------------------------------------------------------------------
# Verifies an evidence package: checksum matches its sidecar, required keys are
# present, release/candidate/revision are well-formed, and no required
# verification result is "absent" (unless ALLOW_ABSENT=1 for a dry-run package).
# Counted verification results (sig/sbom/prov/ocirev/arch/runtime) must be a
# FULL count n/n with n>0 — a partial result like 9/10 REFUSES the seal.
# =============================================================================
set -euo pipefail
_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/release-manifest.sh
. "$_d/lib/release-manifest.sh"

validate_evidence() {
  local E="$1"
  [ -f "$E" ] || die "evidence not found: $E"

  if [ -f "$E.sha256" ]; then
    local want got
    want="$(awk '{print $1}' "$E.sha256")"; got="$(checksum_file "$E")"
    [ "$want" = "$got" ] || die "evidence checksum mismatch: $got != $want"
  fi

  ALLOW_ABSENT="${ALLOW_ABSENT:-0}" python3 - "$E" <<'PY'
import json, sys, re, os
e = json.load(open(sys.argv[1]))
errs = []
def need(path, val, pat=None):
    if val in (None, "", "absent"): errs.append(f"missing/absent: {path}")
    elif pat and not re.match(pat, str(val)): errs.append(f"malformed {path}: {val}")
need("release", e.get("release"), r"^v[0-9]{4}\.[0-9]{2}\.[0-9]{2}(\.[0-9]+)?$")
need("candidate", e.get("candidate"), r"^rc[1-9][0-9]*$")
need("revision", e.get("revision"), r"^[0-9a-f]{40}$")
for k in ("model",):
    if e.get("governance",{}).get(k) in (None,""): errs.append(f"missing governance.{k}")
for k in ("rc_publisher_regexp","issuer"):
    v = e.get("identity",{}).get(k)
    if not v or v == "unknown": errs.append(f"missing identity.{k}")
    if k == "rc_publisher_regexp" and v and "/.*" in v and not v.endswith("\\.yml@refs/heads/master$"):
        errs.append("identity.rc_publisher_regexp looks like a broad wildcard")
ver = e.get("verification") or {}
strict = os.environ.get("ALLOW_ABSENT") != "1"
COUNTED = ("sig_result","sbom_result","prov_result","ocirev_result","arch_result","runtime_result")
if strict:
    for k, v in ver.items():
        if v == "absent": errs.append(f"verification.{k} is absent")
    # a MISSING counted field is as disqualifying as an "absent" one
    for k in COUNTED + ("vuln_result",):
        if ver.get(k) in (None, "", "absent"): errs.append(f"verification.{k} is absent")
# Counted results must be a FULL pass: n/n with equal n and n > 0.
# 9/10 (a real partial count from the verifier) must REFUSE.
nn = re.compile(r"^([1-9][0-9]*)/\1$")
for k in COUNTED:
    v = ver.get(k)
    if v in (None, "", "absent"):
        continue  # absence is handled by the strict block above / ALLOW_ABSENT
    if not nn.match(str(v)):
        errs.append(f"verification.{k} '{v}' is not a full n/n pass (partial results refuse the seal)")
if errs:
    print("EVIDENCE INVALID:", file=sys.stderr)
    for x in errs: print("  - "+x, file=sys.stderr)
    sys.exit(1)
print(f"EVIDENCE VALID: {e['release']} {e['candidate']} @ {e['revision'][:12]}")
PY
}

# --- self-test ---------------------------------------------------------------
# The fixture is a hand-written literal evidence document — deliberately NOT
# produced by build-release-evidence.sh, so the validator is checked against
# independent data rather than its sibling's output.
_vre_self_test() {
  command -v python3 >/dev/null 2>&1 || { echo "SKIP - python3 absent"; return 0; }
  local fail=0 tmp; tmp="$(mktemp -d)"
  local R=7b4985a1234567890abcdef1234567890abcdef1
  cat > "$tmp/good.json" <<EOF
{
  "release": "v2026.07.03", "candidate": "rc1", "revision": "$R",
  "created_at": "2026-07-03T12:00:00Z",
  "governance": {"model": "solo-maintainer", "human_reviewers_required": 0},
  "identity": {
    "rc_publisher_regexp": "https://github.com/zenchron-dynamics/zenchron-foundry/\\\\.github/workflows/publish-rc\\\\.yml@refs/heads/master\$",
    "issuer": "https://token.actions.githubusercontent.com"
  },
  "artifacts": {"rc_manifest_sha256": "deadbeef"},
  "runs": {"RELEASE_RUN_ID": "1"},
  "verification": {
    "sig_result": "10/10", "sbom_result": "10/10", "prov_result": "10/10",
    "ocirev_result": "10/10", "arch_result": "10/10", "runtime_result": "10/10",
    "vuln_result": "enforced"
  },
  "rollback_exercise": "pass", "environment_config": "foundry-production"
}
EOF
  _mut() { python3 - "$1" "$2" <<'PY'    # apply a python expr `e` mutation
import sys, json
f, expr = sys.argv[1], sys.argv[2]
e = json.load(open(f)); exec(expr); json.dump(e, open(f, "w"))
PY
  }
  _ok() { if ( validate_evidence "$1" ) >/dev/null 2>&1; then echo "ok   - $2"; else echo "FAIL - $2 (expected valid)"; fail=1; fi; }
  _no() { if ( validate_evidence "$1" ) >/dev/null 2>&1; then echo "FAIL - $2 (expected reject)"; fail=1; else echo "ok   - $2"; fi; }

  _ok "$tmp/good.json" "full 10/10 evidence valid"
  cp "$tmp/good.json" "$tmp/p1.json"; _mut "$tmp/p1.json" 'e["verification"]["sig_result"]="9/10"'
  _no "$tmp/p1.json" "partial 9/10 signature refused"
  cp "$tmp/good.json" "$tmp/p2.json"; _mut "$tmp/p2.json" 'e["verification"]["runtime_result"]="9/10"'
  _no "$tmp/p2.json" "partial 9/10 runtime refused"
  cp "$tmp/good.json" "$tmp/p3.json"; _mut "$tmp/p3.json" 'e["verification"]["arch_result"]="0/0"'
  _no "$tmp/p3.json" "zero-count 0/0 refused"
  cp "$tmp/good.json" "$tmp/p4.json"; _mut "$tmp/p4.json" 'e["verification"]["prov_result"]="10/11"'
  _no "$tmp/p4.json" "mismatched 10/11 refused"
  cp "$tmp/good.json" "$tmp/ab.json"; _mut "$tmp/ab.json" 'e["verification"]["runtime_result"]="absent"'
  _no "$tmp/ab.json" "absent runtime refused (strict)"
  if ( ALLOW_ABSENT=1 validate_evidence "$tmp/ab.json" ) >/dev/null 2>&1; then
    echo "ok   - absent runtime allowed (dry-run)"
  else
    echo "FAIL - absent runtime allowed (dry-run)"; fail=1
  fi
  cp "$tmp/good.json" "$tmp/miss.json"; _mut "$tmp/miss.json" 'del e["verification"]["sbom_result"]'
  _no "$tmp/miss.json" "missing counted field refused (strict)"
  cp "$tmp/good.json" "$tmp/tamper.json"
  checksum_file "$tmp/good.json" > "$tmp/tamper.json.sha256"; printf '\n' >> "$tmp/tamper.json"
  _no "$tmp/tamper.json" "checksum tamper refused"
  rm -rf "$tmp"; return $fail
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-}" in
    --self-test) _vre_self_test && echo "validate-release-evidence.sh: SELF-TEST OK" ;;
    "") echo "usage: validate-release-evidence.sh <evidence.json> | --self-test" >&2; exit 2 ;;
    *) validate_evidence "$1" ;;
  esac
fi
