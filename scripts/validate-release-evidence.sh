#!/usr/bin/env bash
# =============================================================================
# scripts/validate-release-evidence.sh <evidence.json>
# -----------------------------------------------------------------------------
# Verifies an evidence package: checksum matches its sidecar, required keys are
# present, release/candidate/revision are well-formed, and no required
# verification result is "absent" (unless ALLOW_ABSENT=1 for a dry-run package).
# =============================================================================
set -euo pipefail
_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/release-manifest.sh
. "$_d/lib/release-manifest.sh"

E="${1:?usage: validate-release-evidence.sh <evidence.json>}"
[ -f "$E" ] || die "evidence not found: $E"

if [ -f "$E.sha256" ]; then
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
if os.environ.get("ALLOW_ABSENT") != "1":
    for k, v in (e.get("verification") or {}).items():
        if v == "absent": errs.append(f"verification.{k} is absent")
if errs:
    print("EVIDENCE INVALID:", file=sys.stderr)
    for x in errs: print("  - "+x, file=sys.stderr)
    sys.exit(1)
print(f"EVIDENCE VALID: {e['release']} {e['candidate']} @ {e['revision'][:12]}")
PY
