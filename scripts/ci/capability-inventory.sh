#!/usr/bin/env bash
# =============================================================================
# scripts/ci/capability-inventory.sh
# -----------------------------------------------------------------------------
# Final-image file-capability inventory + gate (#100).
#
# The runtime contract is ZERO Linux capabilities: images run under
# `cap_drop: ALL` + `no-new-privileges`, where a binary carrying a file
# capability cannot even be exec'd ("operation not permitted"). The Dockerfiles
# now remove capabilities fail-closed and prove it mid-build, but that proof
# covers only the layer it runs in — and for php-frankenphp the verifier
# (libcap2-bin) is purged before the image is finished.
#
# This script verifies the ASSEMBLED image from outside, needing NO tools inside
# it. `docker export` writes file capabilities as PAX records
# (`SCHILY.xattr.security.capability`), so the inventory is read straight from
# the exported filesystem — which is why it works identically for Alpine, Debian,
# and any future distroless image with no shell at all.
#
# Usage:
#   capability-inventory.sh <image-ref> [--json <file>]
#   capability-inventory.sh --self-test
#
# Exit: 0 = no file capabilities, 1 = capabilities found or the scan failed.
# A missing docker, a failed export, or an unreadable archive is a FAILURE —
# never an empty inventory reported as clean.
# =============================================================================
set -euo pipefail

# Capability bits we can name; anything else is reported by number rather than
# silently dropped. Source: linux/capability.h.
readonly CAP_NAMES_PY='
CAP_NAMES = {
    0: "chown", 1: "dac_override", 2: "dac_read_search", 3: "fowner", 4: "fsetid",
    5: "kill", 6: "setgid", 7: "setuid", 8: "setpcap", 9: "linux_immutable",
    10: "net_bind_service", 11: "net_broadcast", 12: "net_admin", 13: "net_raw",
    14: "ipc_lock", 15: "ipc_owner", 16: "sys_module", 17: "sys_rawio",
    18: "sys_chroot", 19: "sys_ptrace", 20: "sys_pacct", 21: "sys_admin",
    22: "sys_boot", 23: "sys_nice", 24: "sys_resource", 25: "sys_time",
    26: "sys_tty_config", 27: "mknod", 28: "lease", 29: "audit_write",
    30: "audit_control", 31: "setfcap", 32: "mac_override", 33: "mac_admin",
    34: "syslog", 35: "wake_alarm", 36: "block_suspend", 37: "audit_read",
    38: "perfmon", 39: "bpf", 40: "checkpoint_restore",
}
'

usage() { echo "usage: $(basename "$0") <image-ref> [--json <file>] | --self-test" >&2; exit 1; }

# scan_tar <tar> <image-ref> [json-out] -> prints report, returns 1 if any caps.
scan_tar() {
  TAR="$1" IMAGE="$2" JSON_OUT="${3:-}" python3 - <<PY
import json, os, sys, tarfile
${CAP_NAMES_PY}

def decode(blob):
    """Decode a VFS_CAP_DATA xattr into capability names (v2/v3, little-endian)."""
    if isinstance(blob, str):
        blob = blob.encode("utf-8", "surrogateescape")
    if len(blob) < 12:
        return ["<malformed>"], None
    magic = int.from_bytes(blob[0:4], "little")
    revision, effective = magic & 0xFF000000, bool(magic & 0x000001)
    permitted = int.from_bytes(blob[4:8], "little")
    inheritable = int.from_bytes(blob[8:12], "little")
    if len(blob) >= 20:  # 64-bit: second word of each set
        permitted |= int.from_bytes(blob[12:16], "little") << 32
        inheritable |= int.from_bytes(blob[16:20], "little") << 32
    caps = []
    for bit in range(64):
        if permitted & (1 << bit) or inheritable & (1 << bit):
            caps.append(CAP_NAMES.get(bit, "cap_%d" % bit))
    return caps, effective

tar, image, out = os.environ["TAR"], os.environ["IMAGE"], os.environ.get("JSON_OUT") or ""
findings = []
try:
    with tarfile.open(tar) as t:
        for m in t:
            for key, value in (m.pax_headers or {}).items():
                if key.endswith("security.capability"):
                    caps, eff = decode(value)
                    findings.append({"path": "/" + m.name.lstrip("./"),
                                     "capabilities": caps, "effective": eff})
except Exception as exc:                       # unreadable archive == failure
    print("REFUSE: cannot read exported filesystem: %s" % exc, file=sys.stderr)
    sys.exit(1)

findings.sort(key=lambda f: f["path"])
report = {"image": image, "file_capabilities": findings,
          "count": len(findings), "verdict": "PASS" if not findings else "FAIL"}
if out:
    with open(out, "w") as fh:
        json.dump(report, fh, indent=2)
        fh.write("\n")
    print("inventory written: %s" % out)

if findings:
    print("REFUSE: %d file(s) carry Linux capabilities in %s:" % (len(findings), image), file=sys.stderr)
    for f in findings:
        print("  %s -> %s%s" % (f["path"], ",".join(f["capabilities"]),
                                " (effective)" if f["effective"] else ""), file=sys.stderr)
    sys.exit(1)
print("PASS: no file capabilities in %s" % image)
PY
}

inventory() {
  local image="$1" json_out="${2:-}" cid tmp rc=0
  command -v docker >/dev/null || { echo "REFUSE: docker is required to inventory '${image}'" >&2; return 1; }
  docker image inspect "$image" >/dev/null 2>&1 \
    || { echo "REFUSE: image '${image}' is not present locally" >&2; return 1; }

  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064  # expand now: $tmp must be captured at trap time
  trap "rm -rf '${tmp}'" RETURN

  cid="$(docker create "$image")" \
    || { echo "REFUSE: could not create a container from '${image}'" >&2; return 1; }
  if ! docker export "$cid" > "${tmp}/fs.tar"; then
    docker rm -f "$cid" >/dev/null 2>&1 || true
    echo "REFUSE: docker export failed for '${image}'" >&2
    return 1
  fi
  docker rm -f "$cid" >/dev/null 2>&1 || true

  [ -s "${tmp}/fs.tar" ] || { echo "REFUSE: exported filesystem is empty for '${image}'" >&2; return 1; }

  scan_tar "${tmp}/fs.tar" "$image" "$json_out" || rc=1
  return "$rc"
}

# Offline fixture tests of the decoder + the fail-closed paths. No docker needed.
self_test() {
  local ok=0 bad=0 tmp
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '${tmp}'" RETURN
  t() { if eval "$2"; then ok=$((ok+1)); echo "  ok   $1"; else bad=$((bad+1)); echo "  FAIL $1"; fi; }

  # Build tars carrying real VFS_CAP_DATA payloads.
  python3 - "$tmp" <<'PY'
import io, sys, tarfile
d = sys.argv[1]

def make(path, entries):
    with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as t:
        for name, blob in entries:
            info = tarfile.TarInfo(name)
            info.size = 0
            if blob is not None:
                info.pax_headers = {"SCHILY.xattr.security.capability":
                                    blob.decode("utf-8", "surrogateescape")}
            t.addfile(info, io.BytesIO(b""))

# v2 magic 0x02000000 | effective bit; permitted = CAP_NET_BIND_SERVICE (bit 10)
netbind = (0x02000001).to_bytes(4, "little") + (1 << 10).to_bytes(4, "little") \
          + (0).to_bytes(4, "little") + (0).to_bytes(8, "little")
# CAP_SYS_ADMIN (bit 21), not effective
sysadmin = (0x02000000).to_bytes(4, "little") + (1 << 21).to_bytes(4, "little") \
           + (0).to_bytes(4, "little") + (0).to_bytes(8, "little")

make(d + "/clean.tar",   [("usr/bin/caddy", None), ("bin/sh", None)])
make(d + "/netbind.tar", [("usr/bin/caddy", netbind)])
make(d + "/two.tar",     [("usr/bin/caddy", netbind), ("usr/sbin/x", sysadmin)])
open(d + "/broken.tar", "wb").write(b"not a tar archive at all")
PY

  # `set -o pipefail` is on, so `scan_tar ... | grep` would report scan_tar's
  # (intended) non-zero exit rather than grep's verdict. Capture, then match.
  say() { scan_tar "$1" img 2>&1 || true; }

  t "clean image passes"                 "scan_tar '$tmp/clean.tar' img >/dev/null"
  t "cap_net_bind_service is rejected"   "! scan_tar '$tmp/netbind.tar' img >/dev/null 2>&1"
  t "names the capability it found"      "say '$tmp/netbind.tar' | grep -q net_bind_service"
  t "reports the offending path"         "say '$tmp/netbind.tar' | grep -q '/usr/bin/caddy'"
  t "decodes a second, non-effective cap" "say '$tmp/two.tar' | grep -q sys_admin"
  t "counts every offender"              "! scan_tar '$tmp/two.tar' img >/dev/null 2>&1"
  t "unreadable archive FAILS closed"    "! scan_tar '$tmp/broken.tar' img >/dev/null 2>&1"
  t "writes machine-readable JSON"       "scan_tar '$tmp/clean.tar' img '$tmp/o.json' >/dev/null && python3 -c \"
import json;d=json.load(open('$tmp/o.json'));assert d['verdict']=='PASS' and d['count']==0\""
  t "JSON records the finding on failure" "! scan_tar '$tmp/netbind.tar' img '$tmp/f.json' >/dev/null 2>&1; python3 -c \"
import json;d=json.load(open('$tmp/f.json'))
assert d['verdict']=='FAIL' and d['count']==1
assert d['file_capabilities'][0]['capabilities']==['net_bind_service']
assert d['file_capabilities'][0]['effective'] is True\""
  t "missing image FAILS closed"         "! inventory 'zenchron-nonexistent/nope:none' >/dev/null 2>&1"

  echo "self-test: $ok ok, $bad failed"
  [ "$bad" -eq 0 ]
}

main() {
  [ $# -ge 1 ] || usage
  [ "$1" = "--self-test" ] && { self_test; return $?; }
  local image="$1" json=""; shift
  while [ $# -gt 0 ]; do
    case "$1" in
      --json) json="${2:?--json needs a path}"; shift 2 ;;
      *) usage ;;
    esac
  done
  inventory "$image" "$json"
}

main "$@"
