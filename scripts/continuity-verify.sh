#!/usr/bin/env bash
# =============================================================================
# scripts/continuity-verify.sh — mirror consistency verifier + offline drill.
# -----------------------------------------------------------------------------
# policies/continuity.yaml has named this file as `restore.verification` since
# the continuity work landed. It did not exist. A policy pointing at an absent
# verifier is worse than one pointing at nothing, because it reads as though
# restoration is checked.
#
# What it verifies, between two OCI layouts (a source and its mirror):
#
#   1. both are real OCI layouts, not directories that look like one
#   2. every manifest the source publishes is PRESENT in the mirror
#   3. every mirrored manifest digest EQUALS the source digest
#   4. every referenced blob — config and layers, transitively — is present
#   5. every blob's CONTENT still hashes to the digest naming it
#
# (5) is the one that matters and the one a digest list cannot give you. A
# mirror can hold the right digest names over corrupted bytes; then the failover
# everybody rehearsed serves garbage that no signature covers. Content is
# rehashed here, not assumed.
#
# `--drill` runs a real disaster exercise OFFLINE: no docker, no network, no
# registry. It builds an OCI layout, mirrors it digest-preserving, verifies
# equality, then SABOTAGES the mirror and proves the verifier refuses. A drill
# that only ever passes has not tested anything.
#
# THIS IS NOT A MIRROR. No independent mirror is provisioned (#116) — this
# verifies the mechanism that a mirror would use, against local layouts.
#
# Usage:
#   continuity-verify.sh --verify <src-layout> <dst-layout>
#   continuity-verify.sh --drill [workdir]
#   continuity-verify.sh --self-test
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MIRROR_POLICY="${MIRROR_POLICY:-$ROOT/policies/continuity-mirror.yaml}"

usage() {
  sed -n '30,33p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 64
}

# -----------------------------------------------------------------------------
# verify <src> <dst>
# -----------------------------------------------------------------------------
verify() {
  SRC="$1" DST="$2" python3 <<'PY'
import hashlib, json, os, sys

src, dst = os.environ["SRC"], os.environ["DST"]
problems = []

def load_layout(path, role):
    if not os.path.isdir(path):
        problems.append("%s layout %s does not exist" % (role, path))
        return None
    marker = os.path.join(path, "oci-layout")
    if not os.path.isfile(marker):
        problems.append("%s %s is not an OCI layout (no oci-layout marker)" % (role, path))
        return None
    idx = os.path.join(path, "index.json")
    if not os.path.isfile(idx):
        problems.append("%s %s has no index.json" % (role, path))
        return None
    try:
        with open(idx) as fh:
            return json.load(fh)
    except ValueError as e:
        problems.append("%s %s has an unreadable index.json: %s" % (role, path, e))
        return None

def blob_path(root, digest):
    algo, _, hexd = digest.partition(":")
    return os.path.join(root, "blobs", algo, hexd)

def read_blob(root, digest, role, referrer):
    """Return blob bytes, verifying the content hashes to its own digest."""
    p = blob_path(root, digest)
    if not os.path.isfile(p):
        problems.append("%s: blob %s is MISSING (referenced by %s)" % (role, digest, referrer))
        return None
    with open(p, "rb") as fh:
        data = fh.read()
    algo = digest.split(":", 1)[0]
    try:
        actual = hashlib.new(algo, data).hexdigest()
    except ValueError:
        problems.append("%s: blob %s uses unsupported algorithm %r" % (role, digest, algo))
        return None
    if actual != digest.split(":", 1)[1]:
        # The whole point. Right name, wrong bytes.
        problems.append(
            "%s: blob %s is CORRUPT — content hashes to %s:%s"
            % (role, digest, algo, actual))
        return None
    return data

def walk(root, digest, role, referrer, seen):
    """Verify a manifest and everything it references, transitively."""
    if digest in seen:
        return
    seen.add(digest)
    data = read_blob(root, digest, role, referrer)
    if data is None:
        return
    try:
        doc = json.loads(data)
    except ValueError:
        return   # a non-JSON blob is a layer, already content-verified
    for child in doc.get("manifests") or []:
        if child.get("digest"):
            walk(root, child["digest"], role, digest, seen)
    cfg = doc.get("config") or {}
    if cfg.get("digest"):
        read_blob(root, cfg["digest"], role, digest)
    for layer in doc.get("layers") or []:
        if layer.get("digest"):
            read_blob(root, layer["digest"], role, digest)

src_idx = load_layout(src, "source")
dst_idx = load_layout(dst, "mirror")

if src_idx is not None and dst_idx is not None:
    src_manifests = {m["digest"]: m for m in (src_idx.get("manifests") or []) if m.get("digest")}
    dst_manifests = {m["digest"]: m for m in (dst_idx.get("manifests") or []) if m.get("digest")}

    if not src_manifests:
        problems.append("source layout publishes NO manifests — an empty export is not a backup")

    for dg in sorted(src_manifests):
        if dg not in dst_manifests:
            problems.append("mirror is MISSING manifest %s present in the source" % dg)
            continue
        s, d = src_manifests[dg], dst_manifests[dg]
        if s.get("size") is not None and d.get("size") is not None and s["size"] != d["size"]:
            problems.append("manifest %s size differs: source %s, mirror %s"
                            % (dg, s["size"], d["size"]))
        walk(src, dg, "source", "index.json", set())
        walk(dst, dg, "mirror", "index.json", set())

    for dg in sorted(dst_manifests):
        if dg not in src_manifests:
            # Not fatal to recoverability, but a mirror holding artefacts the
            # source never published is a provenance question, not a detail.
            problems.append("mirror holds manifest %s that the source does not publish" % dg)

    n = len(src_manifests)
else:
    n = 0

if problems:
    sys.stderr.write("REFUSE: mirror is not a faithful copy of the source — %d problem(s):\n"
                     % len(problems))
    for p in problems:
        sys.stderr.write("  - %s\n" % p)
    sys.stderr.write("\n  A failover onto this mirror would not serve what was released.\n")
    raise SystemExit(1)

print("mirror consistency OK: %d manifest(s), every digest equal, every blob rehashed" % n)
PY
}

# -----------------------------------------------------------------------------
# make_layout <dir> — build a small but REAL OCI layout, offline.
# -----------------------------------------------------------------------------
make_layout() {
  LAYOUT="$1" python3 <<'PY'
import hashlib, json, os

root = os.environ["LAYOUT"]
blobs = os.path.join(root, "blobs", "sha256")
os.makedirs(blobs, exist_ok=True)

def put(data):
    if isinstance(data, str):
        data = data.encode()
    h = hashlib.sha256(data).hexdigest()
    with open(os.path.join(blobs, h), "wb") as fh:
        fh.write(data)
    return "sha256:" + h, len(data)

manifests = []
for name in ("php-fpm-8.4", "nginx-prod"):
    layer_d, layer_s = put(("layer bytes for %s" % name) * 32)
    cfg_d, cfg_s = put(json.dumps({
        "architecture": "amd64", "os": "linux",
        "rootfs": {"type": "layers", "diff_ids": [layer_d]},
    }, sort_keys=True))
    man = json.dumps({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                   "digest": cfg_d, "size": cfg_s},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": layer_d, "size": layer_s}],
    }, sort_keys=True)
    man_d, man_s = put(man)
    manifests.append({
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "digest": man_d, "size": man_s,
        "annotations": {"org.opencontainers.image.ref.name": name},
    })

with open(os.path.join(root, "oci-layout"), "w") as fh:
    json.dump({"imageLayoutVersion": "1.0.0"}, fh)
with open(os.path.join(root, "index.json"), "w") as fh:
    json.dump({"schemaVersion": 2, "manifests": manifests}, fh, indent=2)
print(" ".join(m["digest"] for m in manifests))
PY
}

# -----------------------------------------------------------------------------
# mirror_copy <src> <dst> — digest-preserving copy.
# A copy that re-encodes anything changes the digest, and a changed digest
# breaks every pinned reference and invalidates every signature over the
# original. So this copies BYTES and re-uses the source index verbatim.
# -----------------------------------------------------------------------------
mirror_copy() {
  local src="$1" dst="$2"
  mkdir -p "$dst"
  cp -R "$src/blobs" "$dst/blobs"
  cp "$src/oci-layout" "$dst/oci-layout"
  cp "$src/index.json" "$dst/index.json"
}

# -----------------------------------------------------------------------------
# drill — the offline disaster exercise.
# -----------------------------------------------------------------------------
drill() {
  local work="${1:-}" owned=0 rc=0 ok=0 bad=0
  if [ -z "$work" ]; then work="$(mktemp -d)"; owned=1; fi
  mkdir -p "$work"

  d() { if eval "$2"; then echo "ok   - $1"; ok=$((ok + 1)); else echo "FAIL - $1"; bad=$((bad + 1)); fi; }

  echo "== continuity drill — LOCAL OCI layouts, offline =="
  echo "   No registry, no network, no mirror. This exercises the RESTORE"
  echo "   MECHANISM only. No independent mirror is provisioned (#116)."
  echo

  rm -rf "$work/source" "$work/mirror" "$work/tampered" "$work/truncated"
  echo "-- 1. build a source layout"
  make_layout "$work/source" >/dev/null || return 1
  d "the source is a valid OCI layout" "test -f '$work/source/oci-layout' && test -f '$work/source/index.json'"

  echo "-- 2. mirror it, preserving digests"
  mirror_copy "$work/source" "$work/mirror"
  d "every source digest is present in the mirror, byte for byte" \
    "verify '$work/source' '$work/mirror' >/dev/null 2>&1"

  echo "-- 3. sabotage: corrupt one blob, keep its name"
  mirror_copy "$work/source" "$work/tampered"
  python3 - "$work/tampered" <<'PY'
import os, sys, glob
# Overwrite the largest blob (a layer) with different bytes of the same length.
blobs = sorted(glob.glob(os.path.join(sys.argv[1], "blobs", "sha256", "*")),
               key=os.path.getsize, reverse=True)
with open(blobs[0], "rb") as fh:
    data = fh.read()
with open(blobs[0], "wb") as fh:
    fh.write(b"X" * len(data))
PY
  d "a mirror with the right digest over WRONG BYTES is refused" \
    "! verify '$work/source' '$work/tampered' >/dev/null 2>&1"
  verify "$work/source" "$work/tampered" >"$work/out" 2>&1 || true
  d "...and the refusal says the blob is CORRUPT" "grep -q 'is CORRUPT' '$work/out'"

  echo "-- 4. sabotage: drop a blob the index still references"
  mirror_copy "$work/source" "$work/truncated"
  python3 - "$work/truncated" <<'PY'
import os, sys, glob
blobs = sorted(glob.glob(os.path.join(sys.argv[1], "blobs", "sha256", "*")),
               key=os.path.getsize, reverse=True)
os.remove(blobs[0])
PY
  d "a mirror missing a referenced blob is refused" \
    "! verify '$work/source' '$work/truncated' >/dev/null 2>&1"
  verify "$work/source" "$work/truncated" >"$work/out" 2>&1 || true
  d "...and the refusal names it MISSING" "grep -q 'is MISSING' '$work/out'"

  echo "-- 5. sabotage: an empty directory is not a mirror"
  mkdir -p "$work/empty"
  d "an empty directory is refused, never reported as a clean mirror" \
    "! verify '$work/source' '$work/empty' >/dev/null 2>&1"

  echo "-- 6. the policy must still say no independent mirror exists"
  d "the drill cannot be mistaken for evidence that a mirror was created" \
    "python3 -c \"
import yaml
m = yaml.safe_load(open('$MIRROR_POLICY'))
assert m['mirror']['status'] == 'not-provisioned', m['mirror']['status']
assert m['mirror']['independent'] is False, m['mirror']
\""

  echo
  printf 'continuity drill: %d ok, %d failed\n' "$ok" "$bad"
  [ "$bad" -eq 0 ] || rc=1
  [ "$owned" -eq 1 ] && rm -rf "$work"
  return "$rc"
}

# -----------------------------------------------------------------------------
# assert_mirror_claims — the refusal for an intentionally unsupported state.
#
# No independent mirror exists, so every artifact class in
# policies/continuity-mirror.yaml carries `mirrored: false`. That value is not
# a chore to be tidied up: `mirrored: true` on any class would be a false
# statement about where a copy is held, and it is the one field a reader checks
# during the outage the plan exists for. It cannot become true by being
# written, so writing it REFUSES here rather than being silently believed.
#
# The refusal is symmetric: claiming a provisioned mirror while the mirror
# block still says not-provisioned is refused too, so the two cannot drift
# apart in either direction.
assert_mirror_claims() {
  python3 - "$MIRROR_POLICY" <<'PY'
import sys, yaml
m = yaml.safe_load(open(sys.argv[1])) or {}
status = (m.get("mirror") or {}).get("status")
classes = m["critical_release_inventory"]["artifact_classes"]
claimed = sorted(c["id"] for c in classes if c.get("mirrored"))
rule = m.get("mirrored_claims") or {}
if not rule.get("permitted_only_when"):
    print("REFUSE: policies/continuity-mirror.yaml states no rule for when a "
          "class may claim to be mirrored. A flag with no stated precondition "
          "is a flag anybody may set", file=sys.stderr)
    sys.exit(1)
if claimed and status != "provisioned":
    print("REFUSE: %d artifact class(es) claim mirrored: true while "
          "mirror.status is %r: %s. No independent mirror exists, so this is a "
          "false statement about where a copy is held — and it is the field a "
          "reader checks during the outage continuity exists for. Provision a "
          "mirror (policies/continuity-mirror.yaml required_human_decisions) "
          "before setting it" % (len(claimed), status, ", ".join(claimed)),
          file=sys.stderr)
    sys.exit(1)
if status == "provisioned" and not claimed:
    print("REFUSE: mirror.status is 'provisioned' and no artifact class claims "
          "to be mirrored. A provisioned mirror holding nothing is not a "
          "mirror", file=sys.stderr)
    sys.exit(1)
if (m.get("mirror") or {}).get("independent") and status != "provisioned":
    print("REFUSE: mirror.independent is true while mirror.status is %r"
          % status, file=sys.stderr)
    sys.exit(1)
print("ok - mirror claims are consistent with mirror.status=%s (%d class(es) "
      "claim to be mirrored)" % (status, len(claimed)))
PY
}

# -----------------------------------------------------------------------------
self_test() {
  local fail=0 tmp
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" EXIT
  ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

  ck "the offline drill runs and passes end to end" "drill '$tmp/drill' >/dev/null 2>&1"

  # --- the mirrored-claim refusal -------------------------------------------
  ck "the committed mirror policy's claims are consistent with its status" \
     "assert_mirror_claims >/dev/null 2>&1"
  python3 - "$MIRROR_POLICY" "$tmp/claimed.yaml" <<'PY'
import sys, yaml
m = yaml.safe_load(open(sys.argv[1]))
for c in m["critical_release_inventory"]["artifact_classes"]:
    if c["id"] == "evidence-bundle":
        c["mirrored"] = True
yaml.safe_dump(m, open(sys.argv[2], "w"))
PY
  ck "SABOTAGE: a class claiming mirrored: true with no mirror is REFUSED" \
     "! ( MIRROR_POLICY='$tmp/claimed.yaml' assert_mirror_claims ) >/dev/null 2>&1"
  # here-string, NOT a pipe: `cmd | grep -q` makes grep exit on the first match,
  # the producer take SIGPIPE, and pipefail report 141 — intermittently.
  ck "...naming the class and the status that contradicts it" \
     "grep -q 'evidence-bundle' <<<\"\$( ( MIRROR_POLICY='$tmp/claimed.yaml' assert_mirror_claims ) 2>&1 )\""
  python3 - "$MIRROR_POLICY" "$tmp/norule.yaml" <<'PY'
import sys, yaml
m = yaml.safe_load(open(sys.argv[1]))
m.pop("mirrored_claims", None)
yaml.safe_dump(m, open(sys.argv[2], "w"))
PY
  ck "SABOTAGE: deleting the rule itself is REFUSED, not treated as permission" \
     "! ( MIRROR_POLICY='$tmp/norule.yaml' assert_mirror_claims ) >/dev/null 2>&1"
  ck "NON-VACUOUS: the unmodified policy still passes after both sabotages" \
     "assert_mirror_claims >/dev/null 2>&1"

  # --- the governance surface travels ---------------------------------------
  ck "the governance surface exports as a bound set" \
     "bash '$ROOT/scripts/continuity-export.sh' --export-governance '$tmp/gov' >/dev/null 2>&1"
  ck "...covering schemas, policies AND the offline verifiers" \
     "python3 -c 'import json,sys
m=json.load(open(sys.argv[1]))
ids={f[\"artifact_class\"] for f in m[\"files\"]}
sys.exit(0 if {\"schemas\",\"policies\",\"verification-tools\"} <= ids else 1)' \
        '$tmp/gov/GOVERNANCE-MANIFEST.json'"
  ck "...and the restored copy revalidates" \
     "bash '$ROOT/scripts/continuity-export.sh' --verify-governance '$tmp/gov' >/dev/null 2>&1"
  cp -R "$tmp/gov" "$tmp/gov-moved"
  ck "NON-VACUOUS: relocating the whole export still revalidates" \
     "bash '$ROOT/scripts/continuity-export.sh' --verify-governance '$tmp/gov-moved' >/dev/null 2>&1"
  cp -R "$tmp/gov" "$tmp/gov-short" \
    && rm -f "$tmp/gov-short/files/schemas/vex-openvex-v1.schema.json"
  ck "SABOTAGE: a restoration missing ONE bound artifact is REFUSED" \
     "! bash '$ROOT/scripts/continuity-export.sh' --verify-governance '$tmp/gov-short' >/dev/null 2>&1"
  ck "...naming the artifact that did not come back" \
     "grep -q 'vex-openvex-v1.schema.json' <<<\"\$( bash '$ROOT/scripts/continuity-export.sh' --verify-governance '$tmp/gov-short' 2>&1 )\""
  cp -R "$tmp/gov" "$tmp/gov-drift" \
    && printf '\n' >> "$tmp/gov-drift/files/policies/retention.yaml"
  ck "SABOTAGE: a restored artifact whose bytes drifted is REFUSED" \
     "! bash '$ROOT/scripts/continuity-export.sh' --verify-governance '$tmp/gov-drift' >/dev/null 2>&1"

  make_layout "$tmp/a" >/dev/null
  mirror_copy "$tmp/a" "$tmp/b"
  ck "an identical copy verifies" "verify '$tmp/a' '$tmp/b' >/dev/null 2>&1"
  ck "...and reports that blobs were rehashed, not assumed" \
     "verify '$tmp/a' '$tmp/b' >'$tmp/o' 2>&1; grep -q 'every blob rehashed' '$tmp/o'"

  # A directory that merely looks like a layout must not pass.
  mkdir -p "$tmp/fake/blobs/sha256"
  cp "$tmp/a/index.json" "$tmp/fake/index.json"
  ck "a directory with no oci-layout marker is refused" \
     "! verify '$tmp/a' '$tmp/fake' >/dev/null 2>&1"

  # A mirror missing an entire manifest.
  mirror_copy "$tmp/a" "$tmp/short"
  python3 -c "
import json
p='$tmp/short/index.json'
d=json.load(open(p)); d['manifests']=d['manifests'][:1]
json.dump(d,open(p,'w'))"
  ck "a mirror missing a whole manifest is refused" \
     "! verify '$tmp/a' '$tmp/short' >/dev/null 2>&1"
  ck "...naming the missing manifest" \
     "verify '$tmp/a' '$tmp/short' >'$tmp/o' 2>&1 || true; grep -q 'MISSING manifest' '$tmp/o'"

  # A mirror holding something the source never published. make_layout is
  # deterministic, so a second layout would carry the SAME digests and dedupe
  # away — the extra entry has to be a digest the source genuinely lacks.
  mirror_copy "$tmp/a" "$tmp/extra"
  python3 -c "
import json
p='$tmp/extra/index.json'
d=json.load(open(p))
d['manifests'].append({
    'mediaType':'application/vnd.oci.image.manifest.v1+json',
    'digest':'sha256:'+'ab'*32, 'size':123,
    'annotations':{'org.opencontainers.image.ref.name':'smuggled'}})
json.dump(d,open(p,'w'))"
  ck "a mirror holding an unpublished manifest is reported" \
     "! verify '$tmp/a' '$tmp/extra' >/dev/null 2>&1"

  ck "a nonexistent source is refused" "! verify '$tmp/nope' '$tmp/b' >/dev/null 2>&1"
  ck "an empty index publishes nothing and is refused" \
     "mkdir -p '$tmp/nul/blobs/sha256'; cp '$tmp/a/oci-layout' '$tmp/nul/oci-layout';
      echo '{\"schemaVersion\":2,\"manifests\":[]}' >'$tmp/nul/index.json';
      ! verify '$tmp/nul' '$tmp/nul' >/dev/null 2>&1"

  ck "the mirror manifest is valid YAML and declares no mirror" \
     "python3 -c \"
import yaml;m=yaml.safe_load(open('$MIRROR_POLICY'))
assert m['mirror']['status']=='not-provisioned'
assert m['mirror']['endpoint'] is None\""

  echo "----"
  if [ "$fail" -eq 0 ]; then echo "continuity-verify: SELF-TEST OK"; else echo "continuity-verify: SELF-TEST FAILED"; fi
  return "$fail"
}

case "${1:-}" in
  --verify)    shift; [ $# -eq 2 ] || usage; verify "$1" "$2" ;;
  --drill)     shift; drill "${1:-}" ;;
  --assert-mirror-claims) assert_mirror_claims ;;
  --self-test) self_test ;;
  *) usage ;;
esac
