#!/usr/bin/env bash
# =============================================================================
# scripts/repro-lock.sh — record and re-check the DECLARED INPUTS of a build (#101).
#
# The lock serves guarantee 1 of the four in policies/reproducibility.yaml:
# "given a release, can the exact declared inputs be recovered and re-presented
# byte-identically at any later date". It records the other three guarantees'
# fields too, because they have to be written down somewhere — but RECORDING IS
# NOT CLAIMING. What each section may support is declared in the policy and
# enforced by scripts/repro-guarantees.sh.
#
#   emit    build a lock from the working tree plus a locally built image.
#           Needs docker. A registry lookup that fails is recorded as an
#           explicit null, never as a silently absent field.
#
#   verify  re-check a lock against a tree. OFFLINE, and this is the control:
#           it refuses on timestamp drift, context drift, base/helper drift, a
#           removed or altered integrity pin, a package fingerprint that does
#           not recompute, and a scanner that is not the inventory's scanner.
#           $ZFR_TREE overrides the tree that is checked against, so a sabotage
#           test can mutate a DISPOSABLE COPY instead of the live checkout.
#
#   digest  the lock's canonical digest with the volatile `generated_at`
#           removed. Evidence records bind to this value, so a measurement
#           cannot be carried across to a different set of declared inputs.
#
# Usage:
#   repro-lock.sh emit --context <dir> --family <f> --selector <s> \
#                      --platform linux/amd64 --image <ref> [--build-arg K=V]... \
#                      [--out <file>]
#   repro-lock.sh verify <lock.json>
#   repro-lock.sh digest <lock.json>
#   repro-lock.sh --self-test
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# common.sh brings `set -e`, which would abort this script at its first
# intentional refusal instead of letting it report every one. Turned back off
# immediately; -u and -o pipefail are re-asserted because they are wanted.
# shellcheck source=lib/common.sh
. "$ROOT/scripts/lib/common.sh"
set +e
set -uo pipefail

SCHEMA="$ROOT/schemas/build-input-lock-v1.schema.json"
REPO_SLUG="zenchron-dynamics/zenchron-foundry"

# --- the ONE definition of a context digest ---------------------------------
# emit and verify must compute this identically; if they ever diverged, verify
# would refuse every honest lock and the control would be switched off within a
# day. Mode is reduced to git's own two states (executable or not) so a
# different umask on a fresh checkout does not read as context drift.
context_digest() { # context_digest <dir>
  python3 - "$1" <<'PY'
import hashlib, os, sys
root = os.path.abspath(sys.argv[1])
if not os.path.isdir(root):
    sys.stderr.write("REFUSE: context is not a directory: %s\n" % root); sys.exit(2)
h = hashlib.sha256(); n = 0
for dirpath, dirnames, filenames in os.walk(root):
    dirnames.sort()
    for fn in sorted(filenames):
        p = os.path.join(dirpath, fn)
        if not os.path.isfile(p):
            continue
        rel = os.path.relpath(p, root)
        mode = "100755" if os.access(p, os.X_OK) else "100644"
        with open(p, "rb") as fh:
            fd = hashlib.sha256(fh.read()).hexdigest()
        h.update(("%s\0%s\0%s\n" % (rel, mode, fd)).encode())
        n += 1
if n == 0:
    sys.stderr.write("REFUSE: context contains no files: %s\n" % root); sys.exit(2)
print("sha256:" + h.hexdigest())
PY
}

file_digest() { # file_digest <file>
  python3 -c 'import hashlib,sys;print("sha256:"+hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$1"
}

# Canonical digest of a lock with `generated_at` removed: two locks describing
# the same declared inputs give the same value though written at different times.
lock_digest() { # lock_digest <lock.json>
  python3 - "$1" <<'PY'
import hashlib, json, sys
d = json.load(open(sys.argv[1]))
d.pop("generated_at", None)
print(hashlib.sha256(json.dumps(d, sort_keys=True, separators=(",", ":")).encode()).hexdigest())
PY
}

# =============================================================================
# emit — needs docker; produces a lock on stdout or --out
# =============================================================================
emit() {
  local ctx="" fam="" sel="" plat="" img="" out=""
  local -a bargs=()
  while [ $# -gt 0 ]; do
    case "$1" in
      --context)   ctx="${2:?}";  shift 2 ;;
      --family)    fam="${2:?}";  shift 2 ;;
      --selector)  sel="${2:?}";  shift 2 ;;
      --platform)  plat="${2:?}"; shift 2 ;;
      --image)     img="${2:?}";  shift 2 ;;
      --out)       out="${2:?}";  shift 2 ;;
      --build-arg) bargs+=("${2:?}"); shift 2 ;;
      *) echo "REFUSE: emit: unknown argument '$1'" >&2; return 64 ;;
    esac
  done
  local v
  for v in ctx fam sel plat img; do
    [ -n "${!v}" ] || { echo "REFUSE: emit: --${v} is required" >&2; return 64; }
  done
  [ -f "$ROOT/$ctx/Dockerfile" ] || { echo "REFUSE: no Dockerfile in $ctx" >&2; return 1; }
  docker image inspect "$img" >/dev/null 2>&1 \
    || { echo "REFUSE: no such local image: $img" >&2; return 1; }

  local sha epoch cdg ddg base_ref base_dig child
  sha="$(git -C "$ROOT" rev-parse HEAD)"
  is_hex40 "$sha" || { echo "REFUSE: could not resolve a 40-hex source revision" >&2; return 1; }
  epoch="$(git -C "$ROOT" log -1 --format=%ct "$sha")"
  cdg="$(context_digest "$ROOT/$ctx")" || return 1
  ddg="$(file_digest "$ROOT/$ctx/Dockerfile")"

  # The base as the Dockerfile declares it: the ARG is the single source of
  # truth each Dockerfile FROMs, so that is what gets recorded.
  base_ref="$(grep -Em1 '^ARG[[:space:]]+[A-Z_]*BASE=' "$ROOT/$ctx/Dockerfile" \
              | sed -E 's/^ARG[[:space:]]+[A-Z_]*BASE=//; s/^"//; s/"$//')"
  [ -n "$base_ref" ] || { echo "REFUSE: $ctx/Dockerfile declares no *_BASE ARG" >&2; return 1; }
  base_dig="${base_ref##*@}"
  is_digest "$base_dig" || { echo "REFUSE: base reference is not digest-pinned: $base_ref" >&2; return 1; }

  # The platform CHILD of that index — the bytes a linux/amd64 build actually
  # consumes, which the index digest does not name. Best effort: an unreachable
  # registry yields an explicit null, which the policy treats as a declared gap
  # and never as agreement.
  child="$(docker buildx imagetools inspect "$base_ref" --raw 2>/dev/null | python3 -c '
import json,sys
try: d = json.load(sys.stdin)
except Exception: sys.exit(0)
os_, arch = sys.argv[1].split("/", 1)
for m in (d.get("manifests") or []):
    p = m.get("platform") or {}
    if p.get("os") == os_ and p.get("architecture") == arch:
        print(m.get("digest", "")); break
' "$plat" 2>/dev/null)"

  # Everything the daemon knows about the produced image, plus the package set
  # and the archive state, gathered here so the python below is pure assembly.
  local cfg_id layers labels runtime_cfg pkgs sources rels files_manifest
  cfg_id="$(docker image inspect "$img" --format '{{.Id}}')"
  layers="$(docker image inspect "$img" --format '{{range .RootFS.Layers}}{{println .}}{{end}}')"
  labels="$(docker image inspect "$img" --format '{{json .Config.Labels}}')"
  # The OBSERVABLE config, canonicalised. Distinct from the config BLOB digest
  # above, which also commits to diff_ids and build history and therefore moves
  # whenever any layer moves. Conflating the two is how an earlier report came
  # to record "config identical" for an image whose config blob differed.
  runtime_cfg="$(docker image inspect "$img" --format '{{json .Config}}' | python3 -c '
import hashlib, json, sys
c = json.load(sys.stdin) or {}
keep = ("Env", "Labels", "Entrypoint", "Cmd", "User", "ExposedPorts",
        "WorkingDir", "Volumes", "StopSignal")
print(hashlib.sha256(json.dumps({k: c.get(k) for k in keep},
      sort_keys=True, separators=(",", ":")).encode()).hexdigest())
')"
  # \${...} are dpkg-query's own substitutions and must reach it INTACT. The
  # format string is single-quoted for the inner sh (which would otherwise
  # expand them to empty) and the backslashes keep bash's hands off them too.
  pkgs="$(docker run --rm --platform "$plat" --entrypoint sh "$img" -c \
          "dpkg-query -W -f='\${Package}\t\${Version}\t\${Architecture}\n' 2>/dev/null | sort" 2>/dev/null)"
  [ -n "$pkgs" ] || { echo "REFUSE: empty package set for $img" >&2; return 1; }
  # Both spellings. Debian moved the official images to deb822
  # (/etc/apt/sources.list.d/debian.sources), so a `^deb ` grep alone silently
  # records "no repositories" for exactly the images this matters most for.
  sources="$(docker run --rm --platform "$plat" --entrypoint sh "$img" -c \
             'cat /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null \
              | grep -E "^(deb |deb-src |URIs:|Suites:|Components:)" | sort -u' 2>/dev/null)"
  rels="$(docker run --rm --platform "$plat" --entrypoint sh "$img" -c \
          'for f in /var/lib/apt/lists/*InRelease /var/lib/apt/lists/*Release; do
             [ -f "$f" ] || continue
             printf "%s\t%s\n" "$(basename "$f")" "$(grep -m1 "^Date:" "$f" 2>/dev/null | cut -d" " -f2-)"
           done' 2>/dev/null)"

  # The rootfs, hashed file by file. Layer digests answer "is the packaging
  # identical"; this answers "is the FILESYSTEM identical" and localises a
  # failure to a path. `tar -tv` once reported nginx identical while 8 files
  # differed byte-for-byte at the same size and mtime.
  local cid exdir
  exdir="$(mktemp -d)" || return 1
  cid="$(docker create --platform "$plat" "$img" 2>/dev/null)"
  [ -n "$cid" ] || { rm -rf "$exdir"; echo "REFUSE: could not create a container from $img" >&2; return 1; }
  docker export "$cid" 2>/dev/null | tar -x -C "$exdir" 2>/dev/null
  docker rm "$cid" >/dev/null 2>&1
  # -print0 | xargs -0 rather than -exec ... \; : one shasum process per file
  # is ~4,300 spawns for a PHP image and turns a 10-second hash into minutes.
  # NUL-delimited so a path with a space cannot split into two arguments.
  files_manifest="$( ( cd "$exdir" && find . -type f -print0 2>/dev/null | xargs -0 shasum -a 256 2>/dev/null | sort -k2 ) )"
  rm -rf "$exdir"
  [ -n "$files_manifest" ] || { echo "REFUSE: exported rootfs was empty for $img" >&2; return 1; }

  local scanner_digest
  scanner_digest="$(python3 -c '
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
e = [x for x in d["inputs"] if x["id"] == "trivy"][0]
print(e["integrity"])' "$ROOT/policies/supply-chain-inputs.yaml")"

  local rendered
  rendered="$(
    CTXP="$ctx" FAM="$fam" SEL="$sel" PLAT="$plat" REPO_SLUG="$REPO_SLUG" \
    SHA="$sha" EPOCH="$epoch" CDG="$cdg" DDG="$ddg" \
    BASE_REF="$base_ref" BASE_DIG="$base_dig" CHILD="${child:-}" \
    BARGS="$(printf '%s\n' ${bargs[@]+"${bargs[@]}"})" \
    CFG="$cfg_id" LAYERS="$layers" LABELS="$labels" RUNCFG="$runtime_cfg" \
    PKGS="$pkgs" SOURCES="$sources" RELS="$rels" FILES="$files_manifest" \
    SCANNER="$scanner_digest" \
    FRONTEND="$(grep -m1 '^# syntax=' "$ROOT/$ctx/Dockerfile" | sed 's/^# syntax=//')" \
    BUILDX="$(docker buildx version 2>/dev/null | awk '{print $2}')" \
    DOCKERD="$(docker version --format '{{.Server.Version}}' 2>/dev/null)" \
    python3 <<'PY'
import hashlib, json, os

def env(k, d=""):
    return os.environ.get(k, d)

pkg_lines = [l for l in env("PKGS").splitlines() if l.strip()]
# The fingerprint is recomputed from the SAME canonical rendering that verify
# uses, so a hand-edited package entry cannot leave the fingerprint agreeing.
canon = "".join("%s\t%s\t%s\n" % tuple((l.split("\t") + ["", ""])[:3]) for l in pkg_lines)
packages = []
for l in pkg_lines:
    f = (l.split("\t") + ["", ""])[:3]
    packages.append({"name": f[0], "version": f[1] or None, "architecture": f[2] or None})

rels = []
for l in env("RELS").splitlines():
    if not l.strip():
        continue
    f = (l.split("\t") + [""])[:2]
    rels.append({"list": f[0], "date": f[1] or None})

build_args = {}
for l in env("BARGS").splitlines():
    if "=" in l:
        k, v = l.split("=", 1)
        build_args[k] = v

files = env("FILES")
doc = {
    "schema_version": 1,
    "repository": env("REPO_SLUG"),
    "generated_at": __import__("time").strftime("%Y-%m-%dT%H:%M:%SZ", __import__("time").gmtime()),
    "image": {"family": env("FAM"), "selector": env("SEL"), "platform": env("PLAT")},
    "build_inputs": {
        "source_sha": env("SHA"),
        "source_date_epoch": int(env("EPOCH")),
        "context_path": env("CTXP"),
        "context_digest": env("CDG"),
        "dockerfile_digest": env("DDG"),
        "base": {
            "reference": env("BASE_REF"),
            "manifest_digest": env("BASE_DIG"),
            "platform_child_digest": env("CHILD") or None,
        },
        "build_args": build_args,
        "toolchain": {
            "dockerfile_frontend": env("FRONTEND", "unknown"),
            "buildx": env("BUILDX", "unknown"),
            "docker_server": env("DOCKERD", "unknown"),
        },
    },
    "package_resolution": {
        # False, and the schema refuses true without a snapshot identity. The
        # Debian archive this resolves against is live; see guarantee
        # `package-resolution` in policies/reproducibility.yaml.
        "guaranteed": False,
        "repositories": [l.strip() for l in env("SOURCES").splitlines() if l.strip()] or ["unrecorded"],
        "snapshot_identity": None,
        "archive_release_dates": rels,
        "package_count": len(packages),
        "package_set_sha256": hashlib.sha256(canon.encode()).hexdigest(),
        "packages": packages,
    },
    "build_outputs": {
        "config_digest": env("CFG"),
        "runtime_config_sha256": env("RUNCFG"),
        "layer_digests": [l.strip() for l in env("LAYERS").splitlines() if l.strip()],
        "rootfs_file_manifest_sha256": hashlib.sha256(files.encode()).hexdigest(),
        "rootfs_file_count": len([l for l in files.splitlines() if l.strip()]),
        # Local builds export to the daemon and produce no OCI manifest. Null is
        # NOT OBSERVED; policies/reproducibility.yaml refuses to claim over it.
        "manifest_digest": None,
        "labels": json.loads(env("LABELS", "null") or "null") or {},
    },
    "vulnerability_verdict": {
        # A verdict is a function of the bytes AND the scanner AND the database.
        # The database is fetched at scan time; no lock emitted outside a frozen
        # release run can name one, so this is false by construction.
        "guaranteed": False,
        "scanner": {"image": "docker.io/aquasec/trivy", "digest": env("SCANNER")},
        "vulnerability_database": {"identity": None, "frozen": False},
    },
}
print(json.dumps(doc, indent=2, sort_keys=False))
PY
  )" || return 1

  if [ -n "$out" ]; then printf '%s\n' "$rendered" > "$out"; echo "lock written: $out"
  else printf '%s\n' "$rendered"; fi
}

# =============================================================================
# verify — offline, and the only place refusals are defined
# =============================================================================
verify() {
  local lock="${1:-}"
  [ -f "$lock" ] || { echo "REFUSE: lock not found: ${lock:-<none>}" >&2; return 1; }
  LOCK="$lock" SCHEMA="$SCHEMA" TREE="${ZFR_TREE:-$ROOT}" REPO_SLUG="$REPO_SLUG" python3 <<'PY'
import hashlib, json, os, re, subprocess, sys, time
import yaml
from jsonschema import Draft202012Validator

TREE = os.environ["TREE"]
refusals, notes, ok = [], [], []
def R(field, msg): refusals.append("%s: %s" % (field, msg))

try:
    lock = json.load(open(os.environ["LOCK"]))
except Exception as e:
    print("REFUSE: lock is not valid JSON: %s" % e); sys.exit(1)

# --- shape first. Structural policy is meaningless on a malformed lock, and a
# --- checker that reads past a schema failure invents the fields it needs.
schema = json.load(open(os.environ["SCHEMA"]))
errs = sorted(Draft202012Validator(schema).iter_errors(lock), key=lambda e: list(e.path))
if errs:
    for e in errs[:12]:
        R("schema", "%s at %s" % (e.message, "/".join(map(str, e.path)) or "<root>"))
    print("REFUSE: build-input lock is not valid against %s" % os.environ["SCHEMA"])
    for r in refusals:
        print("  " + r)
    sys.exit(1)
ok.append("schema: valid against build-input-lock-v1")

if lock["repository"] != os.environ["REPO_SLUG"]:
    R("repository", "%r is not this repository (%r); a lock from elsewhere is "
      "not evidence about this tree" % (lock["repository"], os.environ["REPO_SLUG"]))

bi = lock["build_inputs"]
ctx = os.path.join(TREE, bi["context_path"])
dockerfile = os.path.join(ctx, "Dockerfile")

# --- context drift ----------------------------------------------------------
def context_digest(root):
    h = hashlib.sha256(); n = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for fn in sorted(filenames):
            p = os.path.join(dirpath, fn)
            if not os.path.isfile(p):
                continue
            rel = os.path.relpath(p, root)
            mode = "100755" if os.access(p, os.X_OK) else "100644"
            h.update(("%s\0%s\0%s\n" % (rel, mode,
                      hashlib.sha256(open(p, "rb").read()).hexdigest())).encode())
            n += 1
    return ("sha256:" + h.hexdigest()) if n else None

if not os.path.isdir(ctx):
    R("build_inputs.context_path", "%s does not exist in this tree" % bi["context_path"])
else:
    got = context_digest(ctx)
    if got != bi["context_digest"]:
        R("build_inputs.context_digest",
          "the context has drifted — tree computes %s, lock records %s. Every "
          "file COPYed into the image is covered by this digest, including the "
          "ones no FROM pin can see." % (got, bi["context_digest"]))
    else:
        ok.append("build_inputs.context_digest matches the tree")
    if not os.path.isfile(dockerfile):
        R("build_inputs.dockerfile_digest", "%s/Dockerfile does not exist" % bi["context_path"])
    else:
        dd = "sha256:" + hashlib.sha256(open(dockerfile, "rb").read()).hexdigest()
        if dd != bi["dockerfile_digest"]:
            R("build_inputs.dockerfile_digest",
              "the recipe has drifted — tree computes %s, lock records %s" % (dd, bi["dockerfile_digest"]))
        else:
            ok.append("build_inputs.dockerfile_digest matches the tree")

# --- base / helper drift ----------------------------------------------------
# install-php-extensions is integrity-bound by the base digest
# (supply-chain-inputs.yaml: integrity: inherited-from-base), so a helper that
# changed what it installs surfaces HERE and nowhere else.
declared_base = None
if os.path.isfile(dockerfile):
    m = re.search(r'^ARG\s+[A-Z_]*BASE=(.*)$', open(dockerfile).read(), re.M)
    if m:
        declared_base = m.group(1).strip().strip('"')
if declared_base is None:
    R("build_inputs.base.reference", "the Dockerfile declares no *_BASE ARG to check against")
elif declared_base != bi["base"]["reference"]:
    R("build_inputs.base.reference",
      "base drift — the Dockerfile declares %r, the lock records %r. Inputs "
      "bound by `integrity: inherited-from-base` (the extension installer "
      "helper) move with this digest and with nothing else."
      % (declared_base, bi["base"]["reference"]))
else:
    ok.append("build_inputs.base.reference matches the Dockerfile")

if "@" in bi["base"]["reference"]:
    ref_dig = bi["base"]["reference"].split("@", 1)[1]
    if ref_dig != bi["base"]["manifest_digest"]:
        R("build_inputs.base.manifest_digest",
          "%s does not match the digest in the recorded reference (%s)"
          % (bi["base"]["manifest_digest"], ref_dig))
    else:
        ok.append("build_inputs.base.manifest_digest agrees with its reference")
else:
    R("build_inputs.base.reference", "is not digest-pinned: %r" % bi["base"]["reference"])

if bi["base"]["platform_child_digest"] is None:
    notes.append("build_inputs.base.platform_child_digest is null — the platform "
                 "child was not resolvable at lock time. A consumer needing "
                 "platform-level input identity must refuse this lock.")

# --- timestamp drift --------------------------------------------------------
# Checked in two independent ways. The internal consistency check works with no
# git history at all, which matters because CI checks out shallow; the commit
# check is stronger and runs whenever the object is present.
epoch = bi["source_date_epoch"]
args = bi["build_args"]
want_date = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))
if "BUILD_DATE" in args and args["BUILD_DATE"] != want_date:
    R("build_inputs.build_args.BUILD_DATE",
      "timestamp drift — %r is not the UTC rendering of source_date_epoch %d "
      "(%r). A wall-clock or repository-metadata timestamp changes independently "
      "of the source." % (args["BUILD_DATE"], epoch, want_date))
elif "BUILD_DATE" in args:
    ok.append("build_inputs.build_args.BUILD_DATE is derived from source_date_epoch")
if "VCS_REF" in args and args["VCS_REF"] != bi["source_sha"]:
    R("build_inputs.build_args.VCS_REF",
      "%r is not the recorded source revision %r" % (args["VCS_REF"], bi["source_sha"]))
elif "VCS_REF" in args:
    ok.append("build_inputs.build_args.VCS_REF is the recorded source revision")

def git(*a):
    p = subprocess.run(["git", "-C", TREE] + list(a), capture_output=True, text=True)
    return p.stdout.strip() if p.returncode == 0 else None

if git("cat-file", "-e", bi["source_sha"] + "^{commit}") is not None:
    ct = git("log", "-1", "--format=%ct", bi["source_sha"])
    if ct is not None and int(ct) != epoch:
        R("build_inputs.source_date_epoch",
          "timestamp drift — %d is not the commit timestamp of %s (%s). "
          "SOURCE_DATE_EPOCH must be a property OF the source."
          % (epoch, bi["source_sha"][:12], ct))
    elif ct is not None:
        ok.append("build_inputs.source_date_epoch is the commit's own timestamp")
else:
    notes.append("build_inputs.source_date_epoch: commit %s is not in this "
                 "checkout (shallow clone), so the commit-timestamp binding was "
                 "NOT evaluated here. The internal BUILD_DATE/VCS_REF binding "
                 "above was." % bi["source_sha"][:12])

# --- integrity pins actually present AND actually enforced ------------------
inv_path = os.path.join(TREE, "policies", "supply-chain-inputs.yaml")
if not os.path.isfile(inv_path):
    R("supply_chain_inventory", "policies/supply-chain-inputs.yaml is missing from this tree")
else:
    inv = yaml.safe_load(open(inv_path))
    df_rel = bi["context_path"] + "/Dockerfile"
    body = open(dockerfile).read() if os.path.isfile(dockerfile) else ""
    # COMMENTS ARE STRIPPED BEFORE ANY OF THIS IS SEARCHED, and that is not
    # tidiness. images/php-cli/8.4/Dockerfile carries the line
    #     # Written to a file rather than piped into `sha256sum -c -`: ...
    # explaining why the verification is written the way it is — and a check
    # that greps the whole file for `sha256sum -c` is satisfied by that sentence
    # whether or not the RUN step still verifies anything. A grep that matches
    # its own explanatory comment reports on the documentation, not the build.
    code = "\n".join(l for l in body.splitlines() if not l.lstrip().startswith("#"))
    pinned_here = [e for e in inv["inputs"]
                   if df_rel in (e.get("declared_in") or [])
                   and str(e.get("integrity", "")).startswith("sha256:")]
    for e in pinned_here:
        digest = e["integrity"].split(":", 1)[1]
        if digest not in code:
            R("build_inputs.integrity_pin.%s" % e["id"],
              "the checksum the inventory declares (%s…) does not appear in the "
              "executable part of %s. An artefact fetched by version with no "
              "integrity binding is whatever the server served at that instant."
              % (digest[:16], df_rel))
        elif not re.search(r"sha256sum\s+(-c|--check)", code):
            R("build_inputs.integrity_pin.%s" % e["id"],
              "%s records a checksum but never VERIFIES it — no `sha256sum -c` "
              "outside comments in %s. A pin that is written down and not "
              "checked is decoration." % (e["id"], df_rel))
        else:
            ok.append("build_inputs.integrity_pin.%s is declared and enforced "
                      "outside comments" % e["id"])

    scanner = [e for e in inv["inputs"] if e["id"] == "trivy"]
    if scanner and lock["vulnerability_verdict"]["scanner"]["digest"] != scanner[0]["integrity"]:
        R("vulnerability_verdict.scanner.digest",
          "the locked scanner %s is not the inventory's scanner %s. A verdict "
          "produced by a different scanner is a different verdict."
          % (lock["vulnerability_verdict"]["scanner"]["digest"][:23], scanner[0]["integrity"][:23]))
    elif scanner:
        ok.append("vulnerability_verdict.scanner.digest is the inventory's scanner")

# --- package fingerprint recomputes ----------------------------------------
pr = lock["package_resolution"]
canon = "".join("%s\t%s\t%s\n" % (p["name"], p.get("version") or "", p.get("architecture") or "")
                for p in pr["packages"])
fp = hashlib.sha256(canon.encode()).hexdigest()
if fp != pr["package_set_sha256"]:
    R("package_resolution.package_set_sha256",
      "the fingerprint does not recompute from the recorded set (%s… vs %s…). "
      "The inventory and its summary have been edited apart."
      % (fp[:16], pr["package_set_sha256"][:16]))
else:
    ok.append("package_resolution.package_set_sha256 recomputes from the recorded set")
if pr["package_count"] != len(pr["packages"]):
    R("package_resolution.package_count",
      "%d does not match the %d packages recorded" % (pr["package_count"], len(pr["packages"])))

# --- report -----------------------------------------------------------------
for line in ok:
    print("ok      " + line)
for n in notes:
    print("note    " + n)
if refusals:
    print("\nREFUSE: the build-input lock does not bind to this tree.")
    for r in refusals:
        print("  " + r)
    sys.exit(1)
print("\nbuild-input lock verified: %d binding(s) hold, %d not evaluated" % (len(ok), len(notes)))
PY
}

# =============================================================================
# self-test — every LOCK-side refusal path, on disposable copies
# =============================================================================
# TREE-side sabotage (a Dockerfile whose checksum check was deleted, a base
# digest moved under the lock) lives in tests/reproducibility/test_repro_refusal_paths.sh
# because it needs a disposable copy of the tree. Nothing here or there writes
# into the ambient checkout: a previous generation of self-test in this
# repository did, and corrupted a policy file.
self_test() {
  local ok=0 bad=0 tmp fixture
  tmp="$(mktemp -d)" || return 1
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" EXIT

  fixture="$ROOT/tests/reproducibility/evidence/php-cli-8.4-linux-amd64.lock.json"
  [ -f "$fixture" ] || { echo "REFUSE: self-test fixture missing: $fixture" >&2; return 1; }

  t() { if eval "$2" >/dev/null 2>&1; then ok=$((ok+1)); echo "  ok   $1"
        else bad=$((bad+1)); echo "  FAIL $1"; fi; }

  # A refusal with the wrong diagnostic sends the next reader to the wrong
  # field, so the message is part of the control and is asserted with it.
  refuses() { # refuses <label> <python mutation> <expected diagnostic fragment>
    local label="$1" mut="$2" want="$3" f="$tmp/m.json" got rc
    if ! MUT="$mut" python3 - "$fixture" "$f" <<'PY' >/dev/null 2>&1
import json, os, sys
d = json.load(open(sys.argv[1]))
# ONE namespace, not (globals, locals): a list comprehension inside the
# mutation gets its own scope and resolves free names against GLOBALS, so
# `[g for g in d[...]]` raises NameError when `d` lives only in locals.
exec(os.environ["MUT"], {"d": d})
json.dump(d, open(sys.argv[2], "w"), indent=2)
PY
    then bad=$((bad+1)); echo "  FAIL $label (mutation itself failed)"; return; fi
    got="$(verify "$f" 2>&1)"; rc=$?
    if [ "$rc" -eq 0 ]; then
      bad=$((bad+1)); echo "  FAIL $label (ACCEPTED a lock it must refuse)"; return
    fi
    case "$got" in
      *"$want"*) ok=$((ok+1)); echo "  ok   $label" ;;
      *) bad=$((bad+1)); echo "  FAIL $label (refused, but not for '$want')"
         printf '%s\n' "$got" | tail -4 | sed 's/^/         /' ;;
    esac
  }

  echo "repro-lock self-test"

  # --- non-vacuity ---------------------------------------------------------
  # Without this, every refusal below is equally satisfied by a checker that
  # refuses everything — which is indistinguishable from one that works.
  t "the committed lock verifies clean against this tree (non-vacuity)" \
    "verify '$fixture'"
  t "the context digest is stable across two computations" \
    "[ \"\$(context_digest '$ROOT/images/php-cli/8.4')\" = \"\$(context_digest '$ROOT/images/php-cli/8.4')\" ]"
  t "the lock digest ignores generated_at" \
    "python3 -c \"
import json, hashlib, os, sys
d = json.load(open('$fixture')); d['generated_at'] = '1999-01-01T00:00:00Z'
p = os.path.join('$tmp', 'g.json'); json.dump(d, open(p, 'w'))
def dg(f):
    x = json.load(open(f)); x.pop('generated_at', None)
    return hashlib.sha256(json.dumps(x, sort_keys=True, separators=(',',':')).encode()).hexdigest()
sys.exit(0 if dg('$fixture') == dg(p) else 1)\""

  # --- sabotage: timestamp drift ------------------------------------------
  refuses "timestamp drift: BUILD_DATE is not the recorded epoch" \
    "d['build_inputs']['build_args']['BUILD_DATE'] = '2030-01-01T00:00:00Z'" \
    "build_inputs.build_args.BUILD_DATE"
  refuses "timestamp drift: VCS_REF is not the recorded revision" \
    "d['build_inputs']['build_args']['VCS_REF'] = '0' * 40" \
    "build_inputs.build_args.VCS_REF"
  refuses "timestamp drift: the epoch is not the commit's own timestamp" \
    "import subprocess
h = subprocess.run(['git','-C','$ROOT','rev-parse','HEAD'],capture_output=True,text=True).stdout.strip()
d['build_inputs']['source_sha'] = h
d['build_inputs']['source_date_epoch'] = 1
d['build_inputs']['build_args']['BUILD_DATE'] = '1970-01-01T00:00:01Z'
d['build_inputs']['build_args']['VCS_REF'] = h" \
    "build_inputs.source_date_epoch"

  # --- sabotage: context drift --------------------------------------------
  refuses "context drift: the recorded context digest is not the tree's" \
    "d['build_inputs']['context_digest'] = 'sha256:' + '0' * 64" \
    "build_inputs.context_digest"
  refuses "context drift: the recorded Dockerfile digest is not the tree's" \
    "d['build_inputs']['dockerfile_digest'] = 'sha256:' + '1' * 64" \
    "build_inputs.dockerfile_digest"

  # --- sabotage: base / helper drift --------------------------------------
  refuses "helper drift: the locked base is not the one the Dockerfile declares" \
    "d['build_inputs']['base']['reference'] = 'php:8.4-cli-bookworm@sha256:' + '2' * 64
d['build_inputs']['base']['manifest_digest'] = 'sha256:' + '2' * 64" \
    "build_inputs.base.reference"
  refuses "base drift: manifest_digest disagrees with its own reference" \
    "d['build_inputs']['base']['manifest_digest'] = 'sha256:' + '3' * 64" \
    "build_inputs.base.manifest_digest"

  # --- sabotage: mutable apt index ----------------------------------------
  refuses "mutable apt index: resolution declared guaranteed with no snapshot" \
    "d['package_resolution']['guaranteed'] = True" \
    "package_resolution"
  refuses "mutable apt index: the package fingerprint no longer recomputes" \
    "d['package_resolution']['packages'][0]['version'] = '9:9.9.9'" \
    "package_resolution.package_set_sha256"
  refuses "mutable apt index: the package count contradicts the recorded set" \
    "d['package_resolution']['package_count'] = 1" \
    "package_resolution.package_count"

  # --- sabotage: scanner / vulnerability database -------------------------
  refuses "scanner drift: the locked scanner is not the inventory's scanner" \
    "d['vulnerability_verdict']['scanner']['digest'] = 'sha256:' + '4' * 64" \
    "vulnerability_verdict.scanner.digest"
  refuses "verdict claim with no frozen database" \
    "d['vulnerability_verdict']['guaranteed'] = True" \
    "vulnerability_verdict"
  refuses "a database declared frozen with no identity" \
    "d['vulnerability_verdict']['vulnerability_database']['frozen'] = True" \
    "vulnerability_verdict"

  # --- sabotage: lock bypass ----------------------------------------------
  refuses "lock bypass: an unknown top-level field is not ignored" \
    "d['reproducible'] = True" \
    "schema"
  refuses "lock bypass: a dropped section is not vacuously satisfied" \
    "del d['package_resolution']" \
    "schema"
  refuses "lock bypass: a lock from another repository is not evidence here" \
    "d['repository'] = 'someone-else/foundry'" \
    "repository"
  refuses "lock bypass: an unknown schema_version is refused, not partly read" \
    "d['schema_version'] = 2" \
    "schema"

  echo "self-test: $ok ok, $bad failed"
  [ "$bad" -eq 0 ]
}

case "${1:-}" in
  emit)        shift; emit "$@" ;;
  verify)      shift; verify "$@" ;;
  digest)      shift; lock_digest "${1:?usage: repro-lock.sh digest <lock.json>}" ;;
  --self-test) self_test ;;
  *) sed -n '/^# Usage:/,/^# =====/{/^# =====/d;p;}' "${BASH_SOURCE[0]}" \
       | sed 's/^#\{1,\} \{0,1\}//' >&2; exit 64 ;;
esac
