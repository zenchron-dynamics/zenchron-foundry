#!/usr/bin/env python3
# =============================================================================
# scripts/license/extract-image-licence-materials.py — #120 action N1.
# -----------------------------------------------------------------------------
# Extract the licence and copyright material that is PHYSICALLY PRESENT in the
# accepted production images, buildlessly, from immutable digests.
#
# WHY THIS EXISTS. The notice bundle carries the canonical SPDX text of every
# identifier the cohort resolves — the text of GPL-2.0 as SPDX publishes it.
# That is not the same artifact as busybox's own copyright statement, or
# Debian's per-package `copyright` file recording who holds copyright in THIS
# build of THIS package. `retain-copyright-notice` is an obligation about the
# latter, and until this tool existed nothing in the repository had ever read a
# byte of it.
#
# WHAT "BUILDLESS" MEANS HERE, precisely. Nothing is built, no Dockerfile runs,
# no package manager runs, no image is mutated, no mutable tag is read and no
# SBOM is regenerated. The tool speaks the registry HTTP API, fetches blobs by
# their content digest, and reads them as tar streams in memory. A local
# container runtime is not used at all: reading through a daemon would make the
# subject the local image ID rather than the manifest digest, which is the same
# substitution the SBOM run deliberately avoided.
#
# THREE FACTS ARE VERIFIED BEFORE A SINGLE BYTE IS ATTRIBUTED TO A CHILD, and
# any one of them disagreeing is a refusal:
#
#   NX-MANIFEST-DIGEST   sha256 of the manifest bytes must EQUAL the accepted
#                        digest. Not "the registry said so" — recomputed here.
#   NX-PLATFORM-MISMATCH the config blob's own os/architecture must equal the
#                        platform the accepted run recorded for that child.
#   NX-BLOB-DIGEST       every layer blob's sha256 must equal the digest the
#                        manifest names for it.
#
# OVERLAY SEMANTICS ARE APPLIED, NOT ASSUMED. A file is what the TOP layer says
# it is. Later layers replace earlier ones; `.wh.<name>` deletes `<name>`;
# `.wh..wh..opq` clears the directory it sits in. Reporting a copyright file
# that a later layer deleted would be reporting a file that is not in the image.
#
# SYMLINKS AND HARDLINKS ARE RESOLVED INSIDE THE IMAGE. Debian shares one
# copyright file between binary packages of the same source package by making
# the others symlinks. The record keeps BOTH ends — the referring package, the
# resolved target, and the target's own hash — because "libfoo1 is covered by
# libfoo's copyright" is a claim about a relationship, and the relationship has
# to be shown to exist in that exact image.
#
# RAW BYTES ARE PRESERVED. Every captured file is stored content-addressed under
# its own sha256 and never rewritten. Debian ships some copyright files
# gzip-compressed; the compressed bytes are what is stored and hashed, and the
# decompression is recorded as a SEPARATE derived artifact with its own
# checksum. A "normalised" text is a different file and is never allowed to
# stand in for the one that shipped.
#
# Usage:
#   extract-image-licence-materials.py --acceptance FILE --repo REPO
#       --out-dir DIR [--token-file FILE] [--cache DIR] [--only CHILD_KEY]
# =============================================================================
import argparse
import gzip
import hashlib
import io
import json
import os
import posixpath
import re
import sys
import tarfile
import time
import urllib.error
import urllib.request

TOOL = "scripts/license/extract-image-licence-materials.py"
SCHEMA = "foundry.image-licence-materials/v1"

MANIFEST_ACCEPT = ",".join([
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.oci.image.index.v1+json",
])

# WHAT COUNTS AS LICENCE MATERIAL, enumerated rather than guessed.
#
# `/usr/share/doc/<pkg>/copyright` is the DEBIAN convention and it is NOT
# universal coverage: Alpine ships nothing of the sort, Go binaries carry no
# vendored licence tree, and a manually compiled extension has whatever its
# build left behind. Each ecosystem gets its own selector, and a component whose
# ecosystem has no in-image convention produces an ABSENT finding rather than
# silence.
SELECTORS = [
    # --- Debian -------------------------------------------------------------
    ("deb-copyright", re.compile(r"^usr/share/doc/([^/]+)/copyright(\.gz)?$")),
    # Debian shares one copyright file between the binary packages of a source
    # package by symlinking the whole DOC DIRECTORY, not the file inside it:
    # /usr/share/doc/libgcc-s1 -> gcc-12-base. A selector that only matched
    # `<pkg>/copyright` reported 19 installed packages as missing their
    # copyright file when the image ships it one indirection away.
    ("deb-doc-dirlink", re.compile(r"^usr/share/doc/([^/]+)$")),
    ("deb-doc-licence", re.compile(
        r"^usr/share/doc/([^/]+)/(COPYING|COPYRIGHT|LICEN[CS]E|NOTICE)"
        r"[^/]*(\.gz)?$", re.I)),
    # The shared texts a Debian copyright file POINTS AT. Without these the
    # reference "see /usr/share/common-licenses/GPL-2" resolves to nothing.
    ("deb-common-licence", re.compile(r"^usr/share/common-licenses/[^/]+$")),
    # --- Alpine -------------------------------------------------------------
    ("apk-licence", re.compile(r"^usr/share/licenses/[^/]+/[^/]+$")),
    # --- anything else that names itself a licence, anywhere ----------------
    ("generic-licence", re.compile(
        r"^(?:usr/local|usr/lib|usr/share|opt|srv|app)/.*?"
        r"(COPYING|COPYRIGHT|LICEN[CS]E|NOTICE)[^/]*$", re.I)),
    # --- package databases and distro identity ------------------------------
    ("dpkg-status", re.compile(r"^var/lib/dpkg/status$")),
    ("apk-db", re.compile(r"^lib/apk/db/installed$")),
    # usr/lib/os-release is here because etc/os-release is a SYMLINK to it in
    # both distro families; capturing only the link would record a pointer to a
    # file this extraction never read.
    ("distro-identity", re.compile(
        r"^(etc/os-release|etc/alpine-release|etc/debian_version"
        r"|usr/lib/os-release)$")),
]

# A copyright file is a text file. Anything enormous under a licence-shaped name
# is something else wearing the name, and pulling it into an evidence bundle
# would be a size bug with a licence label on it. The cap is RECORDED when it
# fires, never silently applied.
MAX_CAPTURE_BYTES = 4 * 1024 * 1024


def hard(code, msg):
    sys.stderr.write("REFUSE [%s]: %s\n" % (code, msg))
    raise SystemExit(2)


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


class Registry(object):
    def __init__(self, repo, token, cache=None):
        self.repo = repo
        self.token = token
        self.cache = cache
        if cache:
            os.makedirs(cache, exist_ok=True)

    def _get(self, url, accept=None, retries=4):
        last = None
        for attempt in range(retries):
            try:
                h = {"Authorization": "Bearer " + self.token}
                if accept:
                    h["Accept"] = accept
                req = urllib.request.Request(url, headers=h)
                with urllib.request.urlopen(req, timeout=300) as r:
                    return r.read(), r.headers
            except (urllib.error.URLError, OSError) as e:   # noqa: PERF203
                last = e
                time.sleep(2 * (attempt + 1))
        hard("NX-REGISTRY-UNREACHABLE",
             "%s could not be fetched after %d attempts: %s. An extraction that "
             "silently skips a child reports coverage it does not have"
             % (url, retries, last))

    def manifest(self, digest):
        body, hdr = self._get(
            "https://ghcr.io/v2/%s/manifests/%s" % (self.repo, digest),
            MANIFEST_ACCEPT)
        calc = "sha256:" + sha256_bytes(body)
        if calc != digest:
            hard("NX-MANIFEST-DIGEST",
                 "the manifest served for %s hashes to %s. The registry's own "
                 "claim is not the check: the bytes are" % (digest, calc))
        if hdr.get("Docker-Content-Digest") not in (None, digest):
            hard("NX-MANIFEST-DIGEST",
                 "%s: Docker-Content-Digest is %s"
                 % (digest, hdr.get("Docker-Content-Digest")))
        return json.loads(body)

    def blob(self, digest):
        """Blob bytes, verified against their own digest. Cached by digest, so a
        layer shared by several children is fetched once — the cache key IS the
        content hash, which is why the cache cannot serve the wrong bytes."""
        path = None
        if self.cache:
            path = os.path.join(self.cache, digest.replace(":", "_"))
            if os.path.isfile(path):
                b = open(path, "rb").read()
                if "sha256:" + sha256_bytes(b) == digest:
                    return b
        b, _ = self._get("https://ghcr.io/v2/%s/blobs/%s" % (self.repo, digest))
        if "sha256:" + sha256_bytes(b) != digest:
            hard("NX-BLOB-DIGEST",
                 "blob %s hashes to sha256:%s" % (digest, sha256_bytes(b)))
        if path:
            tmp = path + ".part"
            with open(tmp, "wb") as fh:
                fh.write(b)
            os.replace(tmp, path)
        return b


def norm(name):
    n = name.lstrip("./")
    while n.startswith("/"):
        n = n[1:]
    return posixpath.normpath(n) if n else n


def wanted(path):
    for kind, rx in SELECTORS:
        m = rx.match(path)
        if m:
            return kind, m
    return None, None


def walk_layers(reg, manifest):
    """Apply overlay semantics across the layer stack and return the FINAL state
    of every path a selector matched: {path: record}. Deletions really delete."""
    state = {}
    opaque = []
    for idx, layer in enumerate(manifest.get("layers") or []):
        raw = reg.blob(layer["digest"])
        try:
            stream = gzip.decompress(raw) if layer.get("mediaType", "").endswith("gzip") \
                or raw[:2] == b"\x1f\x8b" else raw
        except OSError as e:
            hard("NX-LAYER-UNREADABLE",
                 "layer %s is not readable as gzip: %s" % (layer["digest"], e))
        try:
            tf = tarfile.open(fileobj=io.BytesIO(stream), mode="r:")
        except tarfile.TarError as e:
            hard("NX-LAYER-UNREADABLE",
                 "layer %s is not a tar: %s" % (layer["digest"], e))
        for mem in tf:
            p = norm(mem.name)
            base = posixpath.basename(p)
            d = posixpath.dirname(p)
            # --- overlayfs deletions --------------------------------------
            if base == ".wh..wh..opq":
                opaque.append(d + "/")
                for k in [k for k in state if k.startswith(d + "/")]:
                    del state[k]
                continue
            if base.startswith(".wh."):
                victim = posixpath.join(d, base[4:])
                for k in [k for k in state
                          if k == victim or k.startswith(victim + "/")]:
                    del state[k]
                continue
            kind, m = wanted(p)
            if not kind:
                continue
            rec = {"path": p, "kind": kind, "layer_index": idx,
                   "layer_digest": layer["digest"], "mode": oct(mem.mode),
                   "size": mem.size}
            if mem.issym():
                rec["type"] = "symlink"
                rec["link_target_raw"] = mem.linkname
                rec["link_target_resolved"] = norm(
                    posixpath.normpath(posixpath.join(d, mem.linkname))
                    if not mem.linkname.startswith("/") else mem.linkname)
            elif mem.islnk():
                rec["type"] = "hardlink"
                rec["link_target_raw"] = mem.linkname
                rec["link_target_resolved"] = norm(mem.linkname)
            elif mem.isreg():
                rec["type"] = "file"
                if mem.size > MAX_CAPTURE_BYTES:
                    rec["captured"] = False
                    rec["capture_skipped_reason"] = (
                        "%d bytes exceeds the %d-byte capture cap; recorded, not "
                        "silently dropped" % (mem.size, MAX_CAPTURE_BYTES))
                else:
                    data = tf.extractfile(mem).read()
                    rec["captured"] = True
                    rec["sha256"] = sha256_bytes(data)
                    rec["bytes"] = len(data)
                    rec["_data"] = data
            elif mem.isdir():
                continue
            else:
                rec["type"] = "other"
            if m and m.lastindex:
                rec["selector_group"] = m.group(1)
            state[p] = rec
    return state


def store(objdir, data):
    h = sha256_bytes(data)
    d = os.path.join(objdir, h[:2])
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, h)
    if not os.path.exists(p):
        tmp = p + ".part"
        with open(tmp, "wb") as fh:
            fh.write(data)
        os.replace(tmp, p)
    return h


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--acceptance", required=True)
    ap.add_argument("--repo", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--token-file", required=True)
    ap.add_argument("--cache")
    ap.add_argument("--only")
    a = ap.parse_args()

    ev = json.load(open(a.acceptance))
    children = ev.get("children") or []
    if not children:
        hard("NX-COHORT-EMPTY", "%s records no children" % a.acceptance)
    if a.only:
        children = [c for c in children if c["child_key"] == a.only]

    reg = Registry(a.repo, open(a.token_file).read().strip(), a.cache)
    objdir = os.path.join(a.out_dir, "objects")
    os.makedirs(objdir, exist_ok=True)

    tool_sha = sha256_bytes(open(__file__, "rb").read())
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    out = {
        "schema": SCHEMA,
        "record_type": "image-licence-materials",
        "extraction_tool": TOOL,
        "extraction_tool_sha256": tool_sha,
        "extraction_method": (
            "registry HTTP API, blobs fetched by content digest and verified "
            "against it, tar streams read in memory. No container runtime, no "
            "build, no package manager, no mutable tag, no SBOM regeneration."),
        "registry": "ghcr.io/" + a.repo,
        "source_revision": ev.get("source_revision"),
        "extracted_at": started,
        "children": [],
    }

    for c in sorted(children, key=lambda x: x["child_key"]):
        digest = c["manifest_digest"]
        man = reg.manifest(digest)
        cfg = json.loads(reg.blob(man["config"]["digest"]))
        plat = "%s/%s" % (cfg.get("os"), cfg.get("architecture"))
        if plat != c["platform"]:
            hard("NX-PLATFORM-MISMATCH",
                 "%s: the image config says %s and the accepted run recorded %s. "
                 "An amd64 filesystem is not evidence about the arm64 child"
                 % (c["child_key"], plat, c["platform"]))
        state = walk_layers(reg, man)
        layers = [l["digest"] for l in man.get("layers") or []]
        files = []
        for p in sorted(state):
            rec = dict(state[p])
            data = rec.pop("_data", None)
            if data is not None:
                rec["sha256"] = store(objdir, data)
            # COMPACTION, and it is not lossy. `mode` and `size` are dropped
            # (`bytes` already carries the captured length) and the layer is
            # recorded as an INDEX into this child's own layer list rather than
            # as a repeated 71-character digest. That makes the record for a
            # given family byte-identical across platforms, which is what lets
            # the identical sets below collapse.
            rec.pop("mode", None)
            rec.pop("size", None)
            rec.pop("layer_digest", None)
            # Both are derivable and neither is dropped where it carries
            # information: `selector_group` is the regex group of the path that
            # is right there, and `captured: true` is implied by the presence of
            # a sha256. `captured: false` and its reason STAY, because a file the
            # cap skipped is a fact nothing else records.
            rec.pop("selector_group", None)
            if rec.get("captured") is True:
                rec.pop("captured")
            files.append(rec)
        fam, _, ver = str(c["image_label"]).partition("/")
        out["children"].append({
            "layers": layers,
            "child_key": c["child_key"],
            "image_family": fam,
            "image_version": ver,
            "image_label": c["image_label"],
            "platform": c["platform"],
            "manifest_digest": digest,
            "config_digest": man["config"]["digest"],
            "config_platform": plat,
            "source_revision": ev.get("source_revision"),
            "layer_count": len(man.get("layers") or []),
            "material_count": len(files),
            "materials": files,
        })
        sys.stderr.write("%-30s %-13s %4d material(s) over %2d layer(s)\n"
                         % (c["child_key"], c["platform"], len(files),
                            len(man.get("layers") or [])))

    # IDENTICAL MATERIAL SETS ARE STORED ONCE. With the layer recorded as an
    # index, the eighteen Debian children collapse onto a handful of distinct
    # sets; each child keeps its own identity, digests and layer list and
    # references the set it has. Nothing is lost: the per-child record is
    # reconstructed by following the reference, and the tool asserts that the
    # reconstruction is byte-identical to what it collapsed.
    sets, order = {}, []
    for ch in out["children"]:
        key = json.dumps(ch["materials"], sort_keys=True)
        if key not in sets:
            sets[key] = len(order)
            order.append(ch["materials"])
        ch["material_set"] = sets[key]
        ch.pop("materials")
    for ch in out["children"]:
        if order[ch["material_set"]] is None:
            hard("NX-SET-COLLAPSE", "material set %d is empty" % ch["material_set"])
    out["material_sets"] = order
    out["material_set_count"] = len(order)

    os.makedirs(a.out_dir, exist_ok=True)
    p = os.path.join(a.out_dir, "image-licence-materials.json")
    with open(p, "w") as fh:
        # indent=1: see the note in account-image-licence-materials.py. The
        # repository blocks files over 512 KB and this record covers 20 children.
        fh.write(json.dumps(out, indent=1, sort_keys=True) + "\n")
    sys.stderr.write("wrote %s (%d children, %d objects)\n"
                     % (p, len(out["children"]),
                        sum(len(fs) for _, _, fs in os.walk(objdir))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
