#!/usr/bin/env bash
# =============================================================================
# scripts/reproducibility-check.sh — build the same source twice, compare (#101).
#
# WHAT IS COMPARED, AND WHY THAT AND NOT THE IMAGE DIGEST.
#
#   RootFS.Layers   the UNCOMPRESSED content digest of every layer. If these
#                   match, the filesystem content is bit-identical. This is the
#                   reproducibility claim.
#   Config          env, labels, entrypoint, cmd, user, exposed ports, working
#                   dir — everything a consumer can observe about the image.
#   packages        dpkg/apk inventory, compared only to ATTRIBUTE a difference
#                   when the layers differ. It is diagnosis, not the claim.
#
# The published image DIGEST is deliberately NOT the claim. BuildKit embeds
# build-time metadata in its attestation manifest, so a local `docker build`
# without `provenance:false` produces an index whose digest differs run to run
# for reasons that are not the source. That exclusion is declared in
# policies/supply-chain-inputs.yaml under `known_nondeterminism` — stated up
# front, not discovered after a failure and used to move the goalposts.
#
# WHICH GUARANTEE THIS TESTS.
#
# Exactly one of the four in policies/reproducibility.yaml: `image-bytes`. It
# does NOT test package-resolution — two builds minutes apart see the same live
# Debian index, so agreement here is a property of the WINDOW, not of the
# archive. It does not test vulnerability-verdict either: the database moves
# underneath unchanged bytes. Those inferences are declared forbidden in the
# policy and scripts/repro-guarantees.sh enforces that they are.
#
# Usage:
#   reproducibility-check.sh <context-dir> <label> [--build-arg K=V ...]
#     [--emit-evidence <dir> --family <f> --selector <s> [--platform linux/amd64]]
#   reproducibility-check.sh --self-test
#
# With --emit-evidence the run also writes, per image:
#   <slug>.lock.json               the build-input lock for build A
#   <slug>-build-input.json        measured evidence for guarantee `build-input`
#   <slug>-image-bytes.json        measured evidence for guarantee `image-bytes`
# Every field is recorded with what was MEASURED — stable, differs, or
# not-observed — and `not-observed` is never written as `stable`.
#
# Exit 0 only if content AND config match. Any failure to build or inspect is a
# failure, never a skip.
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The commit timestamp, so both builds get the same SOURCE_DATE_EPOCH — the
# whole point of #101's timestamp fix. Falls back only when git is unavailable,
# and says so rather than silently using wall-clock.
source_date_epoch() {
  local e
  e="$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || true)"
  case "$e" in
    ''|*[!0-9]*) echo "REFUSE: cannot derive SOURCE_DATE_EPOCH from git" >&2; return 1 ;;
  esac
  printf '%s' "$e"
}

compare() { # compare <ctx> <label> [extra build args...]
  local ctx="$1" label="$2"; shift 2
  local epoch tagA tagB rc=0
  epoch="$(source_date_epoch)" || return 1
  tagA="zenchron-repro/${label}:a"
  tagB="zenchron-repro/${label}:b"

  printf '\n== reproducibility: %s (SOURCE_DATE_EPOCH=%s)\n' "$label" "$epoch"

  # A dedicated buildx builder, and BOTH builds --no-cache. A cached first build
  # would compare an image against its own cache and always "reproduce".
  docker buildx inspect zenchron-repro >/dev/null 2>&1 || \
    docker buildx create --name zenchron-repro --driver docker-container >/dev/null 2>&1 || true

  local a
  for a in a b; do
    local tag="zenchron-repro/${label}:${a}"
    # rewrite-timestamp=true is the whole reason this passes. Without it,
    # directories created by `RUN mkdir` carry the WALL CLOCK mtime of the build,
    # so two builds of the same source differ by a handful of header bytes —
    # measured at 31 differing bytes in a 63 MB caddy rootfs, invisible to
    # `tar -tv` because they were 19 seconds apart inside the same minute.
    # BuildKit rewrites them to SOURCE_DATE_EPOCH when asked; it does not by
    # default.
    if ! docker buildx build --builder zenchron-repro --no-cache \
           --platform linux/amd64 \
           --build-arg "SOURCE_DATE_EPOCH=$epoch" \
           --build-arg "BUILD_DATE=$(date -u -r "$epoch" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "@$epoch" +%Y-%m-%dT%H:%M:%SZ)" \
           --build-arg "VCS_REF=$(git -C "$ROOT" rev-parse HEAD)" \
           --output "type=docker,name=${tag},rewrite-timestamp=true" \
           "$@" "$ctx" >/dev/null 2>"/tmp/repro-$label-$a.err"; then
      echo "FAIL  build $a did not complete"; tail -5 "/tmp/repro-$label-$a.err" | sed 's/^/        /'
      return 1
    fi
    echo "ok    build $a complete (--no-cache, rewrite-timestamp)"
  done

  # --- content -------------------------------------------------------------
  local la lb
  la="$(docker image inspect "$tagA" --format '{{range .RootFS.Layers}}{{println .}}{{end}}' 2>/dev/null)"
  lb="$(docker image inspect "$tagB" --format '{{range .RootFS.Layers}}{{println .}}{{end}}' 2>/dev/null)"
  if [ -z "$la" ] || [ -z "$lb" ]; then
    echo "FAIL  could not read RootFS layers — treating as NOT reproducible"; return 1
  fi
  if [ "$la" = "$lb" ]; then
    echo "PASS  filesystem content identical ($(printf '%s' "$la" | grep -c .) layers)"
  else
    echo "FAIL  filesystem content DIFFERS"
    diff <(printf '%s' "$la") <(printf '%s' "$lb") | sed 's/^/        /' | head -10
    rc=1
    # Attribute it: which packages differ? Diagnosis only — the verdict is above.
    local pa pb
    pa="$(docker run --rm --entrypoint sh "$tagA" -c 'dpkg-query -W -f="${Package}=${Version}\n" 2>/dev/null || apk info -v 2>/dev/null' 2>/dev/null | sort)"
    pb="$(docker run --rm --entrypoint sh "$tagB" -c 'dpkg-query -W -f="${Package}=${Version}\n" 2>/dev/null || apk info -v 2>/dev/null' 2>/dev/null | sort)"
    if [ "$pa" != "$pb" ]; then
      echo "        attributed to package differences:"
      diff <(printf '%s\n' "$pa") <(printf '%s\n' "$pb") | grep -E '^[<>]' | head -10 | sed 's/^/          /'
    else
      echo "        package sets are IDENTICAL — the difference is elsewhere"
    fi
  fi

  # --- filesystem export, the claim in its most direct form ----------------
  # Layer digests answer "is the packaging identical". This answers "is the
  # FILESYSTEM identical", which is what a consumer actually depends on, and it
  # localises a failure to a path instead of to an opaque digest.
  local ea eb da db
  ea="$(mktemp)"; eb="$(mktemp)"; da="$(mktemp -d)"; db="$(mktemp -d)"
  local ca_id cb_id
  ca_id="$(docker create "$tagA" 2>/dev/null)"; cb_id="$(docker create "$tagB" 2>/dev/null)"
  docker export "$ca_id" 2>/dev/null | tar -x -C "$da" 2>/dev/null
  docker export "$cb_id" 2>/dev/null | tar -x -C "$db" 2>/dev/null
  docker rm "$ca_id" "$cb_id" >/dev/null 2>&1 || true
  # sha256 of every regular file. A metadata-only comparison (`tar -tv`) reported
  # nginx as identical while 8 files differed byte-for-byte with the SAME size
  # and mtime — apt/dpkg logs and ldconfig's aux-cache. A check that cannot see
  # the difference it exists to find is not a check.
  # -print0 | xargs -0 rather than -exec ... \; : one shasum process per file is
  # ~4,300 spawns per image here, which turned a ten-second hash into minutes.
  # NUL-delimited so a path containing a space cannot split into two arguments.
  ( cd "$da" && find . -type f -print0 2>/dev/null | xargs -0 shasum -a 256 2>/dev/null | sort -k2 ) > "$ea"
  ( cd "$db" && find . -type f -print0 2>/dev/null | xargs -0 shasum -a 256 2>/dev/null | sort -k2 ) > "$eb"
  rm -rf "$da" "$db"
  if [ ! -s "$ea" ] || [ ! -s "$eb" ]; then
    echo "FAIL  could not export a filesystem — treating as NOT reproducible"; rc=1
  elif cmp -s "$ea" "$eb"; then
    echo "PASS  every file byte-identical ($(wc -l < "$ea" | tr -d ' ') files hashed)"
  else
    echo "FAIL  file CONTENT differs ($(diff "$ea" "$eb" | grep -c '^[<>]') of $(wc -l < "$ea" | tr -d ' ') files)"
    diff "$ea" "$eb" | grep '^[<>]' | head -8 | sed 's/^/        /'
    rc=1
  fi
  rm -f "$ea" "$eb"

  # --- config --------------------------------------------------------------
  # Everything a consumer can observe. Compared whole; no field is excluded
  # here, because the excluded nondeterminism lives in the attestation manifest,
  # not in the config.
  local ca cb
  ca="$(docker image inspect "$tagA" --format '{{json .Config}}' | python3 -m json.tool --sort-keys 2>/dev/null)"
  cb="$(docker image inspect "$tagB" --format '{{json .Config}}' | python3 -m json.tool --sort-keys 2>/dev/null)"
  if [ "$ca" = "$cb" ]; then
    echo "PASS  image configuration identical (env, labels, entrypoint, user, ports)"
  else
    echo "FAIL  image configuration DIFFERS"
    diff <(printf '%s\n' "$ca") <(printf '%s\n' "$cb") | head -14 | sed 's/^/        /'
    rc=1
  fi

  # --- machine-readable evidence -------------------------------------------
  # The prose verdict above is for a human reading a terminal. The policy gate
  # cannot read prose, so the same measurement is written as a record bound to
  # the exact declared inputs it was taken from.
  if [ -n "${EVIDENCE_DIR:-}" ]; then
    emit_evidence "$tagA" "$tagB" "$ctx" "$epoch" || rc=1
  fi

  docker rmi -f "$tagA" "$tagB" >/dev/null 2>&1 || true
  return "$rc"
}

# emit_evidence <tagA> <tagB> <ctx> <epoch>
#
# Emits a build-input lock for EACH build, compares them field by field, and
# writes one evidence record per guarantee those fields belong to. The two locks
# ARE the measurement: that the declared inputs were held fixed is asserted by
# comparison, not assumed, because holding them fixed is the whole experiment.
emit_evidence() {
  local tagA="$1" tagB="$2" ctx="$3" epoch="$4"
  local fam="${EV_FAMILY:?--family is required with --emit-evidence}"
  local sel="${EV_SELECTOR:?--selector is required with --emit-evidence}"
  local plat="${EV_PLATFORM:-linux/amd64}"
  # child_slug() in scripts/lib/common.sh is the ONE definition of a
  # platform-bound child identity, and tests/release/test_child_identity_contract.sh
  # asserts that nothing else in the tree rebuilds a path by substituting '/' in
  # a label. It caught the second implementation that used to be on this line.
  # Sourced in a SUBSHELL because common.sh brings `set -e`, which this script
  # deliberately does not run under: every comparison failure here is a result to
  # report, not an abort. Written "$( ( ... ) )" with spaces — "$(( ... ))" is
  # arithmetic expansion, not a subshell.
  local slug
  slug="$( ( . "$ROOT/scripts/lib/common.sh"; child_slug "$fam" "$sel" "$plat" ) )"
  if [ -z "$slug" ]; then
    echo "FAIL  could not derive a child identity for $fam/$sel on $plat"; return 1
  fi
  local tmp; tmp="$(mktemp -d)" || return 1
  local bd; bd="$(date -u -r "$epoch" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "@$epoch" +%Y-%m-%dT%H:%M:%SZ)"
  local ref; ref="$(git -C "$ROOT" rev-parse HEAD)"

  # The two tags the comparison above just built, carried in rather than
  # re-derived: a second spelling of the same name is a second thing to keep in
  # step, and locks emitted from the wrong tags would compare cleanly and mean
  # nothing.
  local pair t tag
  for pair in "a:$tagA" "b:$tagB"; do
    t="${pair%%:*}"; tag="${pair#*:}"
    if ! bash "$ROOT/scripts/repro-lock.sh" emit \
      --context "$ctx" --family "$fam" --selector "$sel" --platform "$plat" \
      --image "$tag" \
      --build-arg "SOURCE_DATE_EPOCH=$epoch" \
      --build-arg "BUILD_DATE=$bd" \
      --build-arg "VCS_REF=$ref" \
      --out "$tmp/$t.json" >/dev/null; then
        echo "FAIL  could not emit a build-input lock for build $t"
        rm -rf "$tmp"; return 1
    fi
  done

  mkdir -p "$EVIDENCE_DIR"
  A="$tmp/a.json" B="$tmp/b.json" OUTDIR="$EVIDENCE_DIR" SLUG="$slug" \
  REPO_SLUG="zenchron-dynamics/zenchron-foundry" SHA="$ref" \
  python3 <<'PYEV'
import hashlib, json, os, time

a = json.load(open(os.environ["A"]))
b = json.load(open(os.environ["B"]))
outdir, slug = os.environ["OUTDIR"], os.environ["SLUG"]

def canon(x):
    return json.dumps(x, sort_keys=True, separators=(",", ":"))

def lock_digest(d):
    d = dict(d); d.pop("generated_at", None)
    return hashlib.sha256(canon(d).encode()).hexdigest()

def get(d, path):
    cur = d
    for part in path.split("."):
        cur = cur[part]
    return cur

def compare(path):
    va, vb = get(a, path), get(b, path)
    # None means the field was never produced. That is NOT agreement, and
    # recording it as `stable` is exactly the defect this enum exists to stop.
    if va is None and vb is None:
        return {"field": path, "result": "not-observed",
                "detail": "neither build produced this field"}
    if canon(va) == canon(vb):
        return {"field": path, "result": "stable"}
    d = {"field": path, "result": "differs"}
    if isinstance(va, list) and isinstance(vb, list) and len(va) == len(vb):
        n = sum(1 for x, y in zip(va, vb) if x != y)
        d["detail"] = "%d of %d entries differ" % (n, len(va))
    return d

INPUT_FIELDS = [
    "build_inputs.source_sha", "build_inputs.source_date_epoch",
    "build_inputs.context_path", "build_inputs.context_digest",
    "build_inputs.dockerfile_digest", "build_inputs.base.reference",
    "build_inputs.base.manifest_digest", "build_inputs.base.platform_child_digest",
    "build_inputs.build_args", "build_inputs.toolchain",
]
OUTPUT_FIELDS = [
    "build_outputs.config_digest", "build_outputs.runtime_config_sha256",
    "build_outputs.layer_digests", "build_outputs.rootfs_file_manifest_sha256",
    "build_outputs.rootfs_file_count", "build_outputs.manifest_digest",
    "build_outputs.labels",
]

common = {
    "schema_version": 1,
    "repository": os.environ["REPO_SLUG"],
    "source_sha": os.environ["SHA"],
    "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "image": a["image"],
    "method": ("two builds of the same context on one host, both --no-cache on a "
               "dedicated docker-container buildx builder, both --platform %s, "
               "identical --build-arg set, SOURCE_DATE_EPOCH taken from the "
               "source commit, exporter rewrite-timestamp=true. A cached second "
               "build would compare an image against its own cache and always "
               "agree, so neither build may use a cache."
               % a["image"]["platform"]),
    "build_count": 2,
    "declared_inputs_lock_sha256": lock_digest(a),
}

for guarantee, fields in (("build-input", INPUT_FIELDS), ("image-bytes", OUTPUT_FIELDS)):
    rec = dict(common)
    rec["guarantee"] = guarantee
    rec["fields"] = [compare(f) for f in fields]
    p = os.path.join(outdir, "%s-%s.json" % (slug, guarantee))
    with open(p, "w") as fh:
        json.dump(rec, fh, indent=2)
        fh.write("\n")
    print("evidence written: %s" % p)

# Build A's lock is committed as the reviewable input set the evidence binds to.
# generated_at is normalised so re-running the experiment does not churn the
# file for a reason that is not a measurement.
lock = dict(a)
lock["generated_at"] = "1970-01-01T00:00:00Z"
p = os.path.join(outdir, "%s.lock.json" % slug)
with open(p, "w") as fh:
    json.dump(lock, fh, indent=2)
    fh.write("\n")
print("lock written: %s" % p)
PYEV
  local rc=$?
  rm -rf "$tmp"
  return "$rc"
}

self_test() {
  local ok=0 bad=0
  t() { if eval "$2"; then ok=$((ok+1)); echo "  ok   $1"; else bad=$((bad+1)); echo "  FAIL $1"; fi; }
  t "SOURCE_DATE_EPOCH resolves from the git history" \
    "[ -n \"\$(source_date_epoch)\" ]"
  t "...and is a plain integer" \
    "case \"\$(source_date_epoch)\" in ''|*[!0-9]*) false ;; *) true ;; esac"
  t "...and is stable across calls (it is a property of the commit)" \
    "[ \"\$(source_date_epoch)\" = \"\$(source_date_epoch)\" ]"
  # The claim's boundary must be declared in the inventory, not invented here.
  t "the excluded nondeterminism is declared in the inventory" \
    "python3 -c \"
import yaml
d=yaml.safe_load(open('$ROOT/policies/supply-chain-inputs.yaml'))
kn=d['build_determinism']['known_nondeterminism']
assert kn and all(k.get('excluded_from_claim') is not None for k in kn), kn\""
  t "the inventory declares SOURCE_DATE_EPOCH comes from the source commit" \
    "python3 -c \"
import yaml
d=yaml.safe_load(open('$ROOT/policies/supply-chain-inputs.yaml'))
assert d['build_determinism']['source_date_epoch']['derived_from']=='source-commit'\""
  # This harness answers ONE of the four questions in policies/reproducibility.yaml.
  # Asserting that here stops its answer being quoted for a question it never
  # asked, which is what #101's history is a record of.
  t "the guarantee this harness tests is declared in the policy" \
    "python3 -c \"
import yaml
d=yaml.safe_load(open('$ROOT/policies/reproducibility.yaml'))
g=[x for x in d['guarantees'] if x['id']=='image-bytes']
assert g, 'image-bytes is not declared'
assert g[0]['status'] in ('conditional','guaranteed'), g[0]['status']\""
  t "...and the policy forbids reading its result as package-resolution" \
    "python3 -c \"
import yaml
d=yaml.safe_load(open('$ROOT/policies/reproducibility.yaml'))
pairs={(i['from'],i['to']) for i in d['forbidden_inferences']}
assert ('image-bytes','package-resolution') in pairs, sorted(pairs)\""
  t "...and forbids reading its result as a vulnerability verdict" \
    "python3 -c \"
import yaml
d=yaml.safe_load(open('$ROOT/policies/reproducibility.yaml'))
pairs={(i['from'],i['to']) for i in d['forbidden_inferences']}
assert ('image-bytes','vulnerability-verdict') in pairs, sorted(pairs)\""
  echo "self-test: $ok ok, $bad failed"
  [ "$bad" -eq 0 ]
}

# --emit-evidence and its companions are consumed here rather than inside
# compare(), which passes every remaining argument straight to `docker buildx
# build`. An unrecognised flag reaching buildx fails the build, which is the
# right direction, but the diagnostic would name buildx instead of this script.
EVIDENCE_DIR="" EV_FAMILY="" EV_SELECTOR="" EV_PLATFORM="linux/amd64"
argv=()
while [ $# -gt 0 ]; do
  case "$1" in
    --emit-evidence) EVIDENCE_DIR="${2:?--emit-evidence needs a directory}"; shift 2 ;;
    --family)        EV_FAMILY="${2:?--family needs a value}";   shift 2 ;;
    --selector)      EV_SELECTOR="${2:?--selector needs a value}"; shift 2 ;;
    --platform)      EV_PLATFORM="${2:?--platform needs a value}"; shift 2 ;;
    *) argv+=("$1"); shift ;;
  esac
done
export EVIDENCE_DIR EV_FAMILY EV_SELECTOR EV_PLATFORM
set -- ${argv[@]+"${argv[@]}"}

case "${1:-}" in
  --self-test) self_test ;;
  "") echo "usage: $(basename "$0") <context-dir> <label> [--build-arg K=V ...]" \
           "[--emit-evidence <dir> --family <f> --selector <s> [--platform linux/amd64]]" >&2; exit 64 ;;
  *) compare "$@" ;;
esac
