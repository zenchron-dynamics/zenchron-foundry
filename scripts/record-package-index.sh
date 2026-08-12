#!/usr/bin/env bash
# =============================================================================
# scripts/record-package-index.sh <image-ref> [out.json]
#
# Record the exact package-index state an image was built against (#101).
#
# This does NOT make a build hermetic — the Debian index is still live, and that
# gap is declared in policies/supply-chain-inputs.yaml. What it does is make a
# difference between two builds ATTRIBUTABLE: a digest mismatch resolves to
# "these three packages moved" rather than standing as an unexplained mismatch.
#
# Emits the installed package set and the archive InRelease timestamps, so a
# future rebuild can be compared against the state this one saw.
# =============================================================================
set -euo pipefail

IMG="${1:?usage: record-package-index.sh <image-ref> [out.json]}"
OUT="${2:-package-index-$(printf '%s' "$IMG" | tr '/:' '__').json}"

docker image inspect "$IMG" >/dev/null 2>&1 \
  || { echo "REFUSE: no such image: $IMG" >&2; exit 1; }

# dpkg for Debian, apk for Alpine. An image with neither is a failure, not an
# empty record: an empty package set would read as "nothing installed".
pkgs="$(docker run --rm --entrypoint sh "$IMG" -c '
  if command -v dpkg-query >/dev/null 2>&1; then
    # \${...} escaped: the INNER sh must expand these, not this script.
    dpkg-query -W -f="\${Package}\t\${Version}\t\${Architecture}\n" | sort
  elif command -v apk >/dev/null 2>&1; then
    apk info -v | sort
  else
    exit 3
  fi' 2>/dev/null)" || {
  echo "REFUSE: $IMG has neither dpkg nor apk — cannot record a package set" >&2
  exit 1
}
[ -n "$pkgs" ] || { echo "REFUSE: empty package set for $IMG" >&2; exit 1; }

# The archive state the build resolved against, where the image kept it.
release="$(docker run --rm --entrypoint sh "$IMG" -c '
  for f in /var/lib/apt/lists/*InRelease /var/lib/apt/lists/*Release; do
    [ -f "$f" ] || continue
    printf "%s\t%s\n" "$(basename "$f")" "$(grep -m1 "^Date:" "$f" 2>/dev/null | cut -d" " -f2-)"
  done' 2>/dev/null || true)"

PKGS="$pkgs" RELEASE="$release" IMG="$IMG" python3 -c '
import json, os, hashlib
pkgs = [l.split("\t") for l in os.environ["PKGS"].splitlines() if l.strip()]
rel  = [l.split("\t") for l in os.environ["RELEASE"].splitlines() if l.strip()]
doc = {
  "image": os.environ["IMG"],
  "package_count": len(pkgs),
  # A stable fingerprint of the whole set: two builds with the same value saw
  # the same index, and that is the condition the reproducibility claim rests on.
  "package_set_sha256": hashlib.sha256(os.environ["PKGS"].encode()).hexdigest(),
  "packages": [{"name": p[0], "version": p[1] if len(p) > 1 else None} for p in pkgs],
  "archive_release_dates": [{"list": r[0], "date": r[1] if len(r) > 1 else None} for r in rel],
  "note": "The Debian index is NOT pinned; see policies/supply-chain-inputs.yaml "
          "(debian-package-index) and docs/reproducibility.md.",
}
print(json.dumps(doc, indent=2))' > "$OUT"

echo "package index recorded: $OUT ($(python3 -c "
import json;print(json.load(open('$OUT'))['package_count'])") packages, fingerprint $(python3 -c "
import json;print(json.load(open('$OUT'))['package_set_sha256'][:16])"))"
