#!/usr/bin/env bash
# =============================================================================
# scripts/continuity-export.sh — export every shipping digest, and prove a
# restore actually restores (#116).
#
# THE THING THIS DOES NOT DO. It does not create an independent mirror. Foundry
# has one registry, and a second package on the same account is not independence
# — it shares the outage domain, the account and the suspension risk. That gap is
# declared in policies/continuity.yaml and #116 stays open because of it.
#
# What this DOES is prove the mechanism, so that standing up a mirror is a
# procurement decision rather than an untested hope: export by digest to an OCI
# layout, push to a target registry, and verify the restored digest EQUALS the
# source digest. Digest equality is the whole point — a "restore" that produces
# a different digest breaks every pinned consumer reference and every signature.
#
# --exercise runs the full cycle against a LOCAL registry container, so the
# round trip is executed rather than described.
#
# Usage:
#   continuity-export.sh --export [--digests-only] <dir>   OCI layout export
#   continuity-export.sh --exercise                export -> local registry -> verify
#   continuity-export.sh --self-test
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1
REGISTRY="${ZC_REGISTRY:-ghcr.io/zenchron-dynamics}"
POLICY="$ROOT/policies/continuity.yaml"

pass=0; fail=0
ck() { if eval "$2"; then pass=$((pass+1)); echo "ok   - $1"; else fail=$((fail+1)); echo "FAIL - $1"; fi; }

matrix() {
  python3 -c "
import glob, yaml
for f in sorted(glob.glob('contracts/images/*.yaml')):
    d = yaml.safe_load(open(f)); s = d['selector']
    print('%s:%s' % (d['image'], 'prod' if s == 'prod' else s + '-prod'))"
}

resolve() { docker buildx imagetools inspect "$1" --format '{{.Manifest.Digest}}' 2>/dev/null | tr -d '[:space:]'; }

do_export() {
  local dir="${1:?usage: --export <dir>}"
  mkdir -p "$dir"
  local n=0 failed=0 nolayout=0
  : > "$dir/digests.txt"
  while IFS= read -r img; do
    [ -n "$img" ] || continue
    n=$((n + 1))
    local ref dig
    ref="$REGISTRY/$img"
    dig="$(resolve "$ref")"
    case "$dig" in
      sha256:*) ;;
      *) echo "REFUSE: cannot resolve $ref — an export missing an image is not a backup" >&2
         failed=$((failed + 1)); continue ;;
    esac
    printf '%s %s\n' "$img" "$dig" >> "$dir/digests.txt"
    # By DIGEST, never by tag: the tag is what moves, and a backup taken from a
    # tag records whatever the tag meant at that instant.
    if ! docker buildx imagetools create --tag "oci-layout://$dir/layout:${img//[:\/]/_}" \
           "${ref%:*}@${dig}" >/dev/null 2>&1; then
      echo "note: OCI-layout export unavailable for $img; recorded digest only" >&2
      nolayout=$((nolayout + 1))
    fi
  done < <(matrix)

  local want; want="$(matrix | grep -c .)"
  echo "exported $((n - failed))/$want image digest(s) to $dir"
  [ "$failed" -eq 0 ] || { echo "REFUSE: $failed image(s) did not resolve" >&2; return 1; }
  [ "$n" -eq "$want" ] || { echo "REFUSE: short matrix ($n of $want)" >&2; return 1; }
  # A digest list is an INVENTORY, not a backup. policies/continuity.yaml
  # promises `format: OCI layout`, and this used to exit 0 having written
  # nothing but digests.txt when every layout write failed — a "successful"
  # export you cannot restore from. Refuse unless the caller explicitly asked
  # for an inventory-only run.
  if [ "$nolayout" -gt 0 ] && [ "$DIGESTS_ONLY" != "1" ]; then
    echo "REFUSE: $nolayout image(s) exported no OCI layout — a digest list is an" >&2
    echo "        inventory, not a backup, and nothing can be restored from it." >&2
    echo "        Re-run with --digests-only to record an inventory deliberately." >&2
    return 1
  fi
  return 0
}

exercise() {
  echo "== continuity exercise (LOCAL registry — not a mirror, a mechanism test) =="
  command -v docker >/dev/null 2>&1 || { echo "REFUSE: docker required" >&2; return 1; }

  local port=5001 name="zc-continuity-registry" dir
  dir="$(mktemp -d)"
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run -d --rm --name "$name" -p "127.0.0.1:${port}:5000" registry:2 >/dev/null 2>&1 \
    || { echo "REFUSE: could not start a local registry" >&2; return 1; }
  # shellcheck disable=SC2064
  trap "docker rm -f '$name' >/dev/null 2>&1 || true; rm -rf '$dir'" RETURN
  sleep 3

  echo "-- 1. export the shipping matrix by digest"
  do_export "$dir" || return 1

  echo
  echo "-- 2. restore each digest into the alternate registry"
  local restored=0 total=0 mismatched=0
  while read -r img dig; do
    total=$((total + 1))
    local src="$REGISTRY/${img%:*}@${dig}"
    local dst="127.0.0.1:${port}/${img}"
    if docker buildx imagetools create --tag "$dst" "$src" >/dev/null 2>&1; then
      restored=$((restored + 1))
      # THE assertion: the restored digest must EQUAL the source digest. A
      # restore that produces a different digest breaks every pinned reference
      # and invalidates every signature over the original.
      local back
      back="$(resolve "$dst")"
      [ "$back" = "$dig" ] || { mismatched=$((mismatched + 1))
        echo "   MISMATCH $img: source $dig, restored $back" >&2; }
    else
      echo "   FAILED to restore $img" >&2
    fi
  done < "$dir/digests.txt"

  echo
  echo "== verdict =="
  ck "every image in the matrix was exported" \
     "[ '$total' = \"\$(matrix | grep -c .)\" ]"
  ck "every exported digest was restored to the alternate registry" \
     "[ '$restored' = '$total' ]"
  ck "every restored digest EQUALS its source digest" "[ '$mismatched' = 0 ]"
  ck "the policy still declares that no independent mirror exists" \
     "python3 -c \"
import yaml; d=yaml.safe_load(open('$POLICY'))
assert d['current_state']['independent_mirror'] == 'none', \
    'the exercise must not be read as having created a mirror'\""

  echo "----"
  printf 'continuity exercise: %d ok, %d failed  (%d/%d digests restored, %d mismatched)\n' \
    "$pass" "$fail" "$restored" "$total" "$mismatched"
  [ "$fail" -eq 0 ]
}

self_test() {
  ck "the policy declares the absence of an independent mirror" \
     "python3 -c \"
import yaml; d=yaml.safe_load(open('$POLICY'))
assert d['current_state']['independent_mirror']=='none'
assert d['current_state']['acceptance_gap']\""
  ck "a second GHCR package is explicitly rejected as independence" \
     "python3 -c \"
import yaml; d=yaml.safe_load(open('$POLICY'))
n=d['current_state']['independent_mirror_note'].lower()
assert 'would not be independent' in n or 'not be independent' in n, n\""
  ck "RTO and RPO are numbers, not adjectives" \
     "python3 -c \"
import yaml; o=yaml.safe_load(open('$POLICY'))['objectives']
assert isinstance(o['rto_hours'], int) and isinstance(o['rpo_releases'], int)\""
  ck "the export format preserves manifest digests" \
     "python3 -c \"
import yaml; e=yaml.safe_load(open('$POLICY'))['export']
assert e['format']=='OCI layout' and 'docker save' in e['format_note']\""
  ck "signature export is declared absent BECAUSE nothing is signed yet" \
     "python3 -c \"
import yaml; e=yaml.safe_load(open('$POLICY'))['export']
assert 'cosign signatures and attestations' in e['excludes']
assert '139' in e['excludes_note']\""
  ck "the human decisions that actually close this are recorded" \
     "python3 -c \"
import yaml; d=yaml.safe_load(open('$POLICY'))
ids={h['id'] for h in d['required_human_decisions']}
assert 'choose-mirror-provider' in ids and 'mirror-credentials' in ids
assert all(h['blocks']==116 for h in d['required_human_decisions'])\""
  echo "----"
  printf 'self-test: %d ok, %d failed\n' "$pass" "$fail"
  [ "$fail" -eq 0 ]
}

# An inventory-only export must be ASKED for. It is a legitimate thing to want
# — knowing which digests were live is useful — but it is not a backup, so it
# cannot be what you get by accident when every layout write fails.
DIGESTS_ONLY=0
case "${1:-}" in
  --export)    shift
               if [ "${1:-}" = "--digests-only" ]; then DIGESTS_ONLY=1; shift; fi
               do_export "${1:-}" ;;
  --exercise)  exercise ;;
  --self-test) self_test ;;
  *) echo "usage: $(basename "$0") --export [--digests-only] <dir> | --exercise | --self-test" >&2; exit 64 ;;
esac
