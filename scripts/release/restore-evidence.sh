#!/usr/bin/env bash
# =============================================================================
# scripts/release/restore-evidence.sh — the retention half of #128.
# -----------------------------------------------------------------------------
# A bundle that verifies today and cannot be FOUND in three years is not
# retained evidence. This is the archive: a write-once directory layout, a
# checksum index over every bundle in it, a restore that puts a working copy
# back, and a verifier that re-checks the restored copy from its own digests.
#
# The exercise that matters is not "can we write files". It is:
#
#     generate -> archive -> DELETE the working copy -> restore -> verify
#
# run end to end, offline, with the real committed accepted evidence. `--self-test`
# does exactly that, and the same sequence is asserted from outside this script by
# tests/release/test_evidence_bundle.sh. Anything less proves the archive is
# writable, not that the evidence survives.
#
# IMMUTABILITY. Archived bundles are set 0555/0444 as policies/retention.yaml
# requires, so an ordinary write fails before it starts. Permissions are a
# guardrail, not the control — the control is the checksum index, which catches
# a change that root, a restore tool or a filesystem migration made anyway.
#
# DELETION IS AN ACT, NOT AN EXPIRY. There is no `prune`, no `--expired`, no
# scheduled sweep. `list` reports retention state and marks what is eligible;
# removing it is a maintainer's explicit act, after verification. An automatic
# deleter is an automatic evidence destroyer the day the clock or the class is
# wrong.
#
# Usage:
#   restore-evidence.sh archive --bundle <dir> --archive-root <root>
#   restore-evidence.sh restore --archive-root <root> --bundle-id <id> --dest <dir>
#   restore-evidence.sh verify  --archive-root <root> [--bundle-id <id>]
#   restore-evidence.sh list    --archive-root <root> [--today YYYY-MM-DD]
#   restore-evidence.sh --self-test
# =============================================================================
set -euo pipefail
_RE_D="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RE_ROOT="${RE_ROOT:-$(cd "$_RE_D/../.." && pwd)}"
# shellcheck source=../lib/common.sh
. "$_RE_D/../lib/common.sh"

RE_RETENTION="$RE_ROOT/policies/retention.yaml"
RE_INDEX="INDEX.sha256"

# The archive path for a bundle, read from policies/retention.yaml's template so
# the layout has ONE definition. A second spelling of the path is a bundle
# nobody can find with the documented one.
_re_path_for() { # <class> <revision> <bundle_id>
  python3 - "$RE_RETENTION" "$1" "$2" "$3" <<'PY'
import sys, yaml
pol = yaml.safe_load(open(sys.argv[1])) or {}
tpl = ((pol.get("storage") or {}).get("archive_layout") or {}).get("path_template")
if not tpl:
    print("REFUSE: policies/retention.yaml declares no archive path_template", file=sys.stderr)
    sys.exit(1)
print(tpl.replace("<evidence_class>", sys.argv[2])
         .replace("<source_revision>", sys.argv[3])
         .replace("<bundle_id>", sys.argv[4]))
PY
}

re_archive() {
  local bundle="" root=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --bundle)       bundle="${2:?}"; shift 2 ;;
      --archive-root) root="${2:?}"; shift 2 ;;
      *) die "archive: unknown argument: $1" ;;
    esac
  done
  [ -n "$bundle" ] || die "archive: --bundle is required"
  [ -n "$root" ]   || die "archive: --archive-root is required"
  [ -d "$bundle" ] || die "archive: not a bundle directory: $bundle"

  # Archiving an unverified bundle preserves whatever was there, which is the
  # opposite of evidence.
  bash "$_RE_D/generate-evidence-bundle.sh" verify "$bundle" >/dev/null \
    || die "archive: the bundle does not verify; refusing to preserve unverified bytes"

  local cls rev bid rel dest agg
  cls="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["evidence_class"])' "$bundle/manifest.json")"
  rev="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["source_revision"])' "$bundle/manifest.json")"
  bid="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["bundle_id"])' "$bundle/manifest.json")"
  rel="$(_re_path_for "$cls" "$rev" "$bid")" || return 1
  dest="$root/$rel"

  # The class must be one policies/retention.yaml actually promises to keep.
  python3 - "$RE_RETENTION" "$cls" <<'PY' || return 1
import sys, yaml
pol = yaml.safe_load(open(sys.argv[1])) or {}
if sys.argv[2] not in [c["evidence_class"] for c in pol.get("classes") or []]:
    print("REFUSE: policies/retention.yaml states no retention for evidence class "
          "%r — archiving it would promise a durability nobody wrote down"
          % sys.argv[2], file=sys.stderr)
    sys.exit(1)
PY

  [ -e "$dest" ] && die "archive: $rel already exists. The archive is write-once:
  a bundle_id that already has bytes is either the same bundle (nothing to do)
  or a different one wearing its name (which must never silently replace it)"

  mkdir -p "$(dirname "$dest")"
  cp -R "$bundle" "$dest"
  agg="$(awk '{print $1}' "$dest/BUNDLE.sha256")"

  # Index BEFORE the tree goes read-only, so the index write is never the thing
  # that needs a permission exception.
  local idx="$root/$RE_INDEX"
  touch "$idx"
  if grep -q "  $rel\$" "$idx" 2>/dev/null; then
    die "archive: $rel is already indexed"
  fi
  printf '%s  %s\n' "$agg" "$rel" >> "$idx"
  LC_ALL=C sort -o "$idx" "$idx"

  # 0444 / 0555 per policies/retention.yaml.
  chmod -R a-w "$dest"
  find "$dest" -type d -exec chmod 555 {} +
  find "$dest" -type f -exec chmod 444 {} +
  log "archived: $rel"
  log "  aggregate: $agg"
  log "  index:     $RE_INDEX ($(wc -l < "$idx" | tr -d ' ') bundle(s))"
}

re_restore() {
  local root="" bid="" dest=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --archive-root) root="${2:?}"; shift 2 ;;
      --bundle-id)    bid="${2:?}"; shift 2 ;;
      --dest)         dest="${2:?}"; shift 2 ;;
      *) die "restore: unknown argument: $1" ;;
    esac
  done
  [ -n "$root" ] || die "restore: --archive-root is required"
  [ -n "$bid" ]  || die "restore: --bundle-id is required"
  [ -n "$dest" ] || die "restore: --dest is required"
  [ -f "$root/$RE_INDEX" ] || die "restore: no $RE_INDEX in $root — an archive
  with no index is a pile of directories nobody can check"
  [ -e "$dest" ] && die "restore: $dest already exists; restore never overwrites"

  local rel agg
  rel="$(awk -v b="/$bid" '$2 ~ b"$" {print $2}' "$root/$RE_INDEX" | head -1)"
  [ -n "$rel" ] || die "restore: bundle_id '$bid' is not in $RE_INDEX. Every
  restorable bundle is indexed; an unindexed directory is not evidence anyone
  promised to keep"
  agg="$(awk -v r="$rel" '$2 == r {print $1}' "$root/$RE_INDEX")"
  [ -d "$root/$rel" ] || die "restore: $rel is indexed but absent from the archive"

  # The index value is checked BEFORE the copy, so a corrupted archive is not
  # copied out and handed to somebody as evidence.
  local got; got="$(awk '{print $1}' "$root/$rel/BUNDLE.sha256")"
  [ "$got" = "$agg" ] || die "restore: $rel has aggregate $got, the index records
  $agg — the archived bundle changed after it was indexed"

  mkdir -p "$(dirname "$dest")"
  cp -R "$root/$rel" "$dest"
  # A restored copy is a WORKING copy: writable, so it can be inspected and
  # re-archived elsewhere. The archived original stays read-only.
  chmod -R u+w "$dest"
  bash "$_RE_D/generate-evidence-bundle.sh" verify "$dest" >/dev/null \
    || die "restore: the restored copy does not verify"
  log "restored: $rel -> $dest (aggregate $agg, verified)"
}

re_verify() {
  local root="" bid=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --archive-root) root="${2:?}"; shift 2 ;;
      --bundle-id)    bid="${2:?}"; shift 2 ;;
      *) die "verify: unknown argument: $1" ;;
    esac
  done
  [ -n "$root" ] || die "verify: --archive-root is required"
  [ -f "$root/$RE_INDEX" ] || die "verify: no $RE_INDEX in $root"

  local rc=0 n=0 rel agg got
  while read -r agg rel; do
    [ -n "$rel" ] || continue
    if [ -n "$bid" ]; then
      case "$rel" in *"/$bid") : ;; *) continue ;; esac
    fi
    n=$((n + 1))
    if [ ! -d "$root/$rel" ]; then
      warn "REFUSE: indexed bundle is missing from the archive: $rel"; rc=1; continue
    fi
    got="$(awk '{print $1}' "$root/$rel/BUNDLE.sha256" 2>/dev/null || true)"
    if [ "$got" != "$agg" ]; then
      warn "REFUSE: $rel aggregate is $got, the index records $agg"; rc=1; continue
    fi
    if ! bash "$_RE_D/generate-evidence-bundle.sh" verify "$root/$rel" >/dev/null 2>&1; then
      warn "REFUSE: $rel does not verify against its own checksum index"; rc=1; continue
    fi
    log "ok - $rel"
  done < "$root/$RE_INDEX"

  # An archive that indexes nothing must not report success: "0 bundles, all
  # good" is the shape every vacuous gate takes.
  if [ "$n" -eq 0 ]; then
    die "verify: no bundle matched. An empty result is not a passing result"
  fi
  # Unindexed directories are the retention equivalent of a file outside
  # checksum coverage.
  local stray
  stray="$(python3 - "$root" "$RE_INDEX" <<'PY'
import os, sys
root, idx = sys.argv[1], sys.argv[2]
indexed = set()
for ln in open(os.path.join(root, idx)):
    parts = ln.split()
    if len(parts) == 2:
        indexed.add(parts[1])
found = set()
for dp, _d, names in os.walk(root):
    if "manifest.json" in names and "BUNDLE.sha256" in names:
        found.add(os.path.relpath(dp, root))
print("\n".join(sorted(found - indexed)))
PY
)"
  if [ -n "$stray" ]; then
    warn "REFUSE: bundle director(ies) present but not indexed:"
    printf '  %s\n' $stray >&2
    rc=1
  fi
  [ "$rc" -eq 0 ] && log "archive verified: $n bundle(s)"
  return $rc
}

re_list() {
  local root="" today=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --archive-root) root="${2:?}"; shift 2 ;;
      --today)        today="${2:?}"; shift 2 ;;
      *) die "list: unknown argument: $1" ;;
    esac
  done
  [ -n "$root" ] || die "list: --archive-root is required"
  [ -f "$root/$RE_INDEX" ] || die "list: no $RE_INDEX in $root"
  today="${today:-$(date -u +%F)}"
  python3 - "$root" "$RE_INDEX" "$today" <<'PY'
import datetime, json, os, sys
root, idx, today = sys.argv[1:4]
d_today = datetime.date.fromisoformat(today)
print("%-46s %-18s %-12s %s" % ("bundle", "class", "retain_until", "state"))
for ln in open(os.path.join(root, idx)):
    parts = ln.split()
    if len(parts) != 2:
        continue
    rel = parts[1]
    mp = os.path.join(root, rel, "manifest.json")
    if not os.path.exists(mp):
        print("%-46s %-18s %-12s MISSING" % (os.path.basename(rel), "?", "?"))
        continue
    m = json.load(open(mp))
    ru = datetime.date.fromisoformat(m["retention"]["retain_until"])
    state = "RETAINED" if ru > d_today else "eligible-for-deletion (manual act only)"
    print("%-46s %-18s %-12s %s"
          % (m["bundle_id"], m["evidence_class"], ru.isoformat(), state))
PY
}

# =============================================================================
_re_self_test() {
  local tmp ok=0 bad=0
  tmp="$(mktemp -d)"
  # Archived trees are 0555; the cleanup has to restore write permission or the
  # temporary directory outlives the test.
  # shellcheck disable=SC2064
  trap "chmod -R u+w '$tmp' 2>/dev/null; rm -rf '$tmp'" EXIT
  set +e
  set +o pipefail
  t() { if eval "$2"; then ok=$((ok+1)); echo "ok   - $1"; else bad=$((bad+1)); echo "FAIL - $1"; fi; }
  arc() { ( re_archive "$@" ); }
  res() { ( re_restore "$@" ); }
  vfy() { ( re_verify "$@" ); }
  lst() { ( re_list "$@" ); }
  gen() { ( bash "$_RE_D/generate-evidence-bundle.sh" generate "$@" ); }
  bver() { ( bash "$_RE_D/generate-evidence-bundle.sh" verify "$@" ); }

  local EV="$RE_ROOT/docs/audits/acceptance-multiarch-2026-08-20/acceptance-evidence.json"
  [ -f "$EV" ] || { echo "SKIP - accepted evidence absent"; return 0; }
  python3 -c 'import yaml' 2>/dev/null || { echo "SKIP - PyYAML absent"; return 0; }
  local DAY=2026-08-25 BID
  BID="staged-candidate-$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["source_revision"][:12])' "$EV")-32395890071"

  # =========================================================================
  # THE EXERCISE: generate -> archive -> DELETE the working copy -> restore ->
  # verify. Offline, on the real committed accepted evidence.
  # =========================================================================
  t "E1 generate a bundle from the real accepted run" \
    "gen --evidence '$EV' --out '$tmp/work' --evidence-class staged-candidate --today '$DAY' >/dev/null"
  t "E2 archive it into a write-once tree" \
    "arc --bundle '$tmp/work' --archive-root '$tmp/archive' >/dev/null"
  t "E3 the archive layout follows policies/retention.yaml" \
    "test -d '$tmp/archive/staged-candidate'"
  t "E4 the archived tree is read-only (0555 directories)" \
    "! ( touch '$tmp/archive/staged-candidate'/*/*/planted ) 2>/dev/null"
  t "E5 the archived files are read-only (0444)" \
    "! ( printf x >> \"\$(find '$tmp/archive' -name manifest.json | head -1)\" ) 2>/dev/null"
  t "E6 DELETE the working copy — the only copy left is the archived one" \
    "rm -rf '$tmp/work' && [ ! -e '$tmp/work' ]"
  t "E7 restore it from the archive by bundle_id" \
    "res --archive-root '$tmp/archive' --bundle-id '$BID' --dest '$tmp/restored' >/dev/null"
  t "E8 the restored copy verifies offline, from its own digests" \
    "bver '$tmp/restored' >/dev/null"
  t "E9 the restored copy is byte-identical to what was archived" \
    "diff -r \"\$(find '$tmp/archive' -name BUNDLE.sha256 | head -1 | xargs dirname)\" '$tmp/restored' >/dev/null"
  t "E10 the archive verifies as a whole" \
    "vfy --archive-root '$tmp/archive' >/dev/null"
  t "E11 list reports the retention state" \
    "lst --archive-root '$tmp/archive' --today '$DAY' | grep -q RETAINED"
  t "E12 ...and marks a bundle past its window as eligible, never deleting it" \
    "lst --archive-root '$tmp/archive' --today 2099-01-01 | grep -q 'eligible-for-deletion'"

  # --- S1 an unindexed bundle directory --------------------------------------
  cp -R "$tmp/restored" "$tmp/archive/staged-candidate/stray-bundle"
  t "S1 a bundle directory that is not in the index is REFUSED" \
    "! vfy --archive-root '$tmp/archive' >/dev/null 2>&1"
  t "S1 ...naming it as unindexed" \
    "vfy --archive-root '$tmp/archive' 2>&1 | grep -q 'not indexed'"
  chmod -R u+w "$tmp/archive/staged-candidate/stray-bundle"; rm -rf "$tmp/archive/staged-candidate/stray-bundle"
  t "S1 ...and the archive verifies again once it is removed" \
    "vfy --archive-root '$tmp/archive' >/dev/null"

  # --- S2 a tampered archived bundle -----------------------------------------
  local ARCDIR; ARCDIR="$(find "$tmp/archive" -name BUNDLE.sha256 | head -1 | xargs dirname)"
  cp -R "$ARCDIR" "$tmp/copy"; chmod -R u+w "$tmp/copy"
  printf 'planted\n' > "$tmp/copy/content/planted.txt"
  t "S2 a file added inside an archived bundle is REFUSED on restore-verify" \
    "! bver '$tmp/copy' >/dev/null 2>&1"

  # --- S3 an index entry whose bytes moved -----------------------------------
  cp -R "$tmp/archive" "$tmp/archive2"; chmod -R u+w "$tmp/archive2"
  python3 - "$tmp/archive2" <<'PY'
import os, sys
root = sys.argv[1]
out = []
for ln in open(os.path.join(root, "INDEX.sha256")):
    parts = ln.split()
    if len(parts) == 2:
        out.append("%s  %s" % ("0" * 64, parts[1]))
open(os.path.join(root, "INDEX.sha256"), "w").write("\n".join(out) + "\n")
PY
  t "S3 an index that disagrees with the archived aggregate is REFUSED" \
    "! vfy --archive-root '$tmp/archive2' >/dev/null 2>&1"
  t "S3 ...and restore refuses BEFORE copying corrupt evidence out" \
    "! res --archive-root '$tmp/archive2' --bundle-id '$BID' --dest '$tmp/nope' >/dev/null 2>&1"
  t "S3 ...leaving no partial restore behind" "[ ! -e '$tmp/nope' ]"

  # --- S4 an unknown bundle_id -----------------------------------------------
  t "S4 restoring an unindexed bundle_id is REFUSED" \
    "! res --archive-root '$tmp/archive' --bundle-id 'no-such-bundle' --dest '$tmp/x' >/dev/null 2>&1"

  # --- S5 write-once ---------------------------------------------------------
  t "S5 re-archiving over an existing bundle_id is REFUSED" \
    "! arc --bundle '$tmp/restored' --archive-root '$tmp/archive' >/dev/null 2>&1"

  # --- S6 restore never overwrites ------------------------------------------
  t "S6 restoring onto an existing path is REFUSED" \
    "! res --archive-root '$tmp/archive' --bundle-id '$BID' --dest '$tmp/restored' >/dev/null 2>&1"

  # --- S7 archiving something that does not verify ---------------------------
  cp -R "$tmp/restored" "$tmp/broken"; printf 'x' >> "$tmp/broken/content/vex/openvex.json"
  t "S7 archiving a bundle that does not verify is REFUSED" \
    "! arc --bundle '$tmp/broken' --archive-root '$tmp/archive3' >/dev/null 2>&1"

  # --- S8 a class with no stated retention -----------------------------------
  cp -R "$tmp/restored" "$tmp/unclassed"
  python3 - "$tmp/unclassed" <<'PY'
import json, os, sys
mp = os.path.join(sys.argv[1], "manifest.json")
m = json.load(open(mp)); m["evidence_class"] = "foundry-child"
m["retention"]["evidence_class"] = "foundry-child"
json.dump(m, open(mp, "w"), indent=2)
PY
  t "S8 archiving a bundle whose manifest was edited is REFUSED (checksums)" \
    "! arc --bundle '$tmp/unclassed' --archive-root '$tmp/archive4' >/dev/null 2>&1"

  # --- NON-VACUITY ----------------------------------------------------------
  t "NON-VACUOUS: the untouched archive still verifies after every sabotage" \
    "vfy --archive-root '$tmp/archive' >/dev/null"
  t "NON-VACUOUS: verify refuses an empty archive rather than reporting success" \
    "mkdir -p '$tmp/empty' && touch '$tmp/empty/INDEX.sha256' && ! vfy --archive-root '$tmp/empty' >/dev/null 2>&1"

  echo "self-test: $ok ok, $bad failed"
  [ "$bad" -eq 0 ]
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-}" in
    archive) shift; re_archive "$@" ;;
    restore) shift; re_restore "$@" ;;
    verify)  shift; re_verify "$@" ;;
    list)    shift; re_list "$@" ;;
    --self-test) _re_self_test && echo "restore-evidence.sh: SELF-TEST OK" ;;
    *) cat >&2 <<'EOF'
usage:
  restore-evidence.sh archive --bundle <dir> --archive-root <root>
  restore-evidence.sh restore --archive-root <root> --bundle-id <id> --dest <dir>
  restore-evidence.sh verify  --archive-root <root> [--bundle-id <id>]
  restore-evidence.sh list    --archive-root <root> [--today YYYY-MM-DD]
  restore-evidence.sh --self-test
EOF
       exit 2 ;;
  esac
fi
