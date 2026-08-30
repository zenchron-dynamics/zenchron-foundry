#!/usr/bin/env bash
# =============================================================================
# scripts/ci/evidence-restore-drill.sh — #241, the restore drill.
# -----------------------------------------------------------------------------
# Prove that a staged evidence bundle survives the GitHub Actions artifact
# boundary and can be restored, by a DIFFERENT runner, from nothing but the
# bytes that came back.
#
# WHAT THIS PROVES AND WHAT IT DOES NOT. It proves TRANSPORT AND RESTORATION:
# upload, download onto a fresh filesystem, archive, restore by bundle id,
# offline re-verify, and byte-for-byte equality with what was handed over. It
# does NOT produce production evidence and its bundle is NOT an accepted
# candidate. The input is a committed acceptance record and a FIXTURE
# authorization record built by tests/lib/make_authorization_fixture.py; every
# artifact it writes is named `evidence-drill-*` and every verdict it emits
# repeats this sentence. Nothing here builds an image, scans anything,
# dispatches acceptance, publishes, tags or releases.
#
# A PRODUCER AND A CONSUMER SHARING A DIRECTORY IS NOT A RESTORE DRILL. The
# `produce` and `restore` subcommands are invoked from two different jobs on two
# different runners; the only thing that crosses between them is an artifact.
#
# EVERY REFUSAL CARRIES ITS OWN CODE:
#
#   DR-ARTIFACT-ABSENT       the bundle artifact did not come back
#   DR-RECEIPT-ABSENT        the receipt artifact did not come back
#   DR-FILE-MISSING          a file that was uploaded is not in the copy
#   DR-BYTES-DIFFER          a file came back with different bytes
#   DR-EXTRA-FILE            a file appeared that was never uploaded
#   DR-BUNDLE-REFUSED        the production bundle verifier refused the copy
#   DR-ARCHIVE-WRITABLE      the archived tree is not write-once (R3)
#   DR-RESTORE-FAILED        the production restore consumer refused
#   DR-CLASS-MISMATCH        the evidence class is not the one being drilled
#   DR-BINDING-MISMATCH      the receipt is not about this bundle
#   DR-VERDICT-ABSENT        the drill produced no verdict, or none was found
#   DR-VERDICT-MALFORMED     the verdict is not a drill verdict
#   DR-VERDICT-UNBOUND       the verdict is for another run or another commit
#   DR-VERDICT-NOT-PASS      the verdict exists and does not say the drill passed
#   DR-RESTORE-NOT-EXECUTED  the verdict records no run of the restore consumer
#
# Usage:
#   evidence-restore-drill.sh produce --evidence FILE --out DIR [--today D]
#   evidence-restore-drill.sh receipt --record FILE --readback-dir DIR
#        --observation FILE --out FILE [--repository OWNER/REPO]
#   evidence-restore-drill.sh restore --bundle-artifact DIR --receipt-artifact DIR
#        --work DIR --verdict FILE --run-id N --commit SHA
#   evidence-restore-drill.sh consume --verdict FILE --run-id N --commit SHA
# =============================================================================
set -uo pipefail
_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$_d/../.." && pwd)"

GEN="$ROOT/scripts/release/generate-evidence-bundle.sh"
RES="$ROOT/scripts/release/restore-evidence.sh"
EMIT="$ROOT/scripts/release/emit-storage-receipt.sh"
VER="$ROOT/scripts/release/verify-storage-receipt.sh"
MKREC="$ROOT/tests/lib/make_authorization_fixture.py"
CLASS=staged-candidate

NOT_PRODUCTION="This is a TRANSPORT AND RESTORATION drill. The bundle is built from a fixture authorization record and is NOT production evidence, NOT an accepted candidate and NOT a release."

refuse() { printf 'REFUSE [%s]: %s\n' "$1" "$2" >&2; exit 1; }
usage()  { sed -n '/^# Usage:/,/^# ===/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//' >&2; exit 64; }

# Every file under a directory, as "sha256  relative/path", sorted. Closed-world
# on purpose: an extra file is as much a transport failure as a missing one.
_index() { ( cd "$1" && find . -type f | sed 's|^\./||' | LC_ALL=C sort \
             | while IFS= read -r f; do printf '%s  %s\n' \
                 "$(shasum -a 256 "$f" | cut -d' ' -f1)" "$f"; done ); }

# Compare a directory against a recorded index and name the FIRST difference.
_compare() { # _compare <index-file> <dir> <what>
  local idx="$1" dir="$2" what="$3" want got line f h
  [ -s "$idx" ] || refuse "DR-ARTIFACT-ABSENT" \
    "no upload index at $idx, so there is nothing to compare $what against"
  while IFS= read -r line; do
    h="${line%%  *}"; f="${line#*  }"
    [ -n "$f" ] || continue
    [ -f "$dir/$f" ] || refuse "DR-FILE-MISSING" \
      "$f was uploaded and is NOT in the $what copy at $dir"
    got="$(shasum -a 256 "$dir/$f" | cut -d' ' -f1)"
    [ "$got" = "$h" ] || refuse "DR-BYTES-DIFFER" \
      "$f came back as ${got:0:16} and was handed over as ${h:0:16}. A byte that changed in transit is not the evidence anybody decided on"
  done < "$idx"
  want="$(cut -d' ' -f3- "$idx" | LC_ALL=C sort)"
  got="$(cd "$dir" && find . -type f | sed 's|^\./||' | LC_ALL=C sort)"
  [ "$want" = "$got" ] || refuse "DR-EXTRA-FILE" \
    "the $what copy holds files that were never uploaded: $(comm -13 <(echo "$want") <(echo "$got") | tr '\n' ' ')"
}

cmd="${1-}"; shift 2>/dev/null || usage

case "$cmd" in
# ---------------------------------------------------------------------------
produce)
  EV="" OUT="" TODAY="2026-08-25"
  while [ $# -gt 0 ]; do case "$1" in
    --evidence) EV="${2-}"; shift 2 ;;
    --out)      OUT="${2-}"; shift 2 ;;
    --today)    TODAY="${2-}"; shift 2 ;;
    *) echo "unknown: $1" >&2; usage ;;
  esac; done
  [ -n "$EV" ] && [ -n "$OUT" ] || usage
  rm -rf "$OUT"; mkdir -p "$OUT"
  python3 "$MKREC" "$EV" "$OUT/record.json" >/dev/null || \
    refuse "DR-BUNDLE-REFUSED" "the fixture authorization record could not be built"
  bash "$GEN" generate --evidence "$EV" --authorization "$OUT/record.json" \
      --out "$OUT/bundle" --evidence-class "$CLASS" --today "$TODAY" >/dev/null || \
    refuse "DR-BUNDLE-REFUSED" "the production bundle producer refused to build the drill bundle"
  bash "$GEN" verify "$OUT/bundle" >/dev/null || \
    refuse "DR-BUNDLE-REFUSED" "the bundle it just wrote does not verify"
  printf '%s\n' "$NOT_PRODUCTION" > "$OUT/DRILL.txt"
  # The index covers EVERY file, including the bundle's own SHA256SUMS and
  # BUNDLE.sha256, because the claim being tested is about bytes in transit and
  # not about the bundle's opinion of itself.
  _index "$OUT/bundle" > "$OUT/UPLOADED.sha256"
  printf 'drill bundle produced: %s (%s file(s))\n' \
    "$OUT/bundle" "$(wc -l < "$OUT/UPLOADED.sha256" | tr -d ' ')" >&2
  ;;
# ---------------------------------------------------------------------------
receipt)
  REC="" RB="" OBS="" OUT="" REPO="${GITHUB_REPOSITORY:-unknown/unknown}"
  while [ $# -gt 0 ]; do case "$1" in
    --record)       REC="${2-}"; shift 2 ;;
    --readback-dir) RB="${2-}"; shift 2 ;;
    --observation)  OBS="${2-}"; shift 2 ;;
    --out)          OUT="${2-}"; shift 2 ;;
    --repository)   REPO="${2-}"; shift 2 ;;
    *) echo "unknown: $1" >&2; usage ;;
  esac; done
  [ -n "$REC" ] && [ -n "$RB" ] && [ -n "$OBS" ] && [ -n "$OUT" ] || usage
  mkdir -p "$(dirname "$OUT")"
  bash "$EMIT" --authorization "$REC" --observation "$OBS" --readback-dir "$RB" \
      --evidence-class "$CLASS" --repository "$REPO" --out "$OUT" || exit 1
  # VERIFIED BEFORE IT IS UPLOADED. A receipt nobody checked is a claim.
  bash "$VER" "$OUT" --authorization "$REC" || exit 1
  cp "$REC" "$(dirname "$OUT")/record.json"
  ;;
# ---------------------------------------------------------------------------
restore)
  BA="" RA="" WORK="" VERDICT="" RUN_ID="" COMMIT=""
  while [ $# -gt 0 ]; do case "$1" in
    --bundle-artifact)  BA="${2-}"; shift 2 ;;
    --receipt-artifact) RA="${2-}"; shift 2 ;;
    --work)             WORK="${2-}"; shift 2 ;;
    --verdict)          VERDICT="${2-}"; shift 2 ;;
    --run-id)           RUN_ID="${2-}"; shift 2 ;;
    --commit)           COMMIT="${2-}"; shift 2 ;;
    *) echo "unknown: $1" >&2; usage ;;
  esac; done
  [ -n "$BA" ] && [ -n "$RA" ] && [ -n "$WORK" ] && [ -n "$VERDICT" ] || usage

  [ -d "$BA/bundle" ] || refuse "DR-ARTIFACT-ABSENT" \
    "no bundle came back at $BA/bundle. An artifact that is not there is a refusal, never a skip: a drill that passes when nothing was restored proves nothing"
  [ -s "$RA/storage-receipt.json" ] || refuse "DR-RECEIPT-ABSENT" \
    "no storage receipt came back at $RA/storage-receipt.json"
  [ -s "$RA/record.json" ] || refuse "DR-RECEIPT-ABSENT" \
    "no authorization record came back at $RA/record.json, so the receipt has nothing to be bound to"

  # 1. THE TRANSPORT BOUNDARY, checked before anything interprets the bytes.
  _compare "$BA/UPLOADED.sha256" "$BA/bundle" "downloaded"

  # 2. The production bundle verifier, on the copy that came back.
  bash "$GEN" verify "$BA/bundle" >/dev/null 2>&1 || refuse "DR-BUNDLE-REFUSED" \
    "the production bundle verifier refused the downloaded copy"

  cls="$(python3 -c "import json;print(json.load(open('$BA/bundle/manifest.json')).get('evidence_class'))")"
  [ "$cls" = "$CLASS" ] || refuse "DR-CLASS-MISMATCH" \
    "the restored bundle declares evidence class %r and this drill is for '$CLASS'. A staged candidate is not a release"

  rm -rf "$WORK"; mkdir -p "$WORK"
  bid="$(python3 -c "import json;print(json.load(open('$BA/bundle/manifest.json'))['bundle_id'])")"

  # 3. Archive, then prove the archived tree is write-once (R3 is not relaxed).
  bash "$RES" archive --bundle "$BA/bundle" --archive-root "$WORK/archive" >/dev/null 2>&1 || \
    refuse "DR-RESTORE-FAILED" "the production archiver refused the restored bundle"
  am="$(find "$WORK/archive" -name manifest.json | head -1)"
  if [ -n "$am" ] && ( printf x >> "$am" ) 2>/dev/null; then
    refuse "DR-ARCHIVE-WRITABLE" \
      "the archived tree accepted an ordinary write. A write-once archive that can be written is a directory"
  fi

  # 4. DELETE the downloaded working copy, then restore from the archive alone.
  rm -rf "$BA/bundle"
  bash "$RES" restore --archive-root "$WORK/archive" --bundle-id "$bid" \
      --dest "$WORK/restored" >/dev/null 2>&1 || \
    refuse "DR-RESTORE-FAILED" "the production restore consumer refused to restore $bid"
  bash "$RES" verify --archive-root "$WORK/archive" >/dev/null 2>&1 || \
    refuse "DR-RESTORE-FAILED" "the archive does not verify after the restore"
  bash "$GEN" verify "$WORK/restored" >/dev/null 2>&1 || \
    refuse "DR-BUNDLE-REFUSED" "the restored copy does not verify offline"

  # 5. THE RESTORED bytes, against what was uploaded. Same index, second time:
  # surviving the download is not the same claim as surviving the restore.
  _compare "$BA/UPLOADED.sha256" "$WORK/restored" "restored"

  # 6. The receipt, verified against the record that came back with it.
  bash "$VER" "$RA/storage-receipt.json" --authorization "$RA/record.json" >/dev/null || exit 1
  rrev="$(python3 -c "import json;print(json.load(open('$RA/storage-receipt.json'))['bundle']['source_revision'])")"
  brev="$(python3 -c "import json;print(json.load(open('$WORK/restored/manifest.json'))['source_revision'])")"
  [ "$rrev" = "$brev" ] || refuse "DR-BINDING-MISMATCH" \
    "the receipt is for source revision ${rrev:0:12} and the restored bundle is ${brev:0:12}"
  rcls="$(python3 -c "import json;print(json.load(open('$RA/storage-receipt.json'))['bundle']['retention_class'])")"
  [ "$rcls" = "$CLASS" ] || refuse "DR-CLASS-MISMATCH" \
    "the receipt's retention class is '$rcls', not '$CLASS'"

  mkdir -p "$(dirname "$VERDICT")"
  RD_RUN="$RUN_ID" RD_COMMIT="$COMMIT" RD_BID="$bid" RD_REV="$brev" \
  RD_WORK="$WORK" RD_RA="$RA" RD_NOTE="$NOT_PRODUCTION" RD_RES="$RES" \
  RD_OUT="$VERDICT" python3 <<'PY'
import datetime, hashlib, json, os, subprocess

def sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()

work, ra = os.environ["RD_WORK"], os.environ["RD_RA"]
files = []
for r, _, fs in os.walk(os.path.join(work, "restored")):
    for f in fs:
        p = os.path.join(r, f)
        files.append(os.path.relpath(p, os.path.join(work, "restored")))
v = {
    "schema": "foundry.evidence-restore-drill/v1",
    "result": "pass",
    "not_production_evidence": os.environ["RD_NOTE"],
    "run_id": os.environ["RD_RUN"],
    "commit": os.environ["RD_COMMIT"],
    "bundle_id": os.environ["RD_BID"],
    "evidence_class": "staged-candidate",
    "source_revision": os.environ["RD_REV"],
    "files_restored": len(files),
    "manifest_sha256": sha(os.path.join(work, "restored", "manifest.json")),
    "receipt_sha256": sha(os.path.join(ra, "storage-receipt.json")),
    # WHICH CONSUMER RAN, by its own content hash. A verdict that cannot name
    # the restore consumer it ran is a verdict about nothing.
    "restore_consumer": {
        "name": "scripts/release/restore-evidence.sh",
        "sha256": sha(os.environ["RD_RES"]),
        "exit": 0,
    },
    "at": datetime.datetime.now(datetime.timezone.utc)
          .isoformat(timespec="seconds").replace("+00:00", "Z"),
}
with open(os.environ["RD_OUT"], "w") as fh:
    json.dump(v, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY
  printf 'restore drill PASSED: %s restored and re-verified from the archive alone\n' "$bid" >&2
  ;;
# ---------------------------------------------------------------------------
consume)
  V="" RUN_ID="" COMMIT=""
  while [ $# -gt 0 ]; do case "$1" in
    --verdict) V="${2-}"; shift 2 ;;
    --run-id)  RUN_ID="${2-}"; shift 2 ;;
    --commit)  COMMIT="${2-}"; shift 2 ;;
    *) echo "unknown: $1" >&2; usage ;;
  esac; done
  [ -n "$V" ] || usage
  [ -s "$V" ] || refuse "DR-VERDICT-ABSENT" \
    "no restore-drill verdict at $V. The drill either did not run or did not finish, and either way nothing here has been shown to survive a round trip"
  RD_V="$V" RD_RUN="$RUN_ID" RD_COMMIT="$COMMIT" python3 <<'PY' || exit 1
import json, os, sys

def refuse(code, msg):
    sys.stderr.write("REFUSE [%s]: %s\n" % (code, msg))
    raise SystemExit(1)

try:
    v = json.load(open(os.environ["RD_V"]))
except Exception as exc:                                  # noqa: BLE001
    refuse("DR-VERDICT-MALFORMED", "%s is not readable JSON: %s"
           % (os.environ["RD_V"], exc))
if v.get("schema") != "foundry.evidence-restore-drill/v1":
    refuse("DR-VERDICT-MALFORMED",
           "schema is %r, not a restore-drill verdict" % v.get("schema"))
want_run, want_commit = os.environ.get("RD_RUN") or "", os.environ.get("RD_COMMIT") or ""
if want_run and str(v.get("run_id")) != want_run:
    refuse("DR-VERDICT-UNBOUND",
           "the verdict is for run %r and this is run %r. A verdict from another "
           "run says nothing about this one" % (v.get("run_id"), want_run))
if want_commit and str(v.get("commit")) != want_commit:
    refuse("DR-VERDICT-UNBOUND",
           "the verdict is for commit %s and this is %s"
           % (str(v.get("commit"))[:12], want_commit[:12]))
rc = v.get("restore_consumer") or {}
if not rc.get("name") or rc.get("exit") != 0 or not rc.get("sha256"):
    refuse("DR-RESTORE-NOT-EXECUTED",
           "the verdict records no successful run of a named restore consumer: %r. "
           "Generating a verdict is not restoring anything" % (rc or None))
if v.get("result") != "pass":
    refuse("DR-VERDICT-NOT-PASS",
           "the drill verdict is %r" % v.get("result"))
if not v.get("not_production_evidence"):
    refuse("DR-VERDICT-MALFORMED",
           "the verdict does not state that it is a drill and not production evidence")
sys.stderr.write(
    "restore-drill verdict CONSUMED: %s, %d file(s) restored and re-verified by %s\n"
    % (v["bundle_id"], v["files_restored"], rc["name"]))
PY
  ;;
*) usage ;;
esac
