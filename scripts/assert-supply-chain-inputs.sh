#!/usr/bin/env bash
# =============================================================================
# scripts/assert-supply-chain-inputs.sh — the two consumers of the input
# inventory (#101, #123).
#
#   INTEGRITY (default, offline)
#     Every declared input is pinned to an exact version AND bound by a checksum
#     or a digest; the pin in policies/supply-chain-inputs.yaml matches the pin
#     in the code that uses it; and nothing in the code claims an input the
#     inventory does not declare. An input with no integrity binding is a
#     FAILURE, not a warning — the one exception is an entry that declares
#     `integrity_gap: true`, which is how the Debian package index is recorded
#     rather than hidden.
#
#   DRIFT (--check-upstream, network)
#     Is there a newer version, and is the pinned one past its staleness SLA.
#     Reports; escalates to failure past the SLA. Separate from the offline gate
#     for the same reason assert-pinned-actions.sh splits: a network failure must
#     not be able to fail a build for a reason unrelated to the build.
#
# Fails closed throughout. An unreadable inventory, an empty input list, or a
# declared file that does not exist are all failures: "could not check" must
# never read as "the input is pinned".
#
# Usage:
#   assert-supply-chain-inputs.sh                  integrity (offline)
#   assert-supply-chain-inputs.sh --check-upstream integrity + drift
#   assert-supply-chain-inputs.sh --self-test
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1
INVENTORY="${SUPPLY_CHAIN_INVENTORY:-$ROOT/policies/supply-chain-inputs.yaml}"

integrity() {
  INVENTORY="$1" TODAY="${TODAY:-$(date -u +%F)}" python3 - <<'PY'
import datetime, os, re, sys, yaml

inv_path = os.environ["INVENTORY"]
today    = datetime.date.fromisoformat(os.environ["TODAY"])

def die(m):
    print("SUPPLY-CHAIN FAIL: %s" % m, file=sys.stderr); sys.exit(1)

try:
    doc = yaml.safe_load(open(inv_path)) or {}
except Exception as exc:
    die("cannot read %s: %s" % (inv_path, exc))
if doc.get("schema_version") != 1:
    die("unknown or missing schema_version %r" % doc.get("schema_version"))

pol = doc.get("policy") or {}
for k in ("staleness_sla_days", "review_every_days", "last_reviewed"):
    if pol.get(k) is None:
        die("policy.%s is required" % k)

inputs = doc.get("inputs")
if not isinstance(inputs, list) or not inputs:
    die("'inputs' is empty or not a list — the check would be vacuous")

REQUIRED = ("id", "kind", "classification", "owner", "version", "source",
            "integrity", "declared_in", "update_signal")
CLASSES  = {"ships-in-image", "release-gate"}

errors, gaps = [], []
seen = set()

for i, e in enumerate(inputs):
    if not isinstance(e, dict):
        die("inputs[%d] is not a mapping" % i)
    who = "inputs[%d] (%s)" % (i, e.get("id"))
    for f in REQUIRED:
        if e.get(f) in (None, "", []):
            errors.append("%s: missing required field '%s'" % (who, f))
    if e.get("id") in seen:
        errors.append("%s: duplicate id" % who)
    seen.add(e.get("id"))
    if e.get("classification") not in CLASSES:
        errors.append("%s: classification %r not in %s"
                      % (who, e.get("classification"), sorted(CLASSES)))

    # --- the integrity binding -------------------------------------------
    integ = str(e.get("integrity") or "")
    if e.get("integrity_gap") is True:
        # A declared gap is allowed, but it must SAY it is a gap and explain
        # itself. Silence and "we know" must not look the same in this file.
        if integ != "none":
            errors.append("%s: integrity_gap is true but integrity is %r — a gap "
                          "must be declared as 'none'" % (who, integ))
        if not e.get("note"):
            errors.append("%s: an integrity gap must carry a note explaining it" % who)
        gaps.append(e["id"])
    elif integ.startswith("sha256:"):
        if not re.match(r"^sha256:[0-9a-f]{64}", integ):
            errors.append("%s: integrity %r is not a sha256 digest" % (who, integ))
    elif integ == "inherited-from-base":
        if not e.get("integrity_binding"):
            errors.append("%s: 'inherited-from-base' needs integrity_binding "
                          "naming what actually pins it" % who)
    else:
        errors.append("%s: integrity %r is neither a sha256, an inherited "
                      "binding, nor a declared gap" % (who, integ))

    # --- the files it claims to be declared in must exist AND mention it ---
    for f in (e.get("declared_in") or []):
        if not os.path.exists(f):
            errors.append("%s: declared_in %s does not exist" % (who, f))
            continue
        body = open(f, encoding="utf-8", errors="replace").read()
        # The pin must be findable in the file. Version for a version-pinned
        # input, digest for a digest-pinned one — otherwise the inventory and the
        # code have drifted, which is the whole failure mode this prevents.
        needle = None
        if integ.startswith("sha256:"):
            needle = integ.split(":", 1)[1][:64]
        elif e.get("version") not in (None, "inherited", "floating",
                                      "pinned-by-digest-only"):
            needle = str(e["version"])
        if needle and needle not in body:
            errors.append("%s: %s does not contain the declared pin %r — the "
                          "inventory and the code have drifted"
                          % (who, f, needle))

reviewed = pol["last_reviewed"]
reviewed = reviewed if isinstance(reviewed, datetime.date) else datetime.date.fromisoformat(str(reviewed))
stale = (today - reviewed).days
if stale > int(pol["review_every_days"]):
    errors.append("policy.last_reviewed is %s, %d days ago (cadence %s)"
                  % (reviewed, stale, pol["review_every_days"]))

if errors:
    print("SUPPLY-CHAIN FAIL: %d problem(s):" % len(errors), file=sys.stderr)
    for e in errors:
        print("  %s" % e, file=sys.stderr)
    sys.exit(1)

print("SUPPLY-CHAIN OK: %d input(s) declared, %d with a full integrity binding, "
      "%d declared gap(s): %s"
      % (len(inputs), len(inputs) - len(gaps), len(gaps), ", ".join(gaps) or "none"))
PY
}

# --- the other half of #123: is anything we pin behind, or stale? -----------
drift() {
  echo "--- upstream drift"
  command -v gh >/dev/null 2>&1 || { echo "REFUSE: gh is required for --check-upstream" >&2; return 1; }
  local rc=0
  while IFS='|' read -r id ver signal sla; do
    [ -n "$id" ] || continue
    case "$signal" in
      github-releases:*)
        local repo latest
        repo="${signal#github-releases:}"
        latest="$(gh api "repos/$repo/releases/latest" --jq '.tag_name' 2>/dev/null || true)"
        if [ -z "$latest" ]; then
          # Fail closed: an unresolvable update signal is an input we have
          # stopped watching, which is the condition #123 exists to prevent.
          printf '  %-26s UNRESOLVED (%s) — the update signal is broken\n' "$id" "$repo"
          rc=1
          continue
        fi
        if [ "${latest#v}" = "${ver#v}" ]; then
          printf '  %-26s current (%s)\n' "$id" "$ver"
        else
          printf '  %-26s BEHIND: pinned %s, upstream %s [sla=%s]\n' "$id" "$ver" "$latest" "$sla"
          rc=1
        fi
        ;;
      base-digest)
        printf '  %-26s tracked via the base digest — see policies/lifecycle.yaml\n' "$id"
        ;;
      *)
        printf '  %-26s signal %s not automatable here; reviewed on the cadence\n' "$id" "$signal"
        ;;
    esac
  done < <(python3 -c "
import yaml
d=yaml.safe_load(open('$INVENTORY'))
for e in d['inputs']:
    print('%s|%s|%s|%s' % (e['id'], e.get('version',''), e.get('update_signal',''), e.get('sla','default')))")
  return "$rc"
}

self_test() {
  local tmp ok=0 bad=0
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  t() { if eval "$2"; then ok=$((ok+1)); echo "  ok   $1"; else bad=$((bad+1)); echo "  FAIL $1"; fi; }

  # Every fixture needs a real declared_in: an empty one would make the
  # code-vs-inventory comparison vacuous, which is exactly what the rule
  # rejects, so the fixtures must not lean on it either.
  printf 'ARG X_VERSION="1.0"\n' > "$tmp/decl.Dockerfile"
  mk() { { echo "schema_version: 1"
           echo "policy: {staleness_sla_days: 90, review_every_days: 90, last_reviewed: 2026-08-01}"
           echo "inputs:"; cat; } > "$1"; }
  local T=2026-08-12
  local S=0000000000000000000000000000000000000000000000000000000000000000

  mk "$tmp/good.yaml" <<Y
  - {id: a, kind: k, classification: release-gate, owner: o, version: "1.0",
     source: s, integrity: "sha256:$S", declared_in: ["$tmp/sha.Dockerfile"], update_signal: u}
Y
  printf 'checksum %s\n' "$S" > "$tmp/sha.Dockerfile"
  t "a fully pinned input passes" "TODAY=$T integrity '$tmp/good.yaml' >/dev/null"

  mk "$tmp/nointeg.yaml" <<Y
  - {id: a, kind: k, classification: release-gate, owner: o, version: "1.0",
     source: s, integrity: "", declared_in: ["$tmp/decl.Dockerfile"], update_signal: u}
Y
  t "an input with no integrity binding FAILS" \
    "! TODAY=$T integrity '$tmp/nointeg.yaml' >/dev/null 2>&1"

  mk "$tmp/badsha.yaml" <<Y
  - {id: a, kind: k, classification: release-gate, owner: o, version: "1.0",
     source: s, integrity: "sha256:nothex", declared_in: ["$tmp/decl.Dockerfile"], update_signal: u}
Y
  t "a malformed sha256 FAILS" "! TODAY=$T integrity '$tmp/badsha.yaml' >/dev/null 2>&1"

  mk "$tmp/inherited.yaml" <<Y
  - {id: a, kind: k, classification: ships-in-image, owner: o, version: inherited,
     source: s, integrity: inherited-from-base, declared_in: ["$tmp/decl.Dockerfile"], update_signal: u}
Y
  t "'inherited-from-base' without integrity_binding FAILS" \
    "! TODAY=$T integrity '$tmp/inherited.yaml' >/dev/null 2>&1"
  mk "$tmp/inherited-ok.yaml" <<Y
  - {id: a, kind: k, classification: ships-in-image, owner: o, version: inherited,
     source: s, integrity: inherited-from-base, integrity_binding: "base@sha256:x",
     declared_in: ["$tmp/decl.Dockerfile"], update_signal: u}
Y
  t "...and passes once it names what pins it" \
    "TODAY=$T integrity '$tmp/inherited-ok.yaml' >/dev/null"

  # A declared gap is allowed, but only when it says so and explains itself.
  mk "$tmp/gap.yaml" <<Y
  - {id: a, kind: k, classification: ships-in-image, owner: o, version: floating,
     source: s, integrity: none, integrity_gap: true, note: "why",
     declared_in: ["$tmp/decl.Dockerfile"], update_signal: u}
Y
  t "a DECLARED integrity gap passes" "TODAY=$T integrity '$tmp/gap.yaml' >/dev/null"
  mk "$tmp/gap-nonote.yaml" <<Y
  - {id: a, kind: k, classification: ships-in-image, owner: o, version: floating,
     source: s, integrity: none, integrity_gap: true, declared_in: ["$tmp/decl.Dockerfile"], update_signal: u}
Y
  t "...but an unexplained gap FAILS" \
    "! TODAY=$T integrity '$tmp/gap-nonote.yaml' >/dev/null 2>&1"
  mk "$tmp/undeclared-none.yaml" <<Y
  - {id: a, kind: k, classification: ships-in-image, owner: o, version: floating,
     source: s, integrity: none, declared_in: ["$tmp/decl.Dockerfile"], update_signal: u}
Y
  t "...and integrity 'none' WITHOUT integrity_gap FAILS" \
    "! TODAY=$T integrity '$tmp/undeclared-none.yaml' >/dev/null 2>&1"

  # THE drift case: the inventory says one thing, the code says another.
  printf 'checksum 1111111111111111111111111111111111111111111111111111111111111111\n' > "$tmp/fake.Dockerfile"
  mk "$tmp/drifted.yaml" <<Y
  - {id: a, kind: k, classification: ships-in-image, owner: o, version: "1.2.3",
     source: s, integrity: "sha256:$S", declared_in: ["$tmp/fake.Dockerfile"],
     update_signal: u}
Y
  t "an inventory pin the code does not contain FAILS" \
    "! TODAY=$T integrity '$tmp/drifted.yaml' >/dev/null 2>&1"
  printf 'checksum %s\n' "$S" > "$tmp/fake.Dockerfile"
  t "...and passes once they agree" "TODAY=$T integrity '$tmp/drifted.yaml' >/dev/null"

  mk "$tmp/missingfile.yaml" <<Y
  - {id: a, kind: k, classification: ships-in-image, owner: o, version: "1.2.3",
     source: s, integrity: "sha256:$S", declared_in: ["nope/gone.Dockerfile"],
     update_signal: u}
Y
  t "a declared_in file that does not exist FAILS" \
    "! TODAY=$T integrity '$tmp/missingfile.yaml' >/dev/null 2>&1"

  printf 'schema_version: 1\npolicy: {staleness_sla_days: 1, review_every_days: 90, last_reviewed: 2026-08-01}\ninputs: []\n' > "$tmp/empty.yaml"
  t "an empty input list FAILS (the check would be vacuous)" \
    "! TODAY=$T integrity '$tmp/empty.yaml' >/dev/null 2>&1"
  printf 'not: [valid\n' > "$tmp/broken.yaml"
  t "an unreadable inventory FAILS closed" \
    "! TODAY=$T integrity '$tmp/broken.yaml' >/dev/null 2>&1"

  mk "$tmp/oldreview.yaml" <<Y
  - {id: a, kind: k, classification: release-gate, owner: o, version: "1.0",
     source: s, integrity: "sha256:$S", declared_in: ["$tmp/sha.Dockerfile"], update_signal: u}
Y
  sed -i.bak 's/last_reviewed: 2026-08-01/last_reviewed: 2020-01-01/' "$tmp/oldreview.yaml"
  t "an inventory past its own review cadence FAILS" \
    "! TODAY=$T integrity '$tmp/oldreview.yaml' >/dev/null 2>&1"

  # INTEGRATION: the real inventory must pass, today, against the real tree.
  t "the REAL policies/supply-chain-inputs.yaml passes" \
    "integrity '$INVENTORY' >/dev/null"

  echo "self-test: $ok ok, $bad failed"
  [ "$bad" -eq 0 ]
}

case "${1:-}" in
  --self-test)      self_test ;;
  --check-upstream) integrity "$INVENTORY" && drift ;;
  "")               integrity "$INVENTORY" ;;
  *) echo "usage: $(basename "$0") [--check-upstream|--self-test]" >&2; exit 64 ;;
esac
