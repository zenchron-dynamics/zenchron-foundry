#!/usr/bin/env bash
# =============================================================================
# scripts/assert-lifecycle.sh — fail before a pinned upstream line goes
# unmaintained, not after (#104, #105, #106).
#
# The gap this closes. Digest pinning fixes WHAT we build on and says nothing
# about whether that thing is still maintained. The nginx base sat on 1.27 — a
# mainline line upstream had superseded and which nginx.org no longer lists —
# while the strategy document called it "nginx 1.27 stable". No gate could see
# it: the vulnerability gate only reports CVEs already published against the
# version we ship, and an unmaintained line's defining property is that new CVEs
# stop getting fixed rather than stop being found.
#
# Usage:
#   assert-lifecycle.sh                  offline: inventory consistency + dates
#   assert-lifecycle.sh --check-upstream additionally re-resolve tracked tags
#   assert-lifecycle.sh --self-test
#
# Exit 0 = every line inside its window, 1 = at least one breach or a malformed
# inventory. TODAY may be overridden for tests only.
#
# Fails closed throughout: an unreadable inventory, an empty `lines:` list, a
# line used by an image but absent from the inventory, or a date it cannot parse
# are all FAILURES. "Could not determine the lifecycle state" must never read as
# "the lifecycle state is fine".
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INVENTORY="${LIFECYCLE_INVENTORY:-$ROOT/policies/lifecycle.yaml}"

check() {
  INVENTORY="$1" TODAY="${TODAY:-$(date -u +%F)}" ROOT_DIR="$ROOT" \
  STRICT_USED_BY="${STRICT_USED_BY:-1}" python3 - <<'PY'
import datetime, os, sys, yaml

inv_path = os.environ["INVENTORY"]
today    = datetime.date.fromisoformat(os.environ["TODAY"])
root     = os.environ["ROOT_DIR"]
strict   = os.environ["STRICT_USED_BY"] != "0"

def die(msg):
    print("LIFECYCLE FAIL: %s" % msg, file=sys.stderr)
    sys.exit(1)

try:
    doc = yaml.safe_load(open(inv_path)) or {}
except Exception as exc:
    die("cannot read %s: %s" % (inv_path, exc))

if doc.get("schema_version") != 1:
    die("unknown or missing schema_version %r" % doc.get("schema_version"))

pol = doc.get("policy")
if not isinstance(pol, dict):
    die("'policy' block missing — the thresholds are what make this enforceable")
for k in ("warn_days_before_support_end", "grace_days_after_support_end",
          "review_every_days", "last_reviewed"):
    if pol.get(k) is None:
        die("policy.%s is required" % k)

lines = doc.get("lines")
if not isinstance(lines, list) or not lines:
    # A gate that checks nothing is worse than no gate: it reports success.
    die("'lines' is empty or not a list — the check would be vacuous")

def as_date(v, who, field):
    if v is None:
        return None
    if isinstance(v, datetime.datetime):
        return v.date()
    if isinstance(v, datetime.date):
        return v
    try:
        return datetime.date.fromisoformat(str(v))
    except ValueError:
        die("%s: %s=%r is not a YYYY-MM-DD date" % (who, field, v))

REQUIRED = ("id", "kind", "tracks", "upstream_state", "source", "used_by")
STATES = {"stable", "oldstable", "supported", "active", "security-only",
          "unsupported", "eol"}

errors, warnings = [], []
by_id = {}

for i, e in enumerate(lines):
    if not isinstance(e, dict):
        die("lines[%d] is not a mapping" % i)
    who = "lines[%d] (%s)" % (i, e.get("id"))
    for f in REQUIRED:
        if e.get(f) is None:
            errors.append("%s: missing required field '%s'" % (who, f))
    if e.get("id") in by_id:
        errors.append("%s: duplicate id" % who)
    by_id[e.get("id")] = e

    if e.get("upstream_state") not in STATES:
        errors.append("%s: upstream_state %r is not one of %s"
                      % (who, e.get("upstream_state"), sorted(STATES)))

    if not isinstance(e.get("used_by"), list):
        errors.append("%s: used_by must be a list (use [] for 'not used yet')" % who)

    ends = as_date(e.get("support_ends"), who, "support_ends")
    # A line with no calendar EOL must SAY so. Silence is indistinguishable from
    # "nobody looked", which is the state this file exists to end.
    if ends is None and not e.get("support_ends_note"):
        errors.append("%s: support_ends is null and no support_ends_note explains "
                      "why — an unexplained null is not evidence of support" % who)

    used = e.get("used_by") or []

    # The core rule. It only bites for lines something actually ships on: an
    # inventory entry for a line we DO NOT use (a successor, or a retired one
    # kept as a tripwire) is documentation, not exposure.
    if used and ends is not None:
        if today > ends:
            overdue = (today - ends).days
            grace = int(pol["grace_days_after_support_end"])
            msg = ("%s: support ended %s (%d days ago) and it is still used by %s"
                   % (who, ends, overdue, ", ".join(used)))
            if overdue > grace:
                errors.append(msg + " — past the %d-day grace period" % grace)
            else:
                warnings.append(msg + " — inside the %d-day grace period; "
                                "migrate now" % grace)
        else:
            left = (ends - today).days
            if left <= int(pol["warn_days_before_support_end"]):
                warnings.append("%s: support ends %s (%d days) and it is used by "
                                "%s — plan the migration"
                                % (who, ends, left, ", ".join(used)))

    # An explicitly unsupported line must not be in use at all, regardless of the
    # date arithmetic. This is what catches a digest bump landing back on 1.27.
    if used and e.get("upstream_state") in ("unsupported", "eol"):
        errors.append("%s: upstream_state is %r but it is still used by %s"
                      % (who, e.get("upstream_state"), ", ".join(used)))

# --- the inventory must be reviewed ----------------------------------------
reviewed = as_date(pol.get("last_reviewed"), "policy", "last_reviewed")
stale = (today - reviewed).days
if stale > int(pol["review_every_days"]):
    errors.append("policy.last_reviewed is %s, %d days ago (cadence %s) — an "
                  "inventory nobody re-reads is the failure it exists to prevent"
                  % (reviewed, stale, pol["review_every_days"]))

# --- every shipped image's base line must be IN the inventory ---------------
# Otherwise a new image family silently escapes lifecycle tracking entirely.
if strict:
    covered = {img for e in lines for img in (e.get("used_by") or [])}
    import glob, re
    shipped = set()
    for df in glob.glob(os.path.join(root, "images", "*", "Dockerfile")) + \
              glob.glob(os.path.join(root, "images", "*", "*", "Dockerfile")):
        rel = os.path.relpath(df, os.path.join(root, "images"))
        shipped.add(rel.split(os.sep)[0])
    missing = sorted(shipped - covered)
    if missing:
        errors.append("image famil(ies) %s ship but no inventory line claims "
                      "them in used_by — they would age out untracked"
                      % ", ".join(missing))

for w in warnings:
    print("LIFECYCLE WARN: %s" % w, file=sys.stderr)
if errors:
    print("LIFECYCLE FAIL: %d breach(es):" % len(errors), file=sys.stderr)
    for e in errors:
        print("  %s" % e, file=sys.stderr)
    sys.exit(1)

print("LIFECYCLE OK: %d line(s) tracked, %d in use, %d warning(s) (as of %s)"
      % (len(lines), sum(1 for e in lines if e.get("used_by")), len(warnings), today))
PY
}

check_upstream() {
  # Re-resolve each tracked tag and report drift from the pinned digest. Network
  # -backed, so it is NOT part of the offline gate — same split as
  # assert-pinned-actions.sh --verify-upstream.
  local rc=0 tag dig
  command -v docker >/dev/null 2>&1 || {
    echo "REFUSE: docker is required for --check-upstream" >&2; return 1; }
  while IFS= read -r tag; do
    [ -n "$tag" ] || continue
    dig="$(docker buildx imagetools inspect "$tag" --format '{{.Manifest.Digest}}' 2>/dev/null \
           | tr -d '[:space:]')" || true
    case "$dig" in
      sha256:*) printf '  %-52s %s\n' "$tag" "$dig" ;;
      *) printf '  %-52s UNRESOLVED\n' "$tag"; rc=1 ;;
    esac
  done < <(python3 -c "
import yaml,sys
d=yaml.safe_load(open('$INVENTORY')) or {}
for e in d.get('lines') or []:
    if e.get('upstream_tag') and (e.get('used_by') or []):
        print(e['upstream_tag'])")
  [ "$rc" -eq 0 ] || echo "REFUSE: a tracked upstream tag did not resolve" >&2
  return "$rc"
}

self_test() {
  local tmp ok=0 bad=0
  tmp="$(mktemp -d)"
  # expand NOW: the local is out of scope by EXIT time
  # shellcheck disable=SC2064
  trap "rm -rf '${tmp}'" EXIT
  t() { if eval "$2"; then ok=$((ok+1)); echo "  ok   $1"; else bad=$((bad+1)); echo "  FAIL $1"; fi; }

  # A minimal well-formed inventory; each fixture below injects ONE defect.
  # STRICT_USED_BY=0 because these fixtures do not describe the real images.
  mk() { # mk <file> <lines-yaml>
    { echo "schema_version: 1"
      echo "policy:"
      echo "  warn_days_before_support_end: 180"
      echo "  grace_days_after_support_end: 90"
      echo "  review_every_days: 90"
      echo "  last_reviewed: 2026-08-01"
      echo "lines:"
      cat
    } > "$1"
  }
  local T=2026-08-12

  mk "$tmp/good.yaml" <<'Y'
  - {id: a, kind: os, tracks: X, upstream_state: stable, source: s, used_by: [nginx], support_ends: 2030-01-01}
Y
  t "a healthy inventory passes" \
    "TODAY=$T STRICT_USED_BY=0 check '$tmp/good.yaml' >/dev/null"

  mk "$tmp/expired.yaml" <<'Y'
  - {id: a, kind: os, tracks: X, upstream_state: stable, source: s, used_by: [nginx], support_ends: 2020-01-01}
Y
  t "a long-expired line IN USE fails" \
    "! TODAY=$T STRICT_USED_BY=0 check '$tmp/expired.yaml' >/dev/null 2>&1"

  # 30 days past, inside the 90-day grace: a warning, not a failure.
  mk "$tmp/grace.yaml" <<'Y'
  - {id: a, kind: os, tracks: X, upstream_state: stable, source: s, used_by: [nginx], support_ends: 2026-07-13}
Y
  t "a line just past EOL warns but does not fail (grace)" \
    "TODAY=$T STRICT_USED_BY=0 check '$tmp/grace.yaml' >/dev/null 2>&1"
  t "...and it says so on stderr" \
    "TODAY=$T STRICT_USED_BY=0 check '$tmp/grace.yaml' 2>&1 >/dev/null | grep -q 'grace period'"

  mk "$tmp/soon.yaml" <<'Y'
  - {id: a, kind: os, tracks: X, upstream_state: stable, source: s, used_by: [nginx], support_ends: 2026-10-01}
Y
  t "a line nearing EOL warns" \
    "TODAY=$T STRICT_USED_BY=0 check '$tmp/soon.yaml' 2>&1 >/dev/null | grep -q 'plan the migration'"

  # The nginx 1.27 case: unsupported AND in use, regardless of dates.
  mk "$tmp/unsup.yaml" <<'Y'
  - {id: a, kind: server, tracks: X, upstream_state: unsupported, source: s, used_by: [nginx], support_ends: 2030-01-01}
Y
  t "an UNSUPPORTED line that is still used fails, whatever its dates" \
    "! TODAY=$T STRICT_USED_BY=0 check '$tmp/unsup.yaml' >/dev/null 2>&1"
  # ...but the same line with nothing using it is a tripwire, not a breach.
  mk "$tmp/unsup-unused.yaml" <<'Y'
  - {id: a, kind: server, tracks: X, upstream_state: unsupported, source: s, used_by: [], support_ends: 2020-01-01}
Y
  t "...and an unsupported line NOT in use is fine (kept as a tripwire)" \
    "TODAY=$T STRICT_USED_BY=0 check '$tmp/unsup-unused.yaml' >/dev/null"

  mk "$tmp/nullends.yaml" <<'Y'
  - {id: a, kind: server, tracks: X, upstream_state: supported, source: s, used_by: [caddy]}
Y
  t "a null support_ends with no explanation fails" \
    "! TODAY=$T STRICT_USED_BY=0 check '$tmp/nullends.yaml' >/dev/null 2>&1"
  mk "$tmp/nullok.yaml" <<'Y'
  - {id: a, kind: server, tracks: X, upstream_state: supported, source: s, used_by: [caddy], support_ends_note: "no published EOL calendar"}
Y
  t "...but an EXPLAINED null is accepted" \
    "TODAY=$T STRICT_USED_BY=0 check '$tmp/nullok.yaml' >/dev/null"

  mk "$tmp/badstate.yaml" <<'Y'
  - {id: a, kind: os, tracks: X, upstream_state: probably-fine, source: s, used_by: [], support_ends: 2030-01-01}
Y
  t "an unknown upstream_state fails" \
    "! TODAY=$T STRICT_USED_BY=0 check '$tmp/badstate.yaml' >/dev/null 2>&1"

  mk "$tmp/dup.yaml" <<'Y'
  - {id: a, kind: os, tracks: X, upstream_state: stable, source: s, used_by: [], support_ends: 2030-01-01}
  - {id: a, kind: os, tracks: Y, upstream_state: stable, source: s, used_by: [], support_ends: 2030-01-01}
Y
  t "a duplicate line id fails" \
    "! TODAY=$T STRICT_USED_BY=0 check '$tmp/dup.yaml' >/dev/null 2>&1"

  mk "$tmp/missing.yaml" <<'Y'
  - {id: a, kind: os, upstream_state: stable, source: s, used_by: [], support_ends: 2030-01-01}
Y
  t "a missing required field fails" \
    "! TODAY=$T STRICT_USED_BY=0 check '$tmp/missing.yaml' >/dev/null 2>&1"

  mk "$tmp/baddate.yaml" <<'Y'
  - {id: a, kind: os, tracks: X, upstream_state: stable, source: s, used_by: [], support_ends: "soon"}
Y
  t "an unparseable date fails closed" \
    "! TODAY=$T STRICT_USED_BY=0 check '$tmp/baddate.yaml' >/dev/null 2>&1"

  printf 'schema_version: 1\npolicy: {warn_days_before_support_end: 1, grace_days_after_support_end: 1, review_every_days: 90, last_reviewed: 2026-08-01}\nlines: []\n' > "$tmp/empty.yaml"
  t "an empty lines list fails (the check would be vacuous)" \
    "! TODAY=$T STRICT_USED_BY=0 check '$tmp/empty.yaml' >/dev/null 2>&1"

  printf 'schema_version: 99\npolicy: {}\nlines: []\n' > "$tmp/badschema.yaml"
  t "an unknown schema_version fails" \
    "! TODAY=$T STRICT_USED_BY=0 check '$tmp/badschema.yaml' >/dev/null 2>&1"

  printf 'not: valid: yaml: [\n' > "$tmp/broken.yaml"
  t "an unreadable inventory fails closed" \
    "! TODAY=$T STRICT_USED_BY=0 check '$tmp/broken.yaml' >/dev/null 2>&1"

  # Stale review of the inventory itself.
  { echo "schema_version: 1"; echo "policy:";
    echo "  warn_days_before_support_end: 180"; echo "  grace_days_after_support_end: 90";
    echo "  review_every_days: 90"; echo "  last_reviewed: 2020-01-01"; echo "lines:";
    echo "  - {id: a, kind: os, tracks: X, upstream_state: stable, source: s, used_by: [], support_ends: 2030-01-01}"; } > "$tmp/oldreview.yaml"
  t "an inventory past its own review cadence fails" \
    "! TODAY=$T STRICT_USED_BY=0 check '$tmp/oldreview.yaml' >/dev/null 2>&1"

  # Coverage: a shipped image family with no inventory line must fail. This runs
  # against the REAL images/ tree, so it cannot pass by fixture construction.
  mk "$tmp/nocover.yaml" <<'Y'
  - {id: a, kind: os, tracks: X, upstream_state: stable, source: s, used_by: [], support_ends: 2030-01-01}
Y
  t "a shipped image family absent from used_by fails" \
    "! TODAY=$T check '$tmp/nocover.yaml' >/dev/null 2>&1"

  # THE integration case: the real inventory must pass, today.
  t "the REAL policies/lifecycle.yaml passes today" \
    "check '$INVENTORY' >/dev/null"

  echo "self-test: $ok ok, $bad failed"
  [ "$bad" -eq 0 ]
}

case "${1:-}" in
  --self-test)      self_test ;;
  --check-upstream) check "$INVENTORY" && check_upstream ;;
  "")               check "$INVENTORY" ;;
  *) echo "usage: $(basename "$0") [--check-upstream|--self-test]" >&2; exit 64 ;;
esac
