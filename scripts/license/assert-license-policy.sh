#!/usr/bin/env bash
# =============================================================================
# scripts/license/assert-license-policy.sh — the fail-closed licence gate (#120).
# -----------------------------------------------------------------------------
# Decides whether a normalised licence inventory may ship, against
# policies/license-policy.yaml. It refuses on FOUR conditions, and the reason it
# refuses on all four is the same: each one means somebody would be shipping a
# licence obligation nobody has actually looked at.
#
#   UNKNOWN               no SBOM asserted any licence for the component
#   CONFLICTING           two sources asserted different licences for it
#   DENIED                the owner has affirmatively refused that licence
#   LEGAL-REVIEW-REQUIRED classified, but the classification is "ask a lawyer"
#
# "Unreviewed" is not a soft state. A component sitting at
# `legal-review-required` is exactly as unshippable as a denied one until a
# human records a decision; the difference is who has to act, not whether the
# release may proceed.
#
# This script contains NO licence judgements of its own. Every verdict is read
# from the policy file. It cannot approve anything the policy does not approve.
#
# Usage:
#   assert-license-policy.sh --inventory FILE [--policy FILE]
#        [--require-release-binding] [--evidence-class CLASS]
#        [--require-image-binding] [--expect-source-revision REV]
#
# --require-release-binding refuses an inventory that names no bundle, evidence
# class or source revision. The gate could always consume the release path and
# nothing made it, so a licence verdict decided nothing about a release;
# --evidence-class makes it specific, because a verdict over a staged candidate
# is not a verdict over what shipped.
#   assert-license-policy.sh --self-test
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

usage() {
  sed -n '23,26p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 64
}

# -----------------------------------------------------------------------------
# gate <inventory> <policy>
# -----------------------------------------------------------------------------
gate() {
  INVENTORY="$1" POLICY="$2" REQUIRE_BINDING="${3:-0}" \
    EXPECT_CLASS="${4:-}" REQUIRE_IMAGE_BINDING="${5:-0}" \
    EXPECT_REVISION="${6:-}" python3 <<'PY'
import json, os, sys, datetime

inv_path = os.environ["INVENTORY"]
pol_path = os.environ["POLICY"]

try:
    import yaml
except ImportError:
    sys.stderr.write("REFUSE: PyYAML is required to read the licence policy\n")
    raise SystemExit(2)

def refuse(msg):
    sys.stderr.write("REFUSE: %s\n" % msg)
    raise SystemExit(1)

try:
    with open(inv_path) as fh:
        inv = json.load(fh)
except (OSError, ValueError) as e:
    refuse("licence inventory %s is unreadable: %s" % (inv_path, e))

if inv.get("schema") != "foundry.license-inventory/v1":
    refuse("%s is not a foundry.license-inventory/v1 document" % inv_path)

# --- the release binding -----------------------------------------------------
# The gate could always consume the release path and nothing made it, so a
# licence verdict named no shipped artifact, no evidence class and no source
# revision. --require-release-binding makes the binding mandatory, and
# --evidence-class makes the verdict specific to what is being decided: a
# verdict over a staged candidate is not a verdict over what shipped.
if os.environ.get("REQUIRE_BINDING") == "1":
    rb = inv.get("release_binding")
    if not rb:
        refuse("%s carries no release_binding. --require-release-binding was "
               "asked for, and a licence verdict that names no bundle, no "
               "evidence class and no source revision decides nothing about a "
               "release. Rebuild it with "
               "scripts/license/license-inventory.sh --bundle <evidence-bundle>"
               % inv_path)
    for f in ("bundle_id", "evidence_class", "source_revision",
              "bundle_content_checksum"):
        if not rb.get(f):
            refuse("%s: release_binding.%s is missing" % (inv_path, f))
    if not rb.get("sbom_complete"):
        refuse("%s: the bound bundle's bill of materials is incomplete. A "
               "licence verdict over a partial SBOM set reports clean for the "
               "components it happened to see" % inv_path)
    want = os.environ.get("EXPECT_CLASS") or ""
    if want and rb["evidence_class"] != want:
        refuse("%s is a licence verdict for evidence class %r; it is being "
               "presented as %r" % (inv_path, rb["evidence_class"], want))

# --- the IMAGE binding -------------------------------------------------------
# --require-release-binding above binds a verdict to a SEALED EVIDENCE BUNDLE.
# That is the right binding once a bundle exists, and it does not exist while a
# run is still staging candidates — which is precisely when the licence question
# has to be answered, because that is the only point at which the candidate
# images are in hand.
#
# --require-image-binding is the staging-time form. It refuses an inventory that
# does not name the authorization record, the source revision and the complete
# child set the SBOMs were produced against. Without it, `--inventory anything`
# passes this gate over any SPDX files at all, which is exactly how a licence
# gate ends up "wired" while gating no image.
if os.environ.get("REQUIRE_IMAGE_BINDING") == "1":
    ib = inv.get("image_binding")
    if not ib:
        refuse("%s carries no image_binding. --require-image-binding was asked "
               "for, and a licence verdict that names no authorization record, "
               "no source revision and no child set decides nothing about a "
               "candidate image. Rebuild it with "
               "scripts/license/assert-image-sbom-licences.sh --authorization "
               "<post-build-authorization.json> --sbom-dir <candidate SBOMs>"
               % inv_path)
    for f in ("source_revision", "children_expected", "children_bound",
              "authorization_record", "platforms"):
        if not ib.get(f):
            refuse("%s: image_binding.%s is missing" % (inv_path, f))
    if not ib.get("all_children_bound"):
        refuse("%s: only %s of %s expected children are bound to a staged "
               "digest. A licence verdict over a partial matrix reports clean "
               "for the images it happened to see"
               % (inv_path, ib.get("children_bound"), ib.get("children_expected")))
    if int(ib["children_bound"]) != int(ib["children_expected"]):
        refuse("%s: image_binding claims completeness while binding %s of %s "
               "children" % (inv_path, ib["children_bound"], ib["children_expected"]))
    want_rev = os.environ.get("EXPECT_REVISION") or ""
    if want_rev and str(ib["source_revision"]) != want_rev:
        refuse("%s is a licence verdict for source revision %s; it is being "
               "presented for %s. An inventory built from another run's SBOMs "
               "licenses another run's images"
               % (inv_path, ib["source_revision"], want_rev))

try:
    with open(pol_path) as fh:
        pol = yaml.safe_load(fh)
except (OSError, ValueError) as e:
    refuse("licence policy %s is unreadable: %s" % (pol_path, e))

# --- the policy must itself be well formed ----------------------------------
# A gate that trusts a malformed policy is not a gate. Validate before using.
states = set(pol.get("states") or [])
if states != {"allowed", "denied", "legal-review-required"}:
    refuse("policy states must be exactly allowed/denied/legal-review-required, got %s"
           % sorted(states))

default_state = pol.get("default_state")
if default_state != "legal-review-required":
    refuse("policy default_state must be 'legal-review-required' (fail-closed), got %r"
           % default_state)

classified = {}
for entry in pol.get("licenses") or []:
    lid, st = entry.get("id"), entry.get("state")
    if not lid:
        refuse("a licences[] entry has no id")
    if st not in states:
        refuse("licence %r has state %r which is not a declared state" % (lid, st))
    if lid in classified:
        refuse("licence %r is classified twice" % lid)
    classified[lid] = st

denied_list = pol.get("denied") or []
for d in denied_list:
    if not isinstance(d, str):
        refuse("denied[] entries must be SPDX id strings, got %r" % (d,))
    classified[d] = "denied"

# --- exceptions must be accountable and time-boxed --------------------------
today = datetime.date.today()
exceptions = {}
for ex in pol.get("exceptions") or []:
    for field in ("component", "license", "granted_by", "expires", "tracked_issue"):
        if not ex.get(field):
            refuse("licence exception %r is missing required field %r — an "
                   "exception without an owner and an expiry is a silent allow"
                   % (ex.get("component", "<unnamed>"), field))
    exp = ex["expires"]
    if isinstance(exp, str):
        try:
            exp = datetime.date.fromisoformat(exp)
        except ValueError:
            refuse("licence exception %r has an unparseable expires %r"
                   % (ex["component"], ex["expires"]))
    if not isinstance(exp, datetime.date):
        refuse("licence exception %r has a non-date expires" % ex["component"])
    exceptions[(ex["component"], ex["license"])] = (exp, ex)

# --- classify every component ------------------------------------------------
RANK = {"allowed": 0, "legal-review-required": 1, "denied": 2}
problems = {"unknown": [], "conflicting": [], "denied": [],
            "unreviewed": [], "expired_exception": []}

# Findings are additionally split by COMPONENT TYPE. A licence inventory that
# carries image FILE components alongside package components must report which is
# which, or a total that moved gives no way to say what moved. The split changes
# no verdict: a file component is gated exactly like a package.
by_type = {"package": 0, "file": 0}

for c in inv.get("components") or []:
    name, ver = c.get("name", ""), c.get("version", "")
    label = "%s@%s" % (name, ver) if ver else name
    ctype = "file" if c.get("component_type") == "file" else "package"

    if c.get("unknown"):
        problems["unknown"].append(label)
        by_type[ctype] += 1
        continue
    if c.get("conflict"):
        detail = sorted({s["value"] for s in c.get("sources", []) if s.get("value")})
        problems["conflicting"].append("%s (%s)" % (label, " vs ".join(detail)))
        by_type[ctype] += 1
        continue

    for lic in c.get("licenses") or []:
        state = classified.get(lic, default_state)
        if state == "allowed":
            continue
        key = (name, lic)
        if key in exceptions:
            exp, ex = exceptions[key]
            if exp < today:
                problems["expired_exception"].append(
                    "%s [%s] exception expired %s (granted by %s, issue %s)"
                    % (label, lic, exp.isoformat(), ex["granted_by"], ex["tracked_issue"]))
                by_type[ctype] += 1
            continue
        if state == "denied":
            problems["denied"].append("%s [%s]" % (label, lic))
        else:
            problems["unreviewed"].append("%s [%s]" % (label, lic))
        by_type[ctype] += 1

total = sum(len(v) for v in problems.values())

HEADINGS = [
    ("unknown", "no licence could be established (SBOM said NOASSERTION/nothing)"),
    ("conflicting", "sources disagree about the licence"),
    ("denied", "licence is DENIED by policy"),
    ("unreviewed", "licence needs legal review and has not had it"),
    ("expired_exception", "the exception that permitted this has EXPIRED"),
]

if total:
    _all = inv.get("components") or []
    _pkgs = sum(1 for c in _all if c.get("component_type") != "file")
    _files = len(_all) - _pkgs
    out = ["REFUSE: licence policy not satisfied — %d finding(s) across %d component(s):"
           % (total, len(_all))]
    out.append("  by component type: %d finding(s) on package components, %d on "
               "image FILE components (%d package + %d file components in the "
               "inventory). A file component is gated exactly like a package; the "
               "split is reported so a total that moves can say what moved."
               % (by_type["package"], by_type["file"], _pkgs, _files))
    for key, heading in HEADINGS:
        items = problems[key]
        if not items:
            continue
        out.append("")
        out.append("  %s (%d):" % (heading, len(items)))
        for it in sorted(items):
            out.append("    - %s" % it)
    out.append("")
    out.append("  No release may ship on an unresolved licence finding. Resolve each")
    out.append("  by recording a decision in %s — not by editing this gate." % pol_path)
    sys.stderr.write("\n".join(out) + "\n")
    raise SystemExit(1)

# --- publication is a SEPARATE question (#98) --------------------------------
# Passing the licence gate says the dependency licences are accounted for. It
# says nothing about whether Foundry may distribute anything at all, which is
# governed by the repository's own LICENSE and is undecided.
publication = pol.get("publication") or {}
decision = publication.get("decision")
_all = inv.get("components") or []
_pkgs = sum(1 for c in _all if c.get("component_type") != "file")
print("licence policy OK: %d component(s) (%d package, %d image file), 0 unknown, "
      "0 conflicting, 0 denied, 0 unreviewed" % (len(_all), _pkgs, len(_all) - _pkgs))
if decision == "undetermined" or not publication.get("notices_approved_for_distribution"):
    print("NOTE: distribution of Foundry itself remains UNDETERMINED (issue %s). "
          "Third-party licences are accounted for; the right to publish is not "
          "established by this gate." % publication.get("tracked_issue"))
PY
}

# -----------------------------------------------------------------------------
# self-test — fixture policies and inventories only, in a scratch dir.
# The real policy is READ, never written. A test that edits a policy file in the
# checkout has already broken the thing it was meant to protect.
# -----------------------------------------------------------------------------
self_test() {
  local fail=0 tmp
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" EXIT

  ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

  # `gate ... | grep` would inherit gate's non-zero status under `set -o
  # pipefail`, so a MATCHING grep on a refusal still reads as a failure — the
  # assertion would pass only when the diagnostic was absent, which is exactly
  # backwards. Capture the diagnostic, then assert against the captured text.
  cap() { gate "$1" "$2" >"$tmp/out" 2>&1 || true; }

  mk_inv() { # mk_inv <file> <components-json>
    printf '{"schema":"foundry.license-inventory/v1","components":%s}\n' "$2" >"$1"
  }

  local base_pol="$tmp/policy.yaml"
  cat >"$base_pol" <<'YAML'
version: 1
default_state: legal-review-required
states: [allowed, denied, legal-review-required]
publication:
  decision: undetermined
  tracked_issue: 98
  notices_approved_for_distribution: false
licenses:
  - id: MIT
    state: allowed
  - id: GPL-3.0-only
    state: legal-review-required
  - id: EVIL-1.0
    state: denied
denied: []
exceptions: []
YAML

  # --- happy path ------------------------------------------------------------
  mk_inv "$tmp/clean.json" '[{"name":"libfoo","version":"1.0","licenses":["MIT"],"unknown":false,"conflict":false,"sources":[]}]'
  ck "an all-permissive inventory PASSES" \
     "gate '$tmp/clean.json' '$base_pol' >/dev/null 2>&1"
  ck "...and still says publication is undetermined" \
     "cap '$tmp/clean.json' '$base_pol'; grep -q 'remains UNDETERMINED' '$tmp/out'"

  # --- the four refusals, each with its diagnostic ---------------------------
  mk_inv "$tmp/unknown.json" '[{"name":"libmystery","version":"2.0","licenses":[],"unknown":true,"conflict":false,"sources":[]}]'
  ck "an UNKNOWN licence refuses" \
     "! gate '$tmp/unknown.json' '$base_pol' >/dev/null 2>&1"
  ck "...naming the component and the reason" \
     "cap '$tmp/unknown.json' '$base_pol'; grep -q 'no licence could be established' '$tmp/out' && grep -q 'libmystery@2.0' '$tmp/out'"

  mk_inv "$tmp/conflict.json" '[{"name":"libsplit","version":"3.0","licenses":["MIT","GPL-3.0-only"],"unknown":false,"conflict":true,"sources":[{"value":"MIT"},{"value":"GPL-3.0-only"}]}]'
  ck "a CONFLICTING licence refuses" \
     "! gate '$tmp/conflict.json' '$base_pol' >/dev/null 2>&1"
  # Asserted values are sorted, so the diagnostic is stable run to run.
  ck "...showing both asserted values" \
     "cap '$tmp/conflict.json' '$base_pol'; grep -q 'GPL-3.0-only vs MIT' '$tmp/out'"

  mk_inv "$tmp/denied.json" '[{"name":"libbad","version":"1.0","licenses":["EVIL-1.0"],"unknown":false,"conflict":false,"sources":[]}]'
  ck "a DENIED licence refuses" \
     "! gate '$tmp/denied.json' '$base_pol' >/dev/null 2>&1"
  ck "...naming it as denied" \
     "cap '$tmp/denied.json' '$base_pol'; grep -q 'licence is DENIED by policy' '$tmp/out'"

  mk_inv "$tmp/unrev.json" '[{"name":"libcopyleft","version":"1.0","licenses":["GPL-3.0-only"],"unknown":false,"conflict":false,"sources":[]}]'
  ck "an UNREVIEWED licence refuses just as hard" \
     "! gate '$tmp/unrev.json' '$base_pol' >/dev/null 2>&1"
  ck "...naming review as the missing act" \
     "cap '$tmp/unrev.json' '$base_pol'; grep -q 'needs legal review and has not had it' '$tmp/out'"

  # An unlisted licence must fall to the fail-closed default, never to allowed.
  mk_inv "$tmp/novel.json" '[{"name":"libnovel","version":"1.0","licenses":["NEVER-HEARD-OF-1.0"],"unknown":false,"conflict":false,"sources":[]}]'
  ck "an UNCLASSIFIED licence defaults to review, not to allowed" \
     "! gate '$tmp/novel.json' '$base_pol' >/dev/null 2>&1"

  # --- exceptions -------------------------------------------------------------
  local ex_ok="$tmp/policy-exception.yaml"
  sed 's/^exceptions: \[\]$//' "$base_pol" >"$ex_ok"
  cat >>"$ex_ok" <<'YAML'
exceptions:
  - component: libcopyleft
    license: GPL-3.0-only
    granted_by: fixture-owner
    expires: "2999-01-01"
    tracked_issue: 120
YAML
  ck "a valid, unexpired exception permits the component" \
     "gate '$tmp/unrev.json' '$ex_ok' >/dev/null 2>&1"

  local ex_exp="$tmp/policy-expired.yaml"
  sed 's/2999-01-01/2000-01-01/' "$ex_ok" >"$ex_exp"
  ck "an EXPIRED exception refuses" \
     "! gate '$tmp/unrev.json' '$ex_exp' >/dev/null 2>&1"
  ck "...and says the exception expired" \
     "cap '$tmp/unrev.json' '$ex_exp'; grep -q 'exception that permitted this has EXPIRED' '$tmp/out'"

  local ex_bad="$tmp/policy-badexception.yaml"
  sed 's/^    granted_by: fixture-owner$//' "$ex_ok" >"$ex_bad"
  ck "an exception with no owner is refused as malformed" \
     "! gate '$tmp/unrev.json' '$ex_bad' >/dev/null 2>&1"
  ck "...naming the missing field" \
     "cap '$tmp/unrev.json' '$ex_bad'; grep -q 'granted_by' '$tmp/out'"

  # --- the gate refuses to trust a broken policy ------------------------------
  local weak="$tmp/policy-weak.yaml"
  sed 's/^default_state: legal-review-required$/default_state: allowed/' "$base_pol" >"$weak"
  ck "a policy defaulting to ALLOWED is refused outright" \
     "! gate '$tmp/clean.json' '$weak' >/dev/null 2>&1"
  ck "...saying it must be fail-closed" \
     "cap '$tmp/clean.json' '$weak'; grep -q 'fail-closed' '$tmp/out'"

  local badstate="$tmp/policy-badstate.yaml"
  sed 's/^    state: allowed$/    state: probably-fine/' "$base_pol" >"$badstate"
  ck "a licence with an undeclared state is refused" \
     "! gate '$tmp/clean.json' '$badstate' >/dev/null 2>&1"

  # --- the release binding --------------------------------------------------
  # The gate could always consume the release path and nothing made it, so a
  # licence verdict named no shipped artifact at all.
  python3 - "$tmp/clean.json" "$tmp/bound.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["release_binding"] = {
    "bundle_id": "staged-candidate-7061caafb3ea-32395890071",
    "evidence_class": "staged-candidate",
    "source_revision": "7061caafb3ea09bd5b2342a1daf022151b33f822",
    "bundle_content_checksum": "c" * 64,
    "children_total": 20,
    "sbom_complete": True,
}
json.dump(d, open(sys.argv[2], "w"), indent=2)
PY
  ck "a bound inventory PASSES with --require-release-binding" \
     "gate '$tmp/bound.json' '$base_pol' 1 '' >/dev/null 2>&1"
  ck "...and PASSES for the class it was actually built for" \
     "gate '$tmp/bound.json' '$base_pol' 1 staged-candidate >/dev/null 2>&1"
  ck "SABOTAGE: an UNBOUND inventory is REFUSED when the binding is required" \
     "! gate '$tmp/clean.json' '$base_pol' 1 '' >/dev/null 2>&1"
  ck "...naming what to rebuild it with, not just that it failed" \
     "grep -q 'license-inventory.sh --bundle' <<<\"\$( gate '$tmp/clean.json' '$base_pol' 1 '' 2>&1 )\""
  ck "SABOTAGE: a candidate's verdict presented as a published release is REFUSED" \
     "! gate '$tmp/bound.json' '$base_pol' 1 published-artifact >/dev/null 2>&1"
  python3 - "$tmp/bound.json" "$tmp/partial.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["release_binding"]["sbom_complete"] = False
json.dump(d, open(sys.argv[2], "w"), indent=2)
PY
  ck "SABOTAGE: a verdict over an INCOMPLETE bill of materials is REFUSED" \
     "! gate '$tmp/partial.json' '$base_pol' 1 '' >/dev/null 2>&1"
  ck "NON-VACUOUS: the same inventory still passes without --require-release-binding" \
     "gate '$tmp/clean.json' '$base_pol' >/dev/null 2>&1"

  ck "a missing inventory is refused, not treated as empty" \
     "! gate '$tmp/nope.json' '$base_pol' >/dev/null 2>&1"
  echo '{"schema":"something-else","components":[]}' >"$tmp/wrong.json"
  ck "a document that is not a licence inventory is refused" \
     "! gate '$tmp/wrong.json' '$base_pol' >/dev/null 2>&1"

  # --- the SHIPPED policy must itself be structurally valid -------------------
  mk_inv "$tmp/mit.json" '[{"name":"x","version":"1","licenses":["MIT"],"unknown":false,"conflict":false,"sources":[]}]'
  ck "the real policies/license-policy.yaml is structurally valid" \
     "gate '$tmp/mit.json' '$ROOT/policies/license-policy.yaml' >/dev/null 2>&1"
  ck "the real policy still leaves publication undetermined (#98 is not ours to close)" \
     "cap '$tmp/mit.json' '$ROOT/policies/license-policy.yaml'; grep -q 'remains UNDETERMINED' '$tmp/out'"
  # Non-vacuity: prove the real policy actually refuses something.
  mk_inv "$tmp/real-gpl.json" '[{"name":"libcopyleft","version":"1","licenses":["GPL-3.0-only"],"unknown":false,"conflict":false,"sources":[]}]'
  ck "the real policy REFUSES an unreviewed copyleft component" \
     "! gate '$tmp/real-gpl.json' '$ROOT/policies/license-policy.yaml' >/dev/null 2>&1"

  echo "----"
  if [ "$fail" -eq 0 ]; then echo "assert-license-policy: SELF-TEST OK"; else echo "assert-license-policy: SELF-TEST FAILED"; fi
  return "$fail"
}

main() {
  local inv="" pol="$ROOT/policies/license-policy.yaml" req=0 cls="" imgreq=0 rev=""
  case "${1:-}" in
    --self-test) self_test; exit $? ;;
    "") usage ;;
  esac
  while [ $# -gt 0 ]; do
    case "$1" in
      --inventory) inv="${2:-}"; shift 2 ;;
      --policy)    pol="${2:-}"; shift 2 ;;
      --require-release-binding) req=1; shift ;;
      --evidence-class) cls="${2:-}"; req=1; shift 2 ;;
      --require-image-binding) imgreq=1; shift ;;
      --expect-source-revision) rev="${2:-}"; imgreq=1; shift 2 ;;
      *) usage ;;
    esac
  done
  [ -n "$inv" ] || usage
  gate "$inv" "$pol" "$req" "$cls" "$imgreq" "$rev"
}

main "$@"
