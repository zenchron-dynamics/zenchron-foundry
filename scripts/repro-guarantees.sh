#!/usr/bin/env bash
# =============================================================================
# scripts/repro-guarantees.sh — the four reproducibility guarantees, enforced (#101).
#
# policies/reproducibility.yaml declares four separate guarantees because
# "reproducible" was being used for four different questions with four different
# answers, and the strongest answer kept being carried across all of them. Prose
# cannot stop that. These rules can:
#
#   1  EXACTLY the four declared ids exist — a fifth cannot be smuggled in and
#      one of the four cannot quietly disappear.
#   2  every status is one of guaranteed / conditional / not-guaranteed.
#   3  attributed fields — `bound_fields` (claimed) plus `unclaimed_fields`
#      (measured, deliberately not claimed) — are DISJOINT across guarantees. No
#      field answers two questions at once; that disjointness IS the
#      anti-conflation mechanism.
#   4  every field the lock schema requires is attributed to exactly one
#      guarantee, so nothing recorded is left unattributed and quietly claimable
#      later by whoever needs it to be.
#   5  a guarantee that is not `not-guaranteed` must name evidence that EXISTS,
#      validates, is evidence FOR THAT GUARANTEE, and reports every field it
#      claims as `stable`. `differs` and `not-observed` both refuse. A claim can
#      never outrun its measurement.
#   6  `unclaimed_fields` may not overlap `bound_fields`, and each needs a
#      reason. A field that is measured and not claimed is a statement, not an
#      oversight.
#   7  package-resolution stays `not-guaranteed` while supply-chain-inputs.yaml
#      declares debian-package-index with `integrity_gap: true`. The claim is
#      bound to the state of the tree, not to what someone remembered to edit.
#   8  every guarantee that is not fully `guaranteed` is the TARGET of at least
#      one declared forbidden inference, so the weaker answer cannot be reached
#      by implication from a stronger one.
#   9  evidence binds to a committed build-input lock by digest, so a favourable
#      measurement cannot be presented against a different set of inputs.
#
# Offline. Exit 0 only when every rule holds.
#
# Usage:
#   repro-guarantees.sh [--policy <file>] [--tree <dir>]
#   repro-guarantees.sh --self-test
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

check() { # check <tree-root> <policy-file>
  TREE="$1" POLICY="$2" python3 <<'PY'
import hashlib, json, os, sys
import yaml
from jsonschema import Draft202012Validator

TREE = os.environ["TREE"]
POLICY = os.environ["POLICY"]
EXPECTED = {"build-input", "package-resolution", "image-bytes", "vulnerability-verdict"}
STATUSES = {"guaranteed", "conditional", "not-guaranteed"}

refusals, ok = [], []
def R(rule, msg): refusals.append("[%s] %s" % (rule, msg))

try:
    pol = yaml.safe_load(open(POLICY))
except Exception as e:
    print("REFUSE: %s is not valid YAML: %s" % (POLICY, e)); sys.exit(1)
if not isinstance(pol, dict) or "guarantees" not in pol:
    print("REFUSE: %s declares no `guarantees`" % POLICY); sys.exit(1)
# The policy names the two schemas it is checked against. Missing keys are a
# refusal, not a traceback: a gate that crashes has no verdict, and a crash is
# too easily read in CI as an infrastructure blip rather than as a finding.
for k in ("lock_schema", "evidence_schema"):
    if not (pol.get("policy") or {}).get(k):
        print("REFUSE: %s declares no policy.%s" % (POLICY, k)); sys.exit(1)

gs = pol["guarantees"]
by_id = {}
for g in gs:
    if "id" not in g:
        R("rule-1", "a guarantee has no id"); continue
    if g["id"] in by_id:
        R("rule-1", "duplicate guarantee id %r" % g["id"]); continue
    by_id[g["id"]] = g

# --- rule 1: exactly the four -----------------------------------------------
got = set(by_id)
for missing in sorted(EXPECTED - got):
    R("rule-1", "guarantee %r is not declared. The four questions have four "
                "different answers; dropping one lets the strongest be read "
                "across the gap." % missing)
for extra in sorted(got - EXPECTED):
    R("rule-1", "guarantee %r is not one of the four. A new guarantee needs a "
                "schema field, evidence and a review, not just a policy entry." % extra)
if got == EXPECTED:
    ok.append("rule-1: exactly the four guarantees are declared")

# --- rule 2: statuses --------------------------------------------------------
for gid, g in sorted(by_id.items()):
    st = g.get("status")
    if st not in STATUSES:
        R("rule-2", "%s: status %r is not one of %s" % (gid, st, sorted(STATUSES)))
if not any(r.startswith("[rule-2]") for r in refusals):
    ok.append("rule-2: every status is a declared value")

# --- rule 3: attributed fields are disjoint ---------------------------------
# A guarantee OWNS a field in one of two ways: `bound_fields` (claimed) or
# `unclaimed_fields` (measured, attributed, deliberately not claimed). Both are
# attribution; only the first is a claim. Disjointness applies to the union,
# because a field owned by two guarantees is precisely how two different answers
# get read as one.
def attributed(g):
    return [f for f in (g.get("bound_fields") or [])] + \
           [u.get("field") for u in (g.get("unclaimed_fields") or []) if u.get("field")]

seen = {}
for gid, g in sorted(by_id.items()):
    if not (g.get("bound_fields") or []) and g.get("status") != "not-guaranteed":
        R("rule-3", "%s claims status %r while binding no fields, so nothing "
                    "anchors the claim" % (gid, g.get("status")))
    for f in attributed(g):
        if f in seen:
            R("rule-3", "field %r is attributed to BOTH %s and %s. A field that "
                        "is evidence for two guarantees is how they get conflated."
                        % (f, seen[f], gid))
        else:
            seen[f] = gid
if not any(r.startswith("[rule-3]") for r in refusals):
    ok.append("rule-3: attributed fields are disjoint across the four guarantees")

# --- rule 4: every required lock field is attributed ------------------------
schema_path = os.path.join(TREE, pol["policy"]["lock_schema"])
if not os.path.isfile(schema_path):
    R("rule-4", "the declared lock schema %s does not exist" % pol["policy"]["lock_schema"])
else:
    schema = json.load(open(schema_path))
    META = {"schema_version", "repository", "generated_at", "image"}

    def leaves(node, prefix):
        props = node.get("properties") or {}
        req = node.get("required") or []
        out = []
        for name in req:
            sub = props.get(name)
            path = "%s.%s" % (prefix, name) if prefix else name
            if isinstance(sub, dict) and sub.get("type") == "object" and sub.get("properties"):
                out.extend(leaves(sub, path))
            else:
                out.append(path)
        return out

    required_paths = []
    for section in (schema.get("required") or []):
        if section in META:
            continue
        sub = (schema.get("properties") or {}).get(section) or {}
        required_paths.extend(leaves(sub, section))
    # `guaranteed` is a self-describing flag constrained by the schema itself
    # (true requires a snapshot / a frozen database); it is not a measurable
    # field a guarantee could bind.
    required_paths = [p for p in required_paths if not p.endswith(".guaranteed")]

    bound = set(seen)
    def covered(p):
        return any(p == b or p.startswith(b + ".") for b in bound)
    unattributed = [p for p in required_paths if not covered(p)]
    for p in sorted(unattributed):
        R("rule-4", "lock field %r is required by the schema but attributed to "
                    "no guarantee — neither claimed nor explicitly unclaimed. An "
                    "unattributed field is one a later reader can claim under "
                    "whichever guarantee suits them." % p)
    stale = sorted(b for b in bound
                   if not any(rp == b or rp.startswith(b + ".") for rp in required_paths))
    for b in stale:
        R("rule-4", "guarantee field %r does not exist in the lock schema — the "
                    "policy and the schema have drifted apart." % b)
    if not unattributed and not stale:
        ok.append("rule-4: all %d required lock fields are attributed to exactly "
                  "one guarantee, claimed or explicitly not" % len(required_paths))

# --- rules 5 + 9: a claim may not outrun its measurement ---------------------
ev_schema_path = os.path.join(TREE, pol["policy"]["evidence_schema"])
ev_schema = json.load(open(ev_schema_path)) if os.path.isfile(ev_schema_path) else None
if ev_schema is None:
    R("rule-5", "the declared evidence schema %s does not exist" % pol["policy"]["evidence_schema"])

def lock_digest(path):
    d = json.load(open(path))
    d.pop("generated_at", None)
    return hashlib.sha256(json.dumps(d, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

evdir = os.path.join(TREE, "tests", "reproducibility", "evidence")
known_locks = {}
if os.path.isdir(evdir):
    for fn in sorted(os.listdir(evdir)):
        if fn.endswith(".lock.json"):
            try:
                known_locks[lock_digest(os.path.join(evdir, fn))] = fn
            except Exception as e:
                R("rule-9", "%s is not a readable build-input lock: %s" % (fn, e))

for gid, g in sorted(by_id.items()):
    st = g.get("status")
    ev_files = g.get("evidence") or []
    if st == "not-guaranteed":
        if ev_files:
            R("rule-5", "%s is not-guaranteed but cites evidence. Evidence for a "
                        "refusal to claim invites the refusal to be re-read as a "
                        "weak claim." % gid)
        continue
    if not ev_files:
        R("rule-5", "%s claims status %r with no evidence record. A claim with no "
                    "measurement behind it is the failure this file exists to "
                    "prevent." % (gid, st))
        continue
    claimed = set(g.get("bound_fields") or [])
    reported = {}
    for rel in ev_files:
        p = os.path.join(TREE, rel)
        if not os.path.isfile(p):
            R("rule-5", "%s cites evidence %s, which does not exist" % (gid, rel)); continue
        try:
            ev = json.load(open(p))
        except Exception as e:
            R("rule-5", "%s: evidence %s is not valid JSON: %s" % (gid, rel, e)); continue
        if ev_schema is not None:
            errs = sorted(Draft202012Validator(ev_schema).iter_errors(ev),
                          key=lambda e: list(e.path))
            for e in errs[:6]:
                R("rule-5", "%s: evidence %s fails its schema: %s at %s"
                  % (gid, rel, e.message, "/".join(map(str, e.path)) or "<root>"))
            if errs:
                continue
        if ev.get("guarantee") != gid:
            R("rule-5", "%s cites %s, which is evidence for %r. Evidence for one "
                        "guarantee is not evidence for another."
              % (gid, rel, ev.get("guarantee")))
            continue
        d = ev["declared_inputs_lock_sha256"]
        if d not in known_locks:
            R("rule-9", "%s: evidence %s binds to build-input lock %s…, which is "
                        "not committed under tests/reproducibility/evidence/. A "
                        "measurement that names no reviewable input set can be "
                        "presented against any input set." % (gid, rel, d[:16]))
        for f in ev["fields"]:
            prev = reported.get(f["field"])
            # Worst result across records wins: two builds agreeing once does
            # not overturn a run in which they differed.
            rank = {"stable": 0, "not-observed": 1, "differs": 2}
            if prev is None or rank[f["result"]] > rank[prev[0]]:
                reported[f["field"]] = (f["result"], rel, f.get("detail", ""))
    for f in sorted(claimed):
        if f not in reported:
            R("rule-5", "%s claims %r but no cited evidence reports that field. "
                        "A field nobody compared is not a stable field." % (gid, f))
        elif reported[f][0] != "stable":
            R("rule-5", "%s claims %r but %s reports it %r%s. Byte reproducibility "
                        "may not be claimed over a field that was measured to "
                        "differ, nor over one that was never observed."
              % (gid, f, reported[f][1], reported[f][0],
                 (" — " + reported[f][2]) if reported[f][2] else ""))
if not any(r.startswith("[rule-5]") or r.startswith("[rule-9]") for r in refusals):
    ok.append("rule-5/9: every claimed field is reported stable by committed, "
              "lock-bound evidence")

# --- rule 6: unclaimed fields are a statement, not an oversight -------------
for gid, g in sorted(by_id.items()):
    for u in (g.get("unclaimed_fields") or []):
        f = u.get("field")
        if not f or not (u.get("why") or "").strip():
            R("rule-6", "%s: unclaimed field %r carries no reason" % (gid, f))
        if f in (g.get("bound_fields") or []):
            R("rule-6", "%s: %r is listed as both bound and unclaimed" % (gid, f))
if not any(r.startswith("[rule-6]") for r in refusals):
    ok.append("rule-6: every deliberately unclaimed field carries a reason")

# --- rule 7: the claim is bound to the state of the tree --------------------
inv_path = os.path.join(TREE, "policies", "supply-chain-inputs.yaml")
if not os.path.isfile(inv_path):
    R("rule-7", "policies/supply-chain-inputs.yaml is missing; the "
                "package-resolution claim cannot be checked against the tree")
else:
    inv = yaml.safe_load(open(inv_path))
    idx = [e for e in inv["inputs"] if e["id"] == "debian-package-index"]
    gap = bool(idx and idx[0].get("integrity_gap") is True)
    pr = by_id.get("package-resolution", {})
    if gap and pr.get("status") != "not-guaranteed":
        R("rule-7", "package-resolution is declared %r while "
                    "supply-chain-inputs.yaml still declares debian-package-index "
                    "with integrity_gap: true. apt resolves a LIVE archive; the "
                    "claim may not be strengthened by editing this file alone."
          % pr.get("status"))
    elif not gap and pr.get("status") == "not-guaranteed":
        R("rule-7", "the debian-package-index integrity gap is gone from the "
                    "inventory but package-resolution is still declared "
                    "not-guaranteed. If the archive was pinned, say so and cite "
                    "the evidence.")
    else:
        ok.append("rule-7: the package-resolution status matches the inventory's "
                  "declared integrity gap")

# --- rule 8: the weaker answer cannot be reached by implication -------------
infs = pol.get("forbidden_inferences") or []
for i in infs:
    for end in ("from", "to"):
        if i.get(end) not in by_id:
            R("rule-8", "forbidden inference names %r as `%s`, which is not a "
                        "declared guarantee" % (i.get(end), end))
    if not (i.get("why") or "").strip():
        R("rule-8", "forbidden inference %s -> %s carries no reason"
          % (i.get("from"), i.get("to")))
targets = {i.get("to") for i in infs}
for gid, g in sorted(by_id.items()):
    if g.get("status") != "guaranteed" and gid not in targets:
        R("rule-8", "%s is %r but no forbidden inference points at it. A "
                    "guarantee that does not fully hold must be unreachable by "
                    "implication from one that does." % (gid, g.get("status")))
if not any(r.startswith("[rule-8]") for r in refusals):
    ok.append("rule-8: every partial guarantee is protected by a forbidden inference")

# --- the controls named as enforcement must exist ---------------------------
for gid, g in sorted(by_id.items()):
    for path in (g.get("enforced_by") or []):
        if not os.path.exists(os.path.join(TREE, path)):
            R("rule-0", "%s names %s as its enforcement, and it does not exist"
              % (gid, path))
if not any(r.startswith("[rule-0]") for r in refusals):
    ok.append("rule-0: every named enforcement path exists")

for line in ok:
    print("ok      " + line)
if refusals:
    print("\nREFUSE: the reproducibility guarantees do not hold as declared.")
    for r in refusals:
        print("  " + r)
    print("\nSource of truth: %s" % os.path.relpath(POLICY, TREE))
    sys.exit(1)
print("\nreproducibility guarantees: %d rule(s) hold" % len(ok))
PY
}

# =============================================================================
# self-test — every rule shown to refuse, on a disposable copy
# =============================================================================
self_test() {
  local ok=0 bad=0 tmp
  tmp="$(mktemp -d)" || return 1
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" EXIT

  # A disposable copy. Nothing here writes into the ambient checkout — an
  # earlier generation of self-test in this repository did, and corrupted a
  # policy file that then shipped.
  mkdir -p "$tmp/tree"
  local d
  for d in policies schemas tests/reproducibility scripts; do
    mkdir -p "$tmp/tree/$(dirname "$d")"
    cp -R "$ROOT/$d" "$tmp/tree/$d" || return 1
  done
  # cp preserves mode. tests/lib/test_no_ambient_mutation.sh runs self-tests
  # against a checkout whose write bits have been REMOVED, so without this the
  # fixture inherits read-only files and the mutations below fail with EPERM —
  # inside the fixture, where it proves nothing and only makes the self-test
  # look broken.
  chmod -R u+w "$tmp/tree" 2>/dev/null || true

  local base="$tmp/tree/policies/reproducibility.yaml"

  t() { if eval "$2" >/dev/null 2>&1; then ok=$((ok+1)); echo "  ok   $1"
        else bad=$((bad+1)); echo "  FAIL $1"; fi; }

  refuses() { # refuses <label> <python mutation on `d`> <expected rule tag>
    local label="$1" mut="$2" want="$3" f="$tmp/p.yaml" got rc
    if ! MUT="$mut" python3 - "$base" "$f" <<'PY' >/dev/null 2>&1
import os, sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
# ONE namespace, not (globals, locals): a list comprehension inside the
# mutation gets its own scope and resolves free names against GLOBALS, so
# `[g for g in d[...]]` raises NameError when `d` lives only in locals.
exec(os.environ["MUT"], {"d": d})
yaml.safe_dump(d, open(sys.argv[2], "w"), sort_keys=False)
PY
    then bad=$((bad+1)); echo "  FAIL $label (mutation itself failed)"; return; fi
    got="$(check "$tmp/tree" "$f" 2>&1)"; rc=$?
    if [ "$rc" -eq 0 ]; then
      bad=$((bad+1)); echo "  FAIL $label (ACCEPTED a policy it must refuse)"; return
    fi
    case "$got" in
      *"$want"*) ok=$((ok+1)); echo "  ok   $label" ;;
      *) bad=$((bad+1)); echo "  FAIL $label (refused, but not for $want)"
         printf '%s\n' "$got" | tail -4 | sed 's/^/         /' ;;
    esac
  }

  echo "repro-guarantees self-test"

  # Non-vacuity. Without it every refusal below is equally satisfied by a gate
  # that refuses everything.
  t "the real policy passes every rule (non-vacuity)" \
    "check '$ROOT' '$ROOT/policies/reproducibility.yaml'"
  t "the disposable copy passes identically" \
    "check '$tmp/tree' '$base'"

  refuses "a fifth guarantee cannot be smuggled in" \
    "d['guarantees'].append({'id':'hermetic','status':'guaranteed','bound_fields':['build_inputs.source_sha'],'enforced_by':[]})" \
    "rule-1"
  refuses "one of the four cannot quietly disappear" \
    "d['guarantees'] = [g for g in d['guarantees'] if g['id'] != 'vulnerability-verdict']" \
    "rule-1"
  refuses "an invented status is refused" \
    "[g for g in d['guarantees'] if g['id']=='image-bytes'][0]['status']='mostly'" \
    "rule-2"
  refuses "the same field may not be evidence for two guarantees" \
    "[g for g in d['guarantees'] if g['id']=='image-bytes'][0]['bound_fields'].append('build_inputs.source_sha')" \
    "rule-3"
  refuses "a lock field may not be left unattributed" \
    "g=[g for g in d['guarantees'] if g['id']=='build-input'][0]
g['bound_fields']=[f for f in g['bound_fields'] if f!='build_inputs.context_digest']" \
    "rule-4"
  refuses "a policy field that no longer exists in the schema is drift" \
    "[g for g in d['guarantees'] if g['id']=='build-input'][0]['bound_fields'].append('build_inputs.hermetic')" \
    "rule-4"
  # THE central refusal: byte reproducibility claimed over a field measured to
  # differ. This is exactly the mistake #101's own history records.
  refuses "byte reproducibility may not be claimed over a field that DIFFERS" \
    "[g for g in d['guarantees'] if g['id']=='image-bytes'][0]['bound_fields'].append('build_outputs.rootfs_file_manifest_sha256')" \
    "rule-5"
  refuses "...nor over a field that was never observed" \
    "[g for g in d['guarantees'] if g['id']=='image-bytes'][0]['bound_fields'].append('build_outputs.manifest_digest')" \
    "rule-5"
  refuses "a claim with no evidence at all is refused" \
    "[g for g in d['guarantees'] if g['id']=='image-bytes'][0]['evidence']=[]" \
    "rule-5"
  refuses "evidence that does not exist is not evidence" \
    "[g for g in d['guarantees'] if g['id']=='image-bytes'][0]['evidence']=['tests/reproducibility/evidence/nope.json']" \
    "rule-5"
  refuses "evidence for another guarantee does not transfer" \
    "[g for g in d['guarantees'] if g['id']=='image-bytes'][0]['evidence']=[[g for g in d['guarantees'] if g['id']=='build-input'][0]['evidence'][0]]" \
    "rule-5"
  refuses "a refusal to claim may not cite evidence" \
    "[g for g in d['guarantees'] if g['id']=='vulnerability-verdict'][0]['evidence']=['tests/reproducibility/evidence/php-cli-8.4-linux-amd64-image-bytes.json']" \
    "rule-5"
  refuses "an unclaimed field with no reason is an oversight, not a statement" \
    "[g for g in d['guarantees'] if g['id']=='image-bytes'][0]['unclaimed_fields'][0]['why']=''" \
    "rule-6"
  refuses "package resolution may not be strengthened while the archive is live" \
    "[g for g in d['guarantees'] if g['id']=='package-resolution'][0]['status']='conditional'" \
    "rule-7"
  refuses "a partial guarantee must stay unreachable by implication" \
    "d['forbidden_inferences']=[i for i in d['forbidden_inferences'] if i['to']!='vulnerability-verdict']" \
    "rule-8"
  refuses "a forbidden inference may not name an undeclared guarantee" \
    "d['forbidden_inferences'][0]['to']='hermetic'" \
    "rule-8"
  refuses "a named enforcement path must exist" \
    "[g for g in d['guarantees'] if g['id']=='build-input'][0]['enforced_by']=['scripts/does-not-exist.sh']" \
    "rule-0"

  # rule-9 needs an evidence mutation rather than a policy one: the evidence is
  # made to name an input set nobody can review.
  local evsrc evdst
  evsrc="$tmp/tree/tests/reproducibility/evidence/php-cli-8.4-linux-amd64-image-bytes.json"
  evdst="$evsrc"
  if python3 - "$evsrc" "$evdst" <<'PY' >/dev/null 2>&1
import json, sys
d = json.load(open(sys.argv[1]))
d["declared_inputs_lock_sha256"] = "b" * 64
json.dump(d, open(sys.argv[2], "w"), indent=2)
PY
  then
    got="$(check "$tmp/tree" "$base" 2>&1)"; rc=$?
    if [ "$rc" -ne 0 ] && printf '%s' "$got" | grep -q 'rule-9'; then
      ok=$((ok+1)); echo "  ok   evidence must bind to a committed build-input lock"
    else
      bad=$((bad+1)); echo "  FAIL evidence must bind to a committed build-input lock"
    fi
  else
    bad=$((bad+1)); echo "  FAIL evidence must bind to a committed build-input lock (mutation failed)"
  fi

  echo "self-test: $ok ok, $bad failed"
  [ "$bad" -eq 0 ]
}

POLICY="$ROOT/policies/reproducibility.yaml"
TREE="$ROOT"
while [ $# -gt 0 ]; do
  case "$1" in
    --policy)    POLICY="${2:?}"; shift 2 ;;
    --tree)      TREE="${2:?}";   shift 2 ;;
    --self-test) self_test; exit $? ;;
    *) echo "usage: $(basename "$0") [--policy <file>] [--tree <dir>] | --self-test" >&2; exit 64 ;;
  esac
done
check "$TREE" "$POLICY"
