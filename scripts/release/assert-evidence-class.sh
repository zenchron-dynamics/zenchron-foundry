#!/usr/bin/env bash
# shellcheck disable=SC2034  # assertion vars are consumed inside eval'd assertion strings
# =============================================================================
# scripts/release/assert-evidence-class.sh — the artifact/evidence CLASS gate.
# -----------------------------------------------------------------------------
# THE DEFECT THIS EXISTS FOR.
#
# An upstream-base scan was reported as Foundry child evidence:
#
#   php:8.4 UPSTREAM BASE   241 CRITICAL/HIGH   170 of them linux-libc-dev
#   php-fpm/8.4 CHILD        47 CRITICAL/HIGH     0 of them linux-libc-dev
#
# The Foundry Dockerfile runs `apt-get purge -y --auto-remove`, so
# linux-libc-dev is NOT INSTALLED in the child. The base record is not a
# pessimistic version of the child record — it is a record about a DIFFERENT
# ARTIFACT, and it can neither confirm nor deny anything about what Foundry
# ships. The bug was not a wrong number; it was a MISSING TYPE.
#
# So: every governance evidence record carries its class, every consumer
# declares which classes it accepts, and NOTHING is inferred. Fail-closed
# throughout — a record that cannot be classified is refused, never guessed.
#
# Identity comes from child_key()/child_slug() in scripts/lib/common.sh. There
# is exactly ONE identity derivation in this repository; a second one would let
# two spellings of the same child diverge, which is the defect that produced
# cancelled run 32123758374.
#
# Usage:
#   assert-evidence-class.sh validate <record.json>
#   assert-evidence-class.sh require-class <class> <record.json>
#   assert-evidence-class.sh consumer <consumer> <record.json>
#   assert-evidence-class.sh bind <record.json> <k=v> [<k=v> ...]
#         k in: class digest platform family version source
#   assert-evidence-class.sh legacy <path-under-repo-root>
#   assert-evidence-class.sh report <record.json>
#   assert-evidence-class.sh --self-test
#
# EVERY REFUSAL CARRIES ITS OWN DIAGNOSTIC. A gate that refuses everything with
# one message teaches the reader nothing and gets bypassed.
# =============================================================================
set -euo pipefail
_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
. "$_d/../lib/common.sh"

# TWO ROOTS, deliberately separate.
#   AEC_ROOT       where the CONTRACT lives (schema + policy). Always this
#                  checkout: a caller must not be able to point the gate at a
#                  policy of their own choosing.
#   AEC_AUDIT_ROOT the tree whose RECORDS are being audited. Defaults to
#                  AEC_ROOT. It exists so tests can exercise the mutation
#                  scenarios against a disposable COPY — this repository has
#                  already destroyed policies/required-release-checks.yaml with
#                  a self-test that mutated the real files in place.
AEC_ROOT="${AEC_ROOT:-$(cd "$_d/../.." && pwd)}"
AEC_AUDIT_ROOT="${AEC_AUDIT_ROOT:-$AEC_ROOT}"
SCHEMA="$AEC_ROOT/schemas/evidence-class-v1.schema.json"
POLICY="$AEC_ROOT/policies/evidence-classes.yaml"

_need_py() {
  python3 -c 'import yaml, jsonschema' 2>/dev/null \
    || die "python3 with PyYAML and jsonschema is required"
}

# -----------------------------------------------------------------------------
# The whole contract lives in one python module so the rules are stated once.
# Bash dispatches; python decides.
# -----------------------------------------------------------------------------
_aec() { # _aec <subcommand> [args...]
  _need_py
  python3 - "$SCHEMA" "$POLICY" "$AEC_AUDIT_ROOT" "$@" <<'PY'
import json, sys, hashlib, os
import yaml
from jsonschema import Draft202012Validator

schema_path, policy_path, root, sub = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
args = sys.argv[5:]
schema = json.load(open(schema_path))
policy = yaml.safe_load(open(policy_path))
CLASSES = {c["name"]: c for c in policy["classes"]}
CONSUMERS = policy["consumers"]
REQUIRED = policy["required_binding"]

def refuse(msg):
    print("REFUSE: " + msg, file=sys.stderr)
    sys.exit(1)

def load(p):
    try:
        return json.load(open(p))
    except FileNotFoundError:
        refuse(f"evidence record not found: {p}")
    except json.JSONDecodeError as e:
        refuse(f"evidence record is not valid JSON: {p}: {e}")

def validate(rec, where):
    # --- structural: the schema ---------------------------------------------
    errs = sorted(Draft202012Validator(schema).iter_errors(rec), key=lambda e: list(e.path))
    if errs:
        e = errs[0]
        loc = "/".join(str(x) for x in e.path) or "<root>"
        # The mutable-tag case deserves its OWN diagnostic: it is a distinct
        # sabotage, not a generic pattern miss.
        if loc == "image_digest":
            refuse(f"{where}: image_digest {rec.get('image_digest')!r} is not an immutable "
                   f"sha256:<64hex> digest — a mutable tag is not an identity, the bytes "
                   f"behind it can change after this evidence is written")
        if loc == "evidence_class":
            refuse(f"{where}: evidence_class {rec.get('evidence_class')!r} is not one of "
                   f"{sorted(CLASSES)} — a class is never inferred")
        missing = [f for f in REQUIRED if f not in rec]
        if missing:
            refuse(f"{where}: evidence record is missing required binding field(s): "
                   f"{', '.join(missing)} — an unbound field is the field that gets "
                   f"chosen later by accident")
        refuse(f"{where}: schema violation at {loc}: {e.message}")

    cls = rec["evidence_class"]
    spec = CLASSES[cls]

    # --- build completion ----------------------------------------------------
    if spec["requires_build_completion"] and not rec["build_completed"]:
        refuse(f"{where}: class {cls!r} requires a COMPLETED build, but "
               f"build_completed=false — a build that did not complete has an "
               f"undefined installed inventory, so it cannot emit {cls} evidence")

    # --- provenance ----------------------------------------------------------
    parent = rec.get("parent")
    if spec["requires_parent"]:
        if parent is None:
            refuse(f"{where}: class {cls!r} requires a parent provenance relation, "
                   f"got null — only upstream-base has no Foundry parent")
        want = spec["parent_class"]
        if parent["evidence_class"] != want:
            refuse(f"{where}: class {cls!r} must descend from {want!r}, but its parent "
                   f"is class {parent['evidence_class']!r}")
    else:
        if parent is not None:
            refuse(f"{where}: class {cls!r} must not declare a parent — an upstream "
                   f"base has no Foundry provenance to claim")

    # --- THE 241-vs-47 RULE --------------------------------------------------
    # An upstream-base scan enumerates the BASE image's packages. A child's
    # installed inventory is a different list, not a subset relation worth
    # relying on. Bind the inventory kind to the class, both directions.
    kind = rec["package_inventory_source"]["kind"]
    if cls == "upstream-base" and kind == "image-child":
        refuse(f"{where}: class 'upstream-base' carries an 'image-child' package "
               f"inventory — an upstream base record must describe the BASE's "
               f"installed packages")
    if cls != "upstream-base" and kind == "image-base":
        refuse(f"{where}: class {cls!r} carries an 'image-base' package inventory. "
               f"THIS IS THE 241-vs-47 DEFECT: the upstream php:8.4 base reports 241 "
               f"CRITICAL/HIGH including 170 linux-libc-dev, while the accepted 8.4 "
               f"child reports 47 and zero linux-libc-dev because the Dockerfile runs "
               f"'apt-get purge -y --auto-remove'. A base scan CANNOT represent a "
               f"Foundry child's installed inventory")
    return cls

def establishes(cls, capability):
    return capability in (CLASSES[cls].get("establishes") or [])

# --------------------------------------------------------------------------
if sub == "validate":
    rec = load(args[0]); validate(rec, args[0]); print(f"ok - {args[0]}: class={rec['evidence_class']}")

elif sub == "require-class":
    want, p = args[0], args[1]
    if want not in CLASSES:
        refuse(f"{want!r} is not a declared evidence class")
    rec = load(p); got = validate(rec, p)
    if got != want:
        forb = (CLASSES[got].get("forbidden") or {})
        extra = ""
        if got == "upstream-base" and want in ("foundry-child", "staged-candidate"):
            extra = " — " + forb["foundry-child-inventory"]
        refuse(f"{p}: expected evidence class {want!r}, got {got!r}{extra}")
    print(f"ok - {p}: class={got}")

elif sub == "consumer":
    name, p = args[0], args[1]
    if name not in CONSUMERS:
        refuse(f"{name!r} is not a declared consumer; declare it in policies/evidence-classes.yaml")
    rec = load(p); got = validate(rec, p)
    spec = CONSUMERS[name]
    if got not in spec["accepts"]:
        refuse(f"{p}: consumer {name!r} refuses evidence class {got!r} — "
               f"{spec['refuses_diagnostic']}; it accepts only {spec['accepts']}")
    print(f"ok - {p}: consumer {name} accepts class={got}")

elif sub == "bind":
    p, rest = args[0], args[1:]
    rec = load(p); got = validate(rec, p)
    FIELD = {"class": "evidence_class", "digest": "image_digest", "platform": "platform",
             "family": "image_family", "version": "image_version", "source": "source_revision"}
    WHY = {
      "class":    "evidence cannot be reused across a CLASS boundary",
      "digest":   "evidence is bound to ONE immutable digest; attaching it to another "
                  "digest describes bytes that were never scanned",
      "platform": "evidence is per-platform; an amd64 child and an arm64 child have "
                  "different digests and different installed inventories",
      "family":   "evidence is bound to one image family",
      "version":  "evidence is bound to one image version; an 8.3 record never "
                  "satisfies an 8.4 requirement",
      "source":   "evidence is bound to ONE source revision; a later commit needs its "
                  "own evidence",
    }
    for kv in rest:
        if "=" not in kv:
            refuse(f"bind expects k=v, got {kv!r}")
        k, v = kv.split("=", 1)
        if k not in FIELD:
            refuse(f"bind: unknown binding key {k!r}; known: {sorted(FIELD)}")
        actual = rec.get(FIELD[k])
        if actual != v:
            refuse(f"{p}: {k} mismatch — expected {v!r}, evidence says {actual!r}: {WHY[k]}")
    print(f"ok - {p}: bound ({len(rest)} expectation(s)), class={got}")

elif sub == "legacy":
    rel = args[0]
    entries = {e["path"]: e for e in policy["legacy_records"]}
    if rel not in entries:
        refuse(f"{rel}: no EXPLICIT historical-compatibility entry in "
               f"policies/evidence-classes.yaml. Pre-contract evidence is admitted "
               f"individually, by content digest, with a human-declared class. There "
               f"is deliberately NO inferred default: 'records without a class are "
               f"children' is exactly the rule that would have classified the "
               f"241-finding base scan as a child")
    e = entries[rel]
    ap = os.path.join(root, rel)
    if not os.path.exists(ap):
        refuse(f"{rel}: listed as a legacy record but not present in the checkout")
    got = hashlib.sha256(open(ap, "rb").read()).hexdigest()
    if got != e["sha256"]:
        refuse(f"{rel}: legacy record bytes changed — pinned {e['sha256']}, found {got}. "
               f"The compatibility grant is for THOSE bytes; re-declare it deliberately")
    rec = json.load(open(ap))
    ident = e["identified_by"]
    if rec.get(ident["field"]) != ident["value"]:
        refuse(f"{rel}: legacy grant identifies this record by "
               f"{ident['field']}={ident['value']!r}, but the record carries "
               f"{rec.get(ident['field'])!r}")
    if e["declared_class"] not in CLASSES:
        refuse(f"{rel}: declared_class {e['declared_class']!r} is not a declared class")
    # Every binding field is either supplied (and resolvable in the record) or
    # named in waived_bindings. Silence is not a waiver.
    waived = e.get("waived_bindings") or {}
    fmap = e.get("field_map") or {}
    for f in REQUIRED:
        if f == "evidence_class":
            continue   # supplied by declared_class, that IS the compatibility rule
        if f in waived:
            if not str(waived[f]).strip():
                refuse(f"{rel}: waiver for {f!r} has no stated reason")
            continue
        if f not in fmap:
            refuse(f"{rel}: binding field {f!r} is neither mapped into the record nor "
                   f"explicitly waived — an unstated gap is not a compatibility rule")
        # Resolve the mapped path so the map cannot rot into fiction.
        path = fmap[f]
        node = rec
        ok = True
        for part in path.split("."):
            if part.endswith("[]"):
                key = part[:-2]
                if not isinstance(node, dict) or key not in node or not node[key]:
                    ok = False; break
                node = node[key][0]
            else:
                if not isinstance(node, dict) or part not in node:
                    ok = False; break
                node = node[part]
        if not ok:
            refuse(f"{rel}: field_map claims {f!r} lives at {path!r}, but that path does "
                   f"not resolve in the record")
    print(f"ok - {rel}: legacy compatibility grant honoured, class={e['declared_class']} "
          f"({len(waived)} explicit waiver(s))")

elif sub == "report":
    p = args[0]
    rec = load(p); cls = validate(rec, p)
    sev = rec.get("severity_counts") or {}
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    counts = ", ".join(f"{k}={sev[k]}" for k in order if k in sev) or "none recorded"
    # The class is printed FIRST and always. A count without its class is how
    # 241 got read as a replacement for 47.
    print(f"[{cls}] {rec['image_family']}/{rec['image_version']} {rec['platform']} "
          f"{rec['image_digest']}")
    print(f"  inventory={rec['package_inventory_source']['kind']}  {counts}")
    print(f"  source={rec['source_revision']}  db={rec['vulnerability_db_identity']}")

else:
    refuse(f"unknown subcommand {sub!r}")
PY
}

# --- self-test ---------------------------------------------------------------
_aec_self_test() {
  local fail=0 tmp
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" EXIT
  t() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

  if ! python3 -c 'import yaml, jsonschema' 2>/dev/null; then
    echo "SKIP - pyyaml/jsonschema absent"; return 0
  fi

  local DIG_CHILD DIG_BASE DIG_OTHER CTX REV REV2
  DIG_CHILD="sha256:$(printf 'c%.0s' {1..64})"
  DIG_BASE="sha256:$(printf 'b%.0s' {1..64})"
  DIG_OTHER="sha256:$(printf 'd%.0s' {1..64})"
  CTX="sha256:$(printf 'e%.0s' {1..64})"
  REV="$(printf 'a%.0s' {1..40})"
  REV2="$(printf 'f%.0s' {1..40})"

  # --- THE MOTIVATING FIXTURE: php 8.4 base (241) vs child (47) -------------
  cat > "$tmp/base.json" <<JSON
{"schema_version":1,"evidence_class":"upstream-base","image_digest":"$DIG_BASE",
 "platform":"linux/amd64","image_family":"php","image_version":"8.4",
 "source_revision":"$REV","build_input_digest":"$CTX","build_completed":true,
 "scanner_identity":"aquasec/trivy@sha256:$(printf '0%.0s' {1..64})",
 "vulnerability_db_identity":"v2+frozen:2026-08-20","created_at":"2026-08-20T00:00:00Z",
 "package_inventory_source":{"kind":"image-base","sha256":"$(printf 'a%.0s' {1..64})","package_count":423},
 "parent":null,"severity_counts":{"CRITICAL":31,"HIGH":210},
 "findings_by_package":{"linux-libc-dev":170}}
JSON
  cat > "$tmp/child.json" <<JSON
{"schema_version":1,"evidence_class":"foundry-child","image_digest":"$DIG_CHILD",
 "child_key":"$(child_key php-fpm 8.4 linux/amd64)",
 "platform":"linux/amd64","image_family":"php-fpm","image_version":"8.4",
 "source_revision":"$REV","build_input_digest":"$CTX","build_completed":true,
 "scanner_identity":"aquasec/trivy@sha256:$(printf '0%.0s' {1..64})",
 "vulnerability_db_identity":"v2+frozen:2026-08-20","created_at":"2026-08-20T00:00:00Z",
 "package_inventory_source":{"kind":"image-child","sha256":"$(printf 'b%.0s' {1..64})","package_count":178},
 "parent":{"evidence_class":"upstream-base","image_digest":"$DIG_BASE"},
 "severity_counts":{"CRITICAL":6,"HIGH":41},"findings_by_package":{"linux-libc-dev":0}}
JSON
  cat > "$tmp/staged.json" <<JSON
{"schema_version":1,"evidence_class":"staged-candidate","image_digest":"$DIG_CHILD",
 "child_key":"$(child_key php-fpm 8.4 linux/amd64)",
 "platform":"linux/amd64","image_family":"php-fpm","image_version":"8.4",
 "source_revision":"$REV","build_input_digest":"$CTX","build_completed":true,
 "scanner_identity":"aquasec/trivy@sha256:$(printf '0%.0s' {1..64})",
 "vulnerability_db_identity":"v2+frozen:2026-08-20","created_at":"2026-08-20T00:00:00Z",
 "package_inventory_source":{"kind":"image-child","sha256":"$(printf 'b%.0s' {1..64})","package_count":178},
 "parent":{"evidence_class":"foundry-child","image_digest":"$DIG_CHILD"},
 "staging_package":"ghcr.io/zenchron-dynamics/foundry-staging",
 "severity_counts":{"CRITICAL":6,"HIGH":41}}
JSON

  local A="$_d/assert-evidence-class.sh"
  # positive control first: the contract must ACCEPT correct evidence, or every
  # refusal below is meaningless.
  t "a well-formed upstream-base record validates"  "bash '$A' validate '$tmp/base.json' >/dev/null"
  t "a well-formed foundry-child record validates"  "bash '$A' validate '$tmp/child.json' >/dev/null"
  t "a well-formed staged-candidate validates"      "bash '$A' validate '$tmp/staged.json' >/dev/null"
  t "the fixture encodes the real 241/47 discrepancy" \
    "[ \"\$(jq '.severity_counts.CRITICAL + .severity_counts.HIGH' '$tmp/base.json')\" = 241 ] &&
     [ \"\$(jq '.severity_counts.CRITICAL + .severity_counts.HIGH' '$tmp/child.json')\" = 47 ] &&
     [ \"\$(jq '.findings_by_package[\"linux-libc-dev\"]' '$tmp/base.json')\" = 170 ] &&
     [ \"\$(jq '.findings_by_package[\"linux-libc-dev\"]' '$tmp/child.json')\" = 0 ]"

  # --- what upstream-base MAY establish ------------------------------------
  t "an upstream-base scan CAN establish upstream ownership" \
    "bash '$A' consumer upstream-ownership '$tmp/base.json' >/dev/null"
  t "...and a child record CANNOT stand in for it" \
    "! bash '$A' consumer upstream-ownership '$tmp/child.json' >/dev/null 2>&1"

  echo "--- sabotage: each must refuse for ITS OWN diagnostic ---"
  local out

  # 1. base evidence relabelled as child
  jq '.evidence_class="foundry-child" | .parent={"evidence_class":"upstream-base","image_digest":"'"$DIG_BASE"'"}' \
     "$tmp/base.json" > "$tmp/s1.json"
  out="$(bash "$A" validate "$tmp/s1.json" 2>&1 || true)"
  t "S1 base evidence RELABELLED as child is refused" "! bash '$A' validate '$tmp/s1.json' >/dev/null 2>&1"
  t "S1 diagnostic names the base-vs-child inventory (241/47)" \
    "printf '%s' \"\$out\" | grep -q '241-vs-47' && printf '%s' \"\$out\" | grep -q 'image-base'"

  # 2. child evidence attached to a DIFFERENT digest
  out="$(bash "$A" bind "$tmp/child.json" "digest=$DIG_OTHER" 2>&1 || true)"
  t "S2 child evidence on a different digest is refused" \
    "! bash '$A' bind '$tmp/child.json' 'digest=$DIG_OTHER' >/dev/null 2>&1"
  t "S2 diagnostic names the DIGEST binding" \
    "printf '%s' \"\$out\" | grep -q 'digest mismatch'"

  # 3. missing build completion
  jq '.build_completed=false' "$tmp/child.json" > "$tmp/s3.json"
  out="$(bash "$A" validate "$tmp/s3.json" 2>&1 || true)"
  t "S3 an incomplete build cannot emit foundry-child evidence" \
    "! bash '$A' validate '$tmp/s3.json' >/dev/null 2>&1"
  t "S3 diagnostic names BUILD COMPLETION" \
    "printf '%s' \"\$out\" | grep -q 'COMPLETED build'"

  # 4. amd64 substituted for arm64
  out="$(bash "$A" bind "$tmp/child.json" platform=linux/arm64 2>&1 || true)"
  t "S4 amd64 evidence cannot satisfy an arm64 expectation" \
    "! bash '$A' bind '$tmp/child.json' platform=linux/arm64 >/dev/null 2>&1"
  t "S4 diagnostic names the PLATFORM binding" \
    "printf '%s' \"\$out\" | grep -q 'platform mismatch'"

  # 5. one image version substituted for another
  out="$(bash "$A" bind "$tmp/child.json" version=8.3 2>&1 || true)"
  t "S5 8.4 evidence cannot satisfy an 8.3 expectation" \
    "! bash '$A' bind '$tmp/child.json' version=8.3 >/dev/null 2>&1"
  t "S5 diagnostic names the VERSION binding" \
    "printf '%s' \"\$out\" | grep -q 'version mismatch'"

  # 6. mutable tag, no immutable digest
  jq '.image_digest="ghcr.io/zenchron-dynamics/foundry-staging:latest"' "$tmp/child.json" > "$tmp/s6.json"
  out="$(bash "$A" validate "$tmp/s6.json" 2>&1 || true)"
  t "S6 a mutable tag is refused as an artifact identity" \
    "! bash '$A' validate '$tmp/s6.json' >/dev/null 2>&1"
  t "S6 diagnostic names the MUTABLE TAG" \
    "printf '%s' \"\$out\" | grep -q 'not an immutable' && printf '%s' \"\$out\" | grep -q 'mutable tag is not an identity'"

  # 7. wrong source revision
  out="$(bash "$A" bind "$tmp/child.json" "source=$REV2" 2>&1 || true)"
  t "S7 evidence from another source revision is refused" \
    "! bash '$A' bind '$tmp/child.json' 'source=$REV2' >/dev/null 2>&1"
  t "S7 diagnostic names the SOURCE REVISION binding" \
    "printf '%s' \"\$out\" | grep -q 'source mismatch'"

  # 8. wrong class supplied to GOVERNANCE generation
  out="$(bash "$A" consumer governance-generation "$tmp/base.json" 2>&1 || true)"
  t "S8 governance generation refuses an upstream-base record" \
    "! bash '$A' consumer governance-generation '$tmp/base.json' >/dev/null 2>&1"
  t "S8 diagnostic names GOVERNANCE and the child inventory" \
    "printf '%s' \"\$out\" | grep -q 'governance requires child-installed inventory'"
  t "S8 ...and governance ACCEPTS a foundry-child record" \
    "bash '$A' consumer governance-generation '$tmp/child.json' >/dev/null"

  # 9. wrong class supplied to production AUTHORIZATION
  out="$(bash "$A" consumer production-authorization "$tmp/child.json" 2>&1 || true)"
  t "S9 production authorization refuses a foundry-child record" \
    "! bash '$A' consumer production-authorization '$tmp/child.json' >/dev/null 2>&1"
  t "S9 diagnostic names STAGED-CANDIDATE" \
    "printf '%s' \"\$out\" | grep -q 'requires a staged candidate'"
  t "S9 ...and it ACCEPTS a staged-candidate" \
    "bash '$A' consumer production-authorization '$tmp/staged.json' >/dev/null"
  t "S9 ...and refuses an upstream-base outright" \
    "! bash '$A' consumer production-authorization '$tmp/base.json' >/dev/null 2>&1"

  # --- reports must DISPLAY the class --------------------------------------
  t "a report line displays the evidence class" \
    "bash '$A' report '$tmp/child.json' | head -1 | grep -q '^\\[foundry-child\\]'"
  t "...and the base report is visibly a DIFFERENT class" \
    "bash '$A' report '$tmp/base.json' | head -1 | grep -q '^\\[upstream-base\\]'"
  t "...and the report shows which inventory the counts came from" \
    "bash '$A' report '$tmp/base.json' | grep -q 'inventory=image-base' &&
     bash '$A' report '$tmp/child.json' | grep -q 'inventory=image-child'"

  # --- historical compatibility: EXPLICIT, never inferred ------------------
  t "the REAL accepted multiarch evidence still validates" \
    "bash '$A' legacy docs/audits/acceptance-multiarch-2026-08-20/acceptance-evidence.json >/dev/null"
  t "the REAL accepted amd64 authorization record still validates" \
    "bash '$A' legacy docs/audits/acceptance-amd64-2026-08-14/post-build-authorization.json >/dev/null"
  t "an UNLISTED pre-contract record is REFUSED, not defaulted" \
    "! bash '$A' legacy docs/audits/governance-verification-2026-08-13.json >/dev/null 2>&1"
  out="$(bash "$A" legacy docs/audits/governance-verification-2026-08-13.json 2>&1 || true)"
  t "...and the diagnostic says there is NO inferred default" \
    "printf '%s' \"\$out\" | grep -q 'NO inferred default'"

  # --- identity comes from common.sh, not a second derivation --------------
  t "child_key is the single identity derivation" \
    "[ \"\$(jq -r .child_key '$tmp/child.json')\" = \"\$(child_key php-fpm 8.4 linux/amd64)\" ]"
  # Identity is child_key() from common.sh and nothing else. Asserted by
  # BEHAVIOUR (the value matches) plus the absence of a hand-rolled assembler —
  # not by grepping for a string this file would then match in its own comment.
  t "...this script sources the one identity library" \
    "grep -q '\\. \"\$_d/../lib/common.sh\"' '$A'"

  echo "----"
  [ "$fail" -eq 0 ] && echo "assert-evidence-class: PASS" || echo "assert-evidence-class: FAIL"
  return "$fail"
}

case "${1:-}" in
  --self-test) _aec_self_test ;;
  validate|require-class|consumer|bind|legacy|report) _aec "$@" ;;
  ""|-h|--help) sed -n '2,40p' "${BASH_SOURCE[0]}"; exit 2 ;;
  *) die "unknown subcommand '${1}'; try --help" ;;
esac
