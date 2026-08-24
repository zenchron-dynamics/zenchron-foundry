#!/usr/bin/env bash
# =============================================================================
# tests/reproducibility/test_repro_guarantees.sh — the four guarantees stay four (#101).
#
# #101 asks four questions that were being answered with one word:
#
#   build-input             can the declared inputs be re-presented exactly?
#   package-resolution      would apt resolve the same packages?
#   image-bytes             do two builds produce the same bytes?
#   vulnerability-verdict   does re-scanning give the same verdict?
#
# They have four different answers. This suite asserts the declared answers are
# the MEASURED ones, that no guarantee has been widened past its evidence, and
# that the machinery which enforces that is itself exercised — every refusal
# path shown to refuse, and the honest inputs shown to pass so that "refuses
# everything" cannot masquerade as "works".
#
# Offline. The repeated builds themselves need docker and run via
# `make reproducibility`; the records they produced are committed under
# tests/reproducibility/evidence/ and are what this suite reads.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

EV=tests/reproducibility/evidence
LOCK="$EV/php-cli-8.4-linux-amd64.lock.json"

# --- the harnesses exercise their own refusal paths -------------------------
ck "the guarantee gate self-test passes" \
   "bash scripts/repro-guarantees.sh --self-test >/dev/null"
ck "the build-input lock self-test passes" \
   "bash scripts/repro-lock.sh --self-test >/dev/null"
ck "the repeated-build harness self-test passes" \
   "bash scripts/reproducibility-check.sh --self-test >/dev/null"

# --- the real policy, against the real tree ---------------------------------
ck "the declared guarantees hold against this tree" \
   "bash scripts/repro-guarantees.sh >/dev/null"
ck "the committed build-input lock binds to this tree" \
   "bash scripts/repro-lock.sh verify '$LOCK' >/dev/null"

# --- the four are four, and stay four ---------------------------------------
ck "exactly the four guarantees are declared" \
   'python3 -c "
import yaml
d = yaml.safe_load(open(\"policies/reproducibility.yaml\"))
ids = sorted(g[\"id\"] for g in d[\"guarantees\"])
assert ids == [\"build-input\", \"image-bytes\", \"package-resolution\", \"vulnerability-verdict\"], ids
"'
for g in build-input package-resolution image-bytes vulnerability-verdict; do
  ck "guarantee '$g' declares a question, a status and an owner-visible residual" \
     "python3 -c \"
import yaml
d = yaml.safe_load(open('policies/reproducibility.yaml'))
g = [x for x in d['guarantees'] if x['id'] == '$g'][0]
assert g.get('question'), 'no question'
assert g.get('status'), 'no status'
if g['status'] != 'guaranteed':
    assert g.get('residual') or g.get('does_not_hold_because'), 'a partial guarantee with no named residual'
\""
done

# --- the two answers that must stay negative --------------------------------
# These are the two the issue's own history shows being quietly upgraded.
ck "package-resolution is declared not-guaranteed" \
   'python3 -c "
import yaml
d = yaml.safe_load(open(\"policies/reproducibility.yaml\"))
g = [x for x in d[\"guarantees\"] if x[\"id\"] == \"package-resolution\"][0]
assert g[\"status\"] == \"not-guaranteed\", g[\"status\"]
"'
ck "vulnerability-verdict is declared not-guaranteed" \
   'python3 -c "
import yaml
d = yaml.safe_load(open(\"policies/reproducibility.yaml\"))
g = [x for x in d[\"guarantees\"] if x[\"id\"] == \"vulnerability-verdict\"][0]
assert g[\"status\"] == \"not-guaranteed\", g[\"status\"]
"'
ck "image-bytes is conditional, not guaranteed, and names its condition" \
   'python3 -c "
import yaml
d = yaml.safe_load(open(\"policies/reproducibility.yaml\"))
g = [x for x in d[\"guarantees\"] if x[\"id\"] == \"image-bytes\"][0]
assert g[\"status\"] == \"conditional\", g[\"status\"]
assert \"package-resolution\" in g[\"condition\"], g[\"condition\"]
"'

# --- the claim never exceeds the measurement --------------------------------
ck "every claimed field is reported stable by the cited evidence" \
   'python3 -c "
import json, yaml
d = yaml.safe_load(open(\"policies/reproducibility.yaml\"))
for g in d[\"guarantees\"]:
    if g[\"status\"] == \"not-guaranteed\":
        continue
    seen = {}
    for rel in g[\"evidence\"]:
        for f in json.load(open(rel))[\"fields\"]:
            seen[f[\"field\"]] = f[\"result\"]
    for f in g[\"bound_fields\"]:
        assert seen.get(f) == \"stable\", (g[\"id\"], f, seen.get(f))
"'
ck "the field measured to DIFFER is recorded as differing, not omitted" \
   'python3 -c "
import json
ev = json.load(open(\"'"$EV"'/php-cli-8.4-linux-amd64-image-bytes.json\"))
r = {f[\"field\"]: f[\"result\"] for f in ev[\"fields\"]}
assert r[\"build_outputs.rootfs_file_manifest_sha256\"] == \"differs\", r
"'
ck "a field that was never observed is recorded as not-observed, never stable" \
   'python3 -c "
import json
ev = json.load(open(\"'"$EV"'/php-cli-8.4-linux-amd64-image-bytes.json\"))
r = {f[\"field\"]: f[\"result\"] for f in ev[\"fields\"]}
assert r[\"build_outputs.manifest_digest\"] == \"not-observed\", r
"'
ck "the evidence records at least two builds" \
   'python3 -c "
import glob, json
recs = [json.load(open(p)) for p in glob.glob(\"'"$EV"'/*-build-input.json\")
        + glob.glob(\"'"$EV"'/*-image-bytes.json\")]
assert recs, \"no evidence records\"
for r in recs:
    assert r[\"build_count\"] >= 2, r[\"build_count\"]
"'
ck "the evidence binds to the committed lock by digest" \
   'python3 -c "
import glob, hashlib, json
def dg(p):
    d = json.load(open(p)); d.pop(\"generated_at\", None)
    return hashlib.sha256(json.dumps(d, sort_keys=True, separators=(\",\", \":\")).encode()).hexdigest()
locks = {dg(p) for p in glob.glob(\"'"$EV"'/*.lock.json\")}
for p in glob.glob(\"'"$EV"'/*-image-bytes.json\") + glob.glob(\"'"$EV"'/*-build-input.json\"):
    assert json.load(open(p))[\"declared_inputs_lock_sha256\"] in locks, p
"'

# --- the schema refuses the claims that would be unbacked -------------------
ck "the lock schema refuses guaranteed package resolution with no snapshot" \
   'python3 -c "
import json
from jsonschema import Draft202012Validator
s = json.load(open(\"schemas/build-input-lock-v1.schema.json\"))
d = json.load(open(\"'"$LOCK"'\"))
d[\"package_resolution\"][\"guaranteed\"] = True
assert list(Draft202012Validator(s).iter_errors(d)), \"schema accepted an unbacked claim\"
"'
ck "the lock schema refuses a frozen database with no identity" \
   'python3 -c "
import json
from jsonschema import Draft202012Validator
s = json.load(open(\"schemas/build-input-lock-v1.schema.json\"))
d = json.load(open(\"'"$LOCK"'\"))
d[\"vulnerability_verdict\"][\"vulnerability_database\"][\"frozen\"] = True
assert list(Draft202012Validator(s).iter_errors(d)), \"schema accepted a nameless frozen database\"
"'
ck "the evidence schema refuses a result outside stable/differs/not-observed" \
   'python3 -c "
import json
from jsonschema import Draft202012Validator
s = json.load(open(\"schemas/build-input-lock-evidence-v1.schema.json\"))
d = json.load(open(\"'"$EV"'/php-cli-8.4-linux-amd64-image-bytes.json\"))
d[\"fields\"][0][\"result\"] = \"probably-fine\"
assert list(Draft202012Validator(s).iter_errors(d)), \"schema accepted an invented result\"
"'

# --- the lock records everything #101 asked to be bound ---------------------
for path in build_inputs.source_sha build_inputs.context_digest \
            build_inputs.dockerfile_digest build_inputs.base.manifest_digest \
            build_inputs.base.platform_child_digest build_inputs.build_args \
            build_inputs.toolchain package_resolution.snapshot_identity \
            package_resolution.packages build_outputs.config_digest \
            build_outputs.layer_digests build_outputs.manifest_digest \
            vulnerability_verdict.scanner vulnerability_verdict.vulnerability_database; do
  ck "the lock records '$path'" \
     "python3 -c \"
import json
d = json.load(open('$LOCK'))
cur = d
for p in '$path'.split('.'):
    assert p in cur, '$path'
    cur = cur[p]
\""
done

# --- documentation states the same four answers -----------------------------
# The doc is where a consumer reads the claim. A doc that has drifted from the
# policy is the version people will quote.
ck "docs/reproducibility.md names all four guarantees" \
   'for g in build-input package-resolution image-bytes vulnerability-verdict; do
      grep -q "$g" docs/reproducibility.md || exit 1
    done; true'
ck "docs/reproducibility.md states each guarantee's declared status" \
   'python3 -c "
import re, yaml
doc = open(\"docs/reproducibility.md\").read()
d = yaml.safe_load(open(\"policies/reproducibility.yaml\"))
for g in d[\"guarantees\"]:
    row = [l for l in doc.splitlines() if re.search(r\"\\b%s\\b\" % re.escape(g[\"id\"]), l)
           and g[\"status\"] in l]
    assert row, (g[\"id\"], g[\"status\"])
"'
ck "the gate is wired into the offline macro-validation sweep" \
   "grep -q 'repro-guarantees.sh' scripts/macro-validate.sh"

echo "----"
[ "$fail" -eq 0 ] && echo "test_repro_guarantees: PASS" || echo "test_repro_guarantees: FAIL"
exit "$fail"
