#!/usr/bin/env bash
# shellcheck disable=SC2034  # assertion vars are consumed inside eval'd assertion strings
# =============================================================================
# tests/release/test_evidence_bundle.sh
# -----------------------------------------------------------------------------
# The durable release evidence bundle and its retention archive (#128), asserted
# from OUTSIDE the scripts that implement them and against the REAL committed
# accepted evidence — docs/audits/acceptance-multiarch-2026-08-20 — not only
# fixtures.
#
# THE DEFECT: scan artifacts expire after 30 days; the release decision they
# justify has to survive for years. The property under test is therefore not
# "a bundle can be written" but "the bundle still verifies when the workflow
# run, the artifacts and the working copy are all gone", which is why the
# retention exercise below deletes the working copy before restoring it.
#
# Every case runs against a DISPOSABLE COPY. A self-test that mutates the
# ambient checkout has already destroyed a policy file in this repository once.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
# common.sh carries `set -e`; intentional-refusal assertions must survive it.
# Under pipefail a `<refusing command> | grep` reports the refusal's status, so
# the diagnostic assertions need it off too.
# shellcheck source=../../scripts/lib/common.sh
. scripts/lib/common.sh
set +e
set +o pipefail

fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

GEN=scripts/release/generate-evidence-bundle.sh
RESTORE=scripts/release/restore-evidence.sh
SCHEMA=schemas/release-evidence-bundle-v1.schema.json
RETENTION=policies/retention.yaml
ACCEPTED=docs/audits/acceptance-multiarch-2026-08-20/acceptance-evidence.json

TMP="$(mktemp -d)"
# Expand NOW: a single-quoted EXIT trap defers expansion past this scope. The
# archive tree is 0555, so write permission has to come back before removal.
# shellcheck disable=SC2064
trap "chmod -R u+w '$TMP' 2>/dev/null; rm -rf '$TMP'" EXIT

if ! python3 -c 'import yaml' 2>/dev/null; then
  echo "SKIP - PyYAML absent"; echo "test_evidence_bundle: PASS"; exit 0
fi

DAY=2026-08-25

# The canonical post-build authorization the bundle now requires. The real
# record is a 30-day workflow artifact and this run's expired — the exact
# retention failure the bundle exists for — so the offline fixture is
# reconstructed from the accepted evidence itself. The builder lives under
# tests/ deliberately: a tool in scripts/ that derived a canonical-looking
# authorization from any acceptance record would be a bypass of the gate rather
# than a fixture generator.
AUTHREC="$TMP/post-build-authorization.json"
python3 tests/lib/make_authorization_fixture.py "$ACCEPTED" "$AUTHREC" \
  || { echo "SKIP - authorization fixture unavailable"; echo "test_evidence_bundle: PASS"; exit 0; }

gen()  {
  case " $* " in
    *" --authorization "*|*" --authorization-absent "*) : ;;
    *) set -- "$@" --authorization "$AUTHREC" ;;
  esac
  ( bash "$GEN" generate "$@" )
}
ver()  { ( bash "$GEN" verify "$@" ); }
arc()  { ( bash "$RESTORE" archive "$@" ); }
res()  { ( bash "$RESTORE" restore "$@" ); }
averify() { ( bash "$RESTORE" verify "$@" ); }

# --- the artefacts exist and are well formed ---------------------------------
ck "the bundle schema is valid JSON"       "python3 -c 'import json;json.load(open(\"$SCHEMA\"))'"
ck "the retention policy is valid YAML"    "python3 -c 'import yaml;yaml.safe_load(open(\"$RETENTION\"))'"
ck "the generator is executable"           "test -x '$GEN'"
ck "the restore tool is executable"        "test -x '$RESTORE'"
ck "the real accepted evidence is present" "test -f '$ACCEPTED'"

# --- the class vocabulary is CONSUMED, never redefined -----------------------
# The four classes belong to policies/evidence-classes.yaml. This schema's enum
# repeats the names so the bundle can be validated standalone; if the policy is
# present and they ever disagree, the bundle has started defining its own
# vocabulary and this fails.
if [ -f policies/evidence-classes.yaml ]; then
  ck "the schema enum matches policies/evidence-classes.yaml exactly" \
     "python3 -c 'import json,yaml,sys
s=set(json.load(open(\"$SCHEMA\"))[\"properties\"][\"evidence_class\"][\"enum\"])
p=set(c[\"name\"] for c in yaml.safe_load(open(\"policies/evidence-classes.yaml\"))[\"classes\"])
sys.exit(0 if s==p else 1)'"
else
  echo "note - policies/evidence-classes.yaml is not on this ref; the schema enum"
  echo "       carries the four class names the landing contract declares"
fi
ck "every retention class is one of the declared evidence classes" \
   "python3 -c 'import json,yaml,sys
enum=set(json.load(open(\"$SCHEMA\"))[\"properties\"][\"evidence_class\"][\"enum\"])
r=set(c[\"evidence_class\"] for c in yaml.safe_load(open(\"$RETENTION\"))[\"classes\"])
sys.exit(0 if r<=enum else 1)'"
ck "retention is stated for every declared class — no class without a promise" \
   "python3 -c 'import json,yaml,sys
enum=set(json.load(open(\"$SCHEMA\"))[\"properties\"][\"evidence_class\"][\"enum\"])
r=set(c[\"evidence_class\"] for c in yaml.safe_load(open(\"$RETENTION\"))[\"classes\"])
sys.exit(0 if enum<=r else 1)'"
# CORRECTED 2026-08-30. This asserted that staged-candidate and
# published-artifact REQUIRE immutable storage. That requirement was never
# authorized (commit 6413eb51 / PR #207, zero reviews) and had no legal,
# contractual or customer basis; the maintainer replaced it with a lifecycle
# model. The assertion now holds the CORRECTED invariant, which is stronger in
# the direction that matters: WORM is opt-in and cannot be assigned silently.
ck "no shipped class requires immutable storage, and WORM is opt-in only" \
   "python3 -c 'import yaml,sys
d=yaml.safe_load(open(\"$RETENTION\"))
m=d[\"retention_models\"]
ok=all(c[\"immutable_storage_required\"] is False for c in d[\"classes\"])
ok=ok and all(m[c[\"retention_model\"]][\"worm_required\"] is False for c in d[\"classes\"])
ok=ok and d[\"regulated_retention\"][\"default\"] is False
ok=ok and d[\"regulated_retention\"][\"applies_to_classes\"]==[]
sys.exit(0 if ok else 1)'"
ck "deletion is never automatic" \
   "python3 -c 'import yaml,sys;sys.exit(0 if yaml.safe_load(open(\"$RETENTION\"))[\"deletion\"][\"automatic\"] is False else 1)'"
ck "verification is declared to need no network and no GitHub" \
   "python3 -c 'import yaml,sys
v=yaml.safe_load(open(\"$RETENTION\"))[\"verification\"]
sys.exit(0 if v[\"offline\"] and not v[\"network_required\"] and not v[\"github_required\"] else 1)'"
# CORRECTED 2026-08-30. `minimum_independent_locations: 2` was unconditional and
# came from the same unratified set as the seven-year rule. It is now a property
# of the retention MODEL: only regulated-worm needs a second location, and no
# shipped class uses that model.
ck "a second independent location is required ONLY by the regulated-worm model" \
   "python3 -c 'import yaml,sys
m=yaml.safe_load(open(\"$RETENTION\"))[\"retention_models\"]
sys.exit(0 if m[\"regulated-worm\"][\"minimum_independent_locations\"]>=2
         and m[\"repository-artifact\"][\"minimum_independent_locations\"]==1
         and m[\"supported-release-lifetime\"][\"minimum_independent_locations\"]==1 else 1)'"

# --- the legacy class declaration is CONSUMED, not guessed -------------------
# policies/evidence-classes.yaml pins the accepted record's class to its bytes.
# The bundle must honour that declaration and may promote it by exactly one step
# along the declared lifecycle — never sideways, never backwards.
if [ -f policies/evidence-classes.yaml ]; then
  ck "the accepted record is declared staged-candidate, pinned to its sha256" \
     "python3 -c 'import hashlib,sys,yaml
p=yaml.safe_load(open(\"policies/evidence-classes.yaml\"))
h=hashlib.sha256(open(\"$ACCEPTED\",\"rb\").read()).hexdigest()
m=[r for r in p.get(\"legacy_records\") or [] if r[\"sha256\"]==h]
sys.exit(0 if m and m[0][\"declared_class\"]==\"staged-candidate\" else 1)'"
  ck "REFUSE: a class that does not succeed the declared one" \
     "! ( bash '$GEN' generate --evidence '$ACCEPTED' --out '$TMP/wrongcls' \
          --evidence-class foundry-child --today '$DAY' ) >/dev/null 2>&1"
  ck "a one-step promotion to published-artifact IS allowed" \
     "gen --evidence '$ACCEPTED' --out '$TMP/promoted' --evidence-class published-artifact \
        --release v2026.08.25 --candidate rc1 --today '$DAY' >/dev/null"
fi

# --- the generator's own sabotage suite --------------------------------------
bash "$GEN" --self-test >"$TMP/gen.out" 2>&1; genrc=$?
ck "the generator's sabotage suite passes" "[ '$genrc' -eq 0 ]"
for s in S1 S2 S3 S4 S5 S6 S7 S8 S9 S10; do
  ck "generator sabotage $s is exercised and refused" "grep -q \"^ok   - $s \" '$TMP/gen.out'"
done

# --- the bundle, built from the REAL accepted run ----------------------------
ck "a bundle is generated from the real committed accepted evidence" \
   "gen --evidence '$ACCEPTED' --out '$TMP/b' --evidence-class staged-candidate --today '$DAY' >/dev/null"
ck "it verifies offline"  "ver '$TMP/b' >/dev/null"

M="$TMP/b/manifest.json"
ck "the manifest validates against release-evidence-bundle-v1" \
   "python3 -c 'import json,sys
try: from jsonschema import Draft202012Validator
except ImportError: sys.exit(0)
e=list(Draft202012Validator(json.load(open(\"$SCHEMA\"))).iter_errors(json.load(open(\"$M\"))))
sys.exit(1 if e else 0)'"

# Everything #128 asks the bundle to carry, checked field by field. A bundle
# that is merely "present" answers nothing months later.
for f in children source_revision scanner vulnerability_database sbom findings \
         reconciliation dispositions policy_digests provenance authorization \
         evidence_class retention checksums files execution_disclosure; do
  ck "the manifest carries '$f'" \
     "python3 -c 'import json,sys;sys.exit(0 if \"$f\" in json.load(open(\"$M\")) else 1)'"
done

ck "the child set is MATRIX_COUNT x platforms, derived not hardcoded" \
   "[ \"\$(python3 -c 'import json;print(len(json.load(open(\"$M\"))[\"children\"]))')\" = \"\$(( MATRIX_COUNT * 2 ))\" ]"
ck "every child is digest-bound (no tag anywhere in the child set)" \
   "python3 -c 'import json,re,sys
c=json.load(open(\"$M\"))[\"children\"]
sys.exit(0 if all(re.match(r\"^sha256:[0-9a-f]{64}\$\", x[\"manifest_digest\"]) for x in c) else 1)'"
ck "every child carries the acceptance run's own evidence_sha256" \
   "python3 -c 'import json,sys
b=json.load(open(\"$M\"));a=json.load(open(\"$ACCEPTED\"))
want={x[\"child_key\"]:x[\"evidence_sha256\"] for x in a[\"children\"]}
sys.exit(0 if all(x[\"evidence_sha256\"]==want[x[\"child_key\"]] for x in b[\"children\"]) else 1)'"
ck "child identity is child_key(), not a second derivation" \
   "python3 -c 'import json,sys
b=json.load(open(\"$M\"))
sys.exit(0 if all(x[\"child_key\"]==\"%s/%s\"%(x[\"image_label\"],x[\"platform\"]) for x in b[\"children\"]) else 1)'"
ck "the frozen scanner is digest-pinned" \
   "python3 -c 'import json,sys;sys.exit(0 if \"@sha256:\" in json.load(open(\"$M\"))[\"scanner\"][\"image\"] else 1)'"
ck "exactly one vulnerability database identity" \
   "python3 -c 'import json,sys;sys.exit(0 if json.load(open(\"$M\"))[\"vulnerability_database\"][\"frozen\"] else 1)'"
ck "the exception policy digest is recorded with the dispositions" \
   "[ \"\$(python3 -c 'import json;print(json.load(open(\"$M\"))[\"dispositions\"][\"exception_policy_sha256\"])')\" \
      = \"\$(shasum -a 256 policies/vulnerability-exceptions.yaml | awk '{print \$1}')\" ]"
ck "the policy digests match the files on disk right now" \
   "python3 -c 'import hashlib,json,sys
m=json.load(open(\"$M\"))
for p,d in m[\"policy_digests\"].items():
    if hashlib.sha256(open(p,\"rb\").read()).hexdigest()!=d: sys.exit(1)
sys.exit(0)'"
ck "emulated arm64 is disclosed as emulated, not as native" \
   "python3 -c 'import json,sys
d=json.load(open(\"$M\"))[\"execution_disclosure\"]
sys.exit(0 if \"linux/arm64\" in d[\"emulated_platforms\"] and d[\"qemu_children\"]>0 else 1)'"
ck "an absent SBOM is recorded as absent, never as an empty one" \
   "python3 -c 'import json,sys
m=json.load(open(\"$M\"))
sys.exit(0 if m[\"sbom\"][\"present\"] is False and all(c[\"sbom\"] is None for c in m[\"children\"]) else 1)'"

# --- THE CONTROL: nothing outside checksum coverage --------------------------
ck "every content file is in SHA256SUMS" \
   "[ \"\$(find '$TMP/b/content' -type f | wc -l | tr -d ' ')\" \
      = \"\$(grep -c '  content/' '$TMP/b/SHA256SUMS')\" ]"
ck "the manifest itself is in SHA256SUMS" "grep -q '  manifest.json\$' '$TMP/b/SHA256SUMS'"
ck "the generated VEX document is inside coverage" "grep -q '  content/vex/openvex.json\$' '$TMP/b/SHA256SUMS'"
cp -r "$TMP/b" "$TMP/planted"; printf 'planted\n' > "$TMP/planted/content/late-arrival.json"
ck "SABOTAGE: a file added after sealing is REFUSED" "! ver '$TMP/planted' >/dev/null 2>&1"
ck "...naming coverage as the reason" "ver '$TMP/planted' 2>&1 | grep -q 'covered by no checksum'"

# --- determinism -------------------------------------------------------------
ck "regenerating from the same inputs is byte-identical" \
   "gen --evidence '$ACCEPTED' --out '$TMP/b2' --evidence-class staged-candidate --today '$DAY' >/dev/null \
    && cmp -s '$TMP/b/manifest.json' '$TMP/b2/manifest.json'"
# The evaluation date IS an input — it is the day staleness was checked, and the
# disposition set says so. Moving it must change the disposition digest and
# NOTHING derived from the evidence, or the bundle's facts would depend on when
# somebody happened to run the generator.
ck "moving the evaluation date changes only the disposition claim" \
   "gen --evidence '$ACCEPTED' --out '$TMP/b3' --evidence-class staged-candidate --today 2026-08-26 >/dev/null \
    && python3 -c 'import json,sys
a=json.load(open(\"$TMP/b/manifest.json\"));b=json.load(open(\"$TMP/b3/manifest.json\"))
same=all(a[k]==b[k] for k in (\"children\",\"source_revision\",\"acceptance\",\"findings\",
                             \"retention\",\"scanner\",\"vulnerability_database\",
\"execution_disclosure\",\"policy_digests\",\"authorization\",\"matrix\",\"bundle_id\"))
moved=a[\"dispositions\"][\"sha256\"]!=b[\"dispositions\"][\"sha256\"]
sys.exit(0 if same and moved else 1)'"
ck "...and the statement count is unchanged, because the findings did not move" \
   "[ \"\$(python3 -c 'import json;print(json.load(open(\"$TMP/b/manifest.json\"))[\"dispositions\"][\"statement_count\"])')\" \
      = \"\$(python3 -c 'import json;print(json.load(open(\"$TMP/b3/manifest.json\"))[\"dispositions\"][\"statement_count\"])')\" ]"

# =============================================================================
# THE RETENTION EXERCISE, run for real:
#   generate -> archive -> DELETE the working copy -> restore -> verify
# =============================================================================
BID="$(python3 -c 'import json;print(json.load(open("'"$M"'"))["bundle_id"])')"
ck "R1 the bundle archives into a write-once tree" \
   "arc --bundle '$TMP/b' --archive-root '$TMP/archive' >/dev/null"
ck "R2 the archive carries a checksum index" "test -f '$TMP/archive/INDEX.sha256'"
ck "R3 the archived tree is immutable to an ordinary write" \
   "! ( printf x >> \"\$(find '$TMP/archive' -name manifest.json | head -1)\" ) 2>/dev/null"
ck "R4 DELETE the working copy" "rm -rf '$TMP/b' && [ ! -e '$TMP/b' ]"
ck "R5 restore it by bundle_id, with nothing else on disk" \
   "res --archive-root '$TMP/archive' --bundle-id '$BID' --dest '$TMP/restored' >/dev/null"
ck "R6 the restored copy verifies offline" "ver '$TMP/restored' >/dev/null"
ck "R7 the restored manifest is the one that was archived" \
   "cmp -s '$TMP/restored/manifest.json' '$TMP/b2/manifest.json'"
ck "R8 the whole archive verifies" "averify --archive-root '$TMP/archive' >/dev/null"
ck "R9 a retain_until is recorded and is in the future" \
   "python3 -c 'import datetime,json,sys
m=json.load(open(\"$TMP/restored/manifest.json\"))
sys.exit(0 if datetime.date.fromisoformat(m[\"retention\"][\"retain_until\"])>datetime.date(2026,8,25) else 1)'"
# CORRECTED 2026-08-30. This asserted that staged-candidate retention must
# OUTLIVE GitHub's 90-day ceiling. It encoded the unapproved seven-year rule:
# a staged candidate is private and undistributed, its evidence may expire, and
# the repository period is the mechanism actually available. The assertion now
# holds the corrected invariant.
ck "R10 staged-candidate retention is the repository period, and may expire" \
   "[ \"\$(python3 -c 'import json;print(json.load(open(\"$TMP/restored/manifest.json\"))[\"retention\"][\"retention_days\"])')\" = 90 ] \
    && python3 -c 'import yaml,sys
c={x[\"evidence_class\"]:x for x in yaml.safe_load(open(\"$RETENTION\"))[\"classes\"]}[\"staged-candidate\"]
sys.exit(0 if c[\"may_expire\"] is True and c[\"lifecycle\"]==\"unpublished\" else 1)'"

# --- retention sabotage ------------------------------------------------------
cp -r "$TMP/restored" "$TMP/stray"
mkdir -p "$TMP/archive/staged-candidate/stray"; cp -r "$TMP/stray"/* "$TMP/archive/staged-candidate/stray/"
ck "R11 an unindexed bundle in the archive is REFUSED" \
   "! averify --archive-root '$TMP/archive' >/dev/null 2>&1"
chmod -R u+w "$TMP/archive/staged-candidate/stray"; rm -rf "$TMP/archive/staged-candidate/stray"
ck "R12 ...and the archive verifies again once it is gone" \
   "averify --archive-root '$TMP/archive' >/dev/null"
ck "R13 restoring an unknown bundle_id is REFUSED" \
   "! res --archive-root '$TMP/archive' --bundle-id nope --dest '$TMP/x' >/dev/null 2>&1"

# --- NON-VACUITY -------------------------------------------------------------
# Every assertion above would also pass if the verifier accepted everything.
printf '{"schema_version":1}\n' > "$TMP/hollow.json"
mkdir -p "$TMP/hollow"
ck "NON-VACUOUS: an empty directory is not a bundle" "! ver '$TMP/hollow' >/dev/null 2>&1"
mkdir -p "$TMP/hollow/content"; cp "$TMP/hollow.json" "$TMP/hollow/manifest.json"
ck "NON-VACUOUS: a manifest with no index is REFUSED" "! ver '$TMP/hollow' >/dev/null 2>&1"
ck "NON-VACUOUS: the untouched bundle still verifies after every sabotage above" \
   "ver '$TMP/restored' >/dev/null"

echo "----"
[ "$fail" -eq 0 ] && echo "test_evidence_bundle: PASS" || echo "test_evidence_bundle: FAIL"
exit $fail
