#!/usr/bin/env bash
# shellcheck disable=SC2034  # assertion vars are consumed inside eval'd assertion strings
# =============================================================================
# tests/release/test_release_seal.sh
# -----------------------------------------------------------------------------
# The release-role seal and its verifier (#130), asserted from OUTSIDE the
# scripts and against the REAL committed accepted run and the REAL committed
# identity policy (policies/cosign-identities.yaml).
#
# THE DEFECT: policies/cosign-identities.yaml declares a `release` role and
# states, in the file, "RESERVED, currently consumed by no verifier". Nothing
# made a cryptographic statement AT THE RELEASE CEREMONY binding the promoted
# digest set, the final evidence, the policy state and the tag together.
#
# THE ACCEPTANCE CRITERION THAT MATTERS: "Candidate or RC signatures cannot
# satisfy the release-seal policy." That is asserted here three ways — a
# candidate IDENTITY, a validly-signed seal carrying a candidate identity, and
# candidate EVIDENCE — because refusing only the first would let the other two
# through.
#
# TEST-ONLY, and the suite proves it: the seal script cannot emit a production
# signature, and the verifier's production gate refuses everything it produces.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
# common.sh carries `set -e`; refusal assertions must survive it, and under
# pipefail `<refusing command> | grep` reports the refusal's status.
# shellcheck source=../../scripts/lib/common.sh
. scripts/lib/common.sh
set +e
set +o pipefail

fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

SEAL=scripts/release/release-seal.sh
VERIFY=scripts/release/verify-release-seal.sh
GEN=scripts/release/generate-evidence-bundle.sh
IDS=policies/cosign-identities.yaml
ACCEPTED=docs/audits/acceptance-multiarch-2026-08-20/acceptance-evidence.json

TMP="$(mktemp -d)"
# Expand NOW: a single-quoted EXIT trap defers expansion past this scope.
# shellcheck disable=SC2064
trap "rm -rf '$TMP'" EXIT

if ! python3 -c 'import yaml' 2>/dev/null; then
  echo "SKIP - PyYAML absent"; echo "test_release_seal: PASS"; exit 0
fi
if ! command -v openssl >/dev/null 2>&1; then
  echo "SKIP - openssl absent"; echo "test_release_seal: PASS"; exit 0
fi

DAY=2026-08-25

# See tests/release/test_evidence_bundle.sh for why this fixture is
# reconstructed offline and why its builder lives under tests/.
# The accepted run is EMULATED arm64 and release-seal.sh now refuses to seal it
# while policies/native-arch-requirements.yaml requires native (#111). THIS
# file's subject is the seal's other rules, so the default fixture is a stamped
# native variant of the same run — otherwise R1/R5/R8/R11/R12 would all start
# passing for the native-architecture reason instead of their own. The emulated
# record is used directly, below, as the R9 case.
python3 tests/lib/make_native_arm64_fixture.py "$ACCEPTED" "$TMP/ev-native.json" >/dev/null \
  || { echo "SKIP - native fixture unavailable"; echo "test_release_seal: PASS"; exit 0; }
ACCEPTED_NATIVE="$TMP/ev-native.json"
AUTHREC="$TMP/post-build-authorization.json"
python3 tests/lib/make_authorization_fixture.py "$ACCEPTED_NATIVE" "$AUTHREC" \
  || { echo "SKIP - authorization fixture unavailable"; echo "test_release_seal: PASS"; exit 0; }
AUTHREC_EMUL="$TMP/post-build-authorization-emulated.json"
python3 tests/lib/make_authorization_fixture.py "$ACCEPTED" "$AUTHREC_EMUL" \
  || { echo "SKIP - authorization fixture unavailable"; echo "test_release_seal: PASS"; exit 0; }

seal() { ( bash "$SEAL" seal "$@" ); }
vfy()  { ( bash "$VERIFY" verify "$@" ); }
gen()  {
  case " $* " in
    *" --authorization "*|*" --authorization-absent "*) : ;;
    *) set -- "$@" --authorization "$AUTHREC" ;;
  esac
  ( bash "$GEN" generate "$@" )
}

ck "the seal script is executable"     "test -x '$SEAL'"
ck "the verifier is executable"        "test -x '$VERIFY'"
ck "the identity policy is present"    "test -f '$IDS'"

# --- the seal script cannot produce a production signature -------------------
ck "there is no flag that turns off test_only" "! grep -q 'test_only.*false\|--production' '$SEAL'"
ck "the script refuses to run where a real signature could be minted" \
   "grep -q 'SIGSTORE_ID_TOKEN' '$SEAL'"
ck "the script refuses to run on a tag ref" "grep -q 'GITHUB_REF_TYPE' '$SEAL'"
ck "no production signing tool is invoked" "! grep -qE '^[^#]*\\bcosign (sign|attest)' '$SEAL'"

# --- both self-test suites ---------------------------------------------------
bash "$SEAL" --self-test >"$TMP/seal.out" 2>&1; sealrc=$?
ck "the seal's refusal suite passes" "[ '$sealrc' -eq 0 ]"
for r in R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12; do
  ck "refusal $r is exercised" "grep -q \"^ok   - $r\" '$TMP/seal.out'"
done
bash "$VERIFY" --self-test >"$TMP/vfy.out" 2>&1; vfyrc=$?
ck "the verifier's sabotage suite passes" "[ '$vfyrc' -eq 0 ]"

# --- fixtures ----------------------------------------------------------------
openssl ecparam -name prime256v1 -genkey -noout -out "$TMP/test.key" 2>/dev/null
REL_ID='https://github.com/zenchron-dynamics/zenchron-foundry/.github/workflows/release.yml@refs/tags/v2026.08.25'
RC_ID='https://github.com/zenchron-dynamics/zenchron-foundry/.github/workflows/publish-rc.yml@refs/heads/master'
SR_ID='https://github.com/zenchron-dynamics/zenchron-foundry/.github/workflows/scheduled-rebuild.yml@refs/heads/master'

# These identity strings are not invented for the test: each must be one the
# committed policy actually declares, or the suite would be proving something
# about a fiction.
ck "the release identity fixture matches the committed release regexp" \
   "python3 -c 'import re,sys,yaml
r=yaml.safe_load(open(\"$IDS\"))[\"roles\"][\"release\"][\"identity_regexp\"]
sys.exit(0 if re.match(r, \"$REL_ID\") else 1)'"
ck "the RC identity fixture matches the committed rc-publisher regexp" \
   "python3 -c 'import re,sys,yaml
r=yaml.safe_load(open(\"$IDS\"))[\"roles\"][\"rc-publisher\"][\"identity_regexp\"]
sys.exit(0 if re.match(r, \"$RC_ID\") else 1)'"
ck "the committed release regexp does NOT accept the RC identity" \
   "python3 -c 'import re,sys,yaml
r=yaml.safe_load(open(\"$IDS\"))[\"roles\"][\"release\"][\"identity_regexp\"]
sys.exit(0 if not re.match(r, \"$RC_ID\") else 1)'"

mkdir -p "$TMP/sboms"
python3 - "$ACCEPTED" "$TMP/sboms" <<'PY'
import json, os, sys
ev = json.load(open(sys.argv[1]))
for c in ev["children"]:
    fam, _, ver = c["image_label"].partition("/")
    slug = "%s-%s-linux-%s" % (fam, ver, c["platform"].rsplit("/", 1)[-1])
    json.dump({"spdxVersion": "SPDX-2.3", "name": c["child_key"],
               "documentDescribes": [c["manifest_digest"]]},
              open(os.path.join(sys.argv[2], slug + ".spdx.json"), "w"), indent=2)
PY
printf '{"_type":"https://in-toto.io/Statement/v1","fixture":true}\n' > "$TMP/prov.json"

# The accepted run is EMULATED arm64 and release-seal.sh now refuses to seal it
# while the policy requires native (#111) — asserted in that script's own
# self-test, in tests/release/test_native_arch_release_gate.sh and in the
# end-to-end test. THIS file's subject is the seal's other twelve rules, so it
# needs a bundle that would otherwise seal; otherwise R1/R5/R8/R12 all start
# passing for the native-architecture reason instead of their own.
ck "a published-artifact bundle is generated from the real accepted run" \
   "gen --evidence '$ACCEPTED_NATIVE' --out '$TMP/pub' --evidence-class published-artifact \
      --release v2026.08.25 --candidate rc1 --sbom-dir '$TMP/sboms' \
      --provenance '$TMP/prov.json' --today '$DAY' >/dev/null"
ck "a staged-candidate bundle is generated from the same run" \
   "gen --evidence '$ACCEPTED_NATIVE' --out '$TMP/cand' --evidence-class staged-candidate \
      --sbom-dir '$TMP/sboms' --provenance '$TMP/prov.json' --today '$DAY' >/dev/null"

# --- the happy path ----------------------------------------------------------
ck "the release identity on the matching tag seals the bundle" \
   "seal --bundle '$TMP/pub' --version v2026.08.25 --candidate rc1 --identity '$REL_ID' \
      --test-key '$TMP/test.key' --out '$TMP/seal.json' --today '$DAY' >/dev/null 2>&1"
ck "the seal binds the bundle's content checksum" \
   "[ \"\$(python3 -c 'import json;print(json.load(open(\"$TMP/seal.json\"))[\"bundle\"][\"content_checksum\"])')\" \
      = \"\$(python3 -c 'import json;print(json.load(open(\"$TMP/pub/manifest.json\"))[\"checksums\"][\"content_checksum\"])')\" ]"
ck "the seal binds every promoted digest, derived from MATRIX_COUNT" \
   "[ \"\$(python3 -c 'import json;print(len(json.load(open(\"$TMP/seal.json\"))[\"promoted_digests\"]))')\" \
      = \"\$(( MATRIX_COUNT * 2 ))\" ]"
ck "the seal binds the source revision the run recorded" \
   "[ \"\$(python3 -c 'import json;print(json.load(open(\"$TMP/seal.json\"))[\"source_revision\"])')\" \
      = \"\$(python3 -c 'import json;print(json.load(open(\"$ACCEPTED\"))[\"source_revision\"])')\" ]"
ck "the seal binds the policy digests that decided the verdict" \
   "python3 -c 'import json,sys
s=json.load(open(\"$TMP/seal.json\"));m=json.load(open(\"$TMP/pub/manifest.json\"))
sys.exit(0 if s[\"policy_digests\"]==m[\"policy_digests\"] and s[\"policy_digests\"] else 1)'"
ck "the verifier accepts it" \
   "vfy --seal '$TMP/seal.json' --bundle '$TMP/pub' --pubkey '$TMP/seal.json.pub.pem' \
      --version v2026.08.25 --today '$DAY' >/dev/null"

# =============================================================================
# THE ACCEPTANCE CRITERION: an RC or candidate cannot satisfy the release role.
# =============================================================================
ck "P1 an RC-publisher identity cannot seal" \
   "! seal --bundle '$TMP/pub' --version v2026.08.25 --identity '$RC_ID' \
      --test-key '$TMP/test.key' --out '$TMP/p1.json' --today '$DAY' >/dev/null 2>&1"
ck "P2 a scheduled-rebuild identity cannot seal" \
   "! seal --bundle '$TMP/pub' --version v2026.08.25 --identity '$SR_ID' \
      --test-key '$TMP/test.key' --out '$TMP/p2.json' --today '$DAY' >/dev/null 2>&1"
ck "P3 candidate EVIDENCE cannot be sealed as a release" \
   "! seal --bundle '$TMP/cand' --version v2026.08.25 --identity '$REL_ID' \
      --test-key '$TMP/test.key' --out '$TMP/p3.json' --today '$DAY' >/dev/null 2>&1"

# The strongest form: a seal that IS validly signed by the same key, but carries
# an RC subject. Refusing only unsigned forgeries would be refusing the easy case.
python3 - "$TMP/seal.json" "$TMP/rc.json" "$RC_ID" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["identity"]["subject"] = sys.argv[3]
d.pop("signature", None)
json.dump(d, open(sys.argv[2], "w"), indent=2)
PY
python3 - "$TMP/rc.json" "$TMP/rc.canon" <<'PY'
import json, sys
open(sys.argv[2], "w").write(json.dumps(json.load(open(sys.argv[1])), sort_keys=True,
                                        separators=(",", ":")))
PY
openssl dgst -sha256 -sign "$TMP/test.key" -out "$TMP/rc.sig" "$TMP/rc.canon" 2>/dev/null
python3 - "$TMP/rc.json" "$TMP/rc.canon" "$TMP/rc.sig" "$TMP/seal.json.pub.pem" "$TMP/rc-signed.json" <<'PY'
import base64, hashlib, json, sys
d = json.load(open(sys.argv[1]))
canon = open(sys.argv[2], "rb").read()
d["signature"] = {"algorithm": "ecdsa-with-SHA256 over canonical JSON (fixture key)",
                  "signed_payload_sha256": hashlib.sha256(canon).hexdigest(),
                  "public_key_sha256": hashlib.sha256(open(sys.argv[4], "rb").read()).hexdigest(),
                  "value": base64.b64encode(open(sys.argv[3], "rb").read()).decode()}
json.dump(d, open(sys.argv[5], "w"), indent=2)
PY
ck "P4 a VALIDLY SIGNED seal carrying an RC subject is still REFUSED" \
   "! vfy --seal '$TMP/rc-signed.json' --bundle '$TMP/pub' --pubkey '$TMP/seal.json.pub.pem' --today '$DAY' >/dev/null 2>&1"
ck "P4 ...because the ROLE is what the policy pins, not the signature" \
   "vfy --seal '$TMP/rc-signed.json' --bundle '$TMP/pub' --pubkey '$TMP/seal.json.pub.pem' --today '$DAY' 2>&1 \
      | grep -q \"accepts the 'release' role ONLY\""
ck "P5 a TEST seal cannot satisfy a production release gate" \
   "! vfy --seal '$TMP/seal.json' --bundle '$TMP/pub' --pubkey '$TMP/seal.json.pub.pem' \
      --reject-test-seal --today '$DAY' >/dev/null 2>&1"

# --- the remaining refusals, asserted from outside ---------------------------
# R9, against the REAL emulated record rather than the native fixture. The
# refusal is now the POLICY's: it fires with no claim flag in the command at all,
# which is the state change #111 was blocked on.
ck "R9 the real emulated accepted run cannot be sealed at all while the policy requires native" \
   "gen --evidence '$ACCEPTED' --out '$TMP/pub-emul' --evidence-class published-artifact \
      --release v2026.08.25 --candidate rc1 --sbom-dir '$TMP/sboms' \
      --provenance '$TMP/prov.json' --authorization '$AUTHREC_EMUL' --today '$DAY' >/dev/null 2>&1 \
    && ! seal --bundle '$TMP/pub-emul' --version v2026.08.25 --identity '$REL_ID' \
      --test-key '$TMP/test.key' --out '$TMP/r9p.json' --today '$DAY' >/dev/null 2>&1"
ck "R9 ...and the refusal belongs to the policy, not to the caller" \
   "seal --bundle '$TMP/pub-emul' --version v2026.08.25 --identity '$REL_ID' \
      --test-key '$TMP/test.key' --out '$TMP/r9p.json' --today '$DAY' 2>&1 \
      | grep -q 'does NOT depend on --claim-native-arm64'"
ck "R9 QEMU evidence cannot be presented as native arm64" \
   "! seal --bundle '$TMP/pub-emul' --version v2026.08.25 --identity '$REL_ID' --claim-native-arm64 \
      --test-key '$TMP/test.key' --out '$TMP/r9.json' --today '$DAY' >/dev/null 2>&1"
ck "R9 ...and the seal that IS produced records the policy requirement it satisfied" \
   "[ \"\$(python3 -c 'import json;print(json.load(open(\"$TMP/seal.json\"))[\"arm64_execution\"])')\" = native ] \
    && [ \"\$(python3 -c 'import json;print(json.load(open(\"$TMP/seal.json\"))[\"native_arm64_required_by_policy\"])')\" = True ]"
ck "R11 public exposure requires a separate authorization" \
   "! seal --bundle '$TMP/pub' --version v2026.08.25 --identity '$REL_ID' --public \
      --test-key '$TMP/test.key' --out '$TMP/r11.json' --today '$DAY' >/dev/null 2>&1"
ck "R11 ...and the run's own authorization still governs" \
   "python3 -c 'import json,sys
sys.exit(0 if json.load(open(\"$TMP/pub/manifest.json\"))[\"authorization\"][\"public_exposure_authorized\"] is False else 1)'"
ck "R5 sealing after the earliest acceptance lapsed is REFUSED" \
   "! seal --bundle '$TMP/pub' --version v2026.08.25 --identity '$REL_ID' \
      --test-key '$TMP/test.key' --out '$TMP/r5.json' --today 2099-01-01 >/dev/null 2>&1"
ck "R7 a bundle with no SBOM cannot be sealed" \
   "gen --evidence '$ACCEPTED' --out '$TMP/nosbom' --evidence-class published-artifact \
      --release v2026.08.25 --candidate rc1 --provenance '$TMP/prov.json' --today '$DAY' >/dev/null \
    && ! seal --bundle '$TMP/nosbom' --version v2026.08.25 --identity '$REL_ID' \
      --test-key '$TMP/test.key' --out '$TMP/r7.json' --today '$DAY' >/dev/null 2>&1"
ck "R6 a bundle mutated after generation cannot be sealed" \
   "cp -r '$TMP/pub' '$TMP/mut' && printf x >> '$TMP/mut/content/vex/openvex.json' \
    && ! seal --bundle '$TMP/mut' --version v2026.08.25 --identity '$REL_ID' \
      --test-key '$TMP/test.key' --out '$TMP/r6.json' --today '$DAY' >/dev/null 2>&1"

# --- verifier-side substitution ---------------------------------------------
python3 - "$TMP/seal.json" "$TMP/swap.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["promoted_digests"][0]["manifest_digest"] = "sha256:" + "c" * 64
json.dump(d, open(sys.argv[2], "w"), indent=2)
PY
ck "a substituted promoted digest is REFUSED" \
   "! vfy --seal '$TMP/swap.json' --bundle '$TMP/pub' --pubkey '$TMP/seal.json.pub.pem' --today '$DAY' >/dev/null 2>&1"
ck "a bundle mutated after sealing is REFUSED" \
   "! vfy --seal '$TMP/seal.json' --bundle '$TMP/mut' --pubkey '$TMP/seal.json.pub.pem' --today '$DAY' >/dev/null 2>&1"
ck "correction semantics: a superseded seal is REFUSED, never edited in place" \
   "! vfy --seal '$TMP/seal.json' --bundle '$TMP/pub' --pubkey '$TMP/seal.json.pub.pem' \
      --superseded-by v2026.09.01 --today '$DAY' >/dev/null 2>&1"

# --- SABOTAGE ON THE PRE-CHANGE STATE ----------------------------------------
# Before this work there was no verifier consuming the release role. The
# pre-change state is "no seal"; assert that its absence refuses rather than
# passing by default, in both directions.
ck "SABOTAGE: verifying a seal that does not exist REFUSES" \
   "! vfy --seal '$TMP/absent.json' --bundle '$TMP/pub' --pubkey '$TMP/seal.json.pub.pem' --today '$DAY' >/dev/null 2>&1"
printf '{"schema_version":1}\n' > "$TMP/hollow.json"
ck "SABOTAGE: an unsigned JSON object is not a seal" \
   "! vfy --seal '$TMP/hollow.json' --bundle '$TMP/pub' --pubkey '$TMP/seal.json.pub.pem' --today '$DAY' >/dev/null 2>&1"

# --- NON-VACUITY -------------------------------------------------------------
ck "NON-VACUOUS: the untouched seal still verifies after every sabotage above" \
   "vfy --seal '$TMP/seal.json' --bundle '$TMP/pub' --pubkey '$TMP/seal.json.pub.pem' --today '$DAY' >/dev/null"
ck "NON-VACUOUS: the verifier rejects a seal signed by another key" \
   "openssl ecparam -name prime256v1 -genkey -noout -out '$TMP/other.key' 2>/dev/null \
    && openssl pkey -in '$TMP/other.key' -pubout -out '$TMP/other.pub' 2>/dev/null \
    && ! vfy --seal '$TMP/seal.json' --bundle '$TMP/pub' --pubkey '$TMP/other.pub' --today '$DAY' >/dev/null 2>&1"

echo "----"
[ "$fail" -eq 0 ] && echo "test_release_seal: PASS" || echo "test_release_seal: FAIL"
exit $fail
