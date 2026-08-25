#!/usr/bin/env bash
# =============================================================================
# scripts/release/verify-release-seal.sh — the verifier #130 says does not exist.
# -----------------------------------------------------------------------------
# policies/cosign-identities.yaml describes the `release` role as "RESERVED,
# currently consumed by no verifier". This is that consumer. It validates, from
# the seal and the bundle alone and with no network:
#
#   * the SIGNATURE over the exact canonical bytes the sealer signed
#   * the ROLE — the subject must resolve to `release` and to nothing else; an
#     rc-publisher or scheduled-rebuild subject is refused by name
#   * the TAG — the CalVer tag inside the identity, the tag being verified, and
#     the version the bundle names must be one tag
#   * the SOURCE REVISION — seal, bundle manifest and every child agree
#   * the PROMOTED DIGEST SET — exactly the bundle's children, no more, no fewer
#   * the CHILD ARCHITECTURES — every declared platform, and how it executed
#   * the ARTIFACT CHECKSUMS — the bundle re-verifies from its own index
#
# REVOCATION AND CORRECTION SEMANTICS. A seal is a statement about a moment; it
# is never edited. To correct one, seal again from a new CalVer tag over a
# regenerated bundle and record the superseding in the withdrawal ledger
# (docs/audits/withdrawals/). `--superseded-by <version>` marks a seal
# superseded at verification time, so a consumer holding a cached copy of the
# old statement learns it has been replaced rather than silently trusting it.
# There is deliberately no in-place "revoke" flag: a mutable seal is not a seal.
#
# TEST SEALS. scripts/release/release-seal.sh can only produce `test_only: true`
# seals. `--reject-test-seal` is what a production gate would use, and the
# self-test proves a test seal cannot pass it. That is the honest state of #130:
# the verifier exists and is exercised; no production ceremony is wired to it.
#
# Usage:
#   verify-release-seal.sh verify --seal <seal.json> --bundle <dir>
#        --pubkey <pem> [--version vYYYY.MM.DD] [--platforms "..."]
#        [--reject-test-seal] [--superseded-by vYYYY.MM.DD] [--today YYYY-MM-DD]
#   verify-release-seal.sh --self-test
# =============================================================================
set -euo pipefail
_VS_D="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VS_ROOT="${VS_ROOT:-$(cd "$_VS_D/../.." && pwd)}"
# shellcheck source=../lib/common.sh
. "$_VS_D/../lib/common.sh"

VS_IDENTITIES="$VS_ROOT/policies/cosign-identities.yaml"

vs_verify() {
  local seal="" bundle="" pubkey="" version="" platforms="" reject_test=0
  local superseded="" today=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --seal)       seal="${2:?}"; shift 2 ;;
      --bundle)     bundle="${2:?}"; shift 2 ;;
      --pubkey)     pubkey="${2:?}"; shift 2 ;;
      --version)    version="${2:?}"; shift 2 ;;
      --platforms)  platforms="${2:?}"; shift 2 ;;
      --reject-test-seal) reject_test=1; shift ;;
      --superseded-by) superseded="${2:?}"; shift 2 ;;
      --today)      today="${2:?}"; shift 2 ;;
      *) die "verify: unknown argument: $1" ;;
    esac
  done
  [ -n "$seal" ]   || die "verify: --seal is required"
  [ -n "$bundle" ] || die "verify: --bundle is required"
  [ -n "$pubkey" ] || die "verify: --pubkey is required — a seal nobody checked the signature of is a JSON file"
  [ -f "$seal" ]   || die "verify: seal not found: $seal"
  [ -d "$bundle" ] || die "verify: not a bundle directory: $bundle"
  [ -f "$pubkey" ] || die "verify: public key not found: $pubkey"
  [ -n "$version" ] && require_calver "$version"
  [ -n "$superseded" ] && require_calver "$superseded"
  today="${today:-$(date -u +%F)}"
  command -v openssl >/dev/null 2>&1 || die "openssl is required to check the signature"

  # The bundle must re-verify from its own index first. Checking a signature over
  # a bundle whose files no longer match their digests proves only that somebody
  # once signed something.
  bash "$_VS_D/generate-evidence-bundle.sh" verify "$bundle" >/dev/null \
    || die "the bundle does not verify against its own checksum index; the seal
  over it cannot mean anything"

  local tmp; tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" EXIT

  # --- the signature, over the exact canonical bytes -------------------------
  python3 - "$seal" "$tmp/canonical.json" "$tmp/sig.bin" <<'PY' || return 1
import base64, json, sys
d = json.load(open(sys.argv[1]))
sig = d.pop("signature", None)
if not sig or not sig.get("value"):
    print("REFUSE: the seal carries no signature", file=sys.stderr)
    sys.exit(1)
with open(sys.argv[2], "w") as fh:
    fh.write(json.dumps(d, sort_keys=True, separators=(",", ":")))
open(sys.argv[3], "wb").write(base64.b64decode(sig["value"]))
PY
  openssl dgst -sha256 -verify "$pubkey" -signature "$tmp/sig.bin" "$tmp/canonical.json" >/dev/null 2>&1 \
    || die "SIGNATURE INVALID for $seal against $pubkey — either the seal was
  altered after signing, or it was signed by a different key than the one
  presented. Both mean the release ceremony this claims to record did not
  produce these bytes"

  VS_IDENTITIES="$VS_IDENTITIES" VS_MATRIX_COUNT="$MATRIX_COUNT" \
  python3 - "$seal" "$bundle" "$pubkey" "$version" "$platforms" "$reject_test" \
              "$superseded" "$today" "$tmp/canonical.json" <<'PY' || return 1
import json, os, re, sys, hashlib, collections
import yaml

(seal_p, bundle, pubkey_p, version, platforms_arg, reject_test_s,
 superseded, today, canon_p) = sys.argv[1:10]
reject_test = reject_test_s == "1"
matrix_count = int(os.environ["VS_MATRIX_COUNT"])


def refuse(msg):
    print("REFUSE: " + msg, file=sys.stderr)
    sys.exit(1)


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


s = json.load(open(seal_p))
m = json.load(open(os.path.join(bundle, "manifest.json")))

if s.get("seal_type") != "release-seal":
    refuse("%s: seal_type is %r, expected 'release-seal'" % (seal_p, s.get("seal_type")))

# --- test seals -------------------------------------------------------------
if reject_test and s.get("test_only"):
    refuse("%s is a TEST seal (test_only=true). A production release gate does "
           "not accept it. scripts/release/release-seal.sh cannot produce "
           "anything else, so there is currently no seal in this repository that "
           "satisfies a production release policy — which is the honest state of "
           "#130 rather than a green check over a fixture" % seal_p)
if not reject_test and not s.get("test_only"):
    refuse("%s claims to be a PRODUCTION seal. No production sealing path exists "
           "in this repository yet; a seal that is not marked test_only was not "
           "produced by the reviewed tooling" % seal_p)

# --- the signature body -----------------------------------------------------
canon = open(canon_p, "rb").read()
if s["signature"].get("signed_payload_sha256") != hashlib.sha256(canon).hexdigest():
    refuse("the seal records a signed-payload digest that does not match the "
           "canonical bytes it carries")
if s["signature"].get("public_key_sha256") != hashlib.sha256(open(pubkey_p, "rb").read()).hexdigest():
    refuse("the seal was made with a different key than the one presented: it "
           "records public key %s, this key hashes to %s"
           % (s["signature"].get("public_key_sha256"),
              hashlib.sha256(open(pubkey_p, "rb").read()).hexdigest()))

# --- the ROLE ---------------------------------------------------------------
ids = yaml.safe_load(open(os.environ["VS_IDENTITIES"]))
roles = ids["roles"]
subject = (s.get("identity") or {}).get("subject") or ""
matched = sorted(r for r, spec in roles.items() if re.match(spec["identity_regexp"], subject))
if "release" not in matched:
    refuse("the seal's subject %r resolves to role(s) %s. The release-seal policy "
           "accepts the 'release' role ONLY: an RC or scheduled-rebuild signature "
           "is made from refs/heads/master before any release decision exists, so "
           "accepting it here would mean the ceremony asserted nothing"
           % (subject, ", ".join(matched) or "none"))
if len(matched) > 1:
    refuse("the seal's subject satisfies more than one role (%s)" % ", ".join(matched))
if s["identity"].get("role") != "release":
    refuse("the seal declares role %r but was verified against 'release'"
           % s["identity"].get("role"))
if s["identity"].get("issuer") != ids["issuer"]:
    refuse("the seal declares issuer %r; policy pins %r"
           % (s["identity"].get("issuer"), ids["issuer"]))

# --- the TAG ----------------------------------------------------------------
tag = subject.rsplit("@refs/tags/", 1)[-1]
declared = (s.get("release") or {}).get("version")
if tag != declared:
    refuse("the signing identity is anchored to tag %r, the seal names release %r"
           % (tag, declared))
if version and version != declared:
    refuse("verifying for %r, the seal is for %r" % (version, declared))
if (m.get("release") or {}).get("version") != declared:
    refuse("the seal names release %r, the bundle names %r"
           % (declared, (m.get("release") or {}).get("version")))

# --- the SOURCE REVISION -----------------------------------------------------
if s["source_revision"] != m["source_revision"]:
    refuse("the seal binds revision %s, the bundle was built from %s"
           % (s["source_revision"], m["source_revision"]))
odd = sorted(set(c["source_revision"] for c in m["children"]) - {m["source_revision"]})
if odd:
    refuse("child records carry revision(s) %s, outside the sealed revision %s"
           % (", ".join(odd), m["source_revision"]))

# --- the BUNDLE binding ------------------------------------------------------
b = s["bundle"]
if b["content_checksum"] != m["checksums"]["content_checksum"]:
    refuse("the seal binds content_checksum %s, the bundle now hashes to %s"
           % (b["content_checksum"], m["checksums"]["content_checksum"]))
for name, key in (("SHA256SUMS", "sums_sha256"), ("manifest.json", "manifest_sha256")):
    got = sha256_file(os.path.join(bundle, name))
    if b.get(key) != got:
        refuse("the seal binds %s = %s, the bundle's %s hashes to %s"
               % (name, b.get(key), name, got))
if b["bundle_id"] != m["bundle_id"]:
    refuse("the seal binds bundle_id %r, this bundle is %r" % (b["bundle_id"], m["bundle_id"]))
if b["evidence_class"] != "published-artifact":
    refuse("the sealed bundle carries evidence class %r; the release-seal policy "
           "accepts 'published-artifact' only — a candidate identity cannot "
           "satisfy the release role, and neither can candidate evidence"
           % b["evidence_class"])
if m["evidence_class"] != b["evidence_class"]:
    refuse("the seal records class %r, the bundle now declares %r"
           % (b["evidence_class"], m["evidence_class"]))

# --- the PROMOTED DIGEST SET -------------------------------------------------
sealed = {(d["child_key"], d["platform"], d["manifest_digest"]) for d in s["promoted_digests"]}
actual = {(c["child_key"], c["platform"], c["manifest_digest"]) for c in m["children"]}
if sealed != actual:
    extra = sorted(sealed - actual)
    missing = sorted(actual - sealed)
    refuse("the sealed digest set is not the bundle's: %d sealed digest(s) are "
           "not in the bundle (%s), %d bundle child(ren) are not sealed (%s). A "
           "seal covering a digest the evidence does not describe is exactly the "
           "substitution the seal exists to prevent"
           % (len(extra), ", ".join(k for k, _, _ in extra[:3]) or "-",
              len(missing), ", ".join(k for k, _, _ in missing[:3]) or "-"))

# --- the CHILD ARCHITECTURES --------------------------------------------------
want = sorted(set(platforms_arg.split())) if platforms_arg.strip() else sorted(s["platforms"])
got = sorted(set(c["platform"] for c in m["children"]))
if got != want:
    refuse("the seal covers platforms %s, the bundle covers %s"
           % (", ".join(want), ", ".join(got)))
per_plat = collections.Counter(c["platform"] for c in m["children"])
short = sorted(p for p in want if per_plat[p] != matrix_count)
if short:
    refuse("platform(s) %s carry %s child record(s), the matrix defines %d"
           % (", ".join(short), ", ".join(str(per_plat[p]) for p in short), matrix_count))
for d in s["promoted_digests"]:
    child = next((c for c in m["children"] if c["child_key"] == d["child_key"]), None)
    if child["execution_mode"] != d["execution_mode"]:
        refuse("the seal records %s as %s, the bundle records it as %s"
               % (d["child_key"], d["execution_mode"], child["execution_mode"]))
arm = [c for c in m["children"] if c["platform"] == "linux/arm64"]
emulated = [c for c in arm if c["execution_mode"] != "native"]
if s.get("native_arm64_claimed") and emulated:
    refuse("the seal claims native arm64 while %d of %d arm64 children ran under "
           "emulation" % (len(emulated), len(arm)))
if arm and s.get("arm64_execution") != ("native" if not emulated else "qemu"):
    refuse("the seal records arm64_execution=%r; the bundle's children are %s"
           % (s.get("arm64_execution"), "native" if not emulated else "emulated"))

# --- the DISPOSITIONS travel with it -----------------------------------------
if s.get("dispositions_sha256") != m["dispositions"]["sha256"]:
    refuse("the seal binds a disposition document hashing %s; the bundle carries %s"
           % (s.get("dispositions_sha256"), m["dispositions"]["sha256"]))
for path, dig in (s.get("policy_digests") or {}).items():
    if m["policy_digests"].get(path) != dig:
        refuse("policy %s hashed %s when sealed and %s in the bundle — the "
               "decision inputs changed underneath the seal"
               % (path, dig, m["policy_digests"].get(path)))

# --- correction / revocation --------------------------------------------------
if superseded:
    refuse("seal %s for %s is SUPERSEDED by %s. A seal is never edited: a "
           "correction is a new seal from a new CalVer tag over a regenerated "
           "bundle, recorded in docs/audits/withdrawals/. Consumers holding the "
           "old statement must replace it, not merge it"
           % (os.path.basename(seal_p), declared, superseded))

print("ok - %s: release-role seal verified" % seal_p)
print("   release=%s  tag=%s  revision=%s" % (declared, tag, s["source_revision"]))
print("   %d promoted digest(s) over %s; arm64=%s%s"
      % (len(sealed), ", ".join(want), s.get("arm64_execution"),
         "  [TEST SEAL — NOT A RELEASE]" if s.get("test_only") else ""))
PY
}

# =============================================================================
_vs_self_test() {
  local tmp ok=0 bad=0
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" EXIT
  # Refusals need errexit off; die() exits, so every case runs in a subshell; the
  # diagnostic cases pipe a refusing command into grep, which reports the
  # refusal's status under pipefail.
  set +e
  set +o pipefail
  t() { if eval "$2"; then ok=$((ok+1)); echo "ok   - $1"; else bad=$((bad+1)); echo "FAIL - $1"; fi; }
  vfy() { ( vs_verify "$@" ); }

  local EV="$VS_ROOT/docs/audits/acceptance-multiarch-2026-08-20/acceptance-evidence.json"
  [ -f "$EV" ] || { echo "SKIP - accepted evidence absent"; return 0; }
  python3 -c 'import yaml' 2>/dev/null || { echo "SKIP - PyYAML absent"; return 0; }
  command -v openssl >/dev/null 2>&1 || { echo "SKIP - openssl absent"; return 0; }
  local DAY=2026-08-25
  local REL_ID='https://github.com/zenchron-dynamics/zenchron-foundry/.github/workflows/release.yml@refs/tags/v2026.08.25'

  openssl ecparam -name prime256v1 -genkey -noout -out "$tmp/test.key" 2>/dev/null
  openssl ecparam -name prime256v1 -genkey -noout -out "$tmp/other.key" 2>/dev/null
  openssl pkey -in "$tmp/other.key" -pubout -out "$tmp/other.pub.pem" 2>/dev/null
  mkdir -p "$tmp/sboms"
  python3 - "$EV" "$tmp/sboms" <<'PY'
import json, os, sys
ev = json.load(open(sys.argv[1]))
for c in ev["children"]:
    fam, _, ver = c["image_label"].partition("/")
    slug = "%s-%s-linux-%s" % (fam, ver, c["platform"].rsplit("/", 1)[-1])
    json.dump({"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT",
               "name": c["child_key"],
               "documentDescribes": [c["manifest_digest"]]},
              open(os.path.join(sys.argv[2], slug + ".spdx.json"), "w"), indent=2)
PY
  printf '{"_type":"https://in-toto.io/Statement/v1","fixture":true}\n' > "$tmp/prov.json"
  # The canonical authorization the bundle requires, rebuilt offline from the
  # accepted evidence (see tests/lib/make_authorization_fixture.py).
  local VS_AUTHREC="$tmp/post-build-authorization.json"
  python3 "$VS_ROOT/tests/lib/make_authorization_fixture.py" "$EV" "$VS_AUTHREC" \
    || { echo "SKIP - authorization fixture unavailable"; return 0; }

  ( bash "$_VS_D/generate-evidence-bundle.sh" generate --evidence "$EV" --out "$tmp/pub" \
      --evidence-class published-artifact --release v2026.08.25 --candidate rc1 \
      --authorization "$VS_AUTHREC" \
      --sbom-dir "$tmp/sboms" --provenance "$tmp/prov.json" --today "$DAY" ) >/dev/null 2>&1
  ( bash "$_VS_D/release-seal.sh" seal --bundle "$tmp/pub" --version v2026.08.25 \
      --candidate rc1 --identity "$REL_ID" --test-key "$tmp/test.key" \
      --out "$tmp/seal.json" --today "$DAY" ) >/dev/null 2>&1
  [ -f "$tmp/seal.json" ] || { echo "SKIP - seal fixture could not be produced"; return 0; }

  # --- H the happy path ------------------------------------------------------
  t "H1 a well-formed test seal verifies against its bundle and key" \
    "vfy --seal '$tmp/seal.json' --bundle '$tmp/pub' --pubkey '$tmp/seal.json.pub.pem' \
        --version v2026.08.25 --today '$DAY' >/dev/null"
  t "H2 the verifier names the role it accepted" \
    "vfy --seal '$tmp/seal.json' --bundle '$tmp/pub' --pubkey '$tmp/seal.json.pub.pem' \
        --today '$DAY' | grep -q 'release-role seal verified'"
  t "H3 the verdict says out loud that this is a test seal" \
    "vfy --seal '$tmp/seal.json' --bundle '$tmp/pub' --pubkey '$tmp/seal.json.pub.pem' \
        --today '$DAY' | grep -q 'TEST SEAL'"

  # --- the whole point of #130 ----------------------------------------------
  t "P1 a TEST seal cannot satisfy a production release gate" \
    "! vfy --seal '$tmp/seal.json' --bundle '$tmp/pub' --pubkey '$tmp/seal.json.pub.pem' \
        --reject-test-seal --today '$DAY' >/dev/null 2>&1"
  t "P1 ...stating the honest residual rather than passing a fixture" \
    "vfy --seal '$tmp/seal.json' --bundle '$tmp/pub' --pubkey '$tmp/seal.json.pub.pem' \
        --reject-test-seal --today '$DAY' 2>&1 | grep -q 'no seal in this repository'"

  # --- S1 a forged role ------------------------------------------------------
  python3 - "$tmp/seal.json" "$tmp/s1.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["identity"]["subject"] = ("https://github.com/zenchron-dynamics/zenchron-foundry/"
                            ".github/workflows/publish-rc.yml@refs/heads/master")
json.dump(d, open(sys.argv[2], "w"), indent=2)
PY
  t "S1 an RC subject swapped into the seal is REFUSED (signature first)" \
    "! vfy --seal '$tmp/s1.json' --bundle '$tmp/pub' --pubkey '$tmp/seal.json.pub.pem' --today '$DAY' >/dev/null 2>&1"

  # ...and re-signing it with the same fixture key does not help: the role rule
  # is independent of who signed.
  python3 - "$tmp/s1.json" "$tmp/s1c.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); d.pop("signature", None)
with open(sys.argv[2], "w") as fh:
    fh.write(json.dumps(d, sort_keys=True, separators=(",", ":")))
PY
  openssl dgst -sha256 -sign "$tmp/test.key" -out "$tmp/s1.sig" "$tmp/s1c.json" 2>/dev/null
  python3 - "$tmp/s1.json" "$tmp/s1c.json" "$tmp/s1.sig" "$tmp/seal.json.pub.pem" "$tmp/s1signed.json" <<'PY'
import base64, hashlib, json, sys
d = json.load(open(sys.argv[1]))
canon = open(sys.argv[2], "rb").read()
d["signature"] = {"algorithm": "ecdsa-with-SHA256 over canonical JSON (fixture key)",
                  "signed_payload_sha256": hashlib.sha256(canon).hexdigest(),
                  "public_key_sha256": hashlib.sha256(open(sys.argv[4], "rb").read()).hexdigest(),
                  "value": base64.b64encode(open(sys.argv[3], "rb").read()).decode()}
json.dump(d, open(sys.argv[5], "w"), indent=2)
PY
  t "S1b a VALIDLY SIGNED seal carrying an RC subject is still REFUSED" \
    "! vfy --seal '$tmp/s1signed.json' --bundle '$tmp/pub' --pubkey '$tmp/seal.json.pub.pem' --today '$DAY' >/dev/null 2>&1"
  t "S1b ...because the role, not the signature, is what the policy pins" \
    "vfy --seal '$tmp/s1signed.json' --bundle '$tmp/pub' --pubkey '$tmp/seal.json.pub.pem' --today '$DAY' 2>&1 | grep -q \"accepts the 'release' role ONLY\""

  # --- S2 a seal presented with the wrong key --------------------------------
  t "S2 a seal checked against a different key is REFUSED" \
    "! vfy --seal '$tmp/seal.json' --bundle '$tmp/pub' --pubkey '$tmp/other.pub.pem' --today '$DAY' >/dev/null 2>&1"

  # --- S3 a seal over a different bundle -------------------------------------
  ( bash "$_VS_D/generate-evidence-bundle.sh" generate --evidence "$EV" --out "$tmp/other" \
      --evidence-class published-artifact --release v2026.08.25 --candidate rc1 \
      --authorization "$VS_AUTHREC" \
      --sbom-dir "$tmp/sboms" --today "$DAY" ) >/dev/null 2>&1
  t "S3 a seal presented over a DIFFERENT bundle is REFUSED" \
    "! vfy --seal '$tmp/seal.json' --bundle '$tmp/other' --pubkey '$tmp/seal.json.pub.pem' --today '$DAY' >/dev/null 2>&1"

  # --- S4 a candidate bundle -------------------------------------------------
  ( bash "$_VS_D/generate-evidence-bundle.sh" generate --evidence "$EV" --out "$tmp/cand" \
      --evidence-class staged-candidate --sbom-dir "$tmp/sboms" \
      --authorization "$VS_AUTHREC" \
      --provenance "$tmp/prov.json" --today "$DAY" ) >/dev/null 2>&1
  t "S4 candidate EVIDENCE cannot satisfy the release seal either" \
    "! vfy --seal '$tmp/seal.json' --bundle '$tmp/cand' --pubkey '$tmp/seal.json.pub.pem' --today '$DAY' >/dev/null 2>&1"

  # --- S5 a substituted digest ----------------------------------------------
  python3 - "$tmp/seal.json" "$tmp/s5.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["promoted_digests"][0]["manifest_digest"] = "sha256:" + "a" * 64
json.dump(d, open(sys.argv[2], "w"), indent=2)
PY
  t "S5 a substituted promoted digest is REFUSED" \
    "! vfy --seal '$tmp/s5.json' --bundle '$tmp/pub' --pubkey '$tmp/seal.json.pub.pem' --today '$DAY' >/dev/null 2>&1"

  # --- S6 a mutated bundle after sealing -------------------------------------
  cp -r "$tmp/pub" "$tmp/mut"; printf 'x' >> "$tmp/mut/content/vex/openvex.json"
  t "S6 a bundle mutated after sealing is REFUSED" \
    "! vfy --seal '$tmp/seal.json' --bundle '$tmp/mut' --pubkey '$tmp/seal.json.pub.pem' --today '$DAY' >/dev/null 2>&1"

  # --- S7 the wrong version --------------------------------------------------
  t "S7 verifying for a different CalVer tag is REFUSED" \
    "! vfy --seal '$tmp/seal.json' --bundle '$tmp/pub' --pubkey '$tmp/seal.json.pub.pem' \
        --version v2026.09.01 --today '$DAY' >/dev/null 2>&1"

  # --- S8 supersession -------------------------------------------------------
  t "S8 a superseded seal is REFUSED with correction semantics" \
    "! vfy --seal '$tmp/seal.json' --bundle '$tmp/pub' --pubkey '$tmp/seal.json.pub.pem' \
        --superseded-by v2026.09.01 --today '$DAY' >/dev/null 2>&1"
  t "S8 ...pointing at the withdrawal ledger rather than an in-place revoke" \
    "vfy --seal '$tmp/seal.json' --bundle '$tmp/pub' --pubkey '$tmp/seal.json.pub.pem' \
        --superseded-by v2026.09.01 --today '$DAY' 2>&1 | grep -q 'withdrawals'"

  # --- NON-VACUITY -----------------------------------------------------------
  t "NON-VACUOUS: the untouched seal still verifies after every sabotage above" \
    "vfy --seal '$tmp/seal.json' --bundle '$tmp/pub' --pubkey '$tmp/seal.json.pub.pem' --today '$DAY' >/dev/null"

  echo "self-test: $ok ok, $bad failed"
  [ "$bad" -eq 0 ]
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-}" in
    verify) shift; vs_verify "$@" ;;
    --self-test) _vs_self_test && echo "verify-release-seal.sh: SELF-TEST OK" ;;
    *) cat >&2 <<'EOF'
usage:
  verify-release-seal.sh verify --seal <seal.json> --bundle <dir> --pubkey <pem>
       [--version vYYYY.MM.DD] [--platforms "linux/amd64 linux/arm64"]
       [--reject-test-seal] [--superseded-by vYYYY.MM.DD] [--today YYYY-MM-DD]
  verify-release-seal.sh --self-test
EOF
       exit 2 ;;
  esac
fi
