#!/usr/bin/env bash
# =============================================================================
# scripts/release/release-seal.sh — the release-role seal over an evidence
# bundle. TEST-ONLY: this script cannot produce a production signature.
# -----------------------------------------------------------------------------
# THE DEFECT THIS EXISTS FOR (#130).
#
# policies/cosign-identities.yaml declares a `release` role and says, in the
# file itself, "RESERVED, currently consumed by no verifier". Images and the RC
# manifest are signed by rc-publisher on master, which is correct — the stable
# digests ARE the promoted RC digests. But that means there is no cryptographic
# statement made AT THE RELEASE CEREMONY, from the CalVer tag, binding the
# promoted digest set, the final evidence, the policy state and the release tag
# into one sealed object. Every signature in the chain was made before anyone
# decided to release.
#
# WHAT THIS SCRIPT IS AND IS NOT.
#
# It is the seal LOGIC and its refusals, exercised end-to-end with fixture keys.
# It is NOT a release path: there is no flag that makes it emit a production
# signature, it refuses to run in a context that could produce one, and every
# seal it writes carries `test_only: true` and `not_a_release: true`. Wiring a
# real ceremony to it requires a workflow change plus a real OIDC identity, both
# out of scope here and both reviewable on their own.
#
# THE REFUSALS ARE THE POINT. A seal that signs whatever it is handed moves the
# trust boundary without adding anything to it. This refuses:
#
#   R1  an incomplete child set          (derived from MATRIX_COUNT × platforms)
#   R2  mixed source revisions
#   R3  mixed vulnerability-database identities
#   R4  the wrong platform set
#   R5  expired governance (a lapsed acceptance, or elapsed retention)
#   R6  a checksum mismatch anywhere in the bundle
#   R7  a missing SBOM or missing provenance
#   R8  the wrong evidence class — a staged-candidate is not a release
#   R9  QEMU evidence presented as native arm64
#   R10 an image line that does not build / is not in the shipping matrix
#   R11 public exposure without a separate public-exposure authorization
#   R12 an RC or scheduled-rebuild identity presented for the release role
#
# Usage:
#   release-seal.sh seal --bundle <dir> --version vYYYY.MM.DD --candidate rcN
#        --identity <oidc-subject-url> --test-key <pem> --out <seal.json>
#        [--platforms "linux/amd64 linux/arm64"] [--public]
#        [--public-exposure-authorization FILE] [--claim-native-arm64]
#        [--today YYYY-MM-DD]
#   release-seal.sh --self-test
# =============================================================================
set -euo pipefail
_RS_D="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RS_ROOT="${RS_ROOT:-$(cd "$_RS_D/../.." && pwd)}"
# shellcheck source=../lib/common.sh
. "$_RS_D/../lib/common.sh"

RS_IDENTITIES="$RS_ROOT/policies/cosign-identities.yaml"
RS_LIFECYCLE="$RS_ROOT/policies/lifecycle.yaml"

# --- the test-only boundary ---------------------------------------------------
# Refuse to run anywhere a real signature could be produced or mistaken for one.
# This is not a courtesy check: the whole value of a seal is that it means one
# thing, and a test seal emitted from a release context means two.
_rs_assert_test_only_context() {
  local v
  for v in ACTIONS_ID_TOKEN_REQUEST_URL ACTIONS_ID_TOKEN_REQUEST_TOKEN \
           SIGSTORE_ID_TOKEN COSIGN_EXPERIMENTAL COSIGN_PRIVATE_KEY COSIGN_PASSWORD; do
    eval "test -n \"\${$v:-}\"" && die \
      "refusing to run: $v is set. This script produces TEST seals only, and a
  test seal must never be created in a context that can mint a real one. Unset
  it, or use a workflow that was reviewed as a signing path."
  done
  if [ "${GITHUB_REF_TYPE:-}" = "tag" ]; then
    die "refusing to run on a tag ref (${GITHUB_REF:-unknown}): a seal produced
  from a release tag would be indistinguishable from the real ceremony's output"
  fi
  return 0
}

rs_seal() {
  local bundle="" version="" candidate="" identity="" key="" out="" platforms=""
  local public=0 pea="" claim_native=0 today=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --bundle)    bundle="${2:?}"; shift 2 ;;
      --version)   version="${2:?}"; shift 2 ;;
      --candidate) candidate="${2:?}"; shift 2 ;;
      --identity)  identity="${2:?}"; shift 2 ;;
      --test-key)  key="${2:?}"; shift 2 ;;
      --out)       out="${2:?}"; shift 2 ;;
      --platforms) platforms="${2:?}"; shift 2 ;;
      --public)    public=1; shift ;;
      --public-exposure-authorization) pea="${2:?}"; shift 2 ;;
      --claim-native-arm64) claim_native=1; shift ;;
      --today)     today="${2:?}"; shift 2 ;;
      *) die "seal: unknown argument: $1" ;;
    esac
  done
  [ -n "$bundle" ]   || die "seal: --bundle is required"
  [ -n "$version" ]  || die "seal: --version is required"
  [ -n "$identity" ] || die "seal: --identity is required — a seal with no signer identity binds nothing"
  [ -n "$key" ]      || die "seal: --test-key is required (this script signs with fixture keys only)"
  [ -n "$out" ]      || die "seal: --out is required"
  [ -d "$bundle" ]   || die "seal: not a bundle directory: $bundle"
  [ -f "$key" ]      || die "seal: test key not found: $key"
  require_calver "$version"
  [ -n "$candidate" ] && require_rc "$candidate"
  _rs_assert_test_only_context
  command -v openssl >/dev/null 2>&1 || die "openssl is required to produce the fixture signature"
  today="${today:-$(date -u +%F)}"

  local tmp; tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" EXIT

  RS_IDENTITIES="$RS_IDENTITIES" RS_LIFECYCLE="$RS_LIFECYCLE" \
  RS_MATRIX_COUNT="$MATRIX_COUNT" RS_MATRIX_IMAGES="$MATRIX_IMAGES" \
  python3 - "$bundle" "$version" "$candidate" "$identity" "$platforms" \
              "$public" "$pea" "$claim_native" "$today" "$tmp/payload.json" <<'PY' || return 1
import json, os, re, sys, hashlib, collections
import yaml

(bundle, version, candidate, identity, platforms_arg, public_s, pea,
 claim_native_s, today, payload_out) = sys.argv[1:11]
public = public_s == "1"
claim_native = claim_native_s == "1"
matrix_count = int(os.environ["RS_MATRIX_COUNT"])
matrix_tokens = set(os.environ["RS_MATRIX_IMAGES"].split())


def refuse(code, msg):
    print("REFUSE: %s %s" % (code, msg), file=sys.stderr)
    sys.exit(1)


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


m = json.load(open(os.path.join(bundle, "manifest.json")))

# --- R8 the evidence class ---------------------------------------------------
# A release seal is a statement about what WAS shipped. A staged candidate is a
# statement about what MAY be. The classes are not interchangeable in either
# direction, and this is the exact "candidate signatures cannot satisfy the
# release-seal policy" acceptance criterion of #130 expressed on the evidence
# rather than only on the signature.
if m["evidence_class"] != "published-artifact":
    refuse("R8", "the bundle carries evidence class %r; a release seal requires "
                 "'published-artifact'. A staged candidate has not been published, "
                 "so a seal over it would attest to a release that never happened"
           % m["evidence_class"])

rel = m.get("release") or {}
if rel.get("version") != version:
    refuse("R8", "the bundle names release %r, the seal was asked for %r"
           % (rel.get("version"), version))
if candidate and rel.get("candidate") != candidate:
    refuse("R8", "the bundle names candidate %r, the seal was asked for %r"
           % (rel.get("candidate"), candidate))

# --- R12 the signing identity ------------------------------------------------
ids = yaml.safe_load(open(os.environ["RS_IDENTITIES"]))
roles = ids["roles"]
matched = sorted(r for r, spec in roles.items()
                 if re.match(spec["identity_regexp"], identity))
if not matched:
    refuse("R12", "identity %r matches no declared signing role in "
                  "policies/cosign-identities.yaml. An identity nobody declared is "
                  "an identity nobody scoped" % identity)
if "release" not in matched:
    refuse("R12", "identity %r resolves to role(s) %s, not 'release'. %s cannot "
                  "satisfy the release-seal policy: it signs artifacts produced "
                  "BEFORE anyone decided to release, from refs/heads/master, and "
                  "reusing it here would mean the release ceremony made no "
                  "statement of its own"
           % (identity, ", ".join(matched), matched[0]))
if len(matched) > 1:
    refuse("R12", "identity %r satisfies more than one role (%s); a signer whose "
                  "role is ambiguous can be replayed into the other one"
           % (identity, ", ".join(matched)))
# The release identity is anchored to the tag. The tag in the identity and the
# version being sealed must be the same tag, or the signature proves a ceremony
# that happened for something else.
tag = identity.rsplit("@refs/tags/", 1)[-1]
if tag != version:
    refuse("R12", "the release identity is anchored to tag %r but the seal is for "
                  "%r" % (tag, version))

# --- R2 one revision ---------------------------------------------------------
revs = sorted(set(c["source_revision"] for c in m["children"]))
if len(revs) != 1 or revs[0] != m["source_revision"]:
    refuse("R2", "the bundle mixes source revisions %s (manifest says %s). A "
                 "release is one revision; a sealed set spanning two is a release "
                 "nobody built" % (", ".join(revs), m["source_revision"]))

# --- R3 one database ---------------------------------------------------------
db_ids = set()
for c in m["children"]:
    p = os.path.join(bundle, c["evidence_file"])
    db_ids.add((json.load(open(p)).get("vulnerability_database") or {}).get("identity"))
db_ids.discard(None)
if len(db_ids) != 1:
    refuse("R3", "the children were scanned against %d different vulnerability "
                 "database identities (%s). Findings from two databases are answers "
                 "to two different questions and cannot be sealed as one result"
           % (len(db_ids), ", ".join(sorted(str(x)[:48] for x in db_ids))))
if db_ids and m["vulnerability_database"]["identity"] not in db_ids:
    refuse("R3", "the manifest records database %r, the children were scanned "
                 "against %s" % (m["vulnerability_database"]["identity"],
                                 ", ".join(sorted(str(x)[:48] for x in db_ids))))

# --- R4 the platform set -----------------------------------------------------
want = sorted(set(platforms_arg.split())) if platforms_arg.strip() else sorted(m["matrix"]["platforms"])
got = sorted(set(c["platform"] for c in m["children"]))
if got != want:
    refuse("R4", "the bundle covers platforms %s, the seal was asked for %s. A "
                 "seal that names a platform the evidence does not cover promises "
                 "an artifact nobody tested" % (", ".join(got), ", ".join(want)))

# --- R1 a complete child set -------------------------------------------------
expected = matrix_count * len(want)
if len(m["children"]) != expected:
    refuse("R1", "the bundle carries %d child record(s); the matrix defines %d "
                 "image(s) over %d platform(s) = %d. A partial set is how nine of "
                 "ten images get released with the tenth never checked"
           % (len(m["children"]), matrix_count, len(want), expected))
per_plat = collections.Counter(c["platform"] for c in m["children"])
short = sorted(p for p in want if per_plat[p] != matrix_count)
if short:
    refuse("R1", "platform(s) %s carry %s child record(s), not %d"
           % (", ".join(short), ", ".join(str(per_plat[p]) for p in short), matrix_count))

# --- R10 the shipping matrix and the lifecycle -------------------------------
lc = yaml.safe_load(open(os.environ["RS_LIFECYCLE"])) or {}
lines = {ln["id"]: ln for ln in lc.get("lines") or []}
for c in m["children"]:
    token = "%s:%s" % (c["image_family"], c["image_version"])
    if token not in matrix_tokens:
        refuse("R10", "child %s is not in the shipping matrix (MATRIX_IMAGES in "
                      "scripts/lib/common.sh). An image outside the matrix has no "
                      "build, smoke or scan coverage on the release path"
               % c["child_key"])
    if c["image_family"].startswith("php"):
        ln = lines.get("php-%s" % c["image_version"])
        if ln is None:
            refuse("R10", "child %s runs PHP %s, which policies/lifecycle.yaml does "
                          "not describe" % (c["child_key"], c["image_version"]))
        state = ln.get("foundry_release_state")
        if state:
            refuse("R10", "child %s runs PHP %s, whose lifecycle state is %r. "
                          "An experimental or non-building line must not appear in "
                          "a production bundle: %s"
                   % (c["child_key"], c["image_version"], state,
                      (ln.get("blocker") or {}).get("summary", "see policies/lifecycle.yaml")))

# --- R9 emulation is not native ----------------------------------------------
disc = m["execution_disclosure"]
arm = [c for c in m["children"] if c["platform"] == "linux/arm64"]
emulated = [c for c in arm if c["execution_mode"] != "native"]
if claim_native and emulated:
    refuse("R9", "--claim-native-arm64 was requested, but %d of %d linux/arm64 "
                 "child(ren) ran under %s emulation on an x86 host. QEMU establishes "
                 "that an image builds and that its inventory reconciles; it does "
                 "NOT establish that the binaries run correctly on arm64 hardware — "
                 "syscall coverage, atomics, page size and JIT all differ, which is "
                 "precisely where PHP's JIT and FrankenPHP's Go runtime break. "
                 "policies/native-arch-requirements.yaml states this boundary"
           % (len(emulated), len(arm), emulated[0]["execution_mode"]))
if arm and not disc.get("statement"):
    refuse("R9", "the bundle ships linux/arm64 children with no execution "
                 "disclosure; whether they ran natively or under emulation would be "
                 "left to the reader to assume")
arm64_execution = "native" if (arm and not emulated) else ("qemu" if emulated else "n/a")

# --- R7 SBOM and provenance --------------------------------------------------
sb = m["sbom"]
if not sb["present"] or sb["children_with_sbom"] != sb["children_total"]:
    refuse("R7", "the bundle has SBOMs for %d of %d children. A release whose bill "
                 "of materials is partial cannot answer 'is this package in your "
                 "image' for the children it omits"
           % (sb["children_with_sbom"], sb["children_total"]))
if not m["provenance"].get("attestation_sha256"):
    refuse("R7", "the bundle carries no build provenance attestation. Without it "
                 "the digests are bytes with no statement about where they came from")

# --- R5 governance that has not lapsed ---------------------------------------
import datetime
d_today = datetime.date.fromisoformat(today)
exp = m["dispositions"].get("earliest_exception_expiry")
if exp:
    d_exp = datetime.date.fromisoformat(str(exp)[:10])
    if d_exp <= d_today:
        refuse("R5", "the earliest risk acceptance backing this bundle expired on "
                     "%s and today is %s. Sealing it would publish a decision "
                     "nobody has re-made" % (d_exp.isoformat(), today))
retain_until = datetime.date.fromisoformat(m["retention"]["retain_until"])
if retain_until <= d_today:
    refuse("R5", "the bundle's retention window closed on %s; it is eligible for "
                 "deletion and must not be the basis of a new seal"
           % retain_until.isoformat())

# --- R11 public exposure -----------------------------------------------------
auth = m["authorization"]
pea_sha = None
if public:
    if not pea:
        refuse("R11", "--public was requested without "
                      "--public-exposure-authorization. Making artifacts publicly "
                      "reachable is a SEPARATE decision from accepting the build: "
                      "the acceptance record authorises 'immutable-rc-manifest-input' "
                      "and says nothing about who may pull the image")
    if not os.path.exists(pea):
        refuse("R11", "the public-exposure authorization file does not exist: %s" % pea)
    if not auth["public_exposure_authorized"]:
        refuse("R11", "the bundle's authorization record says "
                      "public_exposure_authorized=false. A separate file cannot "
                      "grant what the authorization run refused")
    pea_sha = sha256_file(pea)
elif auth["public_exposure_authorized"]:
    # Not an error: sealing a private release with a broader authorization is
    # narrowing, which always fails safe. Recorded so it is visible.
    pass

# --- the payload -------------------------------------------------------------
seal = collections.OrderedDict([
    ("schema_version", 1),
    ("seal_type", "release-seal"),
    ("test_only", True),
    ("not_a_release", True),
    ("test_only_note",
     "Produced by scripts/release/release-seal.sh with a fixture key. This is "
     "NOT a release signature and no verifier accepts it as one."),
    ("release", collections.OrderedDict([("version", version),
                                         ("candidate", candidate or rel.get("candidate"))])),
    ("source_revision", m["source_revision"]),
    ("sealed_at", m["generated_at"]),
    ("bundle", collections.OrderedDict([
        ("bundle_id", m["bundle_id"]),
        ("evidence_class", m["evidence_class"]),
        ("content_checksum", m["checksums"]["content_checksum"]),
        ("sums_sha256", sha256_file(os.path.join(bundle, "SHA256SUMS"))),
        ("manifest_sha256", sha256_file(os.path.join(bundle, "manifest.json"))),
    ])),
    ("identity", collections.OrderedDict([
        ("role", "release"),
        ("subject", identity),
        ("issuer", ids["issuer"]),
        ("identity_regexp", roles["release"]["identity_regexp"]),
        ("tag", tag),
    ])),
    ("platforms", want),
    ("arm64_execution", arm64_execution),
    ("native_arm64_claimed", bool(claim_native)),
    ("promoted_digests", [collections.OrderedDict([
        ("child_key", c["child_key"]),
        ("platform", c["platform"]),
        ("manifest_digest", c["manifest_digest"]),
        ("execution_mode", c["execution_mode"]),
    ]) for c in sorted(m["children"], key=lambda c: c["child_key"])]),
    ("vulnerability_database", m["vulnerability_database"]["identity"]),
    ("dispositions_sha256", m["dispositions"]["sha256"]),
    ("policy_digests", m["policy_digests"]),
    ("public_exposure", collections.OrderedDict([
        ("public", public),
        ("authorized_by_run", auth["public_exposure_authorized"]),
        ("authorization_file", pea or None),
        ("authorization_sha256", pea_sha),
    ])),
    ("retention", collections.OrderedDict([
        ("evidence_class", m["retention"]["evidence_class"]),
        ("retain_until", m["retention"]["retain_until"]),
    ])),
])
with open(payload_out, "w") as fh:
    json.dump(seal, fh, indent=2, sort_keys=False)
    fh.write("\n")
print("payload accepted: %d promoted digest(s), platforms %s, arm64=%s"
      % (len(seal["promoted_digests"]), ", ".join(want), arm64_execution))
PY

  # --- R6 ---------------------------------------------------------------------
  # The checksum verification runs AFTER the policy checks and BEFORE the
  # signature. Reading a manifest in order to REFUSE it is safe; signing one is
  # not. Doing it in this order means every refusal above carries its own
  # diagnostic instead of every defect surfacing as "checksum mismatch", while
  # nothing is signed until the bundle's own index holds.
  bash "$_RS_D/generate-evidence-bundle.sh" verify "$bundle" >/dev/null \
    || die "R6 bundle verification FAILED — refusing to sign a bundle whose own
  checksums do not hold. A signature over tampered evidence launders it"

  # --- the fixture signature --------------------------------------------------
  # Canonical bytes: the payload without its signature, serialised with sorted
  # keys and no incidental whitespace, so a verifier reconstructs exactly what
  # was signed instead of re-hashing whatever formatting survived transport.
  python3 - "$tmp/payload.json" "$tmp/canonical.json" <<'PY' || return 1
import json, sys
d = json.load(open(sys.argv[1]))
d.pop("signature", None)
with open(sys.argv[2], "w") as fh:
    fh.write(json.dumps(d, sort_keys=True, separators=(",", ":")))
PY
  openssl dgst -sha256 -sign "$key" -out "$tmp/sig.bin" "$tmp/canonical.json" \
    || die "fixture signing failed"
  openssl pkey -in "$key" -pubout -out "$tmp/pub.pem" 2>/dev/null \
    || die "cannot derive the public key from the fixture key"

  python3 - "$tmp/payload.json" "$tmp/canonical.json" "$tmp/sig.bin" "$tmp/pub.pem" "$out" <<'PY' || return 1
import base64, hashlib, json, sys, collections
payload_p, canon_p, sig_p, pub_p, out = sys.argv[1:6]
d = json.load(open(payload_p), object_pairs_hook=collections.OrderedDict)
canon = open(canon_p, "rb").read()
d["signature"] = collections.OrderedDict([
    ("algorithm", "ecdsa-with-SHA256 over canonical JSON (fixture key)"),
    ("signed_payload_sha256", hashlib.sha256(canon).hexdigest()),
    ("public_key_sha256", hashlib.sha256(open(pub_p, "rb").read()).hexdigest()),
    ("value", base64.b64encode(open(sig_p, "rb").read()).decode()),
])
with open(out, "w") as fh:
    json.dump(d, fh, indent=2, sort_keys=False)
    fh.write("\n")
PY
  cp "$tmp/pub.pem" "$out.pub.pem"
  warn "TEST-ONLY SEAL — this is not a release signature and no production verifier accepts it."
  log "seal written: $out (public key: $out.pub.pem)"
}

# =============================================================================
# Recompute a bundle's own index in place. Used ONLY by the self-test, to make a
# tampered bundle internally consistent again: without it every sabotage below
# would be caught by the checksum rule (R6) and the rule actually under test
# would never run — a suite that proves one control twelve times.
_rs_reseal() { # <bundle-dir>
  python3 - "$1" <<'PY'
import hashlib, json, os, sys
d = sys.argv[1]
files = []
for dp, _dirs, names in os.walk(os.path.join(d, "content")):
    for n in names:
        ap = os.path.join(dp, n)
        files.append((os.path.relpath(ap, d),
                      hashlib.sha256(open(ap, "rb").read()).hexdigest()))
files.sort()
mp = os.path.join(d, "manifest.json")
m = json.load(open(mp))
m["files"] = [{"path": p, "sha256": h} for p, h in files]
json.dump(m, open(mp, "w"), indent=2)
lines = ["%s  manifest.json" % hashlib.sha256(open(mp, "rb").read()).hexdigest()]
lines += ["%s  %s" % (h, p) for p, h in files]
open(os.path.join(d, "SHA256SUMS"), "w").write("\n".join(lines) + "\n")
open(os.path.join(d, "BUNDLE.sha256"), "w").write(
    "%s  SHA256SUMS\n"
    % hashlib.sha256(open(os.path.join(d, "SHA256SUMS"), "rb").read()).hexdigest())
PY
}

_rs_self_test() {
  local tmp ok=0 bad=0
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" EXIT
  # Refusal assertions need errexit off; the diagnostic assertions pipe a
  # refusing command into grep, which reports the refusal's status under
  # pipefail. die() exits, so every case runs in a subshell.
  set +e
  set +o pipefail
  t() { if eval "$2"; then ok=$((ok+1)); echo "ok   - $1"; else bad=$((bad+1)); echo "FAIL - $1"; fi; }
  seal() { ( rs_seal "$@" ); }
  bundle_gen() { ( bash "$_RS_D/generate-evidence-bundle.sh" generate "$@" ); }

  local EV="$RS_ROOT/docs/audits/acceptance-multiarch-2026-08-20/acceptance-evidence.json"
  [ -f "$EV" ] || { echo "SKIP - accepted evidence absent"; return 0; }
  python3 -c 'import yaml' 2>/dev/null || { echo "SKIP - PyYAML absent"; return 0; }
  command -v openssl >/dev/null 2>&1 || { echo "SKIP - openssl absent"; return 0; }
  local DAY=2026-08-25

  # --- fixtures -------------------------------------------------------------
  openssl ecparam -name prime256v1 -genkey -noout -out "$tmp/test.key" 2>/dev/null
  local REL_ID='https://github.com/zenchron-dynamics/zenchron-foundry/.github/workflows/release.yml@refs/tags/v2026.08.25'
  local RC_ID='https://github.com/zenchron-dynamics/zenchron-foundry/.github/workflows/publish-rc.yml@refs/heads/master'
  local SR_ID='https://github.com/zenchron-dynamics/zenchron-foundry/.github/workflows/scheduled-rebuild.yml@refs/heads/master'

  # A complete SBOM set and a provenance attestation — fixtures, generated here,
  # never taken from a real run.
  mkdir -p "$tmp/sboms"
  python3 - "$EV" "$tmp/sboms" <<'PY'
import json, os, sys
ev = json.load(open(sys.argv[1]))
for c in ev["children"]:
    fam, _, ver = c["image_label"].partition("/")
    slug = "%s-%s-linux-%s" % (fam, ver, c["platform"].rsplit("/", 1)[-1])
    json.dump({"spdxVersion": "SPDX-2.3", "name": c["child_key"],
               "documentDescribes": [c["manifest_digest"]], "packages": []},
              open(os.path.join(sys.argv[2], slug + ".spdx.json"), "w"), indent=2)
PY
  printf '{"_type":"https://in-toto.io/Statement/v1","fixture":true}\n' > "$tmp/prov.json"
  printf 'public exposure authorised for v2026.08.25 (FIXTURE)\n' > "$tmp/pea.txt"

  # A publishable bundle, and the candidate bundle it was promoted from.
  t "F1 a published-artifact bundle is generated (SBOMs + provenance)" \
    "bundle_gen --evidence '$EV' --out '$tmp/pub' --evidence-class published-artifact \
       --release v2026.08.25 --candidate rc1 --sbom-dir '$tmp/sboms' \
       --provenance '$tmp/prov.json' --today '$DAY' >/dev/null"
  t "F2 a staged-candidate bundle is generated from the same run" \
    "bundle_gen --evidence '$EV' --out '$tmp/cand' --evidence-class staged-candidate \
       --sbom-dir '$tmp/sboms' --provenance '$tmp/prov.json' --today '$DAY' >/dev/null"

  # --- H the happy path -----------------------------------------------------
  t "H1 the release identity on the matching tag seals the bundle" \
    "seal --bundle '$tmp/pub' --version v2026.08.25 --candidate rc1 \
       --identity '$REL_ID' --test-key '$tmp/test.key' --out '$tmp/seal.json' --today '$DAY' >/dev/null 2>&1"
  t "H2 the seal declares itself TEST-ONLY and not a release" \
    "python3 -c 'import json,sys;d=json.load(open(\"$tmp/seal.json\"));sys.exit(0 if d[\"test_only\"] and d[\"not_a_release\"] else 1)'"
  t "H3 the seal carries every promoted digest" \
    "[ \"\$(python3 -c 'import json;print(len(json.load(open(\"$tmp/seal.json\"))[\"promoted_digests\"]))')\" \
      = \"\$(( MATRIX_COUNT * 2 ))\" ]"
  t "H4 the seal records arm64 as emulated, because it was" \
    "[ \"\$(python3 -c 'import json;print(json.load(open(\"$tmp/seal.json\"))[\"arm64_execution\"])')\" = qemu ]"

  # --- R8 / R12: an RC or candidate cannot satisfy the release role ----------
  t "R8 a staged-candidate bundle CANNOT be sealed as a release" \
    "! seal --bundle '$tmp/cand' --version v2026.08.25 --identity '$REL_ID' \
       --test-key '$tmp/test.key' --out '$tmp/r8.json' --today '$DAY' >/dev/null 2>&1"
  t "R8 ...naming the class it required" \
    "seal --bundle '$tmp/cand' --version v2026.08.25 --identity '$REL_ID' \
       --test-key '$tmp/test.key' --out '$tmp/r8.json' --today '$DAY' 2>&1 | grep -q \"requires 'published-artifact'\""
  t "R12 the rc-publisher identity CANNOT satisfy the release role" \
    "! seal --bundle '$tmp/pub' --version v2026.08.25 --identity '$RC_ID' \
       --test-key '$tmp/test.key' --out '$tmp/r12.json' --today '$DAY' >/dev/null 2>&1"
  t "R12 ...naming the role it resolved to instead" \
    "seal --bundle '$tmp/pub' --version v2026.08.25 --identity '$RC_ID' \
       --test-key '$tmp/test.key' --out '$tmp/r12.json' --today '$DAY' 2>&1 | grep -q 'rc-publisher'"
  t "R12 the scheduled-rebuild identity CANNOT satisfy the release role" \
    "! seal --bundle '$tmp/pub' --version v2026.08.25 --identity '$SR_ID' \
       --test-key '$tmp/test.key' --out '$tmp/r12b.json' --today '$DAY' >/dev/null 2>&1"
  t "R12 an identity anchored to a DIFFERENT tag is REFUSED" \
    "! seal --bundle '$tmp/pub' --version v2026.08.25 \
       --identity 'https://github.com/zenchron-dynamics/zenchron-foundry/.github/workflows/release.yml@refs/tags/v2026.08.26' \
       --test-key '$tmp/test.key' --out '$tmp/r12c.json' --today '$DAY' >/dev/null 2>&1"

  # --- R1 an incomplete child set -------------------------------------------
  python3 - "$EV" "$tmp/ev-short.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); d["children"] = d["children"][:-1]
d["matrix"]["observed_children"] = len(d["children"])
json.dump(d, open(sys.argv[2], "w"), indent=2)
PY
  bundle_gen --evidence "$tmp/ev-short.json" --out "$tmp/short" \
    --evidence-class published-artifact --release v2026.08.25 --candidate rc1 \
    --sbom-dir "$tmp/sboms" --provenance "$tmp/prov.json" --today "$DAY" >/dev/null 2>&1
  t "R1 an incomplete child set is REFUSED" \
    "! seal --bundle '$tmp/short' --version v2026.08.25 --identity '$REL_ID' \
       --test-key '$tmp/test.key' --out '$tmp/r1.json' --today '$DAY' >/dev/null 2>&1"
  t "R1 ...counting against MATRIX_COUNT, not a literal" \
    "seal --bundle '$tmp/short' --version v2026.08.25 --identity '$REL_ID' \
       --test-key '$tmp/test.key' --out '$tmp/r1.json' --today '$DAY' 2>&1 | grep -q 'the matrix defines'"

  # --- R4 the wrong platform set --------------------------------------------
  t "R4 sealing for a platform the evidence does not cover is REFUSED" \
    "! seal --bundle '$tmp/pub' --version v2026.08.25 --identity '$REL_ID' \
       --platforms 'linux/amd64 linux/arm64 linux/s390x' \
       --test-key '$tmp/test.key' --out '$tmp/r4.json' --today '$DAY' >/dev/null 2>&1"

  # --- R9 QEMU presented as native ------------------------------------------
  t "R9 claiming native arm64 over QEMU evidence is REFUSED" \
    "! seal --bundle '$tmp/pub' --version v2026.08.25 --identity '$REL_ID' \
       --claim-native-arm64 --test-key '$tmp/test.key' --out '$tmp/r9.json' --today '$DAY' >/dev/null 2>&1"
  t "R9 ...explaining what emulation does not establish" \
    "seal --bundle '$tmp/pub' --version v2026.08.25 --identity '$REL_ID' \
       --claim-native-arm64 --test-key '$tmp/test.key' --out '$tmp/r9.json' --today '$DAY' 2>&1 | grep -q 'does NOT establish'"

  # --- R7 missing SBOM / provenance -----------------------------------------
  bundle_gen --evidence "$EV" --out "$tmp/nosbom" --evidence-class published-artifact \
    --release v2026.08.25 --candidate rc1 --provenance "$tmp/prov.json" --today "$DAY" >/dev/null 2>&1
  t "R7 a bundle with no SBOM is REFUSED" \
    "! seal --bundle '$tmp/nosbom' --version v2026.08.25 --identity '$REL_ID' \
       --test-key '$tmp/test.key' --out '$tmp/r7.json' --today '$DAY' >/dev/null 2>&1"
  bundle_gen --evidence "$EV" --out "$tmp/noprov" --evidence-class published-artifact \
    --release v2026.08.25 --candidate rc1 --sbom-dir "$tmp/sboms" --today "$DAY" >/dev/null 2>&1
  t "R7 a bundle with no provenance attestation is REFUSED" \
    "! seal --bundle '$tmp/noprov' --version v2026.08.25 --identity '$REL_ID' \
       --test-key '$tmp/test.key' --out '$tmp/r7b.json' --today '$DAY' >/dev/null 2>&1"

  # --- R5 expired governance -------------------------------------------------
  t "R5 sealing after the earliest acceptance lapsed is REFUSED" \
    "! seal --bundle '$tmp/pub' --version v2026.08.25 --identity '$REL_ID' \
       --test-key '$tmp/test.key' --out '$tmp/r5.json' --today 2099-01-01 >/dev/null 2>&1"

  # --- R6 a checksum mismatch ------------------------------------------------
  cp -r "$tmp/pub" "$tmp/tampered"; printf 'planted\n' >> "$tmp/tampered/content/vex/openvex.json"
  t "R6 a bundle whose checksums no longer hold is REFUSED" \
    "! seal --bundle '$tmp/tampered' --version v2026.08.25 --identity '$REL_ID' \
       --test-key '$tmp/test.key' --out '$tmp/r6.json' --today '$DAY' >/dev/null 2>&1"

  # --- R11 public exposure ---------------------------------------------------
  t "R11 --public without a separate authorization is REFUSED" \
    "! seal --bundle '$tmp/pub' --version v2026.08.25 --identity '$REL_ID' --public \
       --test-key '$tmp/test.key' --out '$tmp/r11.json' --today '$DAY' >/dev/null 2>&1"
  t "R11 ...and even WITH a file, the run's authorization still governs" \
    "! seal --bundle '$tmp/pub' --version v2026.08.25 --identity '$REL_ID' --public \
       --public-exposure-authorization '$tmp/pea.txt' \
       --test-key '$tmp/test.key' --out '$tmp/r11b.json' --today '$DAY' >/dev/null 2>&1"
  t "R11 ...naming the scope the acceptance actually granted" \
    "seal --bundle '$tmp/pub' --version v2026.08.25 --identity '$REL_ID' --public \
       --public-exposure-authorization '$tmp/pea.txt' \
       --test-key '$tmp/test.key' --out '$tmp/r11b.json' --today '$DAY' 2>&1 | grep -q 'public_exposure_authorized=false'"

  # --- R10 an image line that does not build --------------------------------
  # PHP 8.5 is absent from MATRIX_IMAGES and marked blocked-does-not-build in
  # policies/lifecycle.yaml. Both facts are READ from those files, so this case
  # cannot rot into a hardcoded version string.
  #
  # Defence in depth, and the first layer fires before the seal is even reached:
  # the exception ledger's cohort selector is `php-8.3-8.4`, so an 8.5 child's
  # findings are ungoverned and no disposition set can be produced for it.
  python3 - "$EV" "$tmp/ev-85.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
for c in d["children"]:
    if c["image_label"] == "php-fpm/8.4":
        c["image_label"] = "php-fpm/8.5"
        c["child_key"] = "php-fpm/8.5/" + c["platform"]
json.dump(d, open(sys.argv[2], "w"), indent=2)
PY
  t "R10a an 8.5 child cannot even reach a bundle — its findings are ungoverned" \
    "! bundle_gen --evidence '$tmp/ev-85.json' --out '$tmp/php85' \
       --evidence-class published-artifact --release v2026.08.25 --candidate rc1 \
       --sbom-dir '$tmp/sboms' --provenance '$tmp/prov.json' --today '$DAY' >/dev/null 2>&1"

  # ...and if a bundle were re-labelled AFTER the fact, with its index resealed
  # so the checksum rule cannot be what catches it, the seal still refuses.
  cp -r "$tmp/pub" "$tmp/php85m"
  python3 - "$tmp/php85m" <<'PY'
import json, os, sys
d = sys.argv[1]
mp = os.path.join(d, "manifest.json")
m = json.load(open(mp))
for c in m["children"]:
    if c["image_family"] == "php-fpm" and c["image_version"] == "8.4":
        c["image_version"] = "8.5"
        c["image_label"] = "php-fpm/8.5"
        c["child_key"] = "php-fpm/8.5/" + c["platform"]
json.dump(m, open(mp, "w"), indent=2)
PY
  _rs_reseal "$tmp/php85m"
  t "R10b a bundle re-labelled to an experimental line is REFUSED by the seal" \
    "! seal --bundle '$tmp/php85m' --version v2026.08.25 --identity '$REL_ID' \
       --test-key '$tmp/test.key' --out '$tmp/r10.json' --today '$DAY' >/dev/null 2>&1"
  t "R10b ...reading the block from the matrix and policies/lifecycle.yaml" \
    "seal --bundle '$tmp/php85m' --version v2026.08.25 --identity '$REL_ID' \
       --test-key '$tmp/test.key' --out '$tmp/r10.json' --today '$DAY' 2>&1 | grep -Eq 'shipping matrix|lifecycle state'"

  # --- R2 mixed source revisions --------------------------------------------
  cp -r "$tmp/pub" "$tmp/mixrev"
  python3 - "$tmp/mixrev" <<'PY'
import json, os, sys
mp = os.path.join(sys.argv[1], "manifest.json")
m = json.load(open(mp))
m["children"][0]["source_revision"] = "b" * 40
json.dump(m, open(mp, "w"), indent=2)
PY
  _rs_reseal "$tmp/mixrev"
  t "R2 a bundle whose children disagree on source revision is REFUSED" \
    "! seal --bundle '$tmp/mixrev' --version v2026.08.25 --identity '$REL_ID' \
       --test-key '$tmp/test.key' --out '$tmp/r2.json' --today '$DAY' >/dev/null 2>&1"
  t "R2 ...with its own diagnostic, not a generic checksum failure" \
    "seal --bundle '$tmp/mixrev' --version v2026.08.25 --identity '$REL_ID' \
       --test-key '$tmp/test.key' --out '$tmp/r2.json' --today '$DAY' 2>&1 | grep -q 'mixes source revisions'"

  # --- R3 mixed database identities -----------------------------------------
  cp -r "$tmp/pub" "$tmp/mixdb"
  python3 - "$tmp/mixdb" <<'PY'
import glob, json, os, sys
p = sorted(glob.glob(os.path.join(sys.argv[1], "content/children/*.json")))[0]
rec = json.load(open(p))
rec["vulnerability_database"]["identity"] = "v2+updated:1999-01-01T00:00:00Z"
json.dump(rec, open(p, "w"), indent=2)
PY
  # Reseal the index, so the refusal under test is R3 and not R6 arriving first.
  _rs_reseal "$tmp/mixdb"
  t "R3 children scanned against two database identities are REFUSED" \
    "! seal --bundle '$tmp/mixdb' --version v2026.08.25 --identity '$REL_ID' \
       --test-key '$tmp/test.key' --out '$tmp/r3.json' --today '$DAY' >/dev/null 2>&1"

  # --- the test-only boundary ------------------------------------------------
  t "B1 refuses to run where a real signature could be minted" \
    "! ( export SIGSTORE_ID_TOKEN=x; rs_seal --bundle '$tmp/pub' --version v2026.08.25 \
        --identity '$REL_ID' --test-key '$tmp/test.key' --out '$tmp/b1.json' --today '$DAY' ) >/dev/null 2>&1"
  t "B2 refuses to run on a tag ref" \
    "! ( export GITHUB_REF_TYPE=tag GITHUB_REF=refs/tags/v2026.08.25; rs_seal --bundle '$tmp/pub' \
        --version v2026.08.25 --identity '$REL_ID' --test-key '$tmp/test.key' --out '$tmp/b2.json' --today '$DAY' ) >/dev/null 2>&1"

  # --- NON-VACUITY -----------------------------------------------------------
  t "NON-VACUOUS: the untouched bundle still seals under the same conditions" \
    "rm -f '$tmp/seal2.json' && seal --bundle '$tmp/pub' --version v2026.08.25 --candidate rc1 \
       --identity '$REL_ID' --test-key '$tmp/test.key' --out '$tmp/seal2.json' --today '$DAY' >/dev/null 2>&1"
  t "NON-VACUOUS: sealing is deterministic for the same bundle" \
    "python3 -c 'import json,sys
a=json.load(open(\"$tmp/seal.json\"));b=json.load(open(\"$tmp/seal2.json\"))
a.pop(\"signature\");b.pop(\"signature\")
sys.exit(0 if a==b else 1)'"

  echo "self-test: $ok ok, $bad failed"
  [ "$bad" -eq 0 ]
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-}" in
    seal) shift; rs_seal "$@" ;;
    --self-test) _rs_self_test && echo "release-seal.sh: SELF-TEST OK" ;;
    *) cat >&2 <<'EOF'
usage:
  release-seal.sh seal --bundle <dir> --version vYYYY.MM.DD [--candidate rcN]
       --identity <oidc-subject-url> --test-key <pem> --out <seal.json>
       [--platforms "linux/amd64 linux/arm64"] [--public]
       [--public-exposure-authorization FILE] [--claim-native-arm64]
       [--today YYYY-MM-DD]
  release-seal.sh --self-test

This script is TEST-ONLY. It signs with a fixture key, marks every seal
test_only, and refuses to run in any context that could mint a real signature.
EOF
       exit 2 ;;
  esac
fi
