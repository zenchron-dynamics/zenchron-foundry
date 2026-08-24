#!/usr/bin/env bash
# =============================================================================
# scripts/assert-publish-platforms-reconciled.sh <platforms-csv> [ledger]
# -----------------------------------------------------------------------------
# Refuses to publish any platform whose vulnerability findings have never been
# reconciled.
#
# Why this exists: reconcile-vulnerabilities.sh runs per architecture and takes
# a mandatory --arch. Every acceptance record therefore records the exact
# architectures it was evidenced against, in `verified_architectures`. Nothing
# previously connected that to publication, so a multi-arch push could ship
# linux/arm64 while every record in the ledger had only ever been evidenced on
# linux/amd64 — the arm64 layers would carry CRITICAL/HIGH findings that no
# human had classified and no gate had seen.
#
# The rule enforced here is deliberately conservative: a platform is publishable
# only if EVERY active acceptance record declares it. A record that omits the
# platform is a record whose reasoning was never checked against that
# architecture's package set, and it is not knowable without scanning that
# architecture whether that record would have been needed there. Unverified is
# therefore treated as unreconciled, never as "probably the same".
#
# WHAT THIS PROVES, AND WHAT IT DOES NOT.
#
# This is TWO checks, and a platform must pass both.
#
#   1. EVIDENCE. Per-platform reconciliation evidence must exist for every one
#      of the ten shipping images, bound to the image family/version, the child
#      manifest digest, the architecture, the source revision, the Trivy
#      database snapshot and the reconciliation result. Every claim the evidence
#      makes that CAN be compared against what the publish knows IS compared:
#      the revision, the repository, the database snapshot and each child
#      digest. All four expectations are mandatory — omitting one is refused,
#      never skipped. The workflow run the evidence names is fetched and must
#      exist, have succeeded, have run a workflow trusted to produce evidence,
#      belong to this repository, and cover the recorded revision.
#
#   2. LEDGER COVERAGE. Every active acceptance record must additionally cover
#      the platform. Evidence alone does not authorise a publish, and neither
#      does an empty ledger: "nothing accepted" and "this architecture was
#      reconciled" are different claims.
#
# What it does NOT do is generate that evidence, or observe the scan itself. It
# verifies a document produced elsewhere. The per-architecture Trivy gate in the
# scanning workflow remains what proves a given scan passed.
#
# CURRENT STATE: publication is intentionally closed. The publish-ghcr preflight
# runs BEFORE the build, so the child digests and the Trivy database metadata do
# not exist and cannot be supplied — and because those expectations are
# mandatory, this gate refuses every publication from there. Reopening
# publication requires final authorisation to move AFTER the builds (capture the
# real child digests and DB metadata, verify the evidence, only then expose the
# manifest) and to consume the immutable RC manifest during stable promotion.
# That restructure is #139; the arm64 evidence run belongs to it.
#
# Env: LEDGER (default policies/vulnerability-exceptions.yaml)
# Exit: 0 every requested platform is reconciled; 1 otherwise.
# =============================================================================
set -euo pipefail
_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
. "$_d/lib/common.sh"

LEDGER="${LEDGER:-$_d/../policies/vulnerability-exceptions.yaml}"
# Per-platform reconciliation evidence. A platform is publishable only if this
# directory holds a complete, digest-bound record for every shipping image.
PLATFORM_EVIDENCE_DIR="${PLATFORM_EVIDENCE_DIR:-$_d/../docs/security/platform-reconciliation}"

# assert_platforms_reconciled <platforms-csv> <ledger>
assert_platforms_reconciled() {
  local csv="$1" ledger="$2"
  [ -n "$csv" ] || die "no platforms given: refusing to publish an unspecified platform set"
  [ -f "$ledger" ] || die "ledger not found: $ledger"
  command -v python3 >/dev/null || die "python3 required"

  PLATFORMS_CSV="$csv" LEDGER_PATH="$ledger" REPO_ROOT="$_d/.." \
  EVIDENCE_DIR="$PLATFORM_EVIDENCE_DIR" \
  CANONICAL_IMAGES="$(matrix_image_labels | paste -sd, -)" \
  python3 - <<'PY'
import json, os, re, subprocess, sys, yaml

# STRICT: this gate reads verified_architectures, which is exactly the field a
# duplicated key would subvert — the second list wins, so a record could gain
# linux/arm64 while the reviewed text shows amd64 only.
sys.path.insert(0, os.path.join(os.environ["REPO_ROOT"], "scripts", "lib"))
import strict_yaml

csv = os.environ["PLATFORMS_CSV"]
path = os.environ["LEDGER_PATH"]
evidence_dir = os.environ["EVIDENCE_DIR"]

plats = [p.strip() for p in csv.split(",")]
if any(p == "" for p in plats):
    sys.exit("REFUSE: empty entry in platform list %r" % csv)
for p in plats:
    # os/arch shape. A bare "arm64" or a stray "--platform" must never be
    # silently treated as reconciled because it matches nothing.
    if p.count("/") != 1 or not all(part.strip() for part in p.split("/")):
        sys.exit("REFUSE: %r is not a valid os/arch platform" % p)
if len(set(plats)) != len(plats):
    sys.exit("REFUSE: duplicate platform in %r" % csv)

try:
    doc = strict_yaml.load(path) or {}
except strict_yaml.DuplicateKeyError as e:
    sys.exit("REFUSE: ledger has a %s" % e)
except yaml.YAMLError as e:
    sys.exit("REFUSE: ledger is not valid YAML: %s" % e)
if not isinstance(doc, dict):
    sys.exit("REFUSE: ledger root is not a mapping")

records = []
for section in ("exceptions", "not_affected"):
    got = doc.get(section)
    if got is None:
        continue
    if not isinstance(got, list):
        sys.exit("REFUSE: ledger section %r is not a list" % section)
    for i, r in enumerate(got):
        if not isinstance(r, dict):
            sys.exit("REFUSE: %s[%d] is not a mapping" % (section, i))
        records.append((section, i, r))

# An empty ledger means nothing has been ACCEPTED. It does NOT mean an
# architecture was scanned. Treating it as universal authorisation was the
# inverse of this gate's purpose: with a fully remediated ledger (#122), an
# unscanned linux/arm64 would have published freely — the exact state #139
# exists to close. "Nothing accepted" and "this architecture was reconciled" are
# different claims, and only the second one authorises a publish.
#
# Eligibility therefore comes from INDEPENDENT evidence, never from the ledger's
# emptiness. The ledger check below still runs on top of it: a platform must
# have evidence AND be covered by every acceptance record.
if not records:
    print("NOTE: the ledger holds no acceptance records. That is a valid "
          "fully-remediated state, and it authorises nothing on its own — "
          "each platform still needs its own reconciliation evidence.")

# Every canonical image label, passed in from scripts/lib/common.sh so this and
# the reconciler cannot disagree about what an image is called.
CANONICAL_IMAGES = [i for i in os.environ["CANONICAL_IMAGES"].split(",") if i]
if not CANONICAL_IMAGES:
    sys.exit("REFUSE: the canonical image matrix is empty; the check would be vacuous")

HEX40 = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

# The facts the PUBLISH supplies, against which the evidence's own claims are
# checked. Schema validation alone only proves a document is well formed; these
# are what make it evidence ABOUT this publish.
EXPECTED_REVISION = (os.environ.get("EXPECTED_REVISION") or "").strip()
EXPECTED_REPOSITORY = (os.environ.get("EXPECTED_REPOSITORY") or "").strip()
if not EXPECTED_REPOSITORY:
    sys.exit(
        "REFUSE: EXPECTED_REPOSITORY was not supplied; evidence must be tied to "
        "the publishing repository.\n"
        "  Left optional, this comparison disappears when the caller omits it — "
        "the same fail-open shape the digest and database bindings had.")
EXPECTED_TRIVY_DB = (os.environ.get("EXPECTED_TRIVY_DB") or "").strip()
if not EXPECTED_TRIVY_DB:
    sys.exit(
        "REFUSE: EXPECTED_TRIVY_DB was not supplied.\n"
        "  Evidence must name the SAME vulnerability database this publish\n"
        "  scanned with. Accepting any non-empty string means the field records\n"
        "  a value nobody checked. Tracked in #139.")

# {image-label: sha256:...} of the child manifests actually being published.
# MANDATORY. Treating an absent map as "skip the comparison" is the fail-open
# shape this whole gate exists to remove: the check silently disappears exactly
# when the caller forgets to wire it, which is when it is most needed.
_digests_raw = os.environ.get("EXPECTED_DIGESTS_JSON") or ""
if not _digests_raw.strip():
    sys.exit(
        "REFUSE: EXPECTED_DIGESTS_JSON was not supplied.\n"
        "  Evidence must be compared against the child manifest digests actually\n"
        "  being published. Without them this gate would confirm only that the\n"
        "  evidence PARSES, which is not a binding.\n"
        "  The publish-ghcr preflight cannot supply them: it runs before the\n"
        "  build, so the digests do not exist yet. Final authorisation has to\n"
        "  move after the builds — capture the child digests and the Trivy DB\n"
        "  metadata, then call this gate before the manifest is exposed.\n"
        "  Tracked in #139. Until then every publish is refused here, which is\n"
        "  the intended fail-closed state.")
try:
    EXPECTED_DIGESTS = json.loads(_digests_raw)
except Exception as exc:
    sys.exit("REFUSE: EXPECTED_DIGESTS_JSON is not valid JSON: %s" % exc)
if not isinstance(EXPECTED_DIGESTS, dict):
    sys.exit("REFUSE: EXPECTED_DIGESTS_JSON must be an object of "
             "{image-label: sha256:...}")
_missing_expect = [i for i in CANONICAL_IMAGES if i not in EXPECTED_DIGESTS]
if _missing_expect:
    sys.exit("REFUSE: EXPECTED_DIGESTS_JSON omits %d shipping image(s): %s"
             % (len(_missing_expect), ", ".join(_missing_expect)))


# Only these workflows may produce evidence. A run of some other workflow — or a
# workflow added on a branch — is not an evidence producer even if it succeeded.
TRUSTED_EVIDENCE_WORKFLOWS = {
    ".github/workflows/scan-images.yml",
    ".github/workflows/trusted-validation.yml",
}

# RUN_FIXTURE_DIR makes the run lookup injectable for offline tests. In a real
# publish the lookup goes to the API; an unreadable API is a REFUSAL, never an
# assumed-good run.
RUN_FIXTURE_DIR = os.environ.get("RUN_FIXTURE_DIR") or ""


def fetch_run(run_id, repo):
    """Return (run_json, why_not). None means the run could not be established."""
    if RUN_FIXTURE_DIR:
        path = os.path.join(RUN_FIXTURE_DIR, "%s.json" % run_id)
        if not os.path.exists(path):
            return None, "workflow run %s does not exist" % run_id
        try:
            with open(path) as fh:
                return json.load(fh), ""
        except Exception as exc:
            return None, "workflow run %s is unreadable: %s" % (run_id, exc)
    try:
        out = subprocess.run(
            ["gh", "api", "repos/%s/actions/runs/%s" % (repo, run_id)],
            capture_output=True, text=True, timeout=30)
    except Exception as exc:
        return None, "cannot query workflow run %s: %s" % (run_id, exc)
    if out.returncode != 0:
        return None, ("cannot read workflow run %s (%s) — an unreadable run is "
                      "not a passing one" % (run_id, out.stderr.strip()[:120]))
    try:
        return json.loads(out.stdout), ""
    except Exception as exc:
        return None, "workflow run %s returned unparseable JSON: %s" % (run_id, exc)


def platform_evidence_ok(plat, evidence_dir):
    """Is there complete, per-image reconciliation evidence for this platform?

    Returns (ok, why_not). Every failure path returns False: absent, unreadable,
    malformed and incomplete evidence are all "not proven", never "fine".
    """
    if not os.path.isdir(evidence_dir):
        return False, "no evidence directory at %s" % evidence_dir
    docs = []
    for name in sorted(os.listdir(evidence_dir)):
        if not name.endswith(".json"):
            continue
        path = os.path.join(evidence_dir, name)
        try:
            with open(path) as fh:
                doc = json.load(fh)
        except Exception as exc:
            return False, "%s is unreadable: %s" % (name, exc)
        if isinstance(doc, dict) and doc.get("platform") == plat:
            docs.append((name, doc))
    if not docs:
        return False, "no evidence file declares platform %s" % plat
    if len(docs) > 1:
        return False, ("%d evidence files declare %s (%s) — ambiguous"
                       % (len(docs), plat, ", ".join(n for n, _ in docs)))

    name, doc = docs[0]
    if doc.get("schema_version") != 1:
        return False, "%s: schema_version must be 1" % name

    rev = doc.get("source_revision")
    if not isinstance(rev, str) or not HEX40.match(rev):
        return False, "%s: source_revision must be a 40-hex commit" % name
    # COMPARED, not merely shaped. A well-formed SHA for an unrelated or older
    # commit is exactly the evidence this gate must refuse: it would let a
    # publish quote a reconciliation of code that is not being published.
    if EXPECTED_REVISION:
        if rev != EXPECTED_REVISION:
            return False, ("%s: source_revision %s is not the commit being "
                           "published (%s)" % (name, rev, EXPECTED_REVISION))
    else:
        return False, ("%s: no commit was supplied to compare source_revision "
                       "against. Set EXPECTED_REVISION; evidence that is not "
                       "tied to the published commit proves nothing." % name)

    snap = doc.get("trivy_db_snapshot")
    if not isinstance(snap, str) or not snap.strip():
        return False, ("%s: trivy_db_snapshot is required — without it the scan "
                       "cannot be tied to a known vulnerability database" % name)
    if snap != EXPECTED_TRIVY_DB:
        return False, ("%s: trivy_db_snapshot %r is not the database this "
                       "publish scanned with (%r)" % (name, snap, EXPECTED_TRIVY_DB))

    # Documented as required, and previously unvalidated.
    scanner = doc.get("scanner")
    if not isinstance(scanner, str) or "@sha256:" not in scanner:
        return False, ("%s: scanner must be a digest-pinned image reference — an "
                       "unpinned scanner cannot be reproduced" % name)
    gen = doc.get("generated_at")
    if not isinstance(gen, str) or not ISO_DATE.match(gen):
        return False, "%s: generated_at must be an ISO date (YYYY-MM-DD)" % name

    # PROVENANCE. A run id on its own is only an audit pointer — it does not
    # show the run exists, belongs here, ran the trusted workflow, succeeded, or
    # covered this revision. So the run is FETCHED and those properties checked.
    run_id = doc.get("workflow_run_id")
    if not isinstance(run_id, (str, int)) or not str(run_id).strip().isdigit():
        return False, ("%s: workflow_run_id is required — evidence must name the "
                       "run that produced it" % name)
    repo = doc.get("repository")
    if repo != EXPECTED_REPOSITORY:
        return False, ("%s: repository %r is not %r" % (name, repo, EXPECTED_REPOSITORY))
    if not isinstance(repo, str) or "/" not in repo:
        return False, "%s: repository must be <owner>/<name>" % name

    run, why = fetch_run(str(run_id).strip(), repo)
    if run is None:
        return False, "%s: %s" % (name, why)
    if run.get("conclusion") != "success":
        return False, ("%s: workflow run %s concluded %r, not success — evidence "
                       "from a run that did not pass certifies nothing"
                       % (name, run_id, run.get("conclusion")))
    if run.get("head_sha") != rev:
        return False, ("%s: workflow run %s ran on %s, not the recorded "
                       "source_revision %s" % (name, run_id, run.get("head_sha"), rev))
    run_repo = (run.get("repository") or {}).get("full_name")
    if run_repo != repo:
        return False, ("%s: workflow run %s belongs to %r, not %r"
                       % (name, run_id, run_repo, repo))
    path = run.get("path") or ""
    if path not in TRUSTED_EVIDENCE_WORKFLOWS:
        return False, ("%s: workflow run %s ran %r, which is not a workflow "
                       "trusted to produce evidence (%s)"
                       % (name, run_id, path, ", ".join(sorted(TRUSTED_EVIDENCE_WORKFLOWS))))

    images = doc.get("images")
    if not isinstance(images, list) or not images:
        return False, "%s: 'images' must be a non-empty list" % name

    seen = {}
    for i, rec in enumerate(images):
        if not isinstance(rec, dict):
            return False, "%s: images[%d] is not an object" % (name, i)
        label = rec.get("image")
        if label in seen:
            return False, "%s: image %r appears twice" % (name, label)
        seen[label] = rec
        if rec.get("architecture") != plat:
            return False, ("%s: %s records architecture %r, not %s"
                           % (name, label, rec.get("architecture"), plat))
        dig = rec.get("manifest_digest")
        if not isinstance(dig, str) or not DIGEST.match(dig):
            return False, ("%s: %s has no sha256 child manifest digest — the "
                           "evidence is not bound to a specific image"
                           % (name, label))
        # COMPARED against the digests actually being published, when they are
        # known. A well-formed digest for some other image passes a shape check
        # and proves nothing.
        want = EXPECTED_DIGESTS.get(label)
        if want is None:
            return False, ("%s: %s is not among the images being published"
                           % (name, label))
        if want != dig:
            return False, ("%s: %s evidence is for %s but the digest being "
                           "published is %s" % (name, label, dig, want))
        if rec.get("reconciliation") != "PASS":
            return False, ("%s: %s reconciliation is %r, not PASS"
                           % (name, label, rec.get("reconciliation")))

    missing = [i for i in CANONICAL_IMAGES if i not in seen]
    if missing:
        return False, ("%s covers %d of %d images; missing: %s"
                       % (name, len(seen), len(CANONICAL_IMAGES), ", ".join(missing)))
    extra = [i for i in seen if i not in CANONICAL_IMAGES]
    if extra:
        return False, "%s covers images outside the matrix: %s" % (name, ", ".join(extra))
    return True, ""


def rid(section, i, r):
    # Identify a record the way the ledger does. `package` is optional (a
    # record may govern a CVE across every package in an image), so it is
    # shown only when present rather than rendered as a misleading "?".
    bits = ["%s[%d]" % (section, i), str(r.get("cve") or r.get("advisory") or "?")]
    img = r.get("image") or r.get("affected_images")
    if img:
        bits.append("image=%s" % (",".join(img) if isinstance(img, list) else img))
    pkg = r.get("package")
    if pkg:
        bits.append("pkg=%s" % (",".join(pkg) if isinstance(pkg, list) else pkg))
    return " ".join(bits)

failed = False
for plat in plats:
    # --- independent evidence, first and unconditionally --------------------
    ok, why = platform_evidence_ok(plat, evidence_dir)
    if not ok:
        failed = True
        print("REFUSE: %s has no usable reconciliation evidence — %s" % (plat, why))
        print("  A platform is publishable only with evidence bound to the image")
        print("  family/version, the child manifest digest, the architecture, the")
        print("  source revision, the Trivy database snapshot, and the")
        print("  reconciliation result, for every one of the %d shipping images."
              % len(CANONICAL_IMAGES))
        print("  See #139 for the outstanding linux/arm64 evidence run.")
        continue

    missing = []
    for section, i, r in records:
        va = r.get("verified_architectures")
        if va is None:
            missing.append((rid(section, i, r), "no verified_architectures"))
            continue
        if not isinstance(va, list) or not va:
            missing.append((rid(section, i, r), "verified_architectures is not a non-empty list"))
            continue
        if not all(isinstance(a, str) for a in va):
            missing.append((rid(section, i, r), "verified_architectures holds a non-string"))
            continue
        if plat not in va:
            missing.append((rid(section, i, r), "verified on %s" % ", ".join(va)))
    if missing:
        failed = True
        print("REFUSE: %s is NOT reconciled — %d of %d acceptance record(s) do not "
              "cover it:" % (plat, len(missing), len(records)))
        for name, why in missing[:15]:
            print("    %-64s (%s)" % (name, why))
        if len(missing) > 15:
            print("    ... and %d more" % (len(missing) - 15))
        print("  Reconcile that architecture first:")
        print("    scripts/reconcile-vulnerabilities.sh --arch %s ..." % plat)
        print("  then record it in verified_architectures on each record it applies to.")
    else:
        print("PUBLISH-PLATFORMS OK: %s reconciled across all %d acceptance record(s)"
              % (plat, len(records)))

sys.exit(1 if failed else 0)
PY
}

# --------------------------------------------------------------------------
_apr_self_test() {
  local ok_n=0     # counted, never hardcoded: a stale total misreports coverage
  command -v python3 >/dev/null || { echo "SKIP - python3 absent"; return 0; }
  python3 -c 'import yaml' 2>/dev/null || { echo "SKIP - PyYAML absent"; return 0; }
  local fail=0 tmp; tmp="$(mktemp -d)"
  # shellcheck disable=SC2317  # invoked via the `t` helper below
  # expand NOW: the local is out of scope by EXIT time
  # shellcheck disable=SC2064
  trap "rm -rf '${tmp}'" EXIT

  cat >"$tmp/amd64-only.yaml" <<'Y'
schema_version: 1
exceptions:
  - cve: CVE-1
    image: nginx
    package: libfoo
    verified_architectures: [linux/amd64]
not_affected:
  - cve: CVE-2
    image: caddy
    package: libbar
    verified_architectures: [linux/amd64]
Y
  cat >"$tmp/both.yaml" <<'Y'
schema_version: 1
exceptions:
  - cve: CVE-1
    image: nginx
    package: libfoo
    verified_architectures: [linux/amd64, linux/arm64]
not_affected:
  - cve: CVE-2
    image: caddy
    package: libbar
    verified_architectures: [linux/arm64, linux/amd64]
Y
  cat >"$tmp/mixed.yaml" <<'Y'
schema_version: 1
exceptions:
  - cve: CVE-1
    image: nginx
    package: libfoo
    verified_architectures: [linux/amd64, linux/arm64]
  - cve: CVE-9
    image: nginx
    package: libbaz
    verified_architectures: [linux/amd64]
Y
  cat >"$tmp/missing-field.yaml" <<'Y'
schema_version: 1
exceptions:
  - cve: CVE-1
    image: nginx
    package: libfoo
Y
  cat >"$tmp/empty-list.yaml" <<'Y'
schema_version: 1
exceptions:
  - cve: CVE-1
    image: nginx
    package: libfoo
    verified_architectures: []
Y
  cat >"$tmp/non-string.yaml" <<'Y'
schema_version: 1
exceptions:
  - cve: CVE-1
    image: nginx
    package: libfoo
    verified_architectures: [linux/amd64, 42]
Y
  cat >"$tmp/zero.yaml" <<'Y'
schema_version: 1
exceptions: []
not_affected: []
Y
  cat >"$tmp/not-a-list.yaml" <<'Y'
schema_version: 1
exceptions:
  cve: CVE-1
Y
  printf 'exceptions: [\n' >"$tmp/broken.yaml"

  # The LEDGER cases below isolate ledger coverage, so they run against a
  # complete evidence set for both platforms. Platform eligibility itself is
  # exercised separately, further down, with the `e` helper.
  local tev="$tmp/ledger-cases-evidence"
  # Workflow-run fixtures. The gate FETCHES the run named by the evidence and
  # checks it exists, succeeded, ran a trusted workflow, belongs to this
  # repository, and covered the recorded revision.
  mkdir -p "$tmp/runs"
  _mkrun() { # _mkrun <id> <conclusion> <head_sha> <repo> <path>
    jq -n --arg c "$2" --arg h "$3" --arg r "$4" --arg p "$5" \
      '{conclusion:$c, head_sha:$h, repository:{full_name:$r}, path:$p}' > "$tmp/runs/$1.json"
  }
  _mkrun 30692919846 success 1111111111111111111111111111111111111111 \
         zenchron-dynamics/zenchron-foundry .github/workflows/trusted-validation.yml
  _mkrun 700000001 failure 1111111111111111111111111111111111111111 \
         zenchron-dynamics/zenchron-foundry .github/workflows/trusted-validation.yml
  _mkrun 700000002 success 3333333333333333333333333333333333333333 \
         zenchron-dynamics/zenchron-foundry .github/workflows/trusted-validation.yml
  _mkrun 700000003 success 1111111111111111111111111111111111111111 \
         attacker/zenchron-foundry .github/workflows/trusted-validation.yml
  _mkrun 700000004 success 1111111111111111111111111111111111111111 \
         zenchron-dynamics/zenchron-foundry .github/workflows/ci.yml

  _digest_map_t() {
    ( . "$_d/lib/common.sh"; matrix_image_labels ) | jq -R . \
      | jq -s --arg d "sha256:$(printf '%064d' 1)" 'map({key:., value:$d}) | from_entries' -c
  }

  # t <expect-rc> <name> <platforms> <ledger>
  t() {
    local want="$1" name="$2" plats="$3" led="$4" rc=0
    # Subshell: die() exits, and an exit here would kill the whole self-test
    # rather than register a single case.
    ( PLATFORM_EVIDENCE_DIR="$tev" \
      EXPECTED_DIGESTS_JSON="$(_digest_map_t)" \
      EXPECTED_TRIVY_DB="2026-08-01T00:00:00Z/abcdef" \
      RUN_FIXTURE_DIR="$tmp/runs" \
      assert_platforms_reconciled "$plats" "$led" ) >/dev/null 2>&1 || rc=$?
    if [ "$rc" -eq "$want" ]; then echo "  ok   $name"; ok_n=$((ok_n + 1)); else
      echo "  FAIL $name (rc=$rc want=$want)"; fail=$((fail + 1)); fi
  }

  mkdir -p "$tev"
  _labels0() { ( . "$_d/lib/common.sh"; matrix_image_labels ); }
  _mkev0() { # _mkev0 <file> <platform>
    local plat="$2"
    { echo '{'; echo '  "schema_version": 1,'; echo "  \"platform\": \"$plat\","
      echo '  "source_revision": "1111111111111111111111111111111111111111",'
      echo '  "trivy_db_snapshot": "2026-08-01T00:00:00Z/abcdef",'
      echo '  "scanner": "aquasec/trivy:0.71.0@sha256:016eae51fdcf989332a5404af7e8f625cd5d95d7c0907a221d080a996f556500",'
      echo '  "generated_at": "2026-08-01",'
      echo '  "workflow_run_id": "30692919846",'
      echo '  "repository": "zenchron-dynamics/zenchron-foundry",'
      echo '  "images": ['
      local first=1 lbl
      while read -r lbl; do
        [ "$first" = 1 ] || echo ","
        first=0
        printf '    {"image": "%s", "architecture": "%s", "manifest_digest": "sha256:%064d", "reconciliation": "PASS"}' \
          "$lbl" "$plat" 1
      done < <(_labels0)
      echo; echo '  ]'; echo '}'
    } > "$1"
  }
  export EXPECTED_REVISION=1111111111111111111111111111111111111111
  export EXPECTED_REPOSITORY=zenchron-dynamics/zenchron-foundry
  _mkev0 "$tev/amd64.json" linux/amd64
  _mkev0 "$tev/arm64.json" linux/arm64

  t 0 "amd64 passes on an amd64-only ledger"          "linux/amd64"              "$tmp/amd64-only.yaml"
  t 1 "arm64 REFUSED on an amd64-only ledger"         "linux/arm64"              "$tmp/amd64-only.yaml"
  t 1 "multi-arch REFUSED when arm64 unverified"      "linux/amd64,linux/arm64"  "$tmp/amd64-only.yaml"
  t 0 "multi-arch passes when both verified"          "linux/amd64,linux/arm64"  "$tmp/both.yaml"
  t 0 "order in verified_architectures is irrelevant" "linux/arm64"              "$tmp/both.yaml"
  t 1 "ONE unverified record blocks the platform"     "linux/arm64"              "$tmp/mixed.yaml"
  t 0 "that same ledger still publishes amd64"        "linux/amd64"              "$tmp/mixed.yaml"
  t 1 "a record with no verified_architectures blocks" "linux/amd64"             "$tmp/missing-field.yaml"
  t 1 "an empty verified_architectures blocks"        "linux/amd64"              "$tmp/empty-list.yaml"
  t 1 "a non-string architecture blocks"              "linux/arm64"              "$tmp/non-string.yaml"
  # INVERTED, and deliberately run with NO evidence present. A zero-exception
  # ledger used to authorise every platform, so a fully remediated ledger
  # published an UNSCANNED arm64 freely. Emptiness must now authorise nothing.
  z() { # z <name> <platforms>
    local rc=0
    ( PLATFORM_EVIDENCE_DIR="$tmp/no-evidence" \
      assert_platforms_reconciled "$2" "$tmp/zero.yaml" ) >/dev/null 2>&1 || rc=$?
    if [ "$rc" -ne 0 ]; then echo "  ok   $1"; ok_n=$((ok_n + 1)); else
      echo "  FAIL $1 (a zero ledger authorised an unscanned platform)"; fail=$((fail + 1)); fi
  }
  z "a zero-exception ledger authorises NOTHING" "linux/amd64,linux/arm64"
  z "...not even arm64 alone"                    "linux/arm64"
  z "...nor amd64 alone"                         "linux/amd64"
  t 1 "a malformed ledger REFUSES (never passes)"     "linux/amd64"              "$tmp/broken.yaml"
  t 1 "a non-list section REFUSES"                    "linux/amd64"              "$tmp/not-a-list.yaml"
  t 1 "an empty platform list REFUSES"                ""                         "$tmp/both.yaml"
  t 1 "a bare arch (no os/) REFUSES"                  "arm64"                    "$tmp/both.yaml"
  t 1 "a trailing comma REFUSES"                      "linux/amd64,"             "$tmp/both.yaml"
  t 1 "a duplicate platform REFUSES"                  "linux/amd64,linux/amd64"  "$tmp/both.yaml"
  t 1 "an over-deep platform REFUSES"                 "linux/arm64/v8"           "$tmp/both.yaml"
  t 1 "a missing ledger REFUSES"                      "linux/amd64"              "$tmp/nope.yaml"
  t 1 "the real ledger does not authorize arm64"      "linux/arm64"              "$_d/../policies/vulnerability-exceptions.yaml"
  t 0 "the real ledger covers amd64 (given evidence)" "linux/amd64"              "$_d/../policies/vulnerability-exceptions.yaml"

  # --- independent platform evidence ---------------------------------------
  # Eligibility comes from evidence bound to six things, never from the ledger.
  local ev="$tmp/ev"; mkdir -p "$ev"
  _labels() { ( . "$_d/lib/common.sh"; matrix_image_labels ); }
  _mkev() { # _mkev <file> <platform> <jq-mutator>
    local plat="$2"
    { echo '{'; echo '  "schema_version": 1,'; echo "  \"platform\": \"$plat\","
      echo '  "source_revision": "1111111111111111111111111111111111111111",'
      echo '  "trivy_db_snapshot": "2026-08-01T00:00:00Z/abcdef",'
      echo '  "scanner": "aquasec/trivy:0.71.0@sha256:016eae51fdcf989332a5404af7e8f625cd5d95d7c0907a221d080a996f556500",'
      echo '  "generated_at": "2026-08-01",'
      echo '  "workflow_run_id": "30692919846",'
      echo '  "repository": "zenchron-dynamics/zenchron-foundry",'
      echo '  "images": ['
      local first=1 lbl
      while read -r lbl; do
        [ "$first" = 1 ] || echo ","
        first=0
        printf '    {"image": "%s", "architecture": "%s", "manifest_digest": "sha256:%064d", "reconciliation": "PASS"}' \
          "$lbl" "$plat" 1
      done < <(_labels)
      echo; echo '  ]'; echo '}'
    } | jq "${3:-.}" > "$1"
  }
  # The facts a real publish supplies. Without them the gate refuses outright.
  export EXPECTED_REVISION=1111111111111111111111111111111111111111
  export EXPECTED_REPOSITORY=zenchron-dynamics/zenchron-foundry
  # e <expect-rc> <name> <platforms> <evidence-dir> [ledger]
  _digest_map() { # _digest_map <digest> -> {"label": "<digest>", ...}
    local d="$1"
    _labels | jq -R . | jq -s --arg d "$d" 'map({key:., value:$d}) | from_entries' -c
  }

  # e <expect-rc> <name> <platforms> <evidence-dir> [ledger] [scenario]
  # <scenario> varies the facts the PUBLISH supplies, which is what turns schema
  # validation into a real comparison.
  e() {
    local want="$1" name="$2" plats="$3" dir="$4" led="${5:-}" scen="${6:-}" rc=0
    [ -n "$led" ] || led="$tmp/zero.yaml"
    local rev="$EXPECTED_REVISION" repo="$EXPECTED_REPOSITORY" runs="$tmp/runs"
    local good_digest; good_digest="sha256:$(printf '%064d' 1)"
    # Both expectations are MANDATORY, so the default scenario supplies them.
    local dj; dj="$(_digest_map "$good_digest")"
    local db="2026-08-01T00:00:00Z/abcdef"
    case "$scen" in
      norev)       rev="" ;;
      norepo)      repo="" ;;
      wrongdigest) dj="$(_digest_map "sha256:$(printf '%064d' 2)")" ;;
      rightdigest) : ;;
      emptydigest) dj='{}' ;;
      nodigest)    dj="" ;;
      nodb)        db="" ;;
      otherdb)     db="2099-01-01T00:00:00Z/ffffff" ;;
    esac
    ( PLATFORM_EVIDENCE_DIR="$dir" EXPECTED_REVISION="$rev" \
      EXPECTED_REPOSITORY="$repo" \
      EXPECTED_DIGESTS_JSON="$dj" EXPECTED_TRIVY_DB="$db" \
      RUN_FIXTURE_DIR="$runs" \
      assert_platforms_reconciled "$plats" "$led" ) >/dev/null 2>&1 || rc=$?
    if [ "$rc" -eq "$want" ]; then echo "  ok   $name"; ok_n=$((ok_n + 1)); else
      echo "  FAIL $name (rc=$rc want=$want)"; fail=$((fail + 1)); fi
  }

  _mkev "$ev/amd64.json" linux/amd64
  e 0 "complete evidence publishes that platform"      "linux/amd64" "$ev"
  e 1 "...but not a platform with no evidence"         "linux/arm64" "$ev"
  e 1 "...and not the pair"                            "linux/amd64,linux/arm64" "$ev"

  _mkev "$ev/bad.json" linux/arm64 'del(.source_revision)'
  e 1 "evidence without source_revision is refused"    "linux/arm64" "$ev"
  rm -f "$ev/bad.json"
  _mkev "$ev/bad.json" linux/arm64 '.source_revision = "not-a-sha"'
  e 1 "a malformed source_revision is refused"         "linux/arm64" "$ev"
  rm -f "$ev/bad.json"
  _mkev "$ev/bad.json" linux/arm64 'del(.trivy_db_snapshot)'
  e 1 "evidence without a Trivy DB snapshot is refused" "linux/arm64" "$ev"
  rm -f "$ev/bad.json"
  _mkev "$ev/bad.json" linux/arm64 '.images[0] |= del(.manifest_digest)'
  e 1 "an image without a child manifest digest is refused" "linux/arm64" "$ev"
  rm -f "$ev/bad.json"
  _mkev "$ev/bad.json" linux/arm64 '.images[0].manifest_digest = "sha256:short"'
  e 1 "a malformed digest is refused"                  "linux/arm64" "$ev"
  rm -f "$ev/bad.json"
  _mkev "$ev/bad.json" linux/arm64 '.images[0].reconciliation = "FAIL"'
  e 1 "a FAILED reconciliation is refused"             "linux/arm64" "$ev"
  rm -f "$ev/bad.json"
  _mkev "$ev/bad.json" linux/arm64 '.images |= .[1:]'
  e 1 "a partial matrix is refused"                    "linux/arm64" "$ev"
  rm -f "$ev/bad.json"
  _mkev "$ev/bad.json" linux/arm64 '.images[0].architecture = "linux/amd64"'
  e 1 "an image recording another architecture is refused" "linux/arm64" "$ev"
  rm -f "$ev/bad.json"
  _mkev "$ev/bad.json" linux/arm64 '.images += [.images[0]]'
  e 1 "a duplicated image label is refused"            "linux/arm64" "$ev"
  rm -f "$ev/bad.json"
  _mkev "$ev/bad.json" linux/arm64 '.schema_version = 2'
  e 1 "an unknown schema_version is refused"           "linux/arm64" "$ev"
  rm -f "$ev/bad.json"
  _mkev "$ev/a.json" linux/arm64; _mkev "$ev/b.json" linux/arm64
  e 1 "two files claiming one platform are ambiguous"  "linux/arm64" "$ev"
  rm -f "$ev/a.json" "$ev/b.json"
  printf 'not json' > "$ev/broken.json"
  e 1 "unreadable evidence is refused"                 "linux/amd64" "$ev"
  rm -f "$ev/broken.json"
  e 1 "a missing evidence directory refuses"           "linux/amd64" "$tmp/nope"

  # --- WELL FORMED BUT WRONG -------------------------------------------------
  # Every field below is valid in shape. Schema validation alone accepts all of
  # them; only comparison against what is actually being published rejects them.
  # This is the difference between "the document parses" and "the document is
  # evidence about THIS publish".
  _mkev "$ev/wrong.json" linux/arm64 '.source_revision = "2222222222222222222222222222222222222222"'
  e 1 "a valid but WRONG source revision is refused"   "linux/arm64" "$ev"
  rm -f "$ev/wrong.json"

  _mkev "$ev/wrong.json" linux/arm64
  e 1 "evidence with NO commit to compare against is refused" "linux/arm64" "$ev" "" norev
  rm -f "$ev/wrong.json"

  _mkev "$ev/wrong.json" linux/arm64 '.repository = "attacker/zenchron-foundry"'
  e 1 "evidence from another repository is refused"    "linux/arm64" "$ev"
  rm -f "$ev/wrong.json"

  _mkev "$ev/wrong.json" linux/arm64 'del(.workflow_run_id)'
  e 1 "evidence naming no workflow run is refused"     "linux/arm64" "$ev"
  rm -f "$ev/wrong.json"
  _mkev "$ev/wrong.json" linux/arm64 '.workflow_run_id = "hand-authored"'
  e 1 "a non-numeric workflow run id is refused"       "linux/arm64" "$ev"
  rm -f "$ev/wrong.json"

  _mkev "$ev/wrong.json" linux/arm64 'del(.scanner)'
  e 1 "evidence with no scanner is refused"            "linux/arm64" "$ev"
  rm -f "$ev/wrong.json"
  _mkev "$ev/wrong.json" linux/arm64 '.scanner = "aquasec/trivy:0.71.0"'
  e 1 "an UNPINNED scanner is refused"                 "linux/arm64" "$ev"
  rm -f "$ev/wrong.json"

  _mkev "$ev/wrong.json" linux/arm64 'del(.generated_at)'
  e 1 "evidence with no generated_at is refused"       "linux/arm64" "$ev"
  rm -f "$ev/wrong.json"
  _mkev "$ev/wrong.json" linux/arm64 '.generated_at = "01/08/2026"'
  e 1 "a non-ISO generated_at is refused"              "linux/arm64" "$ev"
  rm -f "$ev/wrong.json"

  # Digests: shape-valid, but not the images being published.
  _mkev "$ev/wrong.json" linux/arm64
  e 1 "a valid but WRONG child digest is refused"      "linux/arm64" "$ev" "" wrongdigest
  e 0 "...and the RIGHT digest is accepted"            "linux/arm64" "$ev" "" rightdigest
  e 1 "a digest map missing this image is refused"     "linux/arm64" "$ev" "" emptydigest
  rm -f "$ev/wrong.json"

  # A different Trivy DB than the one this publish scanned with.
  _mkev "$ev/wrong.json" linux/arm64
  e 1 "evidence from a DIFFERENT Trivy DB snapshot is refused" "linux/arm64" "$ev" "" otherdb
  rm -f "$ev/wrong.json"

  # --- the expectations are MANDATORY, not optional ---------------------------
  # A comparison that disappears when its environment variable is omitted is
  # fail-open: it vanishes precisely when the caller forgets to wire it.
  _mkev "$ev/mand.json" linux/arm64
  e 1 "complete evidence + NO expected digest map is refused" "linux/arm64" "$ev" "" nodigest
  e 1 "complete evidence + NO expected Trivy DB is refused"   "linux/arm64" "$ev" "" nodb
  e 1 "complete evidence + NO expected repository is refused" "linux/arm64" "$ev" "" norepo
  rm -f "$ev/mand.json"

  # --- the workflow run is PROVEN, not just pointed at -------------------------
  _mkev "$ev/run.json" linux/arm64 '.workflow_run_id = "999999999"'
  e 1 "a run id that does not exist is refused"        "linux/arm64" "$ev"
  rm -f "$ev/run.json"
  _mkev "$ev/run.json" linux/arm64 '.workflow_run_id = "700000001"'
  e 1 "a run with a NON-SUCCESS conclusion is refused" "linux/arm64" "$ev"
  rm -f "$ev/run.json"
  _mkev "$ev/run.json" linux/arm64 '.workflow_run_id = "700000002"'
  e 1 "a run whose head SHA is not the recorded revision is refused" "linux/arm64" "$ev"
  rm -f "$ev/run.json"
  _mkev "$ev/run.json" linux/arm64 '.workflow_run_id = "700000003"'
  e 1 "a run belonging to another repository is refused" "linux/arm64" "$ev"
  rm -f "$ev/run.json"
  _mkev "$ev/run.json" linux/arm64 '.workflow_run_id = "700000004"'
  e 1 "a run of a workflow not trusted to produce evidence is refused" "linux/arm64" "$ev"
  rm -f "$ev/run.json"

  # The reason this whole mechanism exists.
  _mkev "$ev/arm.json" linux/arm64
  e 0 "with real arm64 evidence, arm64 becomes publishable" "linux/arm64" "$ev"
  e 1 "...but the ledger still has the final say"      "linux/arm64" "$ev" "$_d/../policies/vulnerability-exceptions.yaml"
  rm -f "$ev/arm.json"

  # The shipped tree, as it actually stands.
  t 1 "the real repository publishes NO platform today" "linux/amd64,linux/arm64" \
    "$_d/../policies/vulnerability-exceptions.yaml"

  echo "self-test: $ok_n ok, $fail failed"
  [ "$fail" -eq 0 ]
}

case "${1-}" in
  --self-test) _apr_self_test && echo "assert-publish-platforms-reconciled.sh: SELF-TEST OK" ;;
  "") echo "usage: assert-publish-platforms-reconciled.sh <platforms-csv> | --self-test" >&2; exit 2 ;;
  *) assert_platforms_reconciled "$1" "${2:-$LEDGER}" ;;
esac
