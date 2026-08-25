#!/usr/bin/env bash
# =============================================================================
# scripts/release/authorize-staged-candidates.sh
# -----------------------------------------------------------------------------
# The post-build authorization gate. Reads the per-child evidence produced by
# stage-and-authorize.yml and decides whether those EXACT staged platform child
# manifests may become inputs to an immutable release-candidate manifest.
#
# WHY THIS EXISTS AFTER THE BUILD. The previous gate ran in preflight, before
# anything was built, so it could not see the child digests or the vulnerability
# database the scan actually used. It therefore refused every publish outright —
# the honest interim state, but not a control. Authorization has to happen where
# the facts exist: after the children are pushed and evaluated, before anything
# is exposed.
#
# WHAT IT AUTHORIZES, EXACTLY. `authorization_scope` has one legal value,
# `immutable-rc-manifest-input`, and `public_exposure_authorized` is always
# false. A generic {"authorized": true} would invite a later consumer to read
# whatever authorization it needs into a record that never proved it. This
# record proves one thing: these digests, from this run, from this revision,
# judged against this database snapshot, are eligible as RC manifest inputs.
# Public exposure is decided elsewhere, by a protected path.
#
# EVERY EXPECTATION IS MANDATORY. The caller supplies the facts this run is
# claimed to be about, and the evidence is checked against them. Making any of
# them optional would be fail-open in the usual way: the binding disappears
# exactly when nobody wires it. Omitting one REFUSES.
#
#   EXPECTED_REPOSITORY        owner/repo
#   EXPECTED_REVISION          40-hex source revision
#   EXPECTED_RUN_ID            workflow run id
#   EXPECTED_RUN_ATTEMPT       workflow run attempt
#   EXPECTED_PLATFORMS         comma-separated, e.g. linux/amd64
#   EXPECTED_STAGING_PACKAGE   ghcr.io/<org>/<package>
#   EXPECTED_TRIVY_DB          canonical frozen database snapshot identity
#   WORKFLOW_REF               producing workflow reference
#   GENERATED_AT               RFC3339 UTC
#
# Usage:
#   authorize-staged-candidates.sh <child-evidence-dir> <output.json>
#   authorize-staged-candidates.sh --self-test
#
# A FAIL verdict is still WRITTEN before exiting non-zero. A refused
# authorization is exactly when the record matters, and a gate that fails
# without saying why forces the next person to guess.
# =============================================================================
set -euo pipefail
_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
. "$_d/../lib/common.sh"

# Architectures this repository has reconciliation evidence for. It authorizes
# only what has actually been evidenced: the exception ledger records the
# architectures each acceptance was judged against.
#
# linux/arm64 was added 2026-08-17 from MEASURED evidence, not assertion. #139
# Execution A2 (run 31941819983) built, staged, scanned and recorded all ten
# images on linux/arm64 from source 25669a3c under one frozen database, and
# every governed finding was compared against the accepted linux/amd64 baseline
# (run 31792482449) using the tool at master a027b7e6:
#
#   395 transferable — same CVE, package AND installed version on both
#     0 version differences
#     0 findings absent from arm64
#     0 excluded children, 0 missing images
#     6 rows present only in the newer database, subsequently proven present on
#       the accepted amd64 digest by rescanning it — database timing, not
#       architecture — and governed as their own two-architecture entries
#
# EXECUTION MODE. That evidence was produced under QEMU emulation on a trusted
# linux/x64 runner, because no arm64 runner exists in the trusted boundary. It
# is genuine image, package and reconciliation evidence. It is NOT native-arm64
# runtime evidence and does not satisfy #111.
#
# This permits arm64 to be JUDGED; it is not permission to publish arm64.
# public_exposure_authorized stays false, and every ledger entry still governs
# only the architectures it lists — an unevidenced finding on either
# architecture still refuses the whole matrix.
#
# The check is on the REQUESTED MATRIX, not per child. Staging an arm64 child
# and marking it unauthorized inside an otherwise passing record would produce a
# PASS that a careless consumer reads as covering everything present.
AUTHORIZED_PLATFORMS="${AUTHORIZED_PLATFORMS:-linux/amd64,linux/arm64}"

SCOPE="immutable-rc-manifest-input"

# The ONE workflow identity allowed to produce an authorization record. Copying
# whatever the caller happened to be dispatched as would let a branch copy of the
# workflow emit a record that reads as authoritative — and workflow_dispatch can
# select any ref. This is a guard against accidental branch dispatch; it is NOT
# proof, because a record cannot vouch for itself. A consumer must independently
# verify the run through the GitHub API.
CANONICAL_WORKFLOW_REF="${CANONICAL_WORKFLOW_REF:-zenchron-dynamics/zenchron-foundry/.github/workflows/stage-and-authorize.yml@refs/heads/master}"

# The checksum algorithm is SHARED, not reimplemented here. Two copies of it —
# one inline in the workflow, one here — were not the same function: the producer
# hashed `evidence/child`, this recomputed after collection into
# `authorization/child-evidence/<slug>-evidence`, and shasum prints the pathname
# beside each digest, so identical bytes under two prefixes hashed differently.
# Every child would have been refused for a meaningless mismatch.
# shellcheck source=evidence-checksum.sh
. "$_d/evidence-checksum.sh"

# --- THE NATIVE-ARCHITECTURE GATE (#111) -------------------------------------
# policies/native-arch-requirements.yaml carried `require_native_arm64: true`
# alongside a `known_gap` admitting the flag was not load-bearing: the gate was
# invoked by the native smoke workflow and by NO release-gating path, so a
# release built entirely on emulated arm64 evidence would have been authorized
# without ever consulting it. That is closed HERE, in the canonical post-build
# authorizer, because this is the one place the release path decides whether the
# staged children may become RC manifest inputs.
#
# The binding is on THIS run's own children: the digest map handed to the gate is
# built from the manifest digests being authorized, so native evidence about some
# other build, some other revision or some other platform cannot satisfy it.
#
# NATIVE_EVIDENCE_DIR is MANDATORY whenever the policy requires native arm64 and
# this run requests linux/arm64. Its absence is a refusal, not a skip — an
# optional gate is a gate that disappears exactly when nobody wires it.
NATIVE_GATE="${NATIVE_GATE:-$_d/assert-native-arch-evidence.sh}"
NATIVE_POLICY="${NATIVE_POLICY:-$_d/../../policies/native-arch-requirements.yaml}"
NATIVE_PLATFORM="${NATIVE_PLATFORM:-linux/arm64}"

# ---------------------------------------------------------------------------
# Evaluation. Collects EVERY refusal rather than exiting on the first, so one
# run tells the operator everything that is wrong.
# ---------------------------------------------------------------------------
authorize() { # authorize <evidence-dir> <out.json>
  local dir="${1:?usage: authorize-staged-candidates.sh <child-evidence-dir> <output.json>}"
  local out="${2:?usage: authorize-staged-candidates.sh <child-evidence-dir> <output.json>}"
  local refusals=() children='[]'

  command -v jq >/dev/null || die "jq required"

  # --- mandatory expectations ---------------------------------------------
  local v
  for v in EXPECTED_REPOSITORY EXPECTED_REVISION EXPECTED_RUN_ID \
           EXPECTED_RUN_ATTEMPT EXPECTED_PLATFORMS EXPECTED_STAGING_PACKAGE \
           EXPECTED_TRIVY_DB WORKFLOW_REF GENERATED_AT BUILD_CREATED \
           EVIDENCE_ROOT; do
    [ -n "${!v:-}" ] || die "$v is required (every expectation is mandatory)"
  done
  is_hex40 "$EXPECTED_REVISION" || die "EXPECTED_REVISION is not 40-hex"
  case "$EXPECTED_RUN_ID"      in ''|*[!0-9]*) die "EXPECTED_RUN_ID must be numeric" ;; esac
  case "$EXPECTED_RUN_ATTEMPT" in ''|*[!0-9]*) die "EXPECTED_RUN_ATTEMPT must be numeric" ;; esac

  [ -d "$dir" ] || die "evidence directory not found: $dir"
  [ -d "$EVIDENCE_ROOT" ] || die "EVIDENCE_ROOT not found: $EVIDENCE_ROOT"

  # Workflow identity: pinned, not merely recorded.
  [ "$WORKFLOW_REF" = "$CANONICAL_WORKFLOW_REF" ] \
    || refusals+=("workflow_ref '$WORKFLOW_REF' is not the canonical producer '$CANONICAL_WORKFLOW_REF'")

  # --- architecture policy, on the requested matrix ------------------------
  # Both sides are comma-separated, so BOTH are normalised to spaces before the
  # membership test. The first version padded AUTHORIZED_PLATFORMS with spaces
  # and searched for " $plat ", which worked only while the list held exactly one
  # platform: once it became "linux/amd64,linux/arm64" the match needed a space
  # where a comma sat, and EVERY platform was refused — including amd64. Caught
  # by this file's own self-test, which is why the happy path is asserted here
  # and not only the refusals.
  local plat authorized_spaced="${AUTHORIZED_PLATFORMS//,/ }"
  for plat in ${EXPECTED_PLATFORMS//,/ }; do
    case " $authorized_spaced " in
      *" $plat "*) : ;;
      *) refusals+=("unsupported architecture '$plat': no reconciliation evidence exists for it (#139); the whole matrix is refused, not just this platform") ;;
    esac
  done

  # --- expected matrix -----------------------------------------------------
  local n_images n_plats expected_children
  n_images="$(matrix_image_labels | wc -l | tr -d ' ')"
  n_plats="$(printf '%s' "$EXPECTED_PLATFORMS" | tr ',' '\n' | grep -c .)"
  expected_children=$(( n_images * n_plats ))

  # --- collect children ----------------------------------------------------
  # Empty discovery is a refusal, never an empty PASS.
  local files=() f
  while IFS= read -r f; do files+=("$f"); done < <(find "$dir" -name '*.json' -type f | sort)
  [ "${#files[@]}" -gt 0 ] || refusals+=("no child evidence found in '$dir' (empty discovery is never success)")

  local seen_keys=() seen_dbs=() key
  for f in "${files[@]:-}"; do
    [ -n "$f" ] || continue
    local c
    if ! c="$(jq -c . "$f" 2>/dev/null)"; then
      refusals+=("$(basename "$f"): not valid JSON"); continue
    fi

    local label platform ref mdig mtype tdig vis carch db rev rid ratt repo smoke scan recon meta esum
    label="$(jq -r '.image_label      // ""' <<<"$c")"
    platform="$(jq -r '.platform        // ""' <<<"$c")"
    ref="$(jq -r '.digest_reference     // ""' <<<"$c")"
    mdig="$(jq -r '.manifest_digest     // ""' <<<"$c")"
    mtype="$(jq -r '.manifest_media_type // ""' <<<"$c")"
    tdig="$(jq -r '.tag_resolved_digest // ""' <<<"$c")"
    vis="$(jq -r '.visibility           // ""' <<<"$c")"
    carch="$(jq -r '.config_architecture// ""' <<<"$c")"
    db="$(jq -r '.trivy_db_identity     // ""' <<<"$c")"
    rev="$(jq -r '.source_revision      // ""' <<<"$c")"
    rid="$(jq -r '.workflow_run_id      // ""' <<<"$c")"
    ratt="$(jq -r '.workflow_run_attempt// ""' <<<"$c")"
    repo="$(jq -r '.repository          // ""' <<<"$c")"
    smoke="$(jq -r '.smoke_test         // ""' <<<"$c")"
    scan="$(jq -r '.scan                // ""' <<<"$c")"
    recon="$(jq -r '.reconciliation     // ""' <<<"$c")"
    meta="$(jq -r '.metadata_contract   // ""' <<<"$c")"
    esum="$(jq -r '.evidence_sha256     // ""' <<<"$c")"

    local id="${label:-<unlabelled>}@${platform:-<no-platform>}"

    # identity + duplicates
    if [ -z "$label" ] || [ -z "$platform" ]; then
      refusals+=("$(basename "$f"): missing image_label or platform"); continue
    fi
    key="${label}|${platform}"
    case " ${seen_keys[*]:-} " in
      *" $key "*) refusals+=("$id: duplicate entry — one child per image/platform") ;;
      *) seen_keys+=("$key") ;;
    esac

    # provenance: this run, this attempt, this repo, this revision
    [ "$repo" = "$EXPECTED_REPOSITORY" ] || refusals+=("$id: repository '$repo' != expected '$EXPECTED_REPOSITORY'")
    [ "$rev"  = "$EXPECTED_REVISION" ]   || refusals+=("$id: source_revision '$rev' != expected '$EXPECTED_REVISION'")
    [ "$rid"  = "$EXPECTED_RUN_ID" ]     || refusals+=("$id: workflow_run_id '$rid' != expected '$EXPECTED_RUN_ID'")
    [ "$ratt" = "$EXPECTED_RUN_ATTEMPT" ] || refusals+=("$id: workflow_run_attempt '$ratt' != expected '$EXPECTED_RUN_ATTEMPT'")

    # references must be immutable and must name the staging package
    case "$ref" in
      "${EXPECTED_STAGING_PACKAGE}@sha256:"*) : ;;
      *"@sha256:"*) refusals+=("$id: digest_reference '$ref' is not in the staging package '$EXPECTED_STAGING_PACKAGE'") ;;
      *) refusals+=("$id: digest_reference '$ref' is mutable or malformed — a by-digest reference is required") ;;
    esac
    is_digest "$mdig" || refusals+=("$id: manifest_digest '$mdig' is not sha256:<64-hex>")
    is_digest "$tdig" || refusals+=("$id: tag_resolved_digest '$tdig' is not sha256:<64-hex>")
    if is_digest "$mdig" && is_digest "$tdig" && [ "$mdig" != "$tdig" ]; then
      refusals+=("$id: staging tag resolves to '$tdig' but the manifest digest is '$mdig' — the tag does not serve what was evaluated")
    fi
    case "$ref" in *"@${mdig}") : ;; *) refusals+=("$id: digest_reference does not end in the manifest digest") ;; esac

    # The digest must name a platform image, never an index.
    #
    # This matched on " $IMAGE_MEDIA_TYPES " — the ALLOWED LIST — so the
    # index-specific branch tested the list against itself and could never
    # classify the candidate. An index was still refused, by the generic branch,
    # so it was fail-closed; but the classification it claimed to make was not
    # the one it made, and the test passed by grepping for "index", a word the
    # media-type string itself contains.
    case "$mtype" in
      application/vnd.oci.image.manifest.v1+json|application/vnd.docker.distribution.manifest.v2+json)
        : ;;
      application/vnd.oci.image.index.v1+json|application/vnd.docker.distribution.manifest.list.v2+json)
        refusals+=("$id: refusing an INDEX digest '$mtype' — the record must describe a platform child manifest") ;;
      *)
        refusals+=("$id: unknown media type '${mtype:-<missing>}' — not an image manifest") ;;
    esac

    # quarantine must still be private
    [ "$vis" = private ] || refusals+=("$id: staging visibility is '$vis', not private")

    # the child must be the architecture it claims
    case "${platform#linux/}" in
      "$carch") : ;;
      *) refusals+=("$id: config architecture '$carch' does not match platform '$platform'") ;;
    esac

    # one frozen database for the whole record
    [ -n "$db" ] || refusals+=("$id: trivy_db_identity is empty")
    [ "$db" = "$EXPECTED_TRIVY_DB" ] || refusals+=("$id: trivy_db_identity '$db' != the run's frozen snapshot '$EXPECTED_TRIVY_DB'")
    case " ${seen_dbs[*]:-} " in *" $db "*) : ;; *) [ -n "$db" ] && seen_dbs+=("$db") ;; esac

    # per-child gates
    [ "$smoke" = PASS ] || refusals+=("$id: smoke_test is '$smoke'")
    [ "$scan"  = PASS ] || refusals+=("$id: scan is '$scan'")
    [ "$recon" = PASS ] || refusals+=("$id: reconciliation is '$recon' — an ungoverned vulnerability finding")
    [ "$meta"  = PASS ] || refusals+=("$id: metadata_contract is '$meta' (#126)")

    # --- CANONICAL CHILD IDENTITY -------------------------------------------
    # The producer names the artifact, the JSON record and the evidence
    # directory with child_slug() from scripts/lib/common.sh, which BINDS THE
    # PLATFORM. This consumer used to rebuild the slug locally as
    # "${label//\//-}" — the image_label form, which has no platform — so it
    # looked for 'caddy-prod-evidence' while the producer had written
    # 'caddy-prod-linux-amd64-evidence'. In run 32150666171 all twenty children
    # refused for that reason alone, with every image otherwise sound.
    #
    # There is now exactly ONE implementation of child identity. This consumer
    # recovers (family, selector) from the record's own image_label, recomputes
    # the canonical key and slug through the shared helper, and refuses when the
    # record's child_key disagrees with them. A record-supplied path is never
    # trusted, and a filename is never treated as identity.
    local fam ver ckey_rec ckey_canon cslug
    fam="${label%%/*}"; ver="${label#*/}"
    ckey_rec="$(jq -r '.child_key // ""' <<<"$c")"
    ckey_canon=""; cslug=""
    if ! ckey_canon="$(child_key  "$fam" "$ver" "$platform" 2>/dev/null)" ||
       ! cslug="$(child_slug "$fam" "$ver" "$platform" 2>/dev/null)"; then
      ckey_canon=""; cslug=""
      refusals+=("$id: cannot derive a canonical child identity from image_label '$label' and platform '$platform'")
    elif [ "$ckey_rec" != "$ckey_canon" ]; then
      refusals+=("$id: child_key '${ckey_rec:-<missing>}' disagrees with its family/selector/platform (canonical '$ckey_canon')")
    fi

    # The checksum is RECOMPUTED, not merely shape-checked. A well-formed but
    # invented 64-hex value used to pass, which made the binding decorative.
    if ! printf '%s' "$esum" | grep -Eq '^[0-9a-f]{64}$'; then
      refusals+=("$id: evidence_sha256 is missing or malformed")
    elif [ -z "$cslug" ]; then
      : # identity already refused above; a checksum without an identity is meaningless
    else
      local edir actual
      edir="${EVIDENCE_ROOT}/${cslug}-evidence"
      if [ ! -d "$edir" ]; then
        refusals+=("$id: no evidence directory at '${cslug}-evidence' to check the checksum against")
      else
        actual="$(evidence_checksum "$edir")"
        [ "$actual" = "$esum" ] \
          || refusals+=("$id: evidence_sha256 '$esum' does not match the evidence directory (recomputed '$actual')")
      fi
    fi

    children="$(jq -c --argjson c "$c" '. + [$c]' <<<"$children")"
  done

  # more than one database identity across children
  if [ "${#seen_dbs[@]}" -gt 1 ]; then
    refusals+=("children were evaluated against ${#seen_dbs[@]} different vulnerability database snapshots; one record cannot mix knowledge states")
  fi

  # --- completeness, against the DECLARED matrix ---------------------------
  local have="${#seen_keys[@]}"
  if [ "$have" -ne "$expected_children" ]; then
    refusals+=("expected $expected_children children ($n_images images x $n_plats platforms), found $have")
  fi
  local want_label want_plat
  while IFS= read -r want_label; do
    for want_plat in ${EXPECTED_PLATFORMS//,/ }; do
      case " ${seen_keys[*]:-} " in
        *" ${want_label}|${want_plat} "*) : ;;
        *) refusals+=("missing expected child: ${want_label} on ${want_plat}") ;;
      esac
    done
  done < <(matrix_image_labels)
  # unexpected extras
  local KNOWN_LABELS KNOWN_PLATFORMS
  KNOWN_LABELS="$(matrix_image_labels)"
  KNOWN_PLATFORMS="$(printf '%s' "$EXPECTED_PLATFORMS" | tr ',' '\n')"
  for key in "${seen_keys[@]:-}"; do
    [ -n "$key" ] || continue
    local kl="${key%|*}" kp="${key#*|}"
    # NOT `matrix_image_labels | grep -q`. `grep -q` exits at the first match,
    # the producer takes SIGPIPE, and `set -o pipefail` reports the pipeline as
    # failed — so a child that IS in the matrix was intermittently reported as
    # not being in it. Timing-dependent, so it passed on one platform and failed
    # on another. Here-strings have no pipeline to fail.
    if ! grep -qxF "$kl" <<<"$KNOWN_LABELS"; then
      refusals+=("unexpected child '$kl' is not in the image matrix")
    elif ! grep -qxF "$kp" <<<"$KNOWN_PLATFORMS"; then
      refusals+=("unexpected child '$kl' on unrequested platform '$kp'")
    fi
  done

  # --- native-architecture evidence, on the RELEASE path (#111) ------------
  # Runs on this run's own children, after they have been collected, so the
  # digests it binds against are exactly the digests being authorized.
  local ng_required=false ng_verdict=NOT_REQUIRED ng_covered=0 ng_expected=0 ng_records=0
  local ng_wants_arm=0
  case " ${EXPECTED_PLATFORMS//,/ } " in *" $NATIVE_PLATFORM "*) ng_wants_arm=1 ;; esac

  if ! ng_required="$(python3 - "$NATIVE_POLICY" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1])) or {}
print("true" if (d.get("release_gate") or {}).get("require_native_arm64") else "false")
PY
  )"; then
    # A gate that cannot read its own policy must refuse. Treating an unreadable
    # policy as "not required" is how a control silently switches itself off.
    ng_required=unreadable
    ng_verdict=FAIL
    refusals+=("the native-architecture policy at '$NATIVE_POLICY' is unreadable — an unreadable policy is a refusal, never a skipped gate")
  fi

  if [ "$ng_required" = true ] && [ "$ng_wants_arm" -eq 1 ]; then
    ng_verdict=FAIL
    if [ -z "${NATIVE_EVIDENCE_DIR:-}" ]; then
      refusals+=("policies/native-arch-requirements.yaml requires native $NATIVE_PLATFORM runtime evidence and this run requests $NATIVE_PLATFORM, but NATIVE_EVIDENCE_DIR was not supplied — the release path must PRESENT native evidence, and its absence is a refusal, not a pass")
    elif [ ! -d "$NATIVE_EVIDENCE_DIR" ]; then
      refusals+=("NATIVE_EVIDENCE_DIR '$NATIVE_EVIDENCE_DIR' does not exist — native $NATIVE_PLATFORM evidence is required and cannot be assumed")
    else
      local want_file gate_out line gate_rc=0 had_detail=0
      want_file="$(mktemp)"
      # The candidate set IS this run's arm64 children. Nothing external decides
      # which digests count, so evidence cannot be pointed at a friendlier build.
      jq --arg p "$NATIVE_PLATFORM" -c \
        '[.[] | select(.platform==$p and (.image_label|length>0) and (.manifest_digest|length>0))
              | {key:.image_label, value:.manifest_digest}] | from_entries' \
        <<<"$children" > "$want_file"
      ng_expected="$(jq 'length' "$want_file")"
      ng_records="$(find "$NATIVE_EVIDENCE_DIR" -maxdepth 1 -name '*.json' | wc -l | tr -d ' ')"

      gate_out="$(bash "$NATIVE_GATE" "$NATIVE_EVIDENCE_DIR" \
                    --require-native "$NATIVE_PLATFORM" --gate-release \
                    --expect-revision "$EXPECTED_REVISION" \
                    --expect-digests "$want_file" 2>&1)" || gate_rc=$?
      rm -f "$want_file"
      if [ "$gate_rc" -eq 0 ]; then
        ng_verdict=PASS
        ng_covered="$ng_expected"
      else
        # The gate's own diagnostics are carried through VERBATIM. A refusal that
        # says only "the native gate failed" cannot distinguish a wrong-digest
        # refusal from an unreadable file, which is the whole point of having a
        # diagnostic at all.
        while IFS= read -r line; do
          case "$line" in "  - "*) refusals+=("native-arch gate: ${line#  - }"); had_detail=1 ;; esac
        done <<<"$gate_out"
        if [ "$had_detail" -eq 0 ]; then
          while IFS= read -r line; do
            case "$line" in "REFUSE: "*) refusals+=("native-arch gate: ${line#REFUSE: }"); had_detail=1 ;; esac
          done <<<"$gate_out"
        fi
        [ "$had_detail" -eq 1 ] || refusals+=("native-arch gate: refused without a diagnostic (exit $gate_rc)")
      fi
    fi
  fi

  # --- verdict -------------------------------------------------------------
  local verdict=PASS
  [ "${#refusals[@]}" -eq 0 ] || verdict=FAIL

  local refusals_json='[]'
  if [ "${#refusals[@]}" -gt 0 ]; then
    refusals_json="$(printf '%s\n' "${refusals[@]}" | jq -R . | jq -sc .)"
  fi

  mkdir -p "$(dirname "$out")"
  jq -n \
    --arg repo "$EXPECTED_REPOSITORY" --arg rev "$EXPECTED_REVISION" \
    --argjson rid "$EXPECTED_RUN_ID" --argjson ratt "$EXPECTED_RUN_ATTEMPT" \
    --arg wref "$WORKFLOW_REF" --arg gen "$GENERATED_AT" \
    --arg bcreated "$BUILD_CREATED" \
    --arg db "$EXPECTED_TRIVY_DB" --arg pkg "$EXPECTED_STAGING_PACKAGE" \
    --argjson imgs "$n_images" \
    --argjson plats "$(printf '%s' "$EXPECTED_PLATFORMS" | tr ',' '\n' | jq -R . | jq -sc .)" \
    --argjson exp "$expected_children" \
    --argjson children "$children" --arg scope "$SCOPE" \
    --arg ngreq "$ng_required" --arg ngplat "$NATIVE_PLATFORM" \
    --arg ngverdict "$ng_verdict" --argjson ngcov "$ng_covered" \
    --argjson ngexp "$ng_expected" --argjson ngrec "$ng_records" \
    --arg verdict "$verdict" --argjson refusals "$refusals_json" '
    {schema_version: 1, repository: $repo, source_revision: $rev,
     workflow_run_id: $rid, workflow_run_attempt: $ratt, workflow_ref: $wref,
     generated_at: $gen, build_created: $bcreated,
     trivy_db_snapshot: {identity: $db, frozen: true},
     staging_package: $pkg,
     expected_matrix: {images: $imgs, platforms: $plats, expected_children: $exp},
     children: $children,
     native_arch_gate: {
       policy: "policies/native-arch-requirements.yaml",
       required: $ngreq, platform: $ngplat, verdict: $ngverdict,
       evidence_records: $ngrec,
       covered_images: $ngcov, expected_images: $ngexp
     },
     authorization_scope: $scope,
     public_exposure_authorized: false,
     verdict: $verdict}
    | if $verdict == "FAIL" then . + {refusals: $refusals} else . end' > "$out"

  if [ "$verdict" = FAIL ]; then
    printf 'REFUSED (%d):\n' "${#refusals[@]}" >&2
    printf '  - %s\n' "${refusals[@]}" >&2
    return 1
  fi
  log "AUTHORIZED: $have/$expected_children children eligible as $SCOPE (public exposure NOT authorized)"
}

# ---------------------------------------------------------------------------
# self-test
# ---------------------------------------------------------------------------
_asc_self_test() {
  local ok=0 bad=0 tmp; tmp="$(mktemp -d)"
  # expand NOW: the local is out of scope by EXIT time
  # shellcheck disable=SC2064
  trap "rm -rf '${tmp}'" EXIT
  local REV="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  local DIG SUM
  DIG="sha256:$(printf 'b%.0s' {1..64})"
  SUM="$(printf 'c%.0s' {1..64})"
  local PKG="ghcr.io/zenchron-dynamics/foundry-staging"

  export EXPECTED_REPOSITORY="zenchron-dynamics/zenchron-foundry" \
         EXPECTED_REVISION="$REV" EXPECTED_RUN_ID=1 EXPECTED_RUN_ATTEMPT=1 \
         EXPECTED_PLATFORMS="linux/amd64,linux/arm64" EXPECTED_STAGING_PACKAGE="$PKG" \
         EXPECTED_TRIVY_DB="db@2026-08-05" BUILD_CREATED="2026-08-06T00:00:00Z" \
         WORKFLOW_REF="$CANONICAL_WORKFLOW_REF" GENERATED_AT="2026-08-05T00:00:00Z"

  # Writes a full TWO-PLATFORM evidence set. $2/$3 mutate ONE child (the amd64
  # one) so "exactly one bad child" semantics survive the platform doubling.
  #
  # This fixture used to be single-platform, with platform:"linux/amd64" hard
  # coded and the evidence directory rebuilt as "${lbl//\//-}" — the SAME wrong
  # derivation the authorizer itself used. Producer and fixture agreed with each
  # other and both disagreed with reality, so the suite passed while every real
  # child refused. A single-platform fixture structurally cannot detect a
  # platform-collision defect; that is why this is now two-platform.
  _mk() { # _mk <dir> [label-to-mutate] [jq-filter]
    local d="$1" target="${2:-}" filt="${3:-.}" lbl plat i=0
    mkdir -p "$d"
    export EVIDENCE_ROOT="$d"
    while IFS= read -r lbl; do
      local fam="${lbl%%/*}" ver="${lbl#*/}"
      for plat in linux/amd64 linux/arm64; do
        i=$((i+1))
        local arch="${plat#linux/}" base slug edir ckey
        slug="$(child_slug "$fam" "$ver" "$plat")"
        ckey="$(child_key  "$fam" "$ver" "$plat")"
        edir="$d/${slug}-evidence"
        mkdir -p "$edir"; printf 'evidence for %s on %s\n' "$lbl" "$plat" > "$edir/log.txt"
        SUM="$(evidence_checksum "$edir")"
        base="$(jq -nc --arg l "$lbl" --arg ck "$ckey" --arg pl "$plat" --arg a "$arch" \
                  --arg d "$DIG" --arg s "$SUM" --arg p "$PKG" \
                  --arg rev "$REV" --arg repo "$EXPECTED_REPOSITORY" '{
          image_label:$l, child_key:$ck, platform:$pl,
          staging_tag:(($l|gsub("/";"-"))+"-r1-a1-saaaaaaa-"+$a),
          digest_reference:($p+"@"+$d), manifest_digest:$d, tag_resolved_digest:$d,
          visibility:"private", config_architecture:$a,
          manifest_media_type:"application/vnd.oci.image.manifest.v1+json",
          trivy_db_identity:"db@2026-08-05", source_revision:$rev,
          workflow_run_id:1, workflow_run_attempt:1, repository:$repo,
          smoke_test:"PASS", scan:"PASS", reconciliation:"PASS",
          metadata_contract:"PASS", evidence_sha256:$s}')"
        if [ -n "$target" ] && [ "$lbl" = "$target" ] && [ "$plat" = "linux/amd64" ]; then
          base="$(jq -c "$filt" <<<"$base")"
        fi
        printf '%s' "$base" > "$d/child-$i.json"
      done
    done < <(matrix_image_labels)
    _mk_native "$d"
  }

  # NATIVE ARM64 RUNTIME EVIDENCE for the same candidate digests (#111). The
  # release gate now requires it whenever linux/arm64 is requested, so the
  # fixture has to be able to SATISFY it — a fixture that never could would only
  # prove the gate refuses everything, which is not the property under test.
  # The directory is a SIBLING of the child-evidence directory, never inside it:
  # the authorizer collects children with an unbounded `find`, so native records
  # nested under the evidence root would be read back as malformed children and
  # the gate would appear to fail for a reason that was never under test.
  _mk_native() { # _mk_native <dir> [label-to-mutate] [jq-filter]
    local d="${1}-native" target="${2:-}" filt="${3:-.}" lbl rec
    mkdir -p "$d"
    while IFS= read -r lbl; do
      rec="$(jq -nc --arg l "$lbl" --arg ck "$lbl/linux/arm64" --arg dg "$DIG" \
                    --arg p "$PKG" --arg rev "$REV" '{
        record_type:"native-arch-runtime-evidence",
        child_key:$ck, image_label:$l, platform:"linux/arm64",
        host_architecture:"arm64", execution_mode:"native",
        architecture_source:"measured", uname_m:"aarch64",
        runner_kind:"ephemeral-hosted", runner_label:"ubuntu-24.04-arm",
        source_revision:$rev, manifest_digest:$dg,
        digest_reference:($p+"@"+$dg), runtime_smoke:"PASS", authoritative:true}')"
      if [ -n "$target" ] && [ "$lbl" = "$target" ]; then
        rec="$(jq -c "$filt" <<<"$rec")"
      fi
      printf '%s' "$rec" > "$d/$(printf '%s' "$lbl" | tr '/' '-').json"
    done < <(matrix_image_labels)
    export NATIVE_EVIDENCE_DIR="$d"
  }

  # Assert a refusal by its DIAGNOSTIC, not merely by a non-zero exit. A test
  # that accepts any failure cannot tell a wrong-architecture refusal from a
  # typo in the fixture.
  tr_() { # tr_ <name> <dir> <substring the refusal must contain>
    local name="$1" d="$2" want="$3"
    authorize "$d" "$d/out.json" >/dev/null 2>&1 || true
    if [ -s "$d/out.json" ] \
       && [ "$(jq -r .verdict "$d/out.json")" = FAIL ] \
       && jq -e --arg w "$want" 'any(.refusals[]?; contains($w))' "$d/out.json" >/dev/null 2>&1; then
      echo "ok   - $name"; ok=$((ok+1))
    else
      echo "FAIL - $name (no refusal containing '$want')"; bad=$((bad+1))
    fi
  }

  t() { # t <name> <expect pass|fail> <dir>
    local name="$1" expect="$2" d="$3"
    if ( authorize "$d" "$d/out.json" >/dev/null 2>&1 ); then
      [ "$expect" = pass ] && { echo "ok   - $name"; ok=$((ok+1)); return; }
    else
      [ "$expect" = fail ] && { echo "ok   - $name"; ok=$((ok+1)); return; }
    fi
    echo "FAIL - $name (expected $expect)"; bad=$((bad+1))
  }

  local d="$tmp/happy"; _mk "$d"; t "a complete, consistent matrix is authorized" pass "$d"
  [ "$(jq -r .verdict "$d/out.json")" = PASS ] \
    && { echo "ok   - ...verdict PASS"; ok=$((ok+1)); } || { echo "FAIL - ...verdict PASS"; bad=$((bad+1)); }
  [ "$(jq -r .authorization_scope "$d/out.json")" = "$SCOPE" ] \
    && { echo "ok   - ...scope is the single legal value"; ok=$((ok+1)); } || { echo "FAIL - scope"; bad=$((bad+1)); }
  [ "$(jq -r .public_exposure_authorized "$d/out.json")" = false ] \
    && { echo "ok   - ...public exposure NOT authorized"; ok=$((ok+1)); } || { echo "FAIL - exposure"; bad=$((bad+1)); }

  d="$tmp/missing"; _mk "$d"; rm -f "$d/child-1.json"
  t "a missing expected child refuses" fail "$d"

  d="$tmp/extra"; _mk "$d"
  jq -c '.image_label="not-an-image/prod"' "$d/child-1.json" > "$d/child-99.json"
  t "an unexpected extra child refuses" fail "$d"

  d="$tmp/dup"; _mk "$d"; cp "$d/child-1.json" "$d/child-dup.json"
  t "a duplicate image/platform refuses" fail "$d"

  d="$tmp/run"; _mk "$d" "nginx/prod" '.workflow_run_id=999'
  t "evidence from another run refuses" fail "$d"

  d="$tmp/att"; _mk "$d" "nginx/prod" '.workflow_run_attempt=2'
  t "evidence from another attempt refuses" fail "$d"

  d="$tmp/repo"; _mk "$d" "nginx/prod" '.repository="someone/else"'
  t "evidence from another repository refuses" fail "$d"

  d="$tmp/sha"; _mk "$d" "nginx/prod" '.source_revision="0000000000000000000000000000000000000000"'
  t "evidence from another source revision refuses" fail "$d"

  d="$tmp/mutable"; _mk "$d" "nginx/prod" '.digest_reference="ghcr.io/zenchron-dynamics/foundry-staging:sometag"'
  t "a mutable-only reference refuses" fail "$d"

  d="$tmp/otherpkg"; _mk "$d" "nginx/prod" '.digest_reference=("ghcr.io/zenchron-dynamics/php-fpm@"+.manifest_digest)'
  t "a reference outside the staging package refuses" fail "$d"

  d="$tmp/tagdig"; _mk "$d" "nginx/prod" '.tag_resolved_digest="sha256:'"$(printf 'd%.0s' {1..64})"'"'
  t "staging tag/digest disagreement refuses" fail "$d"

  d="$tmp/vis"; _mk "$d" "nginx/prod" '.visibility="public"'
  t "non-private staging visibility refuses" fail "$d"

  d="$tmp/arch"; _mk "$d" "nginx/prod" '.config_architecture="arm64"'
  t "digest architecture mismatch refuses" fail "$d"

  d="$tmp/db"; _mk "$d" "nginx/prod" '.trivy_db_identity="db@2026-01-01"'
  t "a different vulnerability database snapshot refuses" fail "$d"

  d="$tmp/smoke"; _mk "$d" "nginx/prod" '.smoke_test="FAIL"'
  t "a failed smoke test refuses" fail "$d"

  d="$tmp/recon"; _mk "$d" "nginx/prod" '.reconciliation="FAIL"'
  t "an unreconciled vulnerability finding refuses" fail "$d"

  d="$tmp/scan"; _mk "$d" "nginx/prod" '.scan="FAIL"'
  t "a failed scan refuses" fail "$d"

  d="$tmp/meta"; _mk "$d" "nginx/prod" '.metadata_contract="FAIL"'
  t "a metadata contract mismatch refuses (#126)" fail "$d"

  d="$tmp/sum"; _mk "$d" "nginx/prod" 'del(.evidence_sha256)'
  t "a missing evidence checksum refuses" fail "$d"

  d="$tmp/index"; _mk "$d" "nginx/prod" '.manifest_media_type="application/vnd.oci.image.index.v1+json"'
  t "an INDEX digest refuses (it is not a platform child)" fail "$d"

  d="$tmp/mlist"; _mk "$d" "nginx/prod" '.manifest_media_type="application/vnd.docker.distribution.manifest.list.v2+json"'
  t "a docker manifest list refuses" fail "$d"

  d="$tmp/nomtype"; _mk "$d" "nginx/prod" 'del(.manifest_media_type)'
  t "a missing manifest media type refuses" fail "$d"

  # THE case that made the checksum decorative: well-formed, plausible, wrong.
  d="$tmp/badsum"; _mk "$d" "nginx/prod" '.evidence_sha256="'"$(printf 'e%.0s' {1..64})"'"'
  t "a well-formed but INCORRECT evidence checksum refuses" fail "$d"

  d="$tmp/nodir"; _mk "$d"; rm -rf "$d/nginx-prod-linux-amd64-evidence"
  t "a checksum with no evidence directory to check against refuses" fail "$d"

  d="$tmp/tampered"; _mk "$d"; printf 'tampered\n' >> "$d/nginx-prod-linux-amd64-evidence/log.txt"
  t "evidence altered after the checksum was taken refuses" fail "$d"

  d="$tmp/wfref"; _mk "$d"
  ( export WORKFLOW_REF="zenchron-dynamics/zenchron-foundry/.github/workflows/stage-and-authorize.yml@refs/heads/some-branch"
    ! authorize "$d" "$d/out.json" >/dev/null 2>&1 ) \
    && { echo "ok   - a non-canonical workflow identity refuses"; ok=$((ok+1)); } \
    || { echo "FAIL - workflow identity"; bad=$((bad+1)); }

  d="$tmp/empty"; mkdir -p "$d"; export EVIDENCE_ROOT="$d"
  t "empty evidence discovery refuses, never an empty PASS" fail "$d"

  d="$tmp/badjson"; _mk "$d"; printf 'not json' > "$d/child-1.json"
  t "malformed evidence refuses" fail "$d"

  # Architecture policy is on the REQUESTED MATRIX. This used linux/arm64, which
  # stopped proving anything once arm64 gained evidence (#139) — it would still
  # have refused, but on the child-count mismatch, so the assertion would have
  # passed for the wrong reason. It now uses a platform that genuinely has no
  # evidence, and checks the refusal REASON rather than just the exit status.
  d="$tmp/arm"; _mk "$d"
  ( export EXPECTED_PLATFORMS="linux/s390x"
    ! authorize "$d" "$d/out.json" >/dev/null 2>&1 ) \
    && { echo "ok   - an unevidenced architecture refuses the WHOLE matrix"; ok=$((ok+1)); } \
    || { echo "FAIL - unevidenced-architecture matrix"; bad=$((bad+1)); }
  if [ -s "$d/out.json" ] && jq -e '.refusals[]?|select(contains("unsupported architecture"))' "$d/out.json" >/dev/null 2>&1; then
    echo "ok   - ...and says so, rather than refusing for an unrelated reason"; ok=$((ok+1))
  else
    echo "FAIL - unevidenced architecture refused without naming the architecture"; bad=$((bad+1))
  fi

  # The evidenced architectures must NOT be refused — the inverse mistake, and
  # the one that would silently block every release.
  # The fixture is two-platform, so narrowing the expectation to one platform
  # must also narrow the evidence — otherwise this asserts "extras are refused",
  # which is a different test that already exists.
  d="$tmp/amd64only"; _mk "$d"
  rm -rf "$d"/*-linux-arm64-evidence
  for _f in "$d"/child-*.json; do
    [ "$(jq -r .platform "$_f")" = "linux/arm64" ] && rm -f "$_f"
  done
  ( export EXPECTED_PLATFORMS="linux/amd64"
    authorize "$d" "$d/out.json" >/dev/null 2>&1 ) \
    && { echo "ok   - an evidenced architecture is NOT refused"; ok=$((ok+1)); } \
    || { echo "FAIL - evidenced architecture was refused"; bad=$((bad+1)); }
  d="$tmp/arm64only"; _mk "$d"
  rm -rf "$d"/*-linux-amd64-evidence
  for _f in "$d"/child-*.json; do
    [ "$(jq -r .platform "$_f")" = "linux/amd64" ] && rm -f "$_f"
  done
  ( export EXPECTED_PLATFORMS="linux/arm64"
    authorize "$d" "$d/out.json" >/dev/null 2>&1 ) \
    && { echo "ok   - linux/arm64 alone is also evidenced, not refused"; ok=$((ok+1)); } \
    || { echo "FAIL - linux/arm64 was refused"; bad=$((bad+1)); }

  # --- THE NATIVE-ARCHITECTURE GATE, ON THE CANONICAL RELEASE PATH (#111) ---
  # Every one of these asserts the INTENDED DIAGNOSTIC. Exit status alone cannot
  # distinguish a wrong-architecture refusal from a broken fixture.
  d="$tmp/n-ok"; _mk "$d"
  authorize "$d" "$d/out.json" >/dev/null 2>&1 || true
  if [ "$(jq -r .native_arch_gate.verdict "$d/out.json")" = PASS ] \
     && [ "$(jq -r .native_arch_gate.required "$d/out.json")" = true ] \
     && [ "$(jq -r .native_arch_gate.covered_images "$d/out.json")" = "$(jq -r .native_arch_gate.expected_images "$d/out.json")" ]; then
    echo "ok   - the authorization record REPORTS the native gate result, not just the verdict"; ok=$((ok+1))
  else echo "FAIL - native gate result missing from the record"; bad=$((bad+1)); fi

  d="$tmp/n-absent"; _mk "$d"; rm -rf "${d}-native"
  ( export NATIVE_EVIDENCE_DIR=""
    authorize "$d" "$d/out.json" >/dev/null 2>&1 ) || true
  if jq -e 'any(.refusals[]?; contains("NATIVE_EVIDENCE_DIR was not supplied"))' "$d/out.json" >/dev/null 2>&1; then
    echo "ok   - a release path that presents NO native evidence is REFUSED, not skipped"; ok=$((ok+1))
  else echo "FAIL - missing native evidence did not refuse by name"; bad=$((bad+1)); fi

  d="$tmp/n-qemu"; _mk "$d"
  _mk_native "$d" "nginx/prod" '.execution_mode="qemu" | .host_architecture="amd64"'
  tr_ "QEMU evidence does not satisfy the release native requirement" "$d" "ran emulated"

  d="$tmp/n-emulated"; _mk "$d"
  _mk_native "$d" "nginx/prod" '.execution_mode="emulated" | .host_architecture="amd64"'
  tr_ "...and the 'emulated' spelling is diagnosed as emulation too" "$d" "ran emulated"

  d="$tmp/n-partial"; _mk "$d"; rm -f "${d}-native/nginx-prod.json"
  tr_ "9 of 10 native results is a REFUSAL, not a pass" "$d" \
      "a partial native result is a refusal, not a pass"

  d="$tmp/n-digest"; _mk "$d"
  _mk_native "$d" "nginx/prod" '.manifest_digest="sha256:'"$(printf 'f%.0s' {1..64})"'"'
  tr_ "native evidence for another digest REFUSES" "$d" \
      "evidence for another digest cannot authorize this one"

  d="$tmp/n-rev"; _mk "$d"
  _mk_native "$d" "nginx/prod" '.source_revision="0000000000000000000000000000000000000000"'
  tr_ "native evidence for another source revision REFUSES" "$d" \
      "evidence for another source cannot authorize this one"

  d="$tmp/n-plat"; _mk "$d"
  _mk_native "$d" "nginx/prod" '.platform="linux/amd64" | .host_architecture="amd64"'
  tr_ "native evidence for another platform REFUSES" "$d" \
      "evidence for another platform cannot satisfy it"

  d="$tmp/n-label"; _mk "$d"
  _mk_native "$d" "nginx/prod" '.architecture_source="runner-label"'
  tr_ "architecture inferred from the runner label REFUSES" "$d" \
      "execution_mode must never be inferred from it"

  d="$tmp/n-uname"; _mk "$d"
  _mk_native "$d" "nginx/prod" '.uname_m="x86_64"'
  tr_ "a uname -m that contradicts the claimed host REFUSES" "$d" \
      "the measurement and the claim disagree"

  d="$tmp/n-ident"; _mk "$d"
  _mk_native "$d" "nginx/prod" 'del(.runner_kind)'
  tr_ "native evidence that does not identify its runner kind REFUSES" "$d" \
      "native evidence does not identify runner_kind"

  d="$tmp/n-auth"; _mk "$d"
  _mk_native "$d" "nginx/prod" '.authoritative=false'
  tr_ "branch (non-authoritative) native evidence cannot gate a release" "$d" \
      "produced on a non-default ref and cannot gate a release"

  d="$tmp/n-policy"; _mk "$d"
  ( export NATIVE_POLICY="$tmp/no-such-policy.yaml"
    authorize "$d" "$d/out.json" >/dev/null 2>&1 ) || true
  if jq -e 'any(.refusals[]?; contains("unreadable policy is a refusal"))' "$d/out.json" >/dev/null 2>&1; then
    echo "ok   - an unreadable native-arch policy REFUSES rather than switching the gate off"; ok=$((ok+1))
  else echo "FAIL - unreadable policy did not refuse"; bad=$((bad+1)); fi

  # NON-VACUITY: with the policy saying native is NOT required, the same
  # emulated evidence is authorized. The gate is reading the policy, not simply
  # refusing everything.
  d="$tmp/n-off"; _mk "$d"
  _mk_native "$d" "nginx/prod" '.execution_mode="qemu" | .host_architecture="amd64"'
  python3 - "$NATIVE_POLICY" "$tmp/off.yaml" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
d["release_gate"]["require_native_arm64"] = False
yaml.safe_dump(d, open(sys.argv[2], "w"))
PY
  ( export NATIVE_POLICY="$tmp/off.yaml"
    authorize "$d" "$d/out.json" >/dev/null 2>&1 ) \
    && { echo "ok   - NON-VACUOUS: with require_native_arm64 false the same evidence passes"; ok=$((ok+1)); } \
    || { echo "FAIL - the gate refuses regardless of policy"; bad=$((bad+1)); }
  if [ "$(jq -r .native_arch_gate.verdict "$d/out.json")" = NOT_REQUIRED ]; then
    echo "ok   - ...and the record says NOT_REQUIRED rather than implying it ran"; ok=$((ok+1))
  else echo "FAIL - NOT_REQUIRED not recorded"; bad=$((bad+1)); fi

  # a FAIL record is still written
  d="$tmp/writefail"; _mk "$d"; rm -f "$d/child-1.json"
  authorize "$d" "$d/out.json" >/dev/null 2>&1 || true
  if [ -s "$d/out.json" ] && [ "$(jq -r .verdict "$d/out.json")" = FAIL ] \
     && [ "$(jq '.refusals|length' "$d/out.json")" -gt 0 ]; then
    echo "ok   - a FAIL record is written, with its reasons"; ok=$((ok+1))
  else echo "FAIL - FAIL record"; bad=$((bad+1)); fi

  # mandatory expectations
  # `die` exits the subshell, so the status has to be captured by `if` — a `!`
  # in front of the call never runs.
  d="$tmp/mand"; _mk "$d"
  local mv
  for mv in EXPECTED_TRIVY_DB EXPECTED_REPOSITORY EXPECTED_REVISION \
            EXPECTED_STAGING_PACKAGE WORKFLOW_REF BUILD_CREATED EVIDENCE_ROOT; do
    if ( unset "$mv"; authorize "$d" "$d/out.json" ) >/dev/null 2>&1; then
      echo "FAIL - omitting $mv should refuse"; bad=$((bad+1))
    else
      echo "ok   - omitting $mv refuses"; ok=$((ok+1))
    fi
  done

  echo "self-test: $ok ok, $bad failed"
  [ "$bad" -eq 0 ]
}

case "${1:-}" in
  --self-test) _asc_self_test && echo "authorize-staged-candidates.sh: SELF-TEST OK" ;;
  "") echo "usage: authorize-staged-candidates.sh <child-evidence-dir> <output.json> | --self-test" >&2; exit 2 ;;
  *) authorize "$@" ;;
esac
